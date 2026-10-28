// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::{ActivateResult, InterruptTransport, Queue};
use crate::virtio::AsAny;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

/// Configuration for a single virtqueue.
/// This is used by devices to declare their queue requirements,
/// and by the transport to construct the actual queues.
#[derive(Clone, Copy, Debug)]
pub struct QueueConfig {
    /// Maximum size of the queue.
    pub size: u16,
}

impl QueueConfig {
    pub const fn new(size: u16) -> Self {
        Self { size }
    }
}

/// A virtqueue combined with its notification eventfd.
/// This is passed to devices during activation.
pub struct DeviceQueue {
    pub queue: Queue,
    pub event: Arc<EventFd>,
}

impl DeviceQueue {
    pub fn new(queue: Queue, event: Arc<EventFd>) -> Self {
        Self { queue, event }
    }
}

const QUEUE_NOTIFICATION_TIMING_SAMPLE_STRIDE: u64 = 64;

#[derive(Clone, Copy, Debug, Default)]
pub struct QueueNotificationTimingSnapshot {
    pub notify_to_eventfd_samples: u64,
    pub notify_to_eventfd_sample_ns: u64,
    pub notify_to_eventfd_max_ns: u64,
    pub eventfd_write_samples: u64,
    pub eventfd_write_sample_ns: u64,
    pub eventfd_write_max_ns: u64,
    pub notify_while_worker_waiting_samples: u64,
    pub notify_while_worker_busy_samples: u64,
    pub notify_to_kqueue_ready_samples: u64,
    pub notify_to_kqueue_ready_sample_ns: u64,
    pub notify_to_kqueue_ready_max_ns: u64,
    pub kqueue_ready_to_eventfd_samples: u64,
    pub kqueue_ready_to_eventfd_sample_ns: u64,
    pub kqueue_ready_to_eventfd_max_ns: u64,
    pub irq_to_next_notify_samples: u64,
    pub irq_to_next_notify_sample_ns: u64,
    pub irq_to_next_notify_max_ns: u64,
}

#[derive(Default)]
struct QueueNotificationTimingState {
    sampled_notify_sequence: u64,
    sampled_notify_started: Option<Instant>,
    sampled_kqueue_ready_sequence: u64,
    sampled_kqueue_ready_started: Option<Instant>,
    pending_irq_started: Option<Instant>,
    snapshot: QueueNotificationTimingSnapshot,
}

/// Optional low-overhead queue-notification counter used by targeted profiling.
#[derive(Default)]
pub struct QueueNotificationCounter {
    enabled: AtomicBool,
    count: AtomicU64,
    irq_sample_pending: AtomicBool,
    worker_waiting: AtomicBool,
    timing: Mutex<QueueNotificationTimingState>,
}

impl QueueNotificationCounter {
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    pub fn set_worker_waiting(&self, waiting: bool) {
        self.worker_waiting.store(waiting, Ordering::Release);
    }

    pub fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.irq_sample_pending.store(false, Ordering::Relaxed);
        self.worker_waiting.store(false, Ordering::Relaxed);
        *self.timing.lock().unwrap() = QueueNotificationTimingState::default();
    }

    pub fn increment(&self) -> Option<u64> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }

        let sequence = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let sample_notify = sequence % QUEUE_NOTIFICATION_TIMING_SAMPLE_STRIDE == 0;
        let consume_irq = self.irq_sample_pending.swap(false, Ordering::AcqRel);
        if !sample_notify && !consume_irq {
            return None;
        }

        let now = Instant::now();
        let mut timing = self.timing.lock().unwrap();
        if consume_irq {
            if let Some(started) = timing.pending_irq_started.take() {
                let elapsed = now.duration_since(started).as_nanos() as u64;
                timing.snapshot.irq_to_next_notify_samples += 1;
                timing.snapshot.irq_to_next_notify_sample_ns += elapsed;
                timing.snapshot.irq_to_next_notify_max_ns =
                    timing.snapshot.irq_to_next_notify_max_ns.max(elapsed);
            }
        }
        if sample_notify {
            if self.worker_waiting.load(Ordering::Acquire) {
                timing.snapshot.notify_while_worker_waiting_samples += 1;
            } else {
                timing.snapshot.notify_while_worker_busy_samples += 1;
            }
            timing.sampled_notify_sequence = sequence;
            timing.sampled_notify_started = Some(now);
            timing.sampled_kqueue_ready_sequence = 0;
            timing.sampled_kqueue_ready_started = None;
            Some(sequence)
        } else {
            None
        }
    }

    pub fn record_eventfd_write(&self, sequence: u64, elapsed_ns: u64) {
        if !self.enabled.load(Ordering::Acquire)
            || sequence % QUEUE_NOTIFICATION_TIMING_SAMPLE_STRIDE != 0
        {
            return;
        }

        let mut timing = self.timing.lock().unwrap();
        if timing.sampled_notify_sequence != sequence {
            return;
        }
        timing.snapshot.eventfd_write_samples += 1;
        timing.snapshot.eventfd_write_sample_ns += elapsed_ns;
        timing.snapshot.eventfd_write_max_ns =
            timing.snapshot.eventfd_write_max_ns.max(elapsed_ns);
    }

    pub fn observe_kqueue_ready(&self, eventfd_sequence: u64) {
        if !self.enabled.load(Ordering::Acquire)
            || eventfd_sequence % QUEUE_NOTIFICATION_TIMING_SAMPLE_STRIDE != 0
        {
            return;
        }

        let now = Instant::now();
        let mut timing = self.timing.lock().unwrap();
        if timing.sampled_notify_sequence != eventfd_sequence {
            return;
        }
        if let Some(started) = timing.sampled_notify_started {
            let elapsed = now.duration_since(started).as_nanos() as u64;
            timing.snapshot.notify_to_kqueue_ready_samples += 1;
            timing.snapshot.notify_to_kqueue_ready_sample_ns += elapsed;
            timing.snapshot.notify_to_kqueue_ready_max_ns =
                timing.snapshot.notify_to_kqueue_ready_max_ns.max(elapsed);
            timing.sampled_kqueue_ready_sequence = eventfd_sequence;
            timing.sampled_kqueue_ready_started = Some(now);
        }
    }

    pub fn observe_eventfd(&self, eventfd_sequence: u64, value: u64) {
        if !self.enabled.load(Ordering::Acquire)
            || value != 1
            || eventfd_sequence % QUEUE_NOTIFICATION_TIMING_SAMPLE_STRIDE != 0
        {
            return;
        }

        let mut timing = self.timing.lock().unwrap();
        if timing.sampled_notify_sequence != eventfd_sequence {
            return;
        }
        if timing.sampled_kqueue_ready_sequence == eventfd_sequence {
            if let Some(started) = timing.sampled_kqueue_ready_started.take() {
                let elapsed = started.elapsed().as_nanos() as u64;
                timing.snapshot.kqueue_ready_to_eventfd_samples += 1;
                timing.snapshot.kqueue_ready_to_eventfd_sample_ns += elapsed;
                timing.snapshot.kqueue_ready_to_eventfd_max_ns =
                    timing.snapshot.kqueue_ready_to_eventfd_max_ns.max(elapsed);
            }
        }
        if let Some(started) = timing.sampled_notify_started.take() {
            let elapsed = started.elapsed().as_nanos() as u64;
            timing.snapshot.notify_to_eventfd_samples += 1;
            timing.snapshot.notify_to_eventfd_sample_ns += elapsed;
            timing.snapshot.notify_to_eventfd_max_ns =
                timing.snapshot.notify_to_eventfd_max_ns.max(elapsed);
        }
    }

    pub fn record_irq_signal(&self, signal_sequence: u64) {
        if !self.enabled.load(Ordering::Acquire)
            || signal_sequence % QUEUE_NOTIFICATION_TIMING_SAMPLE_STRIDE != 0
        {
            return;
        }

        let mut timing = self.timing.lock().unwrap();
        timing.pending_irq_started = Some(Instant::now());
        self.irq_sample_pending.store(true, Ordering::Release);
    }

    pub fn load(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn timing_snapshot(&self) -> QueueNotificationTimingSnapshot {
        self.timing.lock().unwrap().snapshot
    }
}

/// Enum that indicates if a VirtioDevice is inactive or has been activated
/// and memory attached to it.
pub enum DeviceState {
    Inactive,
    Activated(GuestMemoryMmap, InterruptTransport),
}

impl DeviceState {
    pub fn signal_used_queue(&self) {
        match self {
            Self::Inactive => {
                warn!("DeviceState::signal_used_queue() called, but device is not activated")
            }
            Self::Activated(_, ref interrupt) => interrupt.signal_used_queue(),
        }
    }
}

impl DeviceState {
    pub fn is_activated(&self) -> bool {
        matches!(self, DeviceState::Activated(..))
    }
}

#[derive(Clone)]
pub struct VirtioShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. The transport constructs queues based on queue_config() and passes them to the device
/// during activation, transferring ownership. After reset, the transport recreates queues
/// from queue_config() for the next negotiation cycle.
pub trait VirtioDevice: AsAny + Send {
    /// Get the available features offered by device.
    fn avail_features(&self) -> u64;

    /// Get acknowledged features of the driver.
    fn acked_features(&self) -> u64;

    /// Set acknowledged features of the driver.
    /// This function must maintain the following invariant:
    /// - self.avail_features() & self.acked_features() = self.get_acked_features()
    fn set_acked_features(&mut self, acked_features: u64);

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// Device name used for logging information about the device at the transport layer
    fn device_name(&self) -> &str;

    /// Returns the queue configuration for this device.
    /// The transport uses this to construct the queues during initialization and after reset.
    fn queue_config(&self) -> &[QueueConfig];

    /// Optionally exposes a profiling counter for guest notifications to one queue.
    fn queue_notification_counter(
        &self,
        _queue_index: usize,
    ) -> Option<Arc<QueueNotificationCounter>> {
        None
    }

    /// The set of feature bits shifted by `page * 32`.
    fn avail_features_by_page(&self, page: u32) -> u32 {
        let avail_features = self.avail_features();
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features_by_page(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {page}");
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let avail_features = self.avail_features();
        let unrequested_features = v & !avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {v:x}");
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.set_acked_features(self.acked_features() | v);
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Performs the formal activation for a device, which can be verified also with `is_activated`.
    /// Ownership of the queues is transferred to the device.
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult;

    /// Checks if the resources of this device are activated.
    fn is_activated(&self) -> bool;

    /// Optionally deactivates this device. The device should drop its queues.
    /// After reset, the transport will recreate queues from queue_config().
    fn reset(&mut self) -> bool {
        false
    }

    /// Get base and size of the SHM region
    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        None
    }
}

pub trait VmmExitObserver: Send {
    /// Callback to finish processing or cleanup the device resources
    fn on_vmm_exit(&mut self) {}
}

impl<F: Fn() + Send> VmmExitObserver for F {
    fn on_vmm_exit(&mut self) {
        self()
    }
}

impl std::fmt::Debug for dyn VirtioDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "VirtioDevice type {}", self.device_type())
    }
}
