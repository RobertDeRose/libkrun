// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::virtio::net::Result;
use crate::virtio::net::{CTRL_QUEUE_SIZE, QUEUE_SIZE};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice, TYPE_NET,
};
use crate::Error as DeviceError;

use super::backend::{ReadError, WriteError};
use super::stats::NetTxStatsHandle;
use super::worker::NetWorker;

use std::cmp;
#[cfg(target_os = "macos")]
use std::ffi::c_void;
use std::io::Write;
use std::os::fd::RawFd;
use std::path::PathBuf;
use virtio_bindings::virtio_net::{VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_MAC, VIRTIO_NET_F_MQ};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_RING_PACKED: u32 = 34;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

/// Writes one frame to vmnet from the worker thread: no copy into a staging
/// buffer, no datagram hop to the bridge thread. The function borrows the iovecs
/// only for the call; the bridge outlives every virtio-net device using it.
/// Mirror of vmnet's `struct vmpktdesc`.
#[cfg(target_os = "macos")]
#[repr(C)]
pub struct VmPktDesc {
    pub vm_pkt_size: usize,
    pub vm_pkt_iov: *mut libc::iovec,
    pub vm_pkt_iovcnt: u32,
    pub vm_flags: u32,
}

#[cfg(target_os = "macos")]
pub type VmnetRxSink = unsafe extern "C" fn(*mut c_void, *const VmPktDesc, usize);

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
pub struct VmnetDirectTx {
    pub bridge: *mut c_void,
    pub write_iov:
        unsafe extern "C" fn(*mut c_void, *const libc::iovec, usize, usize) -> i32,
    /// Routes received frames to a sink on the bridge's receive queue instead
    /// of the socket pair. None keeps receive on the socket pair.
    pub set_rx_sink: Option<unsafe extern "C" fn(*mut c_void, Option<VmnetRxSink>, *mut c_void) -> i32>,
    /// Writes several frames with one vmnet_write; reports how many leading
    /// frames were accepted.
    pub write_batch: unsafe extern "C" fn(*mut c_void, *const VmPktDesc, usize, *mut usize) -> i32,
}

// SAFETY: the bridge pointer is only passed back to C, which serializes
// internally. Rust never dereferences it.
#[cfg(target_os = "macos")]
unsafe impl Send for VmnetDirectTx {}

#[cfg(target_os = "macos")]
impl VmnetDirectTx {
    /// Write a batch; returns how many leading frames vmnet accepted (0 = full).
    pub fn write_frames(&self, packets: &[VmPktDesc]) -> std::result::Result<usize, WriteError> {
        let mut written = 0usize;
        // SAFETY: packets and their iovecs point into guest memory or worker
        // buffers, all valid for this synchronous call.
        let result = unsafe { (self.write_batch)(self.bridge, packets.as_ptr(), packets.len(), &mut written) };
        match result {
            0 => Ok(written),
            r if r == -libc::EPIPE => Err(WriteError::ProcessNotRunning),
            r if r < 0 => Err(WriteError::Internal(nix::Error::from_raw(-r))),
            _ => Err(WriteError::Internal(nix::Error::EIO)),
        }
    }

    /// Write one frame; a full vmnet reports NothingWritten for the retry path.
    pub fn write(&self, iovs: &[libc::iovec], frame_len: usize) -> std::result::Result<(), WriteError> {
        // SAFETY: iovs point into guest memory or a worker buffer, both valid
        // for the duration of this synchronous call.
        let result = unsafe { (self.write_iov)(self.bridge, iovs.as_ptr(), iovs.len(), frame_len) };
        match result {
            0 => Ok(()),
            r if r == -libc::ENOBUFS || r == -libc::EAGAIN => Err(WriteError::NothingWritten),
            r if r == -libc::EPIPE => Err(WriteError::ProcessNotRunning),
            r if r < 0 => Err(WriteError::Internal(nix::Error::from_raw(-r))),
            _ => Err(WriteError::Internal(nix::Error::EIO)),
        }
    }
}

#[derive(Clone)]
pub enum VirtioNetBackend {
    UnixstreamFd(RawFd),
    UnixstreamPath(PathBuf),
    UnixgramFd(RawFd),
    #[cfg(target_os = "macos")]
    VmnetFd {
        fd: RawFd,
        /// Opaque native bridge plus a direct frame writer, or None to send
        /// TX frames through the bridge's socketpair.
        direct_tx: Option<VmnetDirectTx>,
    },
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,
    tx_stats: NetTxStatsHandle,
    /// RX/TX queue pairs offered to the guest. Above one, a control queue
    /// follows the pairs and every TX queue gets its own worker thread.
    queue_pairs: u16,
    queue_config: Vec<QueueConfig>,
    auto_queue_pairs: bool,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
        tx_stats: NetTxStatsHandle,
        queue_pairs: u16,
    ) -> Result<Self> {
        let mut avail_features = features as u64
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_F_VERSION_1);
        // Packed virtqueues are implemented and measured neutral on the
        // native vmnet path (eight paced streams 0.77-0.82 of Apple's runtime
        // against 0.83 split, Reno 1.00 against 1.05), so they stay opt-in.
        if std::env::var_os("KRUN_NET_PACKED_RING").is_some_and(|v| v == "1") {
            avail_features |= 1 << VIRTIO_F_RING_PACKED;
        }

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        };

        let mut net = Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,

            device_state: DeviceState::Inactive,
            config,
            tx_stats,
            queue_pairs: 0,
            queue_config: Vec::new(),
            auto_queue_pairs: queue_pairs == 0,
        };
        net.set_queue_pairs(queue_pairs.max(1));
        Ok(net)
    }

    /// True when the pair count should follow the VM's vCPU count, which the
    /// builder applies with set_queue_pairs() once the VM configuration is final.
    pub fn auto_queue_pairs(&self) -> bool {
        self.auto_queue_pairs
    }

    /// Set the RX/TX queue pairs offered to the guest. Only valid before the
    /// MMIO transport reads the queue layout, i.e. before activation.
    pub fn set_queue_pairs(&mut self, queue_pairs: u16) {
        let queue_pairs = queue_pairs.max(1);
        let mq_features = (1 << VIRTIO_NET_F_MQ) | (1 << VIRTIO_NET_F_CTRL_VQ);
        self.avail_features &= !mq_features;
        self.queue_config = vec![QueueConfig::new(QUEUE_SIZE); 2 * queue_pairs as usize];
        if queue_pairs > 1 {
            self.avail_features |= mq_features;
            self.queue_config.push(QueueConfig::new(CTRL_QUEUE_SIZE));
        }
        self.config.max_virtqueue_pairs = queue_pairs;
        self.queue_pairs = queue_pairs;
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Provides the virtio-net backend of this net device.
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_config
    }

    fn queue_notification_counter(
        &self,
        queue_index: usize,
    ) -> Option<std::sync::Arc<crate::virtio::QueueNotificationCounter>> {
        // Every TX queue (odd index below the control queue) feeds one counter.
        (queue_index % 2 == 1 && queue_index < 2 * self.queue_pairs as usize)
            .then(|| self.tx_stats.queue_notification_counter())
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let expected = self.queue_config.len();
        if queues.len() != expected {
            error!("Cannot perform activate. Expected {expected} queue(s)");
            return Err(ActivateError::BadActivate);
        }
        let mut queues = queues.into_iter();
        let rx_q = queues.next().unwrap();
        let tx_q = queues.next().unwrap();
        let mut extra_tx = Vec::with_capacity(self.queue_pairs as usize - 1);
        for _ in 1..self.queue_pairs {
            let _rx = queues.next().unwrap(); // Receive uses pair 0 only.
            extra_tx.push(queues.next().unwrap());
        }
        let ctrl_q = queues.next();

        // With a direct receive hook, frames go from the bridge's receive
        // callback into the guest ring; the worker only handles ring refills.
        #[cfg(target_os = "macos")]
        let rx_direct = match &self.cfg_backend {
            VirtioNetBackend::VmnetFd {
                direct_tx:
                    Some(VmnetDirectTx {
                        bridge,
                        set_rx_sink: Some(set_rx_sink),
                        ..
                    }),
                ..
            } => Some(super::rx_direct::RxDirect::install(
                *bridge,
                *set_rx_sink,
                interrupt.clone(),
                mem.clone(),
            )),
            _ => None,
        };
        #[cfg(not(target_os = "macos"))]
        let rx_direct = None;

        // Pair 0 owns the backend socket, receive, and the control queue.
        let worker = match NetWorker::new(
            rx_q,
            rx_direct,
            tx_q,
            ctrl_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
            self.tx_stats.clone(),
            self.queue_pairs,
        ) {
            Ok(worker) => worker,
            Err(err) => {
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                return Err(ActivateError::BadActivate);
            }
        };
        #[cfg(target_os = "macos")]
        if let VirtioNetBackend::VmnetFd {
            direct_tx: Some(direct_tx),
            ..
        } = &self.cfg_backend
        {
            for (index, tx_q) in extra_tx.into_iter().enumerate() {
                NetWorker::new_tx_only(
                    tx_q,
                    interrupt.clone(),
                    mem.clone(),
                    *direct_tx,
                    self.tx_stats.clone(),
                    index + 1,
                )
                .run();
            }
        } else if !extra_tx.is_empty() {
            error!("virtio-net ({}) offers multiple queues without a direct TX backend", self.id());
            return Err(ActivateError::BadActivate);
        }
        #[cfg(not(target_os = "macos"))]
        if !extra_tx.is_empty() {
            error!("virtio-net ({}) multiqueue is only supported on macOS", self.id());
            return Err(ActivateError::BadActivate);
        }
        worker.run();
        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
