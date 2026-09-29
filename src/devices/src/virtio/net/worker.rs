use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE};
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};
use super::stats::{NetTxStatsHandle, NetTxStatsSnapshot};
use super::VNET_HDR_LEN;

#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread;
use std::time::Instant;
use std::{cmp, result};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const TX_TIMING_SAMPLE_STRIDE: u64 = 64;

#[cfg(target_os = "macos")]
fn set_network_worker_qos() {
    // Use the highest ordinary macOS QoS class for this scheduling experiment.
    // If wake latency falls without a throughput gain, scheduler wakeup time is
    // not the sustained-throughput ceiling and this should be reverted.
    let result = unsafe {
        libc::pthread_set_qos_class_self_np(
            libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE,
            0,
        )
    };
    if result != 0 {
        log::warn!("Failed to set virtio-net worker QoS: {result}");
    }
}

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
    tx_has_deferred_frame: bool,

    tx_stats_handle: NetTxStatsHandle,
    tx_stats: NetTxStatsSnapshot,
    tx_stats_reset_epoch: u64,
    tx_stats_enabled: bool,
}

impl NetWorker {
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        cfg_backend: VirtioNetBackend,
        tx_stats_handle: NetTxStatsHandle,
    ) -> Result<Self, ConnectError> {
        let backend = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "macos")]
            VirtioNetBackend::VmnetFd(fd) => {
                // SAFETY: the native vmnet bridge created and transferred this socketpair fd.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new_batched(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, _vnet_features)?) as Box<dyn NetBackend + Send>
            }
        };

        Ok(Self {
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_has_deferred_frame: false,

            tx_stats_reset_epoch: tx_stats_handle.reset_epoch(),
            tx_stats_enabled: tx_stats_handle.is_enabled(),
            tx_stats_handle,
            tx_stats: NetTxStatsSnapshot::default(),
        })
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        #[cfg(target_os = "macos")]
        set_network_worker_qos();

        #[cfg(target_os = "macos")]
        const TX_TIMER_FD: RawFd = -2;

        let virtq_rx_ev_fd = self.rx_q.event.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            self.tx_stats_handle.set_worker_waiting(true);
            let wait_result = epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice());
            self.tx_stats_handle.set_worker_waiting(false);
            match wait_result {
                Ok(ev_cnt) => {
                    self.sync_tx_stats();
                    if self.tx_stats_enabled
                        && epoll_events[0..ev_cnt].iter().any(|event| {
                            event.fd() == virtq_tx_ev_fd
                                && event.event_set() == EventSet::IN
                        })
                    {
                        self.tx_stats_handle
                            .observe_kqueue_ready(self.tx_stats.eventfd_values + 1);
                    }

                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_rx_ev_fd => {
                                self.process_rx_queue_event();
                            }
                            EventSet::IN if source == virtq_tx_ev_fd => {
                                self.process_tx_queue_event();
                            }
                            _ if source == backend_socket => {
                                if event_set.contains(EventSet::HANG_UP)
                                    || event_set.contains(EventSet::READ_HANG_UP)
                                {
                                    log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                    eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                                } else {
                                    if event_set.contains(EventSet::IN) {
                                        self.process_backend_socket_readable()
                                    }

                                    if event_set.contains(EventSet::OUT) {
                                        self.process_backend_socket_writeable()
                                    }
                                }
                            }
                            #[cfg(target_os = "macos")]
                            _ if event_set.is_empty() && source == TX_TIMER_FD => {
                                self.process_tx_loop();
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_has_deferred_frame.
                    #[cfg(target_os = "macos")]
                    if self.tx_has_deferred_frame {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.rx_q.event.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    fn sync_tx_stats(&mut self) {
        let reset_epoch = self.tx_stats_handle.reset_epoch();
        if reset_epoch != self.tx_stats_reset_epoch {
            self.tx_stats = NetTxStatsSnapshot::default();
            self.tx_stats_reset_epoch = reset_epoch;
        }
        self.tx_stats_enabled = self.tx_stats_handle.is_enabled();
    }

    fn publish_tx_stats(&self) {
        if self.tx_stats_enabled {
            self.tx_stats_handle
                .publish(self.tx_stats_reset_epoch, self.tx_stats);
        }
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        self.sync_tx_stats();
        match self.tx_q.event.read() {
            Ok(value) => {
                if self.tx_stats_enabled {
                    self.tx_stats.eventfd_wakeups += 1;
                    self.tx_stats.eventfd_values += value;
                    self.tx_stats_handle
                        .observe_eventfd(self.tx_stats.eventfd_values, value);
                }
                self.process_tx_loop();
            }
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
        };
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        self.sync_tx_stats();
        match self
            .backend
            .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite) => {
                if self.tx_stats_enabled {
                    self.tx_stats.partial_writes += 1;
                    self.publish_tx_stats();
                }
            }
            Err(WriteError::NothingWritten) => {
                if self.tx_stats_enabled {
                    self.tx_stats.nothing_written += 1;
                    self.publish_tx_stats();
                }
            }
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        // Track used-ring progress, not just successfully delivered frames. A
        // deferred frame or a rejected guest buffer can also complete a chain.
        let mut used_queue = false;
        let result = self.process_rx_frames(&mut used_queue);

        if used_queue
            && self
                .rx_q
                .queue
                .needs_notification(&self.mem)
                .map_err(RxError::QueueError)?
        {
            self.interrupt
                .try_signal_used_queue()
                .map_err(RxError::DeviceError)?;
        }

        result
    }

    fn process_rx_frames(&mut self, used_queue: &mut bool) -> result::Result<(), RxError> {
        // If we have a deferred frame, finish it before reading another one.
        if self.rx_has_deferred_frame {
            if self.write_frame_to_guest(used_queue) {
                self.rx_has_deferred_frame = false;
            } else {
                return Ok(());
            }
        }

        // Read as many frames as possible. The caller checks EVENT_IDX once
        // after the batch, including when a backend error ends the batch.
        loop {
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    if !self.write_frame_to_guest(used_queue) {
                        self.rx_has_deferred_frame = true;
                        return Ok(());
                    }
                }
                Err(ReadError::NothingRead) => return Ok(()),
                Err(e @ ReadError::Internal(_)) => return Err(RxError::Backend(e)),
            }
        }
    }

    fn process_tx_loop(&mut self) {
        self.sync_tx_stats();
        loop {
            let timing_sample = self.tx_stats_enabled
                && self.tx_stats.drain_passes % TX_TIMING_SAMPLE_STRIDE == 0;
            let cycle_started = timing_sample.then(Instant::now);
            let frames_before = self.tx_stats.frames;

            let disable_started = timing_sample.then(Instant::now);
            self.tx_q.queue.disable_notification(&self.mem).unwrap();
            if let Some(started) = disable_started {
                self.tx_stats.tx_queue_disable_sample_ns += started.elapsed().as_nanos() as u64;
            }

            self.tx_has_deferred_frame = match self.process_tx() {
                Err(TxError::Backend(WriteError::NothingWritten)) => true,
                Err(e) => {
                    log::error!("Failed to process tx: {e:?}");
                    false
                }
                _ => false,
            };

            let enable_started = timing_sample.then(Instant::now);
            let has_new_entries = self.tx_q.queue.enable_notification(&self.mem).unwrap();
            if let Some(started) = enable_started {
                self.tx_stats.tx_queue_enable_sample_ns += started.elapsed().as_nanos() as u64;
            }
            if let Some(started) = cycle_started {
                self.tx_stats.drain_cycle_sample_ns += started.elapsed().as_nanos() as u64;
                self.tx_stats.timing_sampled_drain_cycles += 1;
                self.tx_stats.timing_sampled_drain_frames +=
                    self.tx_stats.frames.saturating_sub(frames_before);
            }

            if self.tx_has_deferred_frame || !has_new_entries {
                break;
            }
        }
        self.publish_tx_stats();
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        if self.tx_stats_enabled {
            self.tx_stats.drain_passes += 1;
        }
        let mut drain_frames = 0u64;
        let mut drain_bytes = 0u64;
        let mut flush_frames = 0u64;
        let mut flush_bytes = 0u64;
        let tx_queue = &mut self.tx_q.queue;

        if self.backend.has_unfinished_write() {
            match self
                .backend
                .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
            {
                Ok(()) => {}
                Err(WriteError::NothingWritten) => {
                    if self.tx_stats_enabled {
                        self.tx_stats.nothing_written += 1;
                        self.tx_stats.empty_drain_passes += 1;
                    }
                    return Err(TxError::Backend(WriteError::NothingWritten));
                }
                Err(WriteError::PartialWrite) => {
                    if self.tx_stats_enabled {
                        self.tx_stats.partial_writes += 1;
                        self.tx_stats.empty_drain_passes += 1;
                    }
                    log::trace!("Cannot process tx because of unfinished partial write!");
                    return Ok(());
                }
                Err(_) => {
                    if self.tx_stats_enabled {
                        self.tx_stats.empty_drain_passes += 1;
                    }
                    log::trace!("Cannot process tx because of unfinished partial write!");
                    return Ok(());
                }
            }
        }

        let mut raise_irq = false;
        let mut result = Ok(());

        while let Some(head) = tx_queue.pop(&self.mem) {
            let timing_sample = self.tx_stats_enabled
                && self.tx_stats.frames % TX_TIMING_SAMPLE_STRIDE == 0;
            let descriptor_started = timing_sample.then(Instant::now);
            let head_index = head.index;
            let mut next_desc = Some(head);
            if self.tx_stats_enabled {
                self.tx_stats.descriptor_chains += 1;
            }

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if self.tx_stats_enabled {
                    self.tx_stats.descriptors += 1;
                }
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                next_desc = desc.next_descriptor();
            }

            let copy_started = if let Some(started) = descriptor_started {
                self.tx_stats.descriptor_parse_sample_ns +=
                    started.elapsed().as_nanos() as u64;
                Some(Instant::now())
            } else {
                None
            };

            // Copy buffer from across multiple descriptors.
            let mut read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {e:?}");
                        read_count = 0;
                        break;
                    }
                }
            }

            let backend_started = if let Some(started) = copy_started {
                self.tx_stats.guest_copy_sample_ns += started.elapsed().as_nanos() as u64;
                Some(Instant::now())
            } else {
                None
            };

            self.tx_frame_len = read_count;
            let backend_bytes = read_count.saturating_sub(VNET_HDR_LEN) as u64;
            if self.tx_stats_enabled {
                self.tx_stats.frames += 1;
                self.tx_stats.bytes += backend_bytes;
                self.tx_stats.write_frame_calls += 1;
                self.tx_stats.backend_bytes += backend_bytes;
                drain_frames += 1;
                drain_bytes += backend_bytes;
            }
            let write_result = self
                .backend
                .write_frame(VNET_HDR_LEN, &mut self.tx_frame_buf[..read_count]);
            if let Some(started) = backend_started {
                self.tx_stats.backend_write_sample_ns += started.elapsed().as_nanos() as u64;
                self.tx_stats.timing_sampled_frames += 1;
            }
            match write_result {
                Ok(()) => {
                    if self.tx_stats_enabled {
                        flush_frames += 1;
                        flush_bytes += backend_bytes;
                    }
                    self.tx_frame_len = 0;
                    let add_used_started = timing_sample.then(Instant::now);
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    if let Some(started) = add_used_started {
                        self.tx_stats.add_used_sample_ns += started.elapsed().as_nanos() as u64;
                    }
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    if self.tx_stats_enabled {
                        self.tx_stats.nothing_written += 1;
                    }
                    tx_queue.undo_pop();
                    result = Err(TxError::Backend(WriteError::NothingWritten));
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    if self.tx_stats_enabled {
                        self.tx_stats.partial_writes += 1;
                        flush_frames += 1;
                        flush_bytes += backend_bytes;
                    }
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e))
                }
            }
        }

        if self.tx_stats_enabled {
            if drain_frames == 0 {
                self.tx_stats.empty_drain_passes += 1;
            }
            self.tx_stats.max_frames_per_drain =
                self.tx_stats.max_frames_per_drain.max(drain_frames);
            self.tx_stats.max_bytes_per_drain =
                self.tx_stats.max_bytes_per_drain.max(drain_bytes);
        }

        if result.is_ok() {
            let timing_sample_flush = self.tx_stats_enabled
                && self.tx_stats.flush_calls % TX_TIMING_SAMPLE_STRIDE == 0;
            if self.tx_stats_enabled {
                self.tx_stats.flush_calls += 1;
                self.tx_stats.frames_between_flushes += flush_frames;
                self.tx_stats.bytes_between_flushes += flush_bytes;
                self.tx_stats.max_frames_between_flush =
                    self.tx_stats.max_frames_between_flush.max(flush_frames);
                self.tx_stats.max_bytes_between_flush =
                    self.tx_stats.max_bytes_between_flush.max(flush_bytes);
            }
            let flush_started = timing_sample_flush.then(Instant::now);
            let flush_result = self.backend.flush_writes();
            if let Some(started) = flush_started {
                self.tx_stats.flush_sample_ns += started.elapsed().as_nanos() as u64;
                self.tx_stats.timing_sampled_flushes += 1;
            }
            if let Err(e) = flush_result {
                if self.tx_stats_enabled {
                    match &e {
                        WriteError::NothingWritten => self.tx_stats.nothing_written += 1,
                        WriteError::PartialWrite => self.tx_stats.partial_writes += 1,
                        _ => {}
                    }
                }
                result = Err(TxError::Backend(e));
            }
        }

        if raise_irq {
            let timing_sample_notification = self.tx_stats_enabled
                && self.tx_stats.notification_checks % TX_TIMING_SAMPLE_STRIDE == 0;
            if self.tx_stats_enabled {
                self.tx_stats.notification_checks += 1;
            }
            let notification_started = timing_sample_notification.then(Instant::now);
            let needs_notification = tx_queue.needs_notification(&self.mem).unwrap();
            if let Some(started) = notification_started {
                self.tx_stats.notification_check_sample_ns += started.elapsed().as_nanos() as u64;
                self.tx_stats.timing_sampled_notification_checks += 1;
            }
            if needs_notification {
                if self.tx_stats_enabled {
                    self.tx_stats.notification_true += 1;
                    self.tx_stats.signal_used_queue_calls += 1;
                }
                let irq_started = timing_sample_notification.then(Instant::now);
                self.interrupt
                    .try_signal_used_queue()
                    .map_err(TxError::DeviceError)?;
                if self.tx_stats_enabled {
                    self.tx_stats_handle
                        .record_irq_signal(self.tx_stats.signal_used_queue_calls);
                }
                if let Some(started) = irq_started {
                    self.tx_stats.irq_signal_sample_ns += started.elapsed().as_nanos() as u64;
                    self.tx_stats.timing_sampled_irq_signals += 1;
                }
            } else if self.tx_stats_enabled {
                self.tx_stats.notification_false += 1;
            }
        }

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(
        &mut self,
        used_queue: &mut bool,
    ) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.rx_q.queue;
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        *used_queue = true;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self, used_queue: &mut bool) -> bool {
        let max_iterations = self.rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl(used_queue) {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    // retry
                    continue;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        self.rx_frame_buf_len = self.backend.read_frame(&mut self.rx_frame_buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::virtio::{Queue, VIRTIO_MMIO_INT_VRING};
    use std::collections::VecDeque;
    use std::num::Wrapping;
    use std::os::fd::RawFd;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use utils::eventfd::EventFd;

    const FRAME_LEN: usize = 128;

    struct ScriptedBackend(VecDeque<Result<Vec<u8>, ReadError>>);

    impl ScriptedBackend {
        fn frames(count: usize) -> Self {
            Self((0..count).map(|_| Ok(vec![0x5a; FRAME_LEN])).collect())
        }
    }

    impl NetBackend for ScriptedBackend {
        fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
            let frame = self.0.pop_front().unwrap_or(Err(ReadError::NothingRead))?;
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }

        fn write_frame(&mut self, _: usize, _: &mut [u8]) -> Result<(), WriteError> {
            panic!("RX test attempted a backend write")
        }

        fn has_unfinished_write(&self) -> bool {
            false
        }

        fn try_finish_write(&mut self, _: usize, _: &[u8]) -> Result<(), WriteError> {
            panic!("RX test attempted a deferred backend write")
        }

        fn raw_socket_fd(&self) -> RawFd {
            -1
        }
    }

    fn worker(
        mem: &GuestMemoryMmap,
        rx: &VirtQueue<'_>,
        event_idx: bool,
        frames: usize,
    ) -> NetWorker {
        let mut queue = rx.create_queue();
        queue.set_event_idx(event_idx);
        NetWorker {
            rx_q: DeviceQueue::new(queue, Arc::new(EventFd::new(0).unwrap())),
            tx_q: DeviceQueue::new(Queue::new(8), Arc::new(EventFd::new(0).unwrap())),
            interrupt: InterruptTransport::new(DummyIrqChip::new().into(), "rx-test".into())
                .unwrap(),
            mem: mem.clone(),
            backend: Box::new(ScriptedBackend::frames(frames)),
            rx_frame_buf: [0; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,
            tx_iovec: Vec::new(),
            tx_frame_buf: [0; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_has_deferred_frame: false,
        }
    }

    fn post_buffer(rx: &VirtQueue<'_>, index: usize, flags: u16) {
        rx.dtable[index].set(0x10000 + index as u64 * 256, 256, flags, 0);
        rx.avail.ring[index].set(index as u16);
        rx.avail.idx.set(index as u16 + 1);
    }

    fn irq_pending(worker: &NetWorker) -> bool {
        worker.interrupt.status().load(Ordering::SeqCst) & VIRTIO_MMIO_INT_VRING as usize != 0
    }

    #[test]
    fn test_rx_event_idx_batch_thresholds() {
        for (used_event, notify) in [
            (0, true),
            (1, true),
            (2, false),
            (7, false),
            (u16::MAX, false),
        ] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
            post_buffer(&rx, 1, VIRTQ_DESC_F_WRITE);
            rx.avail.event.set(used_event);
            let mut worker = worker(&mem, &rx, true, 2);

            worker.process_rx().unwrap();

            assert_eq!(rx.used.idx.get(), 2);
            assert_eq!(rx.used.ring[0].get().len, FRAME_LEN as u32);
            assert_eq!(rx.used.ring[1].get().len, FRAME_LEN as u32);
            assert_eq!(irq_pending(&worker), notify, "used_event={used_event}");
        }
    }

    #[test]
    fn test_rx_event_idx_rearms_across_batches() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
        rx.avail.event.set(1);
        let mut worker = worker(&mem, &rx, true, 1);
        worker.process_rx().unwrap();
        assert!(!irq_pending(&worker));

        post_buffer(&rx, 1, VIRTQ_DESC_F_WRITE);
        worker.backend = Box::new(ScriptedBackend::frames(1));
        worker.process_rx().unwrap();
        assert!(irq_pending(&worker));

        worker.interrupt.status().store(0, Ordering::SeqCst);
        post_buffer(&rx, 2, VIRTQ_DESC_F_WRITE);
        worker.backend = Box::new(ScriptedBackend::frames(1));
        worker.process_rx().unwrap();
        assert!(
            !irq_pending(&worker),
            "already crossed the event in the previous batch"
        );
        assert_eq!(rx.used.idx.get(), 3);
    }

    #[test]
    fn test_rx_event_idx_deferred_only_completion() {
        for (used_event, notify) in [(0, true), (1, false)] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
            rx.avail.event.set(used_event);
            let mut worker = worker(&mem, &rx, true, 0);
            worker.rx_has_deferred_frame = true;
            worker.rx_frame_buf_len = FRAME_LEN;

            worker.process_rx().unwrap();

            assert!(!worker.rx_has_deferred_frame);
            assert_eq!(rx.used.idx.get(), 1);
            assert_eq!(irq_pending(&worker), notify);
        }
    }

    #[test]
    fn test_rx_event_idx_rejected_buffer_is_a_completion() {
        for deferred in [false, true] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            post_buffer(&rx, 0, 0); // Device-readable, not a valid RX buffer.
            let mut worker = worker(&mem, &rx, true, usize::from(!deferred));
            worker.rx_has_deferred_frame = deferred;
            worker.rx_frame_buf_len = FRAME_LEN;

            worker.process_rx().unwrap();

            assert!(worker.rx_has_deferred_frame);
            assert_eq!(rx.used.idx.get(), 1);
            assert_eq!(rx.used.ring[0].get().len, 0);
            assert!(irq_pending(&worker), "deferred={deferred}");
        }
    }

    #[test]
    fn test_rx_event_idx_completion_before_backend_error() {
        for (used_event, notify) in [(0, true), (1, false)] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
            rx.avail.event.set(used_event);
            let mut worker = worker(&mem, &rx, true, 0);
            let mut backend = ScriptedBackend::frames(1);
            backend
                .0
                .push_back(Err(ReadError::Internal(nix::errno::Errno::EIO)));
            worker.backend = Box::new(backend);

            assert!(matches!(worker.process_rx(), Err(RxError::Backend(_))));
            assert_eq!(rx.used.idx.get(), 1);
            assert_eq!(irq_pending(&worker), notify);
        }
    }

    #[test]
    fn test_rx_event_idx_no_completion_no_interrupt() {
        for deferred in [false, true] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            let mut worker = worker(&mem, &rx, true, 0);
            worker.rx_has_deferred_frame = deferred;
            worker.rx_frame_buf_len = FRAME_LEN;

            worker.process_rx().unwrap();

            assert_eq!(rx.used.idx.get(), 0);
            assert!(!irq_pending(&worker));
            assert_eq!(worker.rx_has_deferred_frame, deferred);
        }
    }

    #[test]
    fn test_rx_without_event_idx_still_notifies() {
        for deferred in [false, true] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
            rx.avail.event.set(u16::MAX); // Must not be consulted without EVENT_IDX.
            let mut worker = worker(&mem, &rx, false, usize::from(!deferred));
            worker.rx_has_deferred_frame = deferred;
            worker.rx_frame_buf_len = FRAME_LEN;

            worker.process_rx().unwrap();

            assert_eq!(rx.used.idx.get(), 1);
            assert!(irq_pending(&worker));
        }
    }

    #[test]
    fn test_rx_event_idx_used_index_wraparound() {
        for (used_event, notify) in [(u16::MAX, true), (0, false)] {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
            post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
            rx.used.idx.set(u16::MAX);
            rx.avail.event.set(used_event);
            let mut worker = worker(&mem, &rx, true, 1);
            worker.rx_q.queue.next_used = Wrapping(u16::MAX);

            worker.process_rx().unwrap();

            assert_eq!(rx.used.idx.get(), 0);
            assert_eq!(rx.used.ring[7].get().len, FRAME_LEN as u32);
            assert_eq!(irq_pending(&worker), notify);
        }
    }

    #[test]
    fn test_rx_event_idx_unreadable_event_is_an_error() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        post_buffer(&rx, 0, VIRTQ_DESC_F_WRITE);
        let mut worker = worker(&mem, &rx, true, 1);
        // Keep avail.idx and ring[0] readable, but move used_event past RAM.
        worker.rx_q.queue.avail_ring = GuestAddress(0x1fff8);
        mem.write_obj(1u16, GuestAddress(0x1fffa)).unwrap();
        mem.write_obj(0u16, GuestAddress(0x1fffc)).unwrap();

        assert!(matches!(worker.process_rx(), Err(RxError::QueueError(_))));
        assert_eq!(rx.used.idx.get(), 1);
        assert!(!irq_pending(&worker));
    }
}
