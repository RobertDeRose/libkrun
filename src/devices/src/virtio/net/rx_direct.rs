//! Receive path for the native vmnet backend: the bridge's vmnet receive
//! callback writes frames into the guest RX ring directly. The worker thread
//! only drains frames that were waiting for the guest to post buffers.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use vm_memory::{Bytes, GuestMemoryMmap};

use super::device::{FrontendError, VmPktDesc, VmnetRxSink};
use super::{write_virtio_net_hdr, MAX_BUFFER_SIZE};
use crate::virtio::{DeviceQueue, InterruptTransport};

/// Frames held while the guest ring has no free buffers. A real NIC drops
/// beyond its ring; this bound keeps a stalled guest from growing host memory.
const MAX_PENDING_FRAMES: usize = 512;

pub struct RxState {
    rx_q: Option<DeviceQueue>,
    mem: GuestMemoryMmap,
    interrupt: InterruptTransport,
    frame: Vec<u8>,
    pending: VecDeque<Vec<u8>>,
    /// vmnet frames already start with a virtio-net header for the guest.
    vnet_hdr: bool,
    pub dropped: u64,
}

impl RxState {
    fn new(interrupt: InterruptTransport, mem: GuestMemoryMmap, vnet_hdr: bool) -> Self {
        Self {
            rx_q: None,
            mem,
            interrupt,
            frame: vec![0u8; MAX_BUFFER_SIZE],
            pending: VecDeque::new(),
            vnet_hdr,
            dropped: 0,
        }
    }

    /// Hand over the receive queue once the device is activated.
    pub fn attach_queue(&mut self, rx_q: DeviceQueue) {
        self.rx_q = Some(rx_q);
    }

    /// Copy one frame into the next guest buffer chain, behind a zero
    /// virtio-net header unless vmnet supplied one. Returns false when no chain
    /// is available.
    fn write_frame(&mut self, frame: &[u8], used_queue: &mut bool) -> bool {
        let Some(rx_q) = self.rx_q.as_mut() else {
            return false;
        };
        let data = if self.vnet_hdr {
            if frame.len() > self.frame.len() {
                self.dropped += 1;
                return true; // Oversized frames cannot be delivered; do not stall the queue.
            }
            frame
        } else {
            let hdr_len = write_virtio_net_hdr(&mut self.frame);
            let total = hdr_len + frame.len();
            if total > self.frame.len() {
                self.dropped += 1;
                return true; // Oversized frames cannot be delivered; do not stall the queue.
            }
            self.frame[hdr_len..total].copy_from_slice(frame);
            &self.frame[..total]
        };
        let max_iterations = rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            match Self::write_chain(&mut rx_q.queue, &self.mem, data, used_queue) {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => return false,
                Err(_) => continue, // Bad chain was marked used; try the next one.
            }
        }
        false
    }

    fn write_chain(
        queue: &mut crate::virtio::Queue,
        mem: &GuestMemoryMmap,
        data: &[u8],
        used_queue: &mut bool,
    ) -> Result<(), FrontendError> {
        let head = queue.pop(mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head.index;
        let mut result = Ok(());
        let mut remaining = data;
        let mut next = Some(head);
        while let Some(descriptor) = &next {
            if remaining.is_empty() {
                break;
            }
            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }
            let len = remaining.len().min(descriptor.len as usize);
            if let Err(e) = mem.write_slice(&remaining[..len], descriptor.addr) {
                result = Err(FrontendError::GuestMemory(e));
                break;
            }
            remaining = &remaining[len..];
            next = descriptor.next_descriptor();
        }
        if result.is_ok() && !remaining.is_empty() {
            result = Err(FrontendError::DescriptorChainTooSmall);
        }
        let used_len = if result.is_err() { 0 } else { data.len() as u32 };
        queue
            .add_used(mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        *used_queue = true;
        result
    }

    /// Deliver frames held back earlier, in order, while buffers last.
    fn flush_pending(&mut self, used_queue: &mut bool) {
        while let Some(frame) = self.pending.front() {
            let frame = frame.clone();
            if self.write_frame(&frame, used_queue) {
                self.pending.pop_front();
            } else {
                break;
            }
        }
    }

    fn deliver(&mut self, frame: &[u8], used_queue: &mut bool) {
        if self.pending.is_empty() && self.write_frame(frame, used_queue) {
            return;
        }
        if self.pending.len() >= MAX_PENDING_FRAMES {
            self.dropped += 1;
            // Rate-limited: every power of two, so a stalled guest is visible
            // in the VMM log without flooding it.
            if self.dropped.is_power_of_two() {
                log::warn!(
                    "virtio-net rx: guest ring full, {} frames dropped so far ({} waiting)",
                    self.dropped,
                    self.pending.len()
                );
            }
            return;
        }
        self.pending.push_back(frame.to_vec());
    }

    /// Interrupt per batch under EVENT_IDX rules, and ask for guest kicks only
    /// while frames are waiting for buffers. Enabling kicks reports whether the
    /// guest posted buffers in the meantime; those would never kick, so drain
    /// again until the wait list empties or the ring is really empty.
    fn finish_batch(&mut self, mut used_queue: bool) {
        if self.rx_q.is_none() {
            return;
        }
        loop {
            let rx_q = self.rx_q.as_mut().unwrap();
            if self.pending.is_empty() {
                if let Err(e) = rx_q.queue.disable_notification(&self.mem) {
                    log::error!("virtio-net rx: disabling kicks failed: {e:?}");
                }
                break;
            }
            match rx_q.queue.enable_notification(&self.mem) {
                Ok(true) => self.flush_pending(&mut used_queue),
                Ok(false) => break,
                Err(e) => {
                    log::error!("virtio-net rx: enabling kicks failed: {e:?}");
                    break;
                }
            }
        }
        let rx_q = self.rx_q.as_mut().unwrap();
        if used_queue {
            match rx_q.queue.needs_notification(&self.mem) {
                Ok(true) => {
                    if let Err(e) = self.interrupt.try_signal_used_queue() {
                        log::error!("virtio-net rx: failed to signal used queue: {e:?}");
                    }
                }
                Ok(false) => {}
                Err(e) => log::error!("virtio-net rx: needs_notification failed: {e:?}"),
            }
        }
    }

    /// The guest posted buffers: drain what was waiting.
    pub fn on_guest_kick(&mut self) {
        let mut used_queue = false;
        self.flush_pending(&mut used_queue);
        self.finish_batch(used_queue);
    }

    /// One vmnet receive batch.
    pub fn on_frames<'a>(&mut self, frames: impl Iterator<Item = &'a [u8]>) {
        let mut used_queue = false;
        for frame in frames {
            self.deliver(frame, &mut used_queue);
        }
        self.finish_batch(used_queue);
    }
}

/// Shared receive state: the bridge callback thread delivers, the worker refills.
#[derive(Clone)]
pub struct RxDirect(pub Arc<Mutex<RxState>>);

impl RxDirect {
    /// Create the state and register the bridge callback. The registration
    /// leaks one Arc clone to the bridge, which lives as long as the VMM.
    pub fn install(
        bridge: *mut c_void,
        set_rx_sink: unsafe extern "C" fn(*mut c_void, Option<VmnetRxSink>, *mut c_void) -> i32,
        vnet_hdr: bool,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
    ) -> Self {
        let state = Arc::new(Mutex::new(RxState::new(interrupt, mem, vnet_hdr)));
        let opaque = Box::into_raw(Box::new(state.clone())) as *mut c_void;
        // SAFETY: the bridge outlives the device; the opaque is a leaked Arc.
        let result = unsafe { set_rx_sink(bridge, Some(rx_sink), opaque) };
        if result != 0 {
            log::error!("virtio-net rx: failed to install vmnet receive sink: {result}");
        }
        Self(state)
    }
}

/// Runs on the bridge's serial dispatch queue.
unsafe extern "C" fn rx_sink(opaque: *mut c_void, packets: *const VmPktDesc, count: usize) {
    if opaque.is_null() || packets.is_null() || count == 0 {
        return;
    }
    // SAFETY: opaque is the Arc leaked by install(); packets are valid for the call.
    let state = unsafe { &*(opaque as *const Arc<Mutex<RxState>>) };
    let packets = unsafe { std::slice::from_raw_parts(packets, count) };
    let mut scratch: Vec<u8> = Vec::new();
    let frames = packets.iter().filter_map(|packet| {
        if packet.vm_pkt_iov.is_null() || packet.vm_pkt_size == 0 {
            return None;
        }
        let iovs = unsafe { std::slice::from_raw_parts(packet.vm_pkt_iov, packet.vm_pkt_iovcnt as usize) };
        if iovs.len() == 1 {
            let len = packet.vm_pkt_size.min(iovs[0].iov_len);
            return Some(unsafe { std::slice::from_raw_parts(iovs[0].iov_base as *const u8, len) });
        }
        // Rare multi-iov packet: gather into a scratch buffer.
        scratch.clear();
        let mut remaining = packet.vm_pkt_size;
        for iov in iovs {
            let len = remaining.min(iov.iov_len);
            scratch.extend_from_slice(unsafe { std::slice::from_raw_parts(iov.iov_base as *const u8, len) });
            remaining -= len;
        }
        // SAFETY: scratch is not touched again until the next iteration.
        Some(unsafe { std::slice::from_raw_parts(scratch.as_ptr(), scratch.len()) })
    });
    let mut guard = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.on_frames(frames);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
    use super::super::VNET_HDR_LEN;
    use crate::virtio::VIRTIO_MMIO_INT_VRING;
    use std::sync::atomic::Ordering;
    use utils::eventfd::EventFd;
    use vm_memory::GuestAddress;

    fn state(mem: &GuestMemoryMmap, rx: &VirtQueue<'_>) -> RxState {
        let mut queue = rx.create_queue();
        queue.set_event_idx(true);
        let interrupt = InterruptTransport::new(DummyIrqChip::new().into(), "rx-direct-test".into()).unwrap();
        let mut state = RxState::new(interrupt, mem.clone(), false);
        state.attach_queue(DeviceQueue::new(queue, Arc::new(EventFd::new(0).unwrap())));
        state
    }

    fn post_buffer(rx: &VirtQueue<'_>, index: usize) {
        rx.dtable[index].set(0x10000 + index as u64 * 4096, 4096, VIRTQ_DESC_F_WRITE, 0);
        rx.avail.ring[index].set(index as u16);
        rx.avail.idx.set(index as u16 + 1);
    }

    fn irq_pending(state: &RxState) -> bool {
        state.interrupt.status().load(Ordering::SeqCst) & VIRTIO_MMIO_INT_VRING as usize != 0
    }

    #[test]
    fn frames_land_in_posted_buffers_with_header() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        post_buffer(&rx, 0);
        post_buffer(&rx, 1);
        let mut state = state(&mem, &rx);
        let a = [0xaau8; 60];
        let b = [0xbbu8; 1500];
        state.on_frames([&a[..], &b[..]].into_iter());
        assert_eq!(rx.used.idx.get(), 2);
        assert_eq!(rx.used.ring[0].get().len as usize, VNET_HDR_LEN + 60);
        assert_eq!(rx.used.ring[1].get().len as usize, VNET_HDR_LEN + 1500);
        let mut header = [1u8; VNET_HDR_LEN];
        mem.read_slice(&mut header, GuestAddress(0x10000)).unwrap();
        assert_eq!(header, [0u8; VNET_HDR_LEN]);
        let mut payload = [0u8; 60];
        mem.read_slice(&mut payload, GuestAddress(0x10000 + VNET_HDR_LEN as u64)).unwrap();
        assert_eq!(payload, a);
        assert!(irq_pending(&state));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn vnet_hdr_frames_land_with_vmnet_header_unchanged() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        post_buffer(&rx, 0);
        let mut state = state(&mem, &rx);
        state.vnet_hdr = true;
        let mut frame = vec![0xccu8; VNET_HDR_LEN + 60];
        frame[0] = 2; // VIRTIO_NET_HDR_F_DATA_VALID from vmnet.
        state.on_frames([&frame[..]].into_iter());
        assert_eq!(rx.used.ring[0].get().len as usize, frame.len());
        let mut delivered = vec![0u8; frame.len()];
        mem.read_slice(&mut delivered, GuestAddress(0x10000)).unwrap();
        assert_eq!(delivered, frame);
    }

    #[test]
    fn frames_wait_for_buffers_then_drain_in_order_on_kick() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        let mut state = state(&mem, &rx);
        state.on_frames([&[1u8; 64][..], &[2u8; 64][..]].into_iter());
        assert_eq!(rx.used.idx.get(), 0);
        assert_eq!(state.pending.len(), 2);
        assert!(!irq_pending(&state));
        post_buffer(&rx, 0);
        post_buffer(&rx, 1);
        state.on_guest_kick();
        assert_eq!(rx.used.idx.get(), 2);
        assert!(state.pending.is_empty());
        let mut first = [0u8; 1];
        mem.read_slice(&mut first, GuestAddress(0x10000 + VNET_HDR_LEN as u64)).unwrap();
        assert_eq!(first, [1]);
        assert!(irq_pending(&state));
    }

    #[test]
    fn buffers_posted_before_kicks_are_enabled_do_not_strand_frames() {
        // The guest posts buffers after our write fails but before we ask for
        // kicks: no kick will ever come, so the batch itself must drain them.
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        let mut state = state(&mem, &rx);
        state.on_frames([&[1u8; 64][..]].into_iter());
        assert_eq!(state.pending.len(), 1);
        post_buffer(&rx, 0);
        post_buffer(&rx, 1);
        // Another batch arrives; the ring now has buffers but no kick was sent.
        state.on_frames([&[2u8; 64][..]].into_iter());
        assert_eq!(rx.used.idx.get(), 2);
        assert!(state.pending.is_empty());
        assert!(irq_pending(&state));
    }

    #[test]
    fn pending_is_bounded_and_drops_are_counted() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let rx = VirtQueue::new(GuestAddress(0x1000), &mem, 8);
        let mut state = state(&mem, &rx);
        let frame = [7u8; 64];
        state.on_frames(std::iter::repeat(&frame[..]).take(MAX_PENDING_FRAMES + 5));
        assert_eq!(state.pending.len(), MAX_PENDING_FRAMES);
        assert_eq!(state.dropped, 5);
    }
}
