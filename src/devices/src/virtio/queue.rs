// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp::min;
use std::fmt::{self, Debug, Display};
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};
use virtio_bindings::virtio_ring::VRING_USED_F_NO_NOTIFY;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap,
    VolatileMemoryError,
};

/// Size of used ring header: flags (u16) + idx (u16)
pub(crate) const VIRTQ_USED_RING_HEADER_SIZE: u64 = 4;

/// Size of one element in the used ring, id (le32) + len (le32).
pub(crate) const VIRTQ_USED_ELEMENT_SIZE: u64 = 8;

/// Size of available ring header: flags(u16) + idx(u16)
pub(crate) const VIRTQ_AVAIL_RING_HEADER_SIZE: u64 = 4;

/// Size of one element in the available ring (le16).
pub(crate) const VIRTQ_AVAIL_ELEMENT_SIZE: u64 = 2;

pub(super) const VIRTQ_DESC_F_NEXT: u16 = 0x1;
pub(super) const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// Packed ring (virtio 1.1, 2.7): a descriptor's AVAIL and USED bits carry
/// the ring wrap counters; the event suppression areas use these flags.
pub(super) const VIRTQ_DESC_F_AVAIL: u16 = 1 << 7;
pub(super) const VIRTQ_DESC_F_USED: u16 = 1 << 15;
const VRING_PACKED_EVENT_FLAG_ENABLE: u16 = 0;
const VRING_PACKED_EVENT_FLAG_DISABLE: u16 = 1;
const VRING_PACKED_EVENT_FLAG_DESC: u16 = 2;
const VRING_PACKED_EVENT_F_WRAP_CTR: u16 = 15;
const PACKED_DESC_SIZE: u64 = 16;

/// Virtio Queue related errors.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    /// Address overflow.
    AddressOverflow,
    /// Failed to access guest memory.
    GuestMemory(GuestMemoryError),
    /// Invalid indirect descriptor.
    InvalidIndirectDescriptor,
    /// Invalid indirect descriptor table.
    InvalidIndirectDescriptorTable,
    /// Invalid descriptor chain.
    InvalidChain,
    /// Invalid descriptor index.
    InvalidDescriptorIndex,
    /// Invalid max_size.
    InvalidMaxSize,
    /// Invalid Queue Size.
    InvalidSize,
    /// Invalid alignment of descriptor table address.
    InvalidDescTableAlign,
    /// Invalid alignment of available ring address.
    InvalidAvailRingAlign,
    /// Invalid alignment of used ring address.
    InvalidUsedRingAlign,
    /// Invalid available ring index.
    InvalidAvailRingIndex,
    /// The queue is not ready for operation.
    QueueNotReady,
    /// Volatile memory error.
    VolatileMemoryError(VolatileMemoryError),
    /// The combined length of all the buffers in a `DescriptorChain` would overflow.
    DescriptorChainOverflow,
    /// No memory region for this address range.
    FindMemoryRegion,
    /// Descriptor guest memory error.
    GuestMemoryError(GuestMemoryError),
    /// DescriptorChain split is out of bounds.
    SplitOutOfBounds(usize),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AddressOverflow => write!(f, "address overflow"),
            GuestMemory(_) => write!(f, "error accessing guest memory"),
            InvalidChain => write!(f, "invalid descriptor chain"),
            InvalidIndirectDescriptor => write!(f, "invalid indirect descriptor"),
            InvalidIndirectDescriptorTable => write!(f, "invalid indirect descriptor table"),
            InvalidDescriptorIndex => write!(f, "invalid descriptor index"),
            InvalidMaxSize => write!(f, "invalid queue maximum size"),
            InvalidSize => write!(f, "invalid queue size"),
            InvalidDescTableAlign => write!(
                f,
                "virtio queue descriptor table breaks alignment constraints"
            ),
            InvalidAvailRingAlign => write!(
                f,
                "virtio queue available ring breaks alignment constraints"
            ),
            InvalidUsedRingAlign => {
                write!(f, "virtio queue used ring breaks alignment constraints")
            }
            InvalidAvailRingIndex => write!(
                f,
                "invalid available ring index (more descriptors to process than queue size)"
            ),
            QueueNotReady => write!(f, "trying to process requests on a queue that's not ready"),
            VolatileMemoryError(e) => write!(f, "volatile memory error: {e}"),
            DescriptorChainOverflow => write!(
                f,
                "the combined length of all the buffers in a `DescriptorChain` would overflow"
            ),
            FindMemoryRegion => write!(f, "no memory region for this address range"),
            GuestMemoryError(e) => write!(f, "descriptor guest memory error: {e}"),
            SplitOutOfBounds(off) => write!(f, "`DescriptorChain` split is out of bounds: {off}"),
        }
    }
}

impl std::error::Error for Error {}

/// Represents the contents of an element from the used virtqueue ring.
// Note that the `ByteValued` implementation of this structure expects the `VirtqUsedElem` to store
// only plain old data types.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtqUsedElem {
    id: u32,
    len: u32,
}

impl VirtqUsedElem {
    /// Create a new `VirtqUsedElem` instance.
    ///
    /// # Arguments
    /// * `id` - the index of the used descriptor chain.
    /// * `len` - the total length of the descriptor chain which was used (written to).
    pub(crate) fn new(id: u32, len: u32) -> Self {
        VirtqUsedElem { id, len }
    }
}

// SAFETY: This is safe because `VirtqUsedElem` contains only wrappers over POD types
// and all accesses through safe `vm-memory` API will validate any garbage that could be
// included in there.
unsafe impl ByteValued for VirtqUsedElem {}

// GuestMemoryMmap::read_obj_from_addr() will be used to fetch the descriptor,
// which has an explicit constraint that the entire descriptor doesn't
// cross the page boundary. Otherwise the descriptor may be splitted into
// two mmap regions which causes failure of GuestMemoryMmap::read_obj_from_addr().
//
// The Virtio Spec 1.0 defines the alignment of VirtIO descriptor is 16 bytes,
// which fulfills the explicit constraint of GuestMemoryMmap::read_obj_from_addr().

/// An iterator over a single descriptor chain.  Not to be confused with AvailIter,
/// which iterates over the descriptor chain heads in a queue.
pub struct DescIter<'a> {
    next: Option<DescriptorChain<'a>>,
}

impl<'a> DescIter<'a> {
    /// Returns an iterator that only yields the readable descriptors in the chain.
    pub fn readable(self) -> impl Iterator<Item = DescriptorChain<'a>> {
        self.take_while(DescriptorChain::is_read_only)
    }

    /// Returns an iterator that only yields the writable descriptors in the chain.
    pub fn writable(self) -> impl Iterator<Item = DescriptorChain<'a>> {
        self.skip_while(DescriptorChain::is_read_only)
    }
}

impl<'a> Iterator for DescIter<'a> {
    type Item = DescriptorChain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.next.take() {
            self.next = current.next_descriptor();
            Some(current)
        } else {
            None
        }
    }
}

/// A virtio descriptor constraints with C representive.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

unsafe impl ByteValued for Descriptor {}

/// A packed ring descriptor (`struct pvirtq_desc`): the buffer id replaces
/// the split ring's next index, and chains are consecutive ring entries.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct PackedDescriptor {
    pub addr: u64,
    pub len: u32,
    pub id: u16,
    pub flags: u16,
}

unsafe impl ByteValued for PackedDescriptor {}

/// A virtio descriptor chain.
#[derive(Clone)]
pub struct DescriptorChain<'a> {
    desc_table: GuestAddress,
    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycles

    /// Reference to guest memory
    pub mem: &'a GuestMemoryMmap,

    /// Index into the descriptor table
    pub index: u16,

    /// Guest physical address of device specific data
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,

    /// Packed ring layout: `next` is the following ring slot and `index`
    /// stays the head slot for the whole chain.
    packed: bool,
}

impl<'a> DescriptorChain<'a> {
    pub fn checked_new(
        mem: &GuestMemoryMmap,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Option<DescriptorChain<'_>> {
        if index >= queue_size {
            return None;
        }

        let desc_head = mem.checked_offset(desc_table, (index as usize) * 16)?;
        mem.checked_offset(desc_head, 16)?;

        // These reads can't fail unless Guest memory is hopelessly broken.
        let desc = match mem.read_obj::<Descriptor>(desc_head) {
            Ok(ret) => ret,
            Err(_) => {
                // TODO log address
                error!("Failed to read from memory");
                return None;
            }
        };
        let chain = DescriptorChain {
            mem,
            desc_table,
            queue_size,
            ttl: queue_size,
            index,
            addr: GuestAddress(desc.addr),
            len: desc.len,
            flags: desc.flags,
            next: desc.next,
            packed: false,
        };

        if chain.is_valid() {
            Some(chain)
        } else {
            None
        }
    }

    /// A descriptor of a packed ring at `slot`; `ttl` bounds the chain and
    /// `head` is the ring slot the chain started at.
    fn checked_new_packed(
        mem: &GuestMemoryMmap,
        ring: GuestAddress,
        queue_size: u16,
        slot: u16,
        head: u16,
        ttl: u16,
    ) -> Option<DescriptorChain<'_>> {
        if slot >= queue_size || ttl == 0 {
            return None;
        }
        let addr = mem.checked_offset(ring, (slot as usize) * PACKED_DESC_SIZE as usize)?;
        mem.checked_offset(addr, PACKED_DESC_SIZE as usize)?;
        let desc: PackedDescriptor = mem.read_obj(addr).ok()?;
        Some(DescriptorChain {
            mem,
            desc_table: ring,
            queue_size,
            ttl,
            index: head,
            addr: GuestAddress(desc.addr),
            len: desc.len,
            flags: desc.flags,
            next: (slot + 1) % queue_size,
            packed: true,
        })
    }

    fn is_valid(&self) -> bool {
        !self.has_next() || self.next < self.queue_size
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// If the driver designated this as a read only descriptor.
    ///
    /// If this is false, this descriptor is write only.
    /// Read only means the emulated device can read and the driver can write.
    pub fn is_read_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE == 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<DescriptorChain<'a>> {
        if self.has_next() {
            if self.packed {
                return DescriptorChain::checked_new_packed(
                    self.mem,
                    self.desc_table,
                    self.queue_size,
                    self.next,
                    self.index,
                    self.ttl - 1,
                );
            }
            DescriptorChain::checked_new(self.mem, self.desc_table, self.queue_size, self.next).map(
                |mut c| {
                    c.ttl = self.ttl - 1;
                    c
                },
            )
        } else {
            None
        }
    }

    /// Produces an iterator over all the descriptors in this chain.
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> DescIter<'a> {
        DescIter { next: Some(self) }
    }

    pub fn descriptor(&self) -> Descriptor {
        Descriptor {
            addr: self.addr.raw_value(),
            len: self.len,
            flags: self.flags,
            next: self.next,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// A virtio queue's parameters.
pub struct Queue {
    /// The maximal size in elements offered by the device
    pub(crate) max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Indicates if the queue is finished with configuration
    pub ready: bool,

    /// Guest physical address of the descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    pub(crate) next_avail: Wrapping<u16>,
    pub(crate) next_used: Wrapping<u16>,

    /// VIRTIO_F_RING_EVENT_IDX negotiated.
    event_idx_enabled: bool,

    /// The number of descriptor chains placed in the used ring via `add_used`
    /// since the last time `needs_notification` was called on the associated queue.
    num_added: Wrapping<u16>,

    /// VIRTIO_F_RING_PACKED negotiated: `desc_table` is the descriptor ring,
    /// `avail_ring` the driver's event suppression area and `used_ring` the
    /// device's. `next_avail`/`next_used` keep counting freely; the ring slot
    /// is the value modulo the size and the wrap counter follows from the lap.
    packed: bool,
    /// Packed ring, per head slot: buffer id and descriptor count of the chain
    /// popped there, consumed by `add_used`.
    packed_chains: Vec<(u16, u16)>,
    /// Packed ring, per last slot of a popped chain: its descriptor count, so
    /// `undo_pop` can step back over whole chains.
    packed_chain_ends: Vec<u16>,
    /// Packed ring: used positions advanced since the last `needs_notification`.
    packed_used_added: Wrapping<u16>,
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: 0,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            event_idx_enabled: false,
            num_added: Wrapping(0),
            packed: false,
            packed_chains: Vec::new(),
            packed_chain_ends: Vec::new(),
            packed_used_added: Wrapping(0),
        }
    }

    /// Select the packed ring layout (VIRTIO_F_RING_PACKED) before use.
    pub fn set_packed(&mut self, packed: bool) {
        self.packed = packed;
        if packed {
            self.packed_chains = vec![(0, 0); self.max_size as usize];
            self.packed_chain_ends = vec![0; self.max_size as usize];
        } else {
            self.packed_chains.clear();
            self.packed_chain_ends.clear();
        }
    }

    pub fn is_packed(&self) -> bool {
        self.packed
    }

    /// Wrap counter the device expects on the next available descriptor.
    fn avail_wrap(&self) -> bool {
        (self.next_avail.0 / self.actual_size()) % 2 == 0
    }

    /// Wrap counter the device writes into the next used descriptor.
    fn used_wrap(&self) -> bool {
        (self.next_used.0 / self.actual_size()) % 2 == 0
    }

    fn packed_desc_addr(&self, slot: u16) -> GuestAddress {
        self.desc_table
            .unchecked_add(u64::from(slot) * PACKED_DESC_SIZE)
    }

    /// Packed ring: whether the driver has made the descriptor at `slot`
    /// available, judged against `wrap`.
    fn packed_available(&self, mem: &GuestMemoryMmap, slot: u16, wrap: bool) -> bool {
        let flags: u16 = match mem.load(
            self.packed_desc_addr(slot).unchecked_add(14),
            Ordering::Acquire,
        ) {
            Ok(flags) => flags,
            Err(_) => return false,
        };
        let avail = flags & VIRTQ_DESC_F_AVAIL != 0;
        let used = flags & VIRTQ_DESC_F_USED != 0;
        avail == wrap && used != wrap
    }

    fn pop_packed<'b>(&mut self, mem: &'b GuestMemoryMmap) -> Option<DescriptorChain<'b>> {
        let size = self.actual_size();
        if size == 0 {
            return None;
        }
        let head = self.next_avail.0 % size;
        if !self.packed_available(mem, head, self.avail_wrap()) {
            return None;
        }
        // The buffer id travels in the chain's last descriptor; chained
        // descriptors occupy consecutive slots.
        let mut count: u16 = 0;
        let mut slot = head;
        let id = loop {
            let desc: PackedDescriptor = mem.read_obj(self.packed_desc_addr(slot)).ok()?;
            count += 1;
            if desc.flags & VIRTQ_DESC_F_NEXT == 0 || count >= size {
                break desc.id;
            }
            slot = (slot + 1) % size;
        };
        if id >= size {
            error!("packed virtqueue chain carries an out of range buffer id {id}");
            return None;
        }
        let chain =
            DescriptorChain::checked_new_packed(mem, self.desc_table, size, head, head, count)?;
        self.packed_chains[head as usize] = (id, count);
        self.packed_chain_ends[((head + count - 1) % size) as usize] = count;
        self.next_avail += Wrapping(count);
        Some(chain)
    }

    fn packed_len(&self, mem: &GuestMemoryMmap) -> u16 {
        let size = self.actual_size();
        if size == 0 {
            return 0;
        }
        let mut idx = self.next_avail;
        let mut chains = 0u16;
        let mut seen = 0u16;
        while seen < size {
            let slot = idx.0 % size;
            if !self.packed_available(mem, slot, (idx.0 / size) % 2 == 0) {
                break;
            }
            let mut count = 1u16;
            while count < size {
                let flags: u16 = mem
                    .load(
                        self.packed_desc_addr((slot + count - 1) % size).unchecked_add(14),
                        Ordering::Relaxed,
                    )
                    .unwrap_or(0);
                if flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                count += 1;
            }
            chains += 1;
            seen = seen.saturating_add(count);
            idx += Wrapping(count);
        }
        chains
    }

    pub fn get_max_size(&self) -> u16 {
        self.max_size
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    pub fn is_valid(&self, mem: &GuestMemoryMmap) -> bool {
        let queue_size = u64::from(self.actual_size());
        let desc_table = self.desc_table;
        let desc_table_size = 16 * queue_size;
        let avail_ring = self.avail_ring;
        let used_ring = self.used_ring;
        // A packed ring's driver and device areas are one event suppression
        // struct each (off_wrap and flags).
        let (avail_ring_size, used_ring_size) = if self.packed {
            (4, 4)
        } else {
            (6 + 2 * queue_size, 6 + 8 * queue_size)
        };
        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            error!("virtio queue with invalid size: {}", self.size);
            false
        } else if desc_table
            .checked_add(desc_table_size)
            .is_none_or(|v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x} size:0x{:08x}",
                desc_table.raw_value(),
                desc_table_size
            );
            false
        } else if avail_ring
            .checked_add(avail_ring_size)
            .is_none_or(|v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue available ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                avail_ring.raw_value(),
                avail_ring_size
            );
            false
        } else if used_ring
            .checked_add(used_ring_size)
            .is_none_or(|v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue used ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                used_ring.raw_value(),
                used_ring_size
            );
            false
        } else if desc_table.raw_value() & 0xf != 0 {
            error!("virtio queue descriptor table breaks alignment contraints");
            false
        } else if avail_ring.raw_value() & 0x1 != 0 {
            error!("virtio queue available ring breaks alignment contraints");
            false
        } else if used_ring.raw_value() & 0x3 != 0 {
            error!("virtio queue used ring breaks alignment contraints");
            false
        } else {
            true
        }
    }

    /// Returns the number of yet-to-be-popped descriptor chains in the avail ring.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self, mem: &GuestMemoryMmap) -> u16 {
        if self.packed {
            return self.packed_len(mem);
        }
        (self.avail_idx(mem, Ordering::Acquire).unwrap() - self.next_avail).0
    }

    /// Checks if the driver has made any descriptor chains available in the avail ring.
    pub fn is_empty(&self, mem: &GuestMemoryMmap) -> bool {
        if self.packed {
            let size = self.actual_size();
            return size == 0 || !self.packed_available(mem, self.next_avail.0 % size, self.avail_wrap());
        }
        self.len(mem) == 0
    }

    /// Pop the first available descriptor chain from the avail ring.
    pub fn pop<'b>(&mut self, mem: &'b GuestMemoryMmap) -> Option<DescriptorChain<'b>> {
        if self.packed {
            return self.pop_packed(mem);
        }
        if self.len(mem) == 0 || self.actual_size() == 0 {
            return None;
        }

        // We'll need to find the first available descriptor, that we haven't yet popped.
        // In a naive notation, that would be:
        // `descriptor_table[avail_ring[next_avail]]`.
        //
        // First, we compute the byte-offset (into `self.avail_ring`) of the index of the next available
        // descriptor. `self.avail_ring` stores the address of a `struct virtq_avail`, as defined by
        // the VirtIO spec:
        //
        // ```C
        // struct virtq_avail {
        //   le16 flags;
        //   le16 idx;
        //   le16 ring[QUEUE_SIZE];
        //   le16 used_event
        // }
        // ```
        //
        // We use `self.next_avail` to store the position, in `ring`, of the next available
        // descriptor index, with a twist: we always only increment `self.next_avail`, so the
        // actual position will be `self.next_avail % self.actual_size()`.
        // We are now looking for the offset of `ring[self.next_avail % self.actual_size()]`.
        // `ring` starts after `flags` and `idx` (4 bytes into `struct virtq_avail`), and holds
        // 2-byte items, so the offset will be:
        let index_offset = 4 + 2 * (self.next_avail.0 % self.actual_size());

        // Make sure we catch all updates on the queue
        fence(Ordering::Acquire);

        // `self.is_valid()` already performed all the bound checks on the descriptor table
        // and virtq rings, so it's safe to unwrap guest memory reads and to use unchecked
        // offsets.
        let desc_index: u16 = mem
            .read_obj(self.avail_ring.unchecked_add(u64::from(index_offset)))
            .unwrap();

        DescriptorChain::checked_new(mem, self.desc_table, self.actual_size(), desc_index)
            .inspect(|_| self.next_avail += Wrapping(1))
    }

    /// Undo the effects of the last `self.pop()` call.
    /// The caller can use this, if it was unable to consume the last popped descriptor chain.
    pub fn undo_pop(&mut self) {
        if self.packed {
            let size = self.actual_size();
            if size == 0 {
                return;
            }
            let end = (self.next_avail - Wrapping(1)).0 % size;
            let count = self.packed_chain_ends[end as usize].max(1);
            self.next_avail -= Wrapping(count);
            return;
        }
        self.next_avail -= Wrapping(1);
    }

    pub fn add_used(
        &mut self,
        mem: &GuestMemoryMmap,
        head_index: u16,
        len: u32,
    ) -> Result<(), Error> {
        if head_index >= self.size {
            error!("attempted to add out of bounds descriptor to used ring: {head_index}");
            return Err(Error::InvalidDescriptorIndex);
        }

        if self.packed {
            return self.add_used_packed(mem, head_index, len);
        }

        let next_used_index = u64::from(self.next_used.0 % self.size);
        // This can not overflow an u64 since it is working with relatively small numbers compared
        // to u64::MAX.
        let offset = VIRTQ_USED_RING_HEADER_SIZE + next_used_index * VIRTQ_USED_ELEMENT_SIZE;
        let addr = self
            .used_ring
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)?;
        mem.write_obj(VirtqUsedElem::new(head_index.into(), len), addr)
            .map_err(Error::GuestMemory)?;

        self.next_used += Wrapping(1);
        self.num_added += Wrapping(1);

        mem.store(
            self.next_used.0,
            self.used_ring
                .checked_add(2)
                .ok_or(Error::AddressOverflow)?,
            Ordering::Release,
        )
        .map_err(Error::GuestMemory)
    }

    /// Packed ring: one used descriptor per chain, written where the chain
    /// started in used order; the position then advances by the chain's
    /// descriptor count, which is how the driver walks used entries.
    fn add_used_packed(
        &mut self,
        mem: &GuestMemoryMmap,
        head_index: u16,
        len: u32,
    ) -> Result<(), Error> {
        let size = self.actual_size();
        let (id, count) = self.packed_chains[head_index as usize];
        if count == 0 {
            error!("attempted to complete a packed chain that was not popped: {head_index}");
            return Err(Error::InvalidDescriptorIndex);
        }
        let addr = self.packed_desc_addr(self.next_used.0 % size);
        mem.write_obj(id, addr.unchecked_add(12))
            .map_err(Error::GuestMemory)?;
        mem.write_obj(len, addr.unchecked_add(8))
            .map_err(Error::GuestMemory)?;
        // The driver reads the flags first, so id and len must be visible
        // before the AVAIL/USED bits flip.
        fence(Ordering::Release);
        let flags = if self.used_wrap() {
            VIRTQ_DESC_F_AVAIL | VIRTQ_DESC_F_USED
        } else {
            0
        };
        mem.store(flags, addr.unchecked_add(14), Ordering::Release)
            .map_err(Error::GuestMemory)?;
        self.packed_chains[head_index as usize] = (0, 0);
        self.next_used += Wrapping(count);
        self.packed_used_added += Wrapping(count);
        self.num_added += Wrapping(1);
        Ok(())
    }

    // Return the value present in the used_event field of the avail ring.
    //
    // If the VIRTIO_F_EVENT_IDX feature bit is not negotiated, the flags field in the available
    // ring offers a crude mechanism for the driver to inform the device that it doesn’t want
    // interrupts when buffers are used. Otherwise virtq_avail.used_event is a more performant
    // alternative where the driver specifies how far the device can progress before interrupting.
    //
    // Neither of these interrupt suppression methods are reliable, as they are not synchronized
    // with the device, but they serve as useful optimizations. So we only ensure access to the
    // virtq_avail.used_event is atomic, but do not need to synchronize with other memory accesses.
    fn used_event(&self, mem: &GuestMemoryMmap, order: Ordering) -> Result<Wrapping<u16>, Error> {
        // This can not overflow an u64 since it is working with relatively small numbers compared
        // to u64::MAX.
        let used_event_offset =
            VIRTQ_AVAIL_RING_HEADER_SIZE + u64::from(self.size) * VIRTQ_AVAIL_ELEMENT_SIZE;
        let used_event_addr = self
            .avail_ring
            .checked_add(used_event_offset)
            .ok_or(Error::AddressOverflow)?;

        mem.load(used_event_addr, order)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }

    // Helper method that writes `val` to the `avail_event` field of the used ring, using
    // the provided ordering.
    fn set_avail_event(
        &self,
        mem: &GuestMemoryMmap,
        val: u16,
        order: Ordering,
    ) -> Result<(), Error> {
        // This can not overflow an u64 since it is working with relatively small numbers compared
        // to u64::MAX.
        let avail_event_offset =
            VIRTQ_USED_RING_HEADER_SIZE + VIRTQ_USED_ELEMENT_SIZE * u64::from(self.size);
        let addr = self
            .used_ring
            .checked_add(avail_event_offset)
            .ok_or(Error::AddressOverflow)?;

        mem.store(val, addr, order).map_err(Error::GuestMemory)
    }

    pub fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx_enabled = enabled;
    }

    // Set the value of the `flags` field of the used ring, applying the specified ordering.
    fn set_used_flags(
        &mut self,
        mem: &GuestMemoryMmap,
        val: u16,
        order: Ordering,
    ) -> Result<(), Error> {
        mem.store(val, self.used_ring, order)
            .map_err(Error::GuestMemory)
    }

    // Write the appropriate values to enable or disable notifications from the driver.
    //
    // Every access in this method uses `Relaxed` ordering because a fence is added by the caller
    // when appropriate.
    fn set_notification(&mut self, mem: &GuestMemoryMmap, enable: bool) -> Result<(), Error> {
        if self.packed {
            // The device area tells the driver when to kick: always, never,
            // or once it makes the descriptor at off_wrap available.
            let (off_wrap, flags) = if enable {
                if self.event_idx_enabled {
                    let size = self.actual_size();
                    let off = self.next_avail.0 % size;
                    (
                        off | ((self.avail_wrap() as u16) << VRING_PACKED_EVENT_F_WRAP_CTR),
                        VRING_PACKED_EVENT_FLAG_DESC,
                    )
                } else {
                    (0, VRING_PACKED_EVENT_FLAG_ENABLE)
                }
            } else if self.event_idx_enabled {
                // As with the split ring, a descriptor event only fires once.
                return Ok(());
            } else {
                (0, VRING_PACKED_EVENT_FLAG_DISABLE)
            };
            mem.store(off_wrap, self.used_ring, Ordering::Relaxed)
                .map_err(Error::GuestMemory)?;
            return mem
                .store(flags, self.used_ring.unchecked_add(2), Ordering::Relaxed)
                .map_err(Error::GuestMemory);
        }
        if enable {
            if self.event_idx_enabled {
                // We call `set_avail_event` using the `next_avail` value, instead of reading
                // and using the current `avail_idx` to avoid missing notifications. More
                // details in `enable_notification`.
                self.set_avail_event(mem, self.next_avail.0, Ordering::Relaxed)
            } else {
                self.set_used_flags(mem, 0, Ordering::Relaxed)
            }
        } else if !self.event_idx_enabled {
            self.set_used_flags(mem, VRING_USED_F_NO_NOTIFY as u16, Ordering::Relaxed)
        } else {
            // Notifications are effectively disabled by default after triggering once when
            // `VIRTIO_F_EVENT_IDX` is negotiated, so we don't do anything in that case.
            Ok(())
        }
    }

    // TODO: Turn this into a doc comment/example.
    // With the current implementation, a common way of consuming entries from the available ring
    // while also leveraging notification suppression is to use a loop, for example:
    //
    // loop {
    //     // We have to explicitly disable notifications if `VIRTIO_F_EVENT_IDX` has not been
    //     // negotiated.
    //     self.disable_notification()?;
    //
    //     for chain in self.iter()? {
    //         // Do something with each chain ...
    //         // Let's assume we process all available chains here.
    //     }
    //
    //     // If `enable_notification` returns `true`, the driver has added more entries to the
    //     // available ring.
    //     if !self.enable_notification()? {
    //         break;
    //     }
    // }
    pub fn enable_notification(&mut self, mem: &GuestMemoryMmap) -> Result<bool, Error> {
        self.set_notification(mem, true)?;
        // Ensures the following read is not reordered before any previous write operation.
        fence(Ordering::SeqCst);

        // We double check here to avoid the situation where the available ring has been updated
        // just before we re-enabled notifications, and it's possible to miss one. We compare the
        // current `avail_idx` value to `self.next_avail` because it's where we stopped processing
        // entries. There are situations where we intentionally avoid processing everything in the
        // available ring (which will cause this method to return `true`), but in that case we'll
        // probably not re-enable notifications as we already know there are pending entries.
        if self.packed {
            return Ok(!self.is_empty(mem));
        }
        self.avail_idx(mem, Ordering::Relaxed)
            .map(|idx| idx != self.next_avail)
    }

    pub fn disable_notification(&mut self, mem: &GuestMemoryMmap) -> Result<(), Error> {
        self.set_notification(mem, false)
    }

    pub fn needs_notification(&mut self, mem: &GuestMemoryMmap) -> Result<bool, Error> {
        let used_idx = self.next_used;

        // Complete all the writes in add_used() before reading the event.
        fence(Ordering::SeqCst);

        if self.packed {
            return self.needs_notification_packed(mem);
        }

        // The VRING_AVAIL_F_NO_INTERRUPT flag isn't supported yet.

        // When the `EVENT_IDX` feature is negotiated, the driver writes into `used_event`
        // a value that's used by the device to determine whether a notification must
        // be submitted after adding a descriptor chain to the used ring. According to the
        // standard, the notification must be sent when `next_used == used_event + 1`, but
        // various device model implementations rely on an inequality instead, most likely
        // to also support use cases where a bunch of descriptor chains are added to the used
        // ring first, and only afterwards the `needs_notification` logic is called. For example,
        // the approach based on `num_added` below is taken from the Linux Kernel implementation
        // (i.e. https://elixir.bootlin.com/linux/v5.15.35/source/drivers/virtio/virtio_ring.c#L661)

        // The `old` variable below is used to determine the value of `next_used` from when
        // `needs_notification` was called last (each `needs_notification` call resets `num_added`
        // to zero, while each `add_used` called increments it by one). Then, the logic below
        // uses wrapped arithmetic to see whether `used_event` can be found between `old` and
        // `next_used` in the circular sequence space of the used ring.
        if self.event_idx_enabled {
            let used_event = self.used_event(mem, Ordering::Relaxed)?;
            let old = used_idx - self.num_added;
            self.num_added = Wrapping(0);
            return Ok(used_idx - used_event - Wrapping(1) < used_idx - old);
        }

        Ok(true)
    }

    /// Packed ring: the driver area says whether to interrupt: never, always,
    /// or once the device has written the used descriptor named by off_wrap.
    fn needs_notification_packed(&mut self, mem: &GuestMemoryMmap) -> Result<bool, Error> {
        let flags: u16 = mem
            .load(self.avail_ring.unchecked_add(2), Ordering::Relaxed)
            .map_err(Error::GuestMemory)?;
        let added = self.packed_used_added;
        self.packed_used_added = Wrapping(0);
        self.num_added = Wrapping(0);
        if flags == VRING_PACKED_EVENT_FLAG_DISABLE {
            return Ok(false);
        }
        if flags != VRING_PACKED_EVENT_FLAG_DESC || !self.event_idx_enabled {
            return Ok(true);
        }
        let off_wrap: u16 = mem
            .load(self.avail_ring, Ordering::Relaxed)
            .map_err(Error::GuestMemory)?;
        let off = off_wrap & !(1 << VRING_PACKED_EVENT_F_WRAP_CTR);
        let wrap = (off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR) == 1;
        let size = self.actual_size();
        // Place the event in the free-running used index space: in this lap
        // when its wrap counter matches ours, else in the previous lap.
        let new = self.next_used.0;
        let old = new.wrapping_sub(added.0);
        let mut event = (new - new % size).wrapping_add(off);
        if wrap != self.used_wrap() {
            event = event.wrapping_sub(size);
        }
        Ok(new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old))
    }

    /// Goes back one position in the available descriptor chain offered by the driver.
    /// Rust does not support bidirectional iterators. This is the only way to revert the effect
    /// of an iterator increment on the queue.
    pub fn go_to_previous_position(&mut self) {
        self.undo_pop();
    }

    /// Fetch the available ring index (`virtq_avail->idx`) from guest memory.
    /// This is written by the driver, to indicate the next slot that will be filled in the avail
    /// ring.
    fn avail_idx(&self, mem: &GuestMemoryMmap, order: Ordering) -> Result<Wrapping<u16>, Error> {
        let addr = self
            .avail_ring
            .checked_add(2)
            .ok_or(Error::AddressOverflow)?;

        mem.load(addr, order)
            .map(Wrapping)
            .map_err(Error::GuestMemory)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::marker::PhantomData;
    use std::mem;

    pub use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    // Represents a location in GuestMemoryMmap which holds a given type.
    pub struct SomeplaceInMemory<'a, T> {
        pub location: GuestAddress,
        mem: &'a GuestMemoryMmap,
        phantom: PhantomData<*const T>,
    }

    // The ByteValued trait is required to use mem.read_obj_from_addr and write_obj_at_addr.
    impl<'a, T> SomeplaceInMemory<'a, T>
    where
        T: vm_memory::ByteValued,
    {
        fn new(location: GuestAddress, mem: &'a GuestMemoryMmap) -> Self {
            SomeplaceInMemory {
                location,
                mem,
                phantom: PhantomData,
            }
        }

        // Reads from the actual memory location.
        pub fn get(&self) -> T {
            self.mem.read_obj(self.location).unwrap()
        }

        // Writes to the actual memory location.
        pub fn set(&self, val: T) {
            self.mem.write_obj(val, self.location).unwrap()
        }

        // This function returns a place in memory which holds a value of type U, and starts
        // offset bytes after the current location.
        fn map_offset<U>(&self, offset: usize) -> SomeplaceInMemory<'a, U> {
            SomeplaceInMemory {
                location: self.location.checked_add(offset as u64).unwrap(),
                mem: self.mem,
                phantom: PhantomData,
            }
        }

        // This function returns a place in memory which holds a value of type U, and starts
        // immediately after the end of self (which is location + sizeof(T)).
        fn next_place<U>(&self) -> SomeplaceInMemory<'a, U> {
            self.map_offset::<U>(mem::size_of::<T>())
        }

        fn end(&self) -> GuestAddress {
            self.location
                .checked_add(mem::size_of::<T>() as u64)
                .unwrap()
        }
    }

    // Represents a virtio descriptor in guest memory.
    pub struct VirtqDesc<'a> {
        pub addr: SomeplaceInMemory<'a, u64>,
        pub len: SomeplaceInMemory<'a, u32>,
        pub flags: SomeplaceInMemory<'a, u16>,
        pub next: SomeplaceInMemory<'a, u16>,
    }

    impl<'a> VirtqDesc<'a> {
        fn new(start: GuestAddress, mem: &'a GuestMemoryMmap) -> Self {
            assert_eq!(start.0 & 0xf, 0);

            let addr = SomeplaceInMemory::new(start, mem);
            let len = addr.next_place();
            let flags = len.next_place();
            let next = flags.next_place();

            VirtqDesc {
                addr,
                len,
                flags,
                next,
            }
        }

        fn start(&self) -> GuestAddress {
            self.addr.location
        }

        fn end(&self) -> GuestAddress {
            self.next.end()
        }

        pub fn set(&self, addr: u64, len: u32, flags: u16, next: u16) {
            self.addr.set(addr);
            self.len.set(len);
            self.flags.set(flags);
            self.next.set(next);
        }
    }

    // Represents a virtio queue ring. The only difference between the used and available rings,
    // is the ring element type.
    pub struct VirtqRing<'a, T> {
        pub flags: SomeplaceInMemory<'a, u16>,
        pub idx: SomeplaceInMemory<'a, u16>,
        pub ring: Vec<SomeplaceInMemory<'a, T>>,
        pub event: SomeplaceInMemory<'a, u16>,
    }

    impl<'a, T> VirtqRing<'a, T>
    where
        T: vm_memory::ByteValued,
    {
        fn new(
            start: GuestAddress,
            mem: &'a GuestMemoryMmap,
            qsize: u16,
            alignment: usize,
        ) -> Self {
            assert_eq!(start.0 & (alignment as u64 - 1), 0);

            let flags = SomeplaceInMemory::new(start, mem);
            let idx = flags.next_place();

            let mut ring = Vec::with_capacity(qsize as usize);

            ring.push(idx.next_place());

            for _ in 1..qsize as usize {
                let x = ring.last().unwrap().next_place();
                ring.push(x)
            }

            let event = ring.last().unwrap().next_place();

            flags.set(0);
            idx.set(0);
            event.set(0);

            VirtqRing {
                flags,
                idx,
                ring,
                event,
            }
        }

        pub fn end(&self) -> GuestAddress {
            self.event.end()
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct VirtqUsedElem {
        pub id: u32,
        pub len: u32,
    }

    unsafe impl vm_memory::ByteValued for VirtqUsedElem {}

    pub type VirtqAvail<'a> = VirtqRing<'a, u16>;
    pub type VirtqUsed<'a> = VirtqRing<'a, VirtqUsedElem>;

    pub struct VirtQueue<'a> {
        pub dtable: Vec<VirtqDesc<'a>>,
        pub avail: VirtqAvail<'a>,
        pub used: VirtqUsed<'a>,
    }

    impl<'a> VirtQueue<'a> {
        // We try to make sure things are aligned properly :-s
        pub fn new(start: GuestAddress, mem: &'a GuestMemoryMmap, qsize: u16) -> Self {
            // power of 2?
            assert!(qsize > 0 && qsize & (qsize - 1) == 0);

            let mut dtable = Vec::with_capacity(qsize as usize);

            let mut end = start;

            for _ in 0..qsize {
                let d = VirtqDesc::new(end, mem);
                end = d.end();
                dtable.push(d);
            }

            const AVAIL_ALIGN: usize = 2;

            let avail = VirtqAvail::new(end, mem, qsize, AVAIL_ALIGN);

            const USED_ALIGN: u64 = 4;

            let mut x = avail.end().0;
            x = (x + USED_ALIGN - 1) & !(USED_ALIGN - 1);

            let used = VirtqUsed::new(GuestAddress(x), mem, qsize, USED_ALIGN as usize);

            VirtQueue {
                dtable,
                avail,
                used,
            }
        }

        pub fn size(&self) -> u16 {
            self.dtable.len() as u16
        }

        fn dtable_start(&self) -> GuestAddress {
            self.dtable.first().unwrap().start()
        }

        fn avail_start(&self) -> GuestAddress {
            self.avail.flags.location
        }

        fn used_start(&self) -> GuestAddress {
            self.used.flags.location
        }

        // Creates a new Queue, using the underlying memory regions represented by the VirtQueue.
        pub fn create_queue(&self) -> Queue {
            let mut q = Queue::new(self.size());

            q.size = self.size();
            q.ready = true;
            q.desc_table = self.dtable_start();
            q.avail_ring = self.avail_start();
            q.used_ring = self.used_start();

            q
        }

        pub fn end(&self) -> GuestAddress {
            self.used.end()
        }
    }

    /// A packed ring laid out in guest memory, driven like a virtio 1.1 driver.
    struct PackedRing<'a> {
        mem: &'a GuestMemoryMmap,
        ring: GuestAddress,
        driver: GuestAddress,
        device: GuestAddress,
        size: u16,
        next: u16,
        wrap: bool,
    }

    impl<'a> PackedRing<'a> {
        fn new(mem: &'a GuestMemoryMmap, size: u16) -> Self {
            PackedRing {
                mem,
                ring: GuestAddress(0x1000),
                driver: GuestAddress(0x3000),
                device: GuestAddress(0x3100),
                size,
                next: 0,
                wrap: true,
            }
        }

        fn queue(&self) -> Queue {
            let mut q = Queue::new(self.size);
            q.size = self.size;
            q.ready = true;
            q.desc_table = self.ring;
            q.avail_ring = self.driver;
            q.used_ring = self.device;
            q.set_packed(true);
            q.set_event_idx(true);
            q
        }

        fn desc(&self, slot: u16) -> PackedDescriptor {
            self.mem.read_obj(self.ring.unchecked_add(u64::from(slot) * 16)).unwrap()
        }

        /// Make a chain available: one descriptor per buffer, the id in the
        /// last one, the head written last as a driver would.
        fn add_chain(&mut self, buffers: &[(u64, u32, bool)], id: u16) -> u16 {
            let head = self.next;
            let mut slots = Vec::new();
            for (i, &(addr, len, write)) in buffers.iter().enumerate() {
                let last = i + 1 == buffers.len();
                let mut flags = if write { VIRTQ_DESC_F_WRITE } else { 0 };
                if !last {
                    flags |= VIRTQ_DESC_F_NEXT;
                }
                if self.wrap {
                    flags |= VIRTQ_DESC_F_AVAIL;
                } else {
                    flags |= VIRTQ_DESC_F_USED;
                }
                slots.push((self.next, PackedDescriptor { addr, len, id, flags }));
                self.next += 1;
                if self.next == self.size {
                    self.next = 0;
                    self.wrap = !self.wrap;
                }
            }
            for (slot, desc) in slots.iter().skip(1) {
                self.mem.write_obj(*desc, self.ring.unchecked_add(u64::from(*slot) * 16)).unwrap();
            }
            let (slot, desc) = slots[0];
            self.mem.write_obj(desc, self.ring.unchecked_add(u64::from(slot) * 16)).unwrap();
            head
        }

        fn set_driver_event(&self, off_wrap: u16, flags: u16) {
            self.mem.write_obj(off_wrap, self.driver).unwrap();
            self.mem.write_obj(flags, self.driver.unchecked_add(2)).unwrap();
        }

        fn device_event(&self) -> (u16, u16) {
            (
                self.mem.read_obj(self.device).unwrap(),
                self.mem.read_obj(self.device.unchecked_add(2)).unwrap(),
            )
        }
    }

    #[test]
    fn test_packed_pop_follows_chains_and_completes_in_place() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut ring = PackedRing::new(m, 8);
        let mut q = ring.queue();
        assert!(q.is_valid(m));
        assert!(q.is_empty(m));
        assert!(q.pop(m).is_none());

        ring.add_chain(&[(0x5000, 100, false)], 3);
        ring.add_chain(&[(0x6000, 12, false), (0x6100, 500, false), (0x6200, 64, true)], 5);
        assert_eq!(q.len(m), 2);

        let first = q.pop(m).unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(first.addr, GuestAddress(0x5000));
        assert_eq!(first.len, 100);
        assert!(first.next_descriptor().is_none());

        let head = q.pop(m).unwrap();
        assert_eq!(head.index, 1);
        assert_eq!(head.addr, GuestAddress(0x6000));
        let second = head.next_descriptor().unwrap();
        assert_eq!(second.index, 1, "the chain keeps its head slot as index");
        assert_eq!(second.addr, GuestAddress(0x6100));
        let third = second.next_descriptor().unwrap();
        assert!(third.is_write_only());
        assert_eq!(third.len, 64);
        assert!(third.next_descriptor().is_none());
        assert!(q.pop(m).is_none());
        assert!(q.is_empty(m));

        // Used descriptors: one per chain where it started, both wrap bits set
        // in the first lap, and the used position advances by the chain length.
        q.add_used(m, 0, 0).unwrap();
        q.add_used(m, 1, 64).unwrap();
        let used0 = ring.desc(0);
        assert_eq!((used0.id, used0.len), (3, 0));
        assert_eq!(used0.flags & (VIRTQ_DESC_F_AVAIL | VIRTQ_DESC_F_USED), VIRTQ_DESC_F_AVAIL | VIRTQ_DESC_F_USED);
        let used1 = ring.desc(1);
        assert_eq!((used1.id, used1.len), (5, 64));
        assert_eq!(ring.desc(2).id, 5, "the chain's other slots are untouched");
        assert_eq!(q.next_used.0, 4);
    }

    #[test]
    fn test_packed_wrap_counters_flip_per_lap() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut ring = PackedRing::new(m, 4);
        let mut q = ring.queue();
        ring.add_chain(&[(0x5000, 10, false)], 0);
        ring.add_chain(&[(0x5100, 10, false), (0x5200, 10, false), (0x5300, 10, false)], 1);
        let a = q.pop(m).unwrap();
        let b = q.pop(m).unwrap();
        assert!(q.pop(m).is_none());
        q.add_used(m, a.index, 0).unwrap();
        q.add_used(m, b.index, 0).unwrap();

        // Second lap: the driver flips its wrap bit; stale first-lap flags
        // must not look available, fresh second-lap ones must.
        assert!(q.is_empty(m));
        ring.add_chain(&[(0x5400, 10, false)], 2);
        assert!(!q.is_empty(m));
        let c = q.pop(m).unwrap();
        assert_eq!(c.index, 0);
        assert_eq!(c.addr, GuestAddress(0x5400));
        q.add_used(m, c.index, 0).unwrap();
        let used = ring.desc(0);
        assert_eq!(used.id, 2);
        assert_eq!(used.flags & (VIRTQ_DESC_F_AVAIL | VIRTQ_DESC_F_USED), 0, "second-lap used flags are both clear");
    }

    #[test]
    fn test_packed_undo_pop_steps_back_whole_chains() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut ring = PackedRing::new(m, 8);
        let mut q = ring.queue();
        ring.add_chain(&[(0x5000, 10, false)], 0);
        ring.add_chain(&[(0x5100, 10, false), (0x5200, 10, false)], 1);
        ring.add_chain(&[(0x5300, 10, false)], 2);
        q.pop(m).unwrap();
        q.pop(m).unwrap();
        q.pop(m).unwrap();
        assert_eq!(q.next_avail.0, 4);
        q.undo_pop();
        assert_eq!(q.next_avail.0, 3);
        q.undo_pop();
        assert_eq!(q.next_avail.0, 1);
        let again = q.pop(m).unwrap();
        assert_eq!(again.index, 1);
        assert_eq!(again.addr, GuestAddress(0x5100));
    }

    #[test]
    fn test_packed_event_suppression() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut ring = PackedRing::new(m, 8);
        let mut q = ring.queue();
        for i in 0..3u16 {
            ring.add_chain(&[(0x5000 + u64::from(i) * 0x100, 10, false)], i);
        }

        // Enabling notifications publishes the next slot and our wrap bit.
        assert!(q.enable_notification(m).unwrap(), "entries are pending");
        assert_eq!(ring.device_event(), (0 | (1 << 15), VRING_PACKED_EVENT_FLAG_DESC));

        let a = q.pop(m).unwrap();
        let b = q.pop(m).unwrap();
        ring.set_driver_event(0, VRING_PACKED_EVENT_FLAG_DISABLE);
        q.add_used(m, a.index, 0).unwrap();
        assert!(!q.needs_notification(m).unwrap());

        ring.set_driver_event(0, VRING_PACKED_EVENT_FLAG_ENABLE);
        q.add_used(m, b.index, 0).unwrap();
        assert!(q.needs_notification(m).unwrap());

        // Descriptor events: wanted at used slot 2 (first lap). Not reached yet.
        ring.set_driver_event(2 | (1 << 15), VRING_PACKED_EVENT_FLAG_DESC);
        assert!(!q.needs_notification(m).unwrap(), "nothing used since the last check");
        let c = q.pop(m).unwrap();
        q.add_used(m, c.index, 0).unwrap();
        assert!(q.needs_notification(m).unwrap(), "used slot 2 was just written");

        // An event in the next lap (wrap bit differs, slot ahead) is not due.
        ring.add_chain(&[(0x5900, 10, false)], 3);
        ring.set_driver_event(6, VRING_PACKED_EVENT_FLAG_DESC);
        let d = q.pop(m).unwrap();
        q.add_used(m, d.index, 0).unwrap();
        assert!(!q.needs_notification(m).unwrap());
    }

    #[test]
    fn test_checked_new_descriptor_chain() {
        let m = &GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 0x10000),
            (GuestAddress(0x20000), 0x2000),
        ])
        .unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        assert!(vq.end().0 < 0x1000);

        // index >= queue_size
        assert!(DescriptorChain::checked_new(m, vq.dtable_start(), 16, 16).is_none());

        // desc_table address is way off
        assert!(DescriptorChain::checked_new(m, GuestAddress(0x00ff_ffff_ffff), 16, 0).is_none());

        // Let's create an invalid chain.
        {
            // The first desc has a normal len, and the next_descriptor flag is set.
            vq.dtable[0].addr.set(0x1000);
            vq.dtable[0].len.set(0x1000);
            vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
            // .. but the the index of the next descriptor is too large
            vq.dtable[0].next.set(16);

            assert!(DescriptorChain::checked_new(m, vq.dtable_start(), 16, 0).is_none());
        }

        // Finally, let's test an ok chain.
        {
            vq.dtable[0].next.set(1);
            vq.dtable[1].set(0x2000, 0x1000, 0, 0);

            let c = DescriptorChain::checked_new(m, vq.dtable_start(), 16, 0).unwrap();

            assert_eq!(c.mem as *const GuestMemoryMmap, m as *const GuestMemoryMmap);
            assert_eq!(c.desc_table, vq.dtable_start());
            assert_eq!(c.queue_size, 16);
            assert_eq!(c.ttl, c.queue_size);
            assert_eq!(c.index, 0);
            assert_eq!(c.addr, GuestAddress(0x1000));
            assert_eq!(c.len, 0x1000);
            assert_eq!(c.flags, VIRTQ_DESC_F_NEXT);
            assert_eq!(c.next, 1);

            assert!(c.next_descriptor().unwrap().next_descriptor().is_none());
        }
    }

    #[test]
    #[allow(unused)]
    fn test_queue_validation() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();

        // q is currently valid
        assert!(q.is_valid(m));

        // shouldn't be valid when not marked as ready
        q.ready = false;
        assert!(!q.is_valid(m));
        q.ready = true;

        // or when size > max_size
        q.size = q.max_size << 1;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when size is 0
        q.size = 0;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or when size is not a power of 2
        q.size = 11;
        assert!(!q.is_valid(m));
        q.size = q.max_size;

        // or if the various addresses are off

        q.desc_table = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.desc_table = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.desc_table = vq.dtable_start();

        q.avail_ring = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.avail_ring = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.avail_ring = vq.avail_start();

        q.used_ring = GuestAddress(0xffff_ffff);
        assert!(!q.is_valid(m));
        q.used_ring = GuestAddress(0x1001);
        assert!(!q.is_valid(m));
        q.used_ring = vq.used_start();
    }

    #[test]
    fn test_queue_processing() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);
        let mut q = vq.create_queue();

        q.ready = true;

        // Let's create two simple descriptor chains.

        for j in 0..5 {
            vq.dtable[j].set(
                0x1000 * (j + 1) as u64,
                0x1000,
                VIRTQ_DESC_F_NEXT,
                (j + 1) as u16,
            );
        }

        // the chains are (0, 1) and (2, 3, 4)
        vq.dtable[1].flags.set(0);
        vq.dtable[4].flags.set(0);
        vq.avail.ring[0].set(0);
        vq.avail.ring[1].set(2);
        vq.avail.idx.set(2);

        // We've just set up two chains.
        assert_eq!(q.len(m), 2);

        // The first chain should hold exactly two descriptors.
        let d = q.pop(m).unwrap().next_descriptor().unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());

        // We popped one chain, so there should be only one left.
        assert_eq!(q.len(m), 1);

        // The next chain holds three descriptors.
        let d = q
            .pop(m)
            .unwrap()
            .next_descriptor()
            .unwrap()
            .next_descriptor()
            .unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());

        // We've popped both chains, so the queue should be empty.
        assert!(q.is_empty(m));
        assert!(q.pop(m).is_none());

        // Undoing the last pop should let us walk the last chain again.
        q.undo_pop();
        assert_eq!(q.len(m), 1);

        // Walk the last chain again (three descriptors).
        let d = q
            .pop(m)
            .unwrap()
            .next_descriptor()
            .unwrap()
            .next_descriptor()
            .unwrap();
        assert!(!d.has_next());
        assert!(d.next_descriptor().is_none());
    }

    #[test]
    fn test_add_used() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), m, 16);

        let mut q = vq.create_queue();
        assert_eq!(vq.used.idx.get(), 0);

        //index too large
        let _ = q.add_used(m, 16, 0x1000);
        assert_eq!(vq.used.idx.get(), 0);

        //should be ok
        let _ = q.add_used(m, 1, 0x1000);
        assert_eq!(vq.used.idx.get(), 1);
        let x = vq.used.ring[0].get();
        assert_eq!(x.id, 1);
        assert_eq!(x.len, 0x1000);
    }
}
