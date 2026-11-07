use crate::tcp_reassembly::*;
use core::ops::Range;
use std::{collections::VecDeque, vec::Vec};

/// Unused buffers that a [`crate::tcp_reassembly::TcpReassemblyPool`] keeps
/// for re-use, per kind.
#[derive(Clone, Debug, Default)]
pub(crate) struct FreeBuffers {
    /// Buffers for the bytes of streams and for kept SYNs.
    pub bytes: FreeList<Vec<u8>>,
    /// Buffers for the holes of streams.
    pub holes: FreeList<Vec<Range<u64>>>,
    /// Buffers for the gaps of streams.
    pub gaps: FreeList<Vec<Range<u64>>>,
    /// Buffers for the ACKs that streams keep while they have holes.
    pub acks: FreeList<VecDeque<(u64, u64)>>,
}

impl FreeBuffers {
    /// Empty lists that keep buffers within the limits of `config`.
    pub fn new(config: &TcpReassemblyConfig) -> FreeBuffers {
        FreeBuffers {
            bytes: FreeList::new(config),
            holes: FreeList::new(config),
            gaps: FreeList::new(config),
            acks: FreeList::new(config),
        }
    }
}

/// Unused buffers of one kind, kept for re-use.
#[derive(Clone, Debug, Default)]
pub(crate) struct FreeList<B> {
    buffers: Vec<B>,
    /// Maximum number of buffers kept.
    max_buffers: usize,
    /// Capacity in bytes that kept buffers are shrunk to.
    max_capacity: usize,
}

impl<B> FreeList<B> {
    /// Empty list that keeps buffers within the limits of `config`.
    fn new(config: &TcpReassemblyConfig) -> FreeList<B> {
        FreeList {
            buffers: Vec::new(),
            max_buffers: config.max_pooled_buffers,
            max_capacity: config.max_pooled_buffer_capacity,
        }
    }

    /// Capacity that buffers in the list are shrunk to.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

impl<B: Buffer + Default> FreeList<B> {
    /// Takes a buffer, an empty one if none is left.
    pub fn take(&mut self) -> B {
        self.buffers.pop().unwrap_or_default()
    }

    /// Keeps `buf` for re-use, emptied and shrunk to the capacity limit,
    /// unless the list is full.
    pub fn put(&mut self, mut buf: B) {
        if self.buffers.len() >= self.max_buffers {
            return;
        }
        buf.clear();
        buf.shrink_to(self.max_capacity / B::ELEMENT_SIZE);
        // a buffer without capacity saves no allocation, and would take the
        // place of one that does
        if 0 < buf.capacity() {
            self.buffers.push(buf);
        }
    }
}

/// Buffer that a [`FreeList`] can keep.
pub(crate) trait Buffer {
    /// Size of an element in bytes.
    const ELEMENT_SIZE: usize;

    /// Number of elements the buffer can hold without growing.
    fn capacity(&self) -> usize;

    /// Removes all elements.
    fn clear(&mut self);

    /// Shrinks the capacity to `min_capacity` elements, if it is larger.
    fn shrink_to(&mut self, min_capacity: usize);
}

impl<T> Buffer for Vec<T> {
    const ELEMENT_SIZE: usize = core::mem::size_of::<T>();

    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }

    fn clear(&mut self) {
        Vec::clear(self);
    }

    fn shrink_to(&mut self, min_capacity: usize) {
        Vec::shrink_to(self, min_capacity);
    }
}

impl<T> Buffer for VecDeque<T> {
    const ELEMENT_SIZE: usize = core::mem::size_of::<T>();

    fn capacity(&self) -> usize {
        VecDeque::capacity(self)
    }

    fn clear(&mut self) {
        VecDeque::clear(self);
    }

    fn shrink_to(&mut self, min_capacity: usize) {
        VecDeque::shrink_to(self, min_capacity);
    }
}
