use std::vec::Vec;

/// Unused buffers that a [`crate::tcp_reassembly::TcpReassemblyPool`] keeps
/// for re-use.
#[derive(Clone, Debug, Default)]
pub(crate) struct FreeBuffers {
    /// Buffers for the bytes of streams and for kept SYNs.
    pub bytes: FreeList<Vec<u8>>,
}

/// Unused buffers of one kind, kept for re-use.
#[derive(Clone, Debug, Default)]
pub(crate) struct FreeList<B>(Vec<B>);

impl<B: Buffer + Default> FreeList<B> {
    /// Takes a buffer, an empty one if none is left.
    pub fn take(&mut self) -> B {
        self.0.pop().unwrap_or_default()
    }

    /// Keeps `buf` for re-use, emptied.
    pub fn put(&mut self, mut buf: B) {
        buf.clear();
        self.0.push(buf);
    }
}

/// Buffer that a [`FreeList`] can keep.
pub(crate) trait Buffer {
    /// Removes all elements.
    fn clear(&mut self);
}

impl<T> Buffer for Vec<T> {
    fn clear(&mut self) {
        Vec::clear(self);
    }
}
