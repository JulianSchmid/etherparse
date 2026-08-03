/// Result of adding a TCP segment via
/// [`crate::tcp_reassembly::TcpStreamReassemblyBuf::add_segment`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TcpSegmentOutcome {
    /// The segment was added to the currently reconstructed stream.
    Continued,

    /// The segment is the `SYN` of a **new** connection re-using the same
    /// addresses & ports (its initial sequence number does not match the
    /// currently reconstructed stream).
    ///
    /// The buffer was left completely unmodified, so the data of the previous
    /// connection can still be drained. Start reconstructing the new
    /// connection via [`crate::tcp_reassembly::TcpStreamReassemblyBuf::reset`]
    /// (or by switching to a different buffer).
    NewConnection,
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq_hash_ord() {
        let value = TcpSegmentOutcome::Continued;
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_ne!(value, TcpSegmentOutcome::NewConnection);
        assert_eq!(value.cmp(&value), core::cmp::Ordering::Equal);
        assert_eq!(value.partial_cmp(&value), Some(core::cmp::Ordering::Equal));

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            value.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            value.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }
}
