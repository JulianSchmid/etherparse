/// Decides if data has to be acknowledged by the receiver before it is handed
/// out by [`crate::tcp_reassembly::TcpStreamReassemblyBuf::contiguous`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TcpAckPolicy {
    /// Only hand out data that the receiver acknowledged (default).
    ///
    /// Segments that are lost or rejected after the point of capture (out of
    /// window, bad checksum, ...) never reach the receiver, so without this
    /// the reconstructed stream can contain bytes the receiver never
    /// processed.
    ///
    /// Note that the acknowledgments travel in the **opposite** direction of
    /// the data, so they have to be fed via
    /// [`crate::tcp_reassembly::TcpStreamReassemblyBuf::add_ack`] from the
    /// segments of the reverse direction. If a capture does not contain the
    /// reverse direction no data is ever handed out by `contiguous` (check
    /// [`crate::tcp_reassembly::TcpStreamReassemblyBuf::ack_observed`] to
    /// detect this) and
    /// [`crate::tcp_reassembly::TcpStreamReassemblyBuf::contiguous_unacked`]
    /// has to be used instead.
    ///
    /// # This is not a security boundary
    ///
    /// Requiring acknowledgments closes the gap between what a capture sees
    /// and what the receiver actually accepted and forces an attacker to
    /// forge both directions instead of one. It does **not** protect against
    /// someone who can inject packets into the capture, as forged
    /// acknowledgments are indistinguishable from real ones.
    #[default]
    Required,

    /// Hand out all in-order data, regardless of acknowledgments.
    ///
    /// Use this for captures that only contain one direction of the
    /// connections (one-way taps or mirrors) or if the reconstruction should
    /// follow the sender instead of the receiver.
    Ignore,
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq_hash_ord_default() {
        let value = TcpAckPolicy::Required;
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_eq!(value, TcpAckPolicy::default());
        assert_ne!(value, TcpAckPolicy::Ignore);
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
