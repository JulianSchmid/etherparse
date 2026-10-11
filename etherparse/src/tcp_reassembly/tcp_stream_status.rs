use crate::tcp_reassembly::*;

/// How a [`crate::tcp_reassembly::TcpStream`] started, and counters that
/// describe its quality.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpStreamStatus {
    /// Whether the stream's first byte is known from the handshake.
    pub start: TcpStreamStart,

    /// Number of gaps: holes that were given up, e.g. with
    /// [`crate::tcp_reassembly::TcpStream::give_up_hole`].
    ///
    /// Discarded holes don't count (see
    /// [`crate::tcp_reassembly::TcpStream::discard_until`]).
    pub gaps: u64,

    /// Number of bytes in the holes that were given up.
    pub gap_bytes: u64,

    /// Number of times the stream continued at a new position behind a gap
    /// of unknown length ([`crate::tcp_reassembly::TcpRead::Gap`] with
    /// `len: None`), as its sequence numbers jumped far after the
    /// receiver's window, or as
    /// [`crate::tcp_reassembly::TcpStream::force_resync`] forced it.
    pub resyncs: u64,

    /// Number of retransmitted segments whose bytes differ from the bytes
    /// received first at the same positions.
    ///
    /// The bytes received first are kept. Only bytes that are neither ACKed
    /// nor consumed are compared, so keep-alive probes don't count.
    pub conflicting_retransmissions: u64,

    /// Number of segments with bytes that lie outside of the stream: they
    /// start after the receiver's window, lie after the stream's FIN, or lie
    /// before the first byte of a mid-stream pickup that can't take them
    /// anymore (see [`TcpStreamStart::MidStreamPickup`]).
    ///
    /// These bytes are not stored. FINs starting after the receiver's window
    /// count too, and so do SYNs that a mid-stream pickup can't take.
    pub out_of_window_segments: u64,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::format;

    proptest! {
        #[test]
        fn derived_traits(status in tcp_stream_status_any()) {
            // clone
            assert_eq!(status.clone(), status);

            // debug
            assert_eq!(
                format!(
                    "TcpStreamStatus {{ start: {:?}, gaps: {}, gap_bytes: {}, resyncs: {}, conflicting_retransmissions: {}, out_of_window_segments: {} }}",
                    status.start,
                    status.gaps,
                    status.gap_bytes,
                    status.resyncs,
                    status.conflicting_retransmissions,
                    status.out_of_window_segments
                ),
                format!("{:?}", status)
            );

            // hash
            {
                use std::collections::hash_map::DefaultHasher;
                let hash = |status: &TcpStreamStatus| {
                    let mut hasher = DefaultHasher::new();
                    status.hash(&mut hasher);
                    hasher.finish()
                };
                assert_eq!(hash(&status), hash(&status.clone()));
            }
        }
    }
}
