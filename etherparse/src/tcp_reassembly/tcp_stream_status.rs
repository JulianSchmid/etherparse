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

    /// Number of received bytes that were not stored, as a memory limit was
    /// reached (see [`crate::tcp_reassembly::TcpReassemblyConfig`]).
    ///
    /// Bytes are counted each time they arrive. Rejected bytes are holes,
    /// which are overdue (see [`crate::tcp_reassembly::TcpStream::holes`]):
    /// a retransmission still fills them once there is room again, until the
    /// read position reaches them.
    pub rejected_bytes: u64,

    /// Number of segments with bytes that lie outside of the stream: they
    /// start after the receiver's window, lie after the stream's FIN, or
    /// lie before its first byte (a mid-stream pickup takes bytes in front
    /// until it is read from, and the filler byte of a keep-alive right
    /// before an observed start doesn't count).
    ///
    /// These bytes are not stored. FINs after the window count too, and so
    /// do SYNs that a mid-stream pickup can't take, RSTs that the receiver
    /// can't accept (see [`crate::tcp_reassembly::TcpConnectionEnd::Reset`]),
    /// the first segment of a pickup that lies far from the ACK the receiver
    /// sent for it, segments without the ACK flag that are no SYN or RST,
    /// and segments the receiver drops while its own SYN is unanswered, e.g.
    /// a blind RST, FIN or SYN-ACK in the handshake. A
    /// count that keeps growing on a clean pickup can mean that blind
    /// segments anchored it elsewhere, which
    /// [`crate::tcp_reassembly::TcpStream::force_resync`] recovers, unless a
    /// FIN ended it.
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
                    "TcpStreamStatus {{ start: {:?}, gaps: {}, gap_bytes: {}, resyncs: {}, conflicting_retransmissions: {}, rejected_bytes: {}, out_of_window_segments: {} }}",
                    status.start,
                    status.gaps,
                    status.gap_bytes,
                    status.resyncs,
                    status.conflicting_retransmissions,
                    status.rejected_bytes,
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
