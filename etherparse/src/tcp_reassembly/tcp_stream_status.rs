/// Counters that describe the quality of a
/// [`crate::tcp_reassembly::TcpStream`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpStreamStatus {
    /// Number of gaps: holes that were given up, e.g. with
    /// [`crate::tcp_reassembly::TcpStream::give_up_hole`].
    ///
    /// Discarded holes don't count (see
    /// [`crate::tcp_reassembly::TcpStream::discard_until`]).
    pub gaps: u64,

    /// Number of bytes in the holes that were given up.
    pub gap_bytes: u64,

    /// Number of retransmitted segments whose bytes differ from the bytes
    /// received first at the same positions.
    ///
    /// The bytes received first are kept. Only bytes that are neither ACKed
    /// nor consumed are compared, so keep-alive probes don't count.
    pub conflicting_retransmissions: u64,

    /// Number of segments with bytes that lie outside of the stream: they
    /// start after the receiver's window, or lie after the stream's FIN.
    ///
    /// These bytes are not stored. FINs starting after the receiver's window
    /// count too.
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
                    "TcpStreamStatus {{ gaps: {}, gap_bytes: {}, conflicting_retransmissions: {}, out_of_window_segments: {} }}",
                    status.gaps,
                    status.gap_bytes,
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
