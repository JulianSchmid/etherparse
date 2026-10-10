/// Counters that describe the quality of a
/// [`crate::tcp_reassembly::TcpStream`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpStreamStatus {
    /// Number of segments with bytes that lie outside of the stream, e.g.
    /// after its FIN.
    ///
    /// These bytes are not stored.
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
            // copy & clone
            {
                let copy = status;
                assert_eq!(status, copy);
                assert_eq!(status.clone(), status);
            }

            // debug
            assert_eq!(
                format!(
                    "TcpStreamStatus {{ out_of_window_segments: {} }}",
                    status.out_of_window_segments
                ),
                format!("{:?}", status)
            );

            // hash
            {
                use std::collections::hash_map::DefaultHasher;
                let hash = |status: TcpStreamStatus| {
                    let mut hasher = DefaultHasher::new();
                    status.hash(&mut hasher);
                    hasher.finish()
                };
                assert_eq!(hash(status), hash(status.clone()));
            }
        }
    }
}
