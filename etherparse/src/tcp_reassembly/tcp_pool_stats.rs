/// Statistics of a [`crate::tcp_reassembly::TcpReassemblyPool`] (see
/// [`crate::tcp_reassembly::TcpReassemblyPool::stats`]).
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct TcpPoolStats {
    /// Number of open connections.
    pub connections: usize,

    /// Number of ended connections whose late packets the pool still
    /// absorbs (see [`crate::tcp_reassembly::TcpIgnoreReason::AfterEnd`]).
    pub tombstones: usize,

    /// Number of bytes buffered by the streams of the open connections,
    /// counted as for
    /// [`crate::tcp_reassembly::TcpReassemblyConfig::max_total_buffered`].
    pub buffered_bytes: usize,

    /// Number of packets that would have started a connection, but were
    /// ignored as the pool was full (see
    /// [`crate::tcp_reassembly::TcpIgnoreReason::TooManyConnections`]).
    pub rejected_connections: u64,

    /// Number of packets that were applied to no connection (see
    /// [`crate::tcp_reassembly::TcpProcessed::ignored`]), including the
    /// ones counted in [`TcpPoolStats::rejected_connections`].
    pub ignored_packets: u64,
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
        fn derived_traits(stats in tcp_pool_stats_any()) {
            // clone
            assert_eq!(stats.clone(), stats);

            // default
            assert_eq!(
                TcpPoolStats {
                    connections: 0,
                    tombstones: 0,
                    buffered_bytes: 0,
                    rejected_connections: 0,
                    ignored_packets: 0,
                },
                TcpPoolStats::default()
            );

            // debug
            assert_eq!(
                format!(
                    "TcpPoolStats {{ connections: {}, tombstones: {}, buffered_bytes: {}, rejected_connections: {}, ignored_packets: {} }}",
                    stats.connections,
                    stats.tombstones,
                    stats.buffered_bytes,
                    stats.rejected_connections,
                    stats.ignored_packets
                ),
                format!("{:?}", stats)
            );

            // hash
            {
                use std::collections::hash_map::DefaultHasher;
                let hash = |stats: &TcpPoolStats| {
                    let mut hasher = DefaultHasher::new();
                    stats.hash(&mut hasher);
                    hasher.finish()
                };
                assert_eq!(hash(&stats), hash(&stats.clone()));
            }
        }
    }
}
