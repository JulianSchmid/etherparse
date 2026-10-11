/// Configuration of a [`crate::tcp_reassembly::TcpReassemblyPool`].
///
/// Start from the defaults and change what you need:
///
/// ```
/// use etherparse::tcp_reassembly::TcpReassemblyConfig;
///
/// let config = TcpReassemblyConfig {
///     max_stream_buffer: 1024 * 1024,
///     max_connections: Some(10_000),
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TcpReassemblyConfig {
    /// Maximum number of bytes a stream buffers, counted from its read
    /// position to its furthest buffered byte (default 8 MiB).
    ///
    /// Bytes beyond it are rejected.
    pub max_stream_buffer: usize,

    /// Maximum number of holes per stream (default 256).
    ///
    /// A segment that would create more holes is rejected.
    pub max_holes_per_stream: usize,

    /// Number of receiver windows of later data after which a hole is
    /// overdue (default `Some(2)`).
    ///
    /// The receiver must have acknowledged the missing bytes by then. An
    /// overdue hole is given up once the read position reaches it, and late
    /// segments fill it until then. `None` switches this off.
    ///
    /// The same number of windows limits how far after the furthest received
    /// or ACKed byte new bytes are accepted (2 windows with `None`).
    pub hole_give_up_window_factor: Option<u32>,

    /// Receiver window in bytes that is assumed whenever the real one is
    /// unknown (default 4 MiB).
    ///
    /// This is the case if the handshake or the receiver's packets were not
    /// captured.
    pub fallback_window: u32,

    /// Number of further packets of a connection after which a hole that an
    /// ACK covers is overdue (default 16).
    ///
    /// This tolerates captures in which the ACK arrives before the bytes it
    /// ACKs, e.g. when both directions were captured separately and merged.
    /// An overdue hole is given up once the read position reaches it, and
    /// late segments fill it until then. While a stream has holes, it keeps
    /// the ACKs of up to this many packets.
    pub ack_reorder_tolerance: u32,

    /// Number of consecutive out-of-window segments agreeing on a new
    /// position after which a stream continues there, even without an ACK
    /// confirming the jump (default `None`, off).
    ///
    /// Useful for captures that contain only one direction.
    pub resync_after_segments: Option<u32>,

    /// Maximum number of connections in the pool (default `None`, no limit).
    ///
    /// Ended connections whose late packets are still absorbed count
    /// towards it.
    pub max_connections: Option<usize>,

    /// Maximum number of bytes buffered by all streams of the pool together
    /// (default `None`, no limit).
    pub max_total_buffered: Option<usize>,

    /// Maximum number of unused buffers per kind that the pool keeps for
    /// re-use (default 64).
    pub max_pooled_buffers: usize,

    /// Capacity in bytes that buffers are shrunk to when the pool keeps them
    /// for re-use (default 64 KiB).
    pub max_pooled_buffer_capacity: usize,
}

impl Default for TcpReassemblyConfig {
    fn default() -> Self {
        TcpReassemblyConfig {
            max_stream_buffer: 8 * 1024 * 1024,
            max_holes_per_stream: 256,
            hole_give_up_window_factor: Some(2),
            fallback_window: 4 * 1024 * 1024,
            ack_reorder_tolerance: 16,
            resync_after_segments: None,
            max_connections: None,
            max_total_buffered: None,
            max_pooled_buffers: 64,
            max_pooled_buffer_capacity: 64 * 1024,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::hash::{Hash, Hasher};
    use std::format;

    #[test]
    fn derived_traits() {
        let config = TcpReassemblyConfig {
            max_stream_buffer: 1,
            max_holes_per_stream: 2,
            hole_give_up_window_factor: Some(3),
            fallback_window: 4,
            ack_reorder_tolerance: 5,
            resync_after_segments: Some(6),
            max_connections: Some(7),
            max_total_buffered: Some(8),
            max_pooled_buffers: 9,
            max_pooled_buffer_capacity: 10,
        };

        // clone & eq
        assert_eq!(config.clone(), config);
        assert_ne!(config, TcpReassemblyConfig::default());

        // debug
        assert_eq!(
            "TcpReassemblyConfig { \
                max_stream_buffer: 1, \
                max_holes_per_stream: 2, \
                hole_give_up_window_factor: Some(3), \
                fallback_window: 4, \
                ack_reorder_tolerance: 5, \
                resync_after_segments: Some(6), \
                max_connections: Some(7), \
                max_total_buffered: Some(8), \
                max_pooled_buffers: 9, \
                max_pooled_buffer_capacity: 10 \
            }",
            format!("{:?}", config)
        );

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |config: &TcpReassemblyConfig| {
                let mut hasher = DefaultHasher::new();
                config.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(hash(&config), hash(&config.clone()));
        }
    }

    #[test]
    fn default() {
        assert_eq!(
            TcpReassemblyConfig {
                max_stream_buffer: 8 * 1024 * 1024,
                max_holes_per_stream: 256,
                hole_give_up_window_factor: Some(2),
                fallback_window: 4 * 1024 * 1024,
                ack_reorder_tolerance: 16,
                resync_after_segments: None,
                max_connections: None,
                max_total_buffered: None,
                max_pooled_buffers: 64,
                max_pooled_buffer_capacity: 64 * 1024,
            },
            TcpReassemblyConfig::default()
        );
    }
}
