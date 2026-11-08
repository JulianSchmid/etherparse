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
    /// position to its furthest stored byte, with placeholders for the
    /// missing bytes in between (default 8 MiB).
    ///
    /// Bytes beyond it are rejected (see
    /// [`crate::tcp_reassembly::TcpStreamStatus::rejected_bytes`]), and
    /// consuming bytes makes room. A stream's buffer can take up to about
    /// four times as much memory (see
    /// [`TcpReassemblyConfig::max_pooled_buffer_capacity`]).
    ///
    /// Size it above the bytes a connection can have in flight (bandwidth
    /// times round-trip time, e.g. 10 Gbit/s × 20 ms ≈ 25 MB), or a lost
    /// segment whose retransmission arrives after a full window of bytes
    /// becomes a gap although the retransmission was captured.
    pub max_stream_buffer: usize,

    /// Maximum number of holes before the furthest stored byte of a stream
    /// (default 256).
    ///
    /// A segment that would leave more is rejected entirely (see
    /// [`crate::tcp_reassembly::TcpStream::holes`]). The missing bytes after
    /// the furthest stored byte, e.g. rejected bytes or ACKed bytes that
    /// were not captured, don't count, so a stream has at most one more
    /// hole.
    ///
    /// While a stream has more gaps than this that the reader didn't step
    /// over (see [`crate::tcp_reassembly::TcpRead::Gap`]), it doesn't resync
    /// (see [`crate::tcp_reassembly::TcpStreamStatus::resyncs`]).
    pub max_holes_per_stream: usize,

    /// Number of receiver windows of later data after which a hole is
    /// overdue, counting the largest window the receiver advertised
    /// (default `Some(2)`).
    ///
    /// The receiver must have acknowledged the missing bytes by then. An
    /// overdue hole is given up once the read position reaches it, and late
    /// segments fill it until then. `None` switches this off, and `Some(0)`
    /// works like `Some(1)`. The distance is at most half of
    /// [`TcpReassemblyConfig::max_stream_buffer`], so a reader of the ACKed
    /// bytes keeps up before the buffer is full, but never less than the
    /// largest window the receiver advertised. So such a reader only keeps
    /// up without captured ACKs if the buffer is clearly larger than that
    /// window; otherwise the bytes that don't fit show up in
    /// [`crate::tcp_reassembly::TcpStreamStatus::rejected_bytes`].
    ///
    /// The same number of windows limits how far after the furthest received
    /// or ACKed byte new bytes are accepted, and how far before the first
    /// byte of a mid-stream pickup earlier bytes are put in front (2 windows
    /// with `None`).
    pub hole_give_up_window_factor: Option<u32>,

    /// Receiver window in bytes that is assumed whenever the real one is
    /// unknown (default 4 MiB).
    ///
    /// This is the case if the handshake or the receiver's packets were not
    /// captured. It also decides how far from the receiver's ACK the first
    /// segment of a mid-stream pickup may lie (see
    /// [`crate::tcp_reassembly::TcpStreamStatus::out_of_window_segments`]).
    /// For captures that start mid-stream, size it like
    /// [`TcpReassemblyConfig::max_stream_buffer`]: above the bytes a
    /// connection can have in flight.
    pub fallback_window: u32,

    /// Number of further packets of a connection after which a hole that an
    /// ACK covers is overdue (default 256).
    ///
    /// This tolerates captures in which the ACK arrives before the bytes it
    /// ACKs, e.g. when both directions were captured separately and merged.
    /// Size it above the number of packets (of both directions) that a
    /// connection can show within the skew between the directions: 256
    /// packets are a few milliseconds of one connection at 1 Gbit/s. A hole
    /// from real capture loss stalls a reader for this many packets. An
    /// overdue hole is given up once the read position reaches it, and late
    /// segments fill it until then. While a stream has holes, or is a
    /// mid-stream pickup that was not read from yet, it keeps the ACKs of
    /// up to this many packets (16 bytes each).
    pub ack_reorder_tolerance: u32,

    /// Number of consecutive segments after the receiver's window, each
    /// within one window of the one before it, after which a stream
    /// continues at the last of them, even without an ACK confirming the
    /// jump (default `None`, off).
    ///
    /// Useful for captures that contain only one direction. `Some(0)` works
    /// like `Some(1)`. The same count of segments that a side drops while
    /// its SYN is unanswered (see
    /// [`crate::tcp_reassembly::TcpStreamStatus::out_of_window_segments`])
    /// ends that wait for segments with bytes or an ACK.
    pub resync_after_segments: Option<u32>,

    /// Maximum number of connections in the pool (default `None`, no limit).
    ///
    /// Ended connections whose late packets are still absorbed count
    /// towards it. Segments that would start a connection beyond it are
    /// ignored (see
    /// [`crate::tcp_reassembly::TcpIgnoreReason::TooManyConnections`]), while
    /// reconnects that reuse the key of a connection in the pool are not.
    pub max_connections: Option<usize>,

    /// Maximum number of bytes buffered by all streams of the pool together,
    /// each counted as for [`TcpReassemblyConfig::max_stream_buffer`]
    /// (default `None`, no limit).
    ///
    /// Bytes beyond it are rejected, and reading makes room at once.
    /// Connections handed over as ended don't count, and neither does the
    /// SYN of a simultaneous open that a connection keeps until a SYN-ACK
    /// confirms it (at most one per connection). The memory of the streams
    /// stays within about four times this limit, plus
    /// [`TcpReassemblyConfig::max_pooled_buffer_capacity`] per stream, as a
    /// stream gives back the room of consumed bytes (see there).
    pub max_total_buffered: Option<usize>,

    /// Maximum number of unused buffers per kind that the pool keeps for
    /// re-use (default 64).
    pub max_pooled_buffers: usize,

    /// Capacity in bytes that buffers are shrunk to when the pool keeps them
    /// for re-use, and that a stream keeps at least (default 64 KiB).
    ///
    /// Once the consumed bytes make up half of a stream's buffer, the stream
    /// drops them and keeps at most twice the room its bytes need, but this
    /// capacity at least. So a stream whose bytes are read as they come
    /// gives the room of a burst back down to this capacity, and takes it
    /// again for the next burst, and a stream's buffer takes at most about
    /// four times the bytes it holds.
    ///
    /// This capacity is also what an idle stream keeps whose buffer once
    /// grew, e.g. while a hole waited to be given up, even after every byte
    /// was read: with the default, 100,000 idle connections with one such
    /// stream each hold about 6.5 GB, which
    /// [`TcpReassemblyConfig::max_total_buffered`] doesn't bound. A monitor
    /// with many concurrent connections lowers it (e.g. to 4 KiB) and
    /// trades a few more buffer moves per burst for it.
    pub max_pooled_buffer_capacity: usize,
}

impl Default for TcpReassemblyConfig {
    fn default() -> Self {
        TcpReassemblyConfig {
            max_stream_buffer: 8 * 1024 * 1024,
            max_holes_per_stream: 256,
            hole_give_up_window_factor: Some(2),
            fallback_window: 4 * 1024 * 1024,
            ack_reorder_tolerance: 256,
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
                ack_reorder_tolerance: 256,
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
