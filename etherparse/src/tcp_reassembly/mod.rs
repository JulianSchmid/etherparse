mod tcp_ack_policy;
pub use tcp_ack_policy::*;

mod tcp_reassemble_error;
pub use tcp_reassemble_error::*;

mod tcp_segment_outcome;
pub use tcp_segment_outcome::*;

mod tcp_segment_range;
pub use tcp_segment_range::*;

mod tcp_connection;
pub use tcp_connection::*;

mod tcp_connection_id;
pub use tcp_connection_id::*;

mod tcp_direction;
pub use tcp_direction::*;

mod tcp_endpoint;
pub use tcp_endpoint::*;

mod tcp_segment_info;
pub use tcp_segment_info::*;

mod tcp_stream_reassembly_buf;
pub use tcp_stream_reassembly_buf::*;

#[cfg(feature = "std")]
mod tcp_stream_reassembly_pool;
#[cfg(feature = "std")]
pub use tcp_stream_reassembly_pool::*;

/// Default maximum number of bytes buffered ahead of the read cursor per
/// TCP stream (used by [`TcpStreamReassemblyPool::new`]).
pub const DEFAULT_MAX_TCP_STREAM_CAPACITY: usize = 1 << 20;

/// Default maximum number of separate (non-contiguous) data sections that
/// are tracked per TCP stream (used by [`TcpStreamReassemblyBuf::new`] and
/// [`TcpStreamReassemblyPool::new`]).
pub const DEFAULT_MAX_TCP_STREAM_SECTIONS: usize = 1024;

/// Default maximum number of buffers a [`TcpStreamReassemblyPool`] keeps
/// around for re-use after the connections they belonged to ended.
pub const DEFAULT_MAX_TCP_POOLED_BUFS: usize = 32;

/// Default maximum capacity (in bytes) a data buffer may have to be kept for
/// re-use by a [`TcpStreamReassemblyPool`].
///
/// Buffers of streams that grew beyond this are shrunk before being pooled,
/// so a single burst does not make the pool hold on to the memory for the
/// rest of its lifetime.
pub const DEFAULT_MAX_TCP_POOLED_BUF_CAPACITY: usize = 64 * 1024;
