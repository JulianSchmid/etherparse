mod tcp_reassemble_error;
pub use tcp_reassemble_error::*;

mod tcp_segment_range;
pub use tcp_segment_range::*;

mod tcp_stream_id;
pub use tcp_stream_id::*;

mod tcp_stream_ip_id;
pub use tcp_stream_ip_id::*;

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
