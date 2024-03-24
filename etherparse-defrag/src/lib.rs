
mod ip_defrag_buf;
pub use ip_defrag_buf::*;

mod ip_defrag_error;
pub use ip_defrag_error::*;

mod ip_defrag_pool;
pub use ip_defrag_pool::*;

mod ip_frag_id;
pub use ip_frag_id::*;

mod ip_frag_range;
pub use ip_frag_range::*;

/// Maximum length of a defragmented packet as [`u16`].
pub const MAX_IP_DEFRAG_LEN_U16: u16 = u16::MAX;

/// Maximum length of a defragmented packet as [`usize`].
pub const MAX_IP_DEFRAG_LEN: usize = MAX_IP_DEFRAG_LEN_U16 as usize;
