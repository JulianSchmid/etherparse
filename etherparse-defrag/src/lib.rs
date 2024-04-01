
// # Reason for 'bool_comparison' disable:
//
// Clippy triggers triggers errors like the following if the warning stays enabled:
//
//   warning: equality checks against false can be replaced by a negation
//     --> src/packet_decoder.rs:131:20
//      |
//  131 |                 if false == fragmented {
//      |                    ^^^^^^^^^^^^^^^^^^^ help: try simplifying it as shown: `!fragmented`
//
//
// I prefer to write `false == value` instead of `!value` as it
// is more visually striking and is not as easy to overlook as the single
// character '!'.
#![allow(clippy::bool_comparison)]

mod ip_defrag_buf;
pub use ip_defrag_buf::*;

mod ip_defrag_error;
pub use ip_defrag_error::*;

mod ip_defrag_payload_vec;
pub use ip_defrag_payload_vec::*;

mod ip_defrag_pool;
pub use ip_defrag_pool::*;

mod ip_frag_id;
pub use ip_frag_id::*;

mod ip_frag_range;
pub use ip_frag_range::*;

mod ip_frag_version_spec_id;
pub use ip_frag_version_spec_id::*;

/// Maximum length of a defragmented packet as [`u16`].
pub const MAX_IP_DEFRAG_LEN_U16: u16 = u16::MAX;

/// Maximum length of a defragmented packet as [`usize`].
pub const MAX_IP_DEFRAG_LEN: usize = MAX_IP_DEFRAG_LEN_U16 as usize;
