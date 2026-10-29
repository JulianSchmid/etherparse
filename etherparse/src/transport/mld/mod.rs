mod max_response_code;
pub use max_response_code::*;

mod mld_unknown_slice;
pub use mld_unknown_slice::*;

mod multicast_address;
pub use multicast_address::*;

mod multicast_address_record_header;
pub use multicast_address_record_header::*;

mod multicast_address_record_slice;
pub use multicast_address_record_slice::*;

mod multicast_address_record_type;
pub use multicast_address_record_type::*;

mod multicast_listener_done_slice;
pub use multicast_listener_done_slice::*;

mod multicast_listener_done_type;
pub use multicast_listener_done_type::*;

mod multicast_listener_query_slice;
pub use multicast_listener_query_slice::*;

mod multicast_listener_query_type;
pub use multicast_listener_query_type::*;

mod multicast_listener_query_with_sources_header;
pub use multicast_listener_query_with_sources_header::*;

mod multicast_listener_query_with_sources_slice;
pub use multicast_listener_query_with_sources_slice::*;

mod multicast_listener_report_v1_slice;
pub use multicast_listener_report_v1_slice::*;

mod multicast_listener_report_v1_type;
pub use multicast_listener_report_v1_type::*;

mod multicast_listener_report_v2_header;
pub use multicast_listener_report_v2_header::*;

mod multicast_listener_report_v2_slice;
pub use multicast_listener_report_v2_slice::*;

mod qrv;
pub use qrv::*;

mod unknown_header;
pub use unknown_header::*;

/// "Multicast Listener Query" message type (same in MLDv1 & MLDv2).
pub const MLD_TYPE_MULTICAST_LISTENER_QUERY: u8 = 130;

/// MLDv1 "Multicast Listener Report" message type.
pub const MLDV1_TYPE_MULTICAST_LISTENER_REPORT: u8 = 131;

/// MLDv1 "Multicast Listener Done" message type.
pub const MLDV1_TYPE_MULTICAST_LISTENER_DONE: u8 = 132;

/// MLDv2 "Version 2 Multicast Listener Report" message type.
pub const MLDV2_TYPE_MULTICAST_LISTENER_REPORT: u8 = 143;

#[cfg(test)]
mod test {
    use super::*;

    /// The MLD message type constants must keep the type ids assigned by
    /// RFC 2710 & RFC 9777.
    #[test]
    fn constants() {
        assert_eq!(130, MLD_TYPE_MULTICAST_LISTENER_QUERY);
        assert_eq!(131, MLDV1_TYPE_MULTICAST_LISTENER_REPORT);
        assert_eq!(132, MLDV1_TYPE_MULTICAST_LISTENER_DONE);
        assert_eq!(143, MLDV2_TYPE_MULTICAST_LISTENER_REPORT);
    }

    /// The MLD message types are ICMPv6 message types, so they must
    /// match the corresponding `crate::icmpv6` constants.
    #[test]
    fn constants_match_icmpv6() {
        use crate::icmpv6;
        assert_eq!(
            icmpv6::TYPE_MULTICAST_LISTENER_QUERY,
            MLD_TYPE_MULTICAST_LISTENER_QUERY
        );
        assert_eq!(
            icmpv6::TYPE_MULTICAST_LISTENER_REPORT,
            MLDV1_TYPE_MULTICAST_LISTENER_REPORT
        );
        assert_eq!(
            icmpv6::TYPE_MULTICAST_LISTENER_REDUCTION,
            MLDV1_TYPE_MULTICAST_LISTENER_DONE
        );
    }
}
