mod group_address;
pub use group_address::*;

mod leave_group_type;
pub use leave_group_type::*;

mod max_response_code;
pub use max_response_code::*;

mod membership_query_type;
pub use membership_query_type::*;

mod membership_query_with_sources_header;
pub use membership_query_with_sources_header::*;

mod membership_report_v1_type;
pub use membership_report_v1_type::*;

mod membership_report_v2_type;
pub use membership_report_v2_type::*;

mod membership_report_v3_header;
pub use membership_report_v3_header::*;

mod qrv;
pub use qrv::*;

mod unknown_header;
pub use unknown_header::*;

/// "Membership Query" message type (same in IGMPv1, IGMPv2, IGMPv3).
pub const IGMP_TYPE_MEMBERSHIP_QUERY: u8 = 0x11;

/// IGMPv1 "Membership Report" message type.
pub const IGMPV1_TYPE_MEMBERSHIP_REPORT: u8 = 0x12;

/// IGMPv2 "Membership Report" message type.
pub const IGMPV2_TYPE_MEMBERSHIP_REPORT: u8 = 0x16;

/// IGMPv3 "Membership Report" message type.
pub const IGMPV3_TYPE_MEMBERSHIP_REPORT: u8 = 0x22;

/// IGMPv2 "Leave Group" message type.
pub const IGMPV2_TYPE_LEAVE_GROUP: u8 = 0x17;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(0x11, IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(0x12, IGMPV1_TYPE_MEMBERSHIP_REPORT);
        assert_eq!(0x16, IGMPV2_TYPE_MEMBERSHIP_REPORT);
        assert_eq!(0x17, IGMPV2_TYPE_LEAVE_GROUP);
        assert_eq!(0x22, IGMPV3_TYPE_MEMBERSHIP_REPORT);
    }
}
