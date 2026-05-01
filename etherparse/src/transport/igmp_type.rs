use crate::igmp;

/// IGMP message types specific data (excluding checksum).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IgmpType {
    /// Membership Query message type (IGMPv1 & IGMPv2 compatible, type = 0x11 and static size).
    MembershipQuery(igmp::MembershipQueryType),

    /// Membership Query message type (IGMPv3 version, type = 0x11 and dynamic size) with sources.
    MembershipQueryWithSources(igmp::MembershipQueryWithSourcesHeader),

    /// Membership Report message type (introduced in IGMPv1, type = 0x12).
    MembershipReportV1(igmp::MembershipReportV1Type),

    /// Membership Report message type (introduced in IGMPv2, type = 0x16 & fixed size).
    MembershipReportV2(igmp::MembershipReportV2Type),

    /// Membership Report message type (introduced in IGMPv2, type = 0x16 & dynamic size).
    MembershipReportV3(igmp::MembershipReportV3Header),

    /// Leave Group message type (introduced in IGMPv2, type = 0x17).
    LeaveGroup(igmp::LeaveGroupType),
}
