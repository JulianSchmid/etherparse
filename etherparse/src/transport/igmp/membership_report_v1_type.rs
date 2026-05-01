use crate::igmp::GroupAddress;

/// IGMPv1 Membership Report Message.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 0x12  |    Unused     |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Group Address                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MembershipReportV1Type {
    /// IP multicast group address of the group being reported
    pub group_address: GroupAddress,
}

impl MembershipReportV1Type {
    /// Number of bytes/octets an [`MembershipReportV1Type`] takes up in serialized form.
    pub const LEN: usize = 8;
}
