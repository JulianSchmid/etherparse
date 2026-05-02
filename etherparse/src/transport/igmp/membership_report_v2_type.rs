use crate::igmp::GroupAddress;
/// IGMPv2 Membership Report Message.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 0x16  | Max Resp Time |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Group Address                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MembershipReportV2Type {
    /// IP multicast group address of the group being reported
    pub group_address: GroupAddress,
}

impl MembershipReportV2Type {
    /// Number of bytes/octets an [`MembershipReportV2Type`] takes up in serialized form.
    pub const LEN: usize = 8;
}
