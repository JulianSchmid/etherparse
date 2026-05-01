use crate::igmp::GroupAddress;

/// A leave group message type (introduced in IGMPv2).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 0x11  |       0       |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Group Address                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LeaveGroupType {
    /// The IP multicast group address of the group being left.
    pub group_address: GroupAddress,
}

impl LeaveGroupType {
    /// Number of bytes/octets an [`LeaveGroupType`] takes up in serialized form.
    pub const LEN: usize = 8;
}
