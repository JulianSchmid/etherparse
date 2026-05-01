use crate::igmp::GroupAddress;

/// A membership query message type (present in IGMPv1 and IGMPv2, but
/// the values are only filled for IGMPv2 with non zero values).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 0x11  | Max Resp Time |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Group Address                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MembershipQueryType {
    /// The maximum response time for the membership report
    /// (only for IGMPv2, set to 0 for IGMPv1).
    ///
    /// Specifies the maximum allowed time before sending a
    /// responding report in units of 1/10 second.
    ///
    /// For IGMPv1, this field is always set to zero.
    pub max_response_time: u8,

    /// The group address being queried.
    ///
    /// Set to zero for general queries, to learn which groups
    /// have members on an attached network. Filled for group-specific
    /// queries to learn if a particular group has members on an
    /// attached network.
    ///
    /// For IGMPv1, this field is always set to zero.
    pub group_address: GroupAddress,
}

impl MembershipQueryType {
    /// Number of bytes/octets an [`MembershipQueryV2`] takes up in serialized form.
    pub const LEN: usize = 8;
}
