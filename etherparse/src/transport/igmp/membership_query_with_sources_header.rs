use crate::igmp::{GroupAddress, MaxResponseCode, Qrv};

/// A membership report message type (IGMPv3 version) with source addresses.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 0x11  | Max Resp Code |           Checksum            |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | part of header and
/// |                         Group Address                         |  | this type
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                       Source Address [1]                      |  |
/// +-                                                             -+  |
/// |                       Source Address [2]                      |  |
/// +-                              .                              -+  | part of payload
/// .                               .                               .  |
/// .                               .                               .  |
/// +-                                                             -+  |
/// |                       Source Address [N]                      |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MembershipQueryWithSourcesHeader {
    /// The Max Resp Code field specifies the maximum time allowed before
    /// sending a responding report.
    pub max_response_code: MaxResponseCode,

    /// The group address being queried.
    ///
    /// Set to zero for general queries, to learn which groups
    /// have members on an attached network. Filled for group-specific
    /// queries to learn if a particular group has members on an
    /// attached network.
    ///
    /// For IGMPv1, this field is always set to zero.
    pub group_address: GroupAddress,

    /// S Flag (Suppress Router-Side Processing).
    pub s_flag: bool,

    /// QRV (Querier's Robustness Variable)
    pub qrv: Qrv,

    /// QQIC (Querier's Query Interval Code)
    pub qqic: u8,

    /// Number of sources
    pub num_of_sources: u16,
}

impl MembershipQueryWithSourcesHeader {
    /// Number of bytes/octets an [`MembershipQueryWithSourcesHeader`] takes up in serialized form.
    pub const LEN: usize = 12;
}
