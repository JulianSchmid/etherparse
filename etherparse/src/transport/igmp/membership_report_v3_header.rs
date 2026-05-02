/// IGMPv3 Membership Report Message header part (without checksum).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 0x22  |    Reserved   |           Checksum            |  | part of header &
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | this type
/// |             Flags             |  Number of Group Records (M)  |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// .                                                               .  |
/// .                        Group Record [1]                       .  |
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .                        Group Record [2]                       .  | part of payload
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                               .                               |  |
/// .                               .                               .  |
/// |                               .                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .                        Group Record [M]                       .  |
/// .                                                               .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MembershipReportV3Header {
    /// Additional `Flags`.
    ///
    /// Documented in the IANA page
    /// <https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml#igmp-mld-report-message-flags>.
    pub flags: [u8; 2],

    /// The number of group records in the membership report
    pub num_of_records: u16,
}

impl MembershipReportV3Header {
    /// Number of bytes/octets an [`MembershipReportV3Header`] takes up in serialized form.
    pub const LEN: usize = 8;

    /// Mask of "extension" flag in `MembershipReportV3Header::flags[0]`.
    pub const FLAGS_0_EXTENSION_MASK: u8 = 0b0000_0001;
}
