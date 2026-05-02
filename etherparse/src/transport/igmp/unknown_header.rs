/// Unknown IGMP header with an, to etherparse, unknown type id.
///
/// ```text
/// 0                   1                   2                   3
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |   igmp_type   |   raw_byte_1  |           Checksum            |  | part of header &
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | this type
/// |                         raw_bytes_4_7                         |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// .                                                               .  |
/// .                       ..............                          .  | part of payload
/// .                                                               .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownHeader {
    /// Unknown type
    pub igmp_type: u8,

    /// Raw byte value after the type value.
    pub raw_byte_1: u8,

    /// Raw byte values after the checksum.
    pub raw_bytes_4_7: [u8; 4],
}

impl UnknownHeader {
    /// Number of bytes/octets an [`UnknownHeader`] takes up in serialized form.
    pub const LEN: usize = 8;
}
