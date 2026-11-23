/// MLDv2 "Version 2 Multicast Listener Report" message header part.
///
/// Note that the type & checksum are not stored in this type as they are
/// part of the enclosing ICMPv6 message (see [`crate::Icmpv6Slice`]).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 143   |    Reserved   |           Checksum            |  | part of header &
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | this type
/// |             Flags             |Nr of Mcast Address Records (M)|  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// .                                                               .  |
/// .                  Multicast Address Record [1]                 .  |
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .                  Multicast Address Record [2]                 .  | part of payload
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                               .                               |  |
/// .                               .                               .  |
/// |                               .                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .                  Multicast Address Record [M]                 .  |
/// .                                                               .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastListenerReportV2Header {
    /// Additional `Flags`.
    ///
    /// Documented in the IANA page
    /// <https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml#igmp-mld-report-message-flags>.
    pub flags: [u8; 2],

    /// The number of multicast address records in the multicast listener report
    /// ("Nr of Mcast Address Records (M)").
    pub num_of_records: u16,
}

impl MulticastListenerReportV2Header {
    /// Number of bytes/octets the fixed part of an MLDv2 "Version 2
    /// Multicast Listener Report" takes up in serialized form (including
    /// the 8 byte ICMPv6 header).
    ///
    /// All fields of this type are located within the first 8 bytes, so
    /// [`MulticastListenerReportV2Header::PAYLOAD_LEN`] is zero and the
    /// complete ICMPv6 payload consists of multicast address records.
    pub const LEN: usize = 8;

    /// Number of bytes/octets of the ICMPv6 payload (the bytes after the 8
    /// byte ICMPv6 header) the fixed part of an MLDv2 "Version 2 Multicast
    /// Listener Report" takes up (zero, the payload only contains the
    /// multicast address records).
    pub const PAYLOAD_LEN: usize = Self::LEN - 8;

    /// Mask of "extension" flag in `MulticastListenerReportV2Header::flags[0]`.
    pub const FLAGS_0_EXTENSION_MASK: u8 = 0b0000_0001;
}

#[cfg(test)]
// the `clone_eq_debug` test deliberately exercises `Clone` even though
// the type is `Copy`.
#[allow(clippy::clone_on_copy)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    /// The MLDv2 report header is just the 8 byte ICMPv6 header, and the
    /// extension flag must stay the lowest bit of the first flags byte.
    #[test]
    fn constants() {
        assert_eq!(8, MulticastListenerReportV2Header::LEN);
        assert_eq!(
            0b0000_0001,
            MulticastListenerReportV2Header::FLAGS_0_EXTENSION_MASK
        );
    }

    proptest! {
        /// `Clone`, `PartialEq` & `Debug` must be derived and hold for any
        /// flags & record count combination.
        #[test]
        fn clone_eq_debug(
            flags in any::<[u8;2]>(),
            num_of_records in any::<u16>(),
        ) {
            let value = MulticastListenerReportV2Header { flags, num_of_records };
            prop_assert_eq!(value, value.clone());
            let dbg = format!("{:?}", value);
            prop_assert!(dbg.starts_with("MulticastListenerReportV2Header"), "{}", dbg);
        }
    }
}
