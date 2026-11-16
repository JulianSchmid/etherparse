/// Unknown MLD header with an, to etherparse, unknown type id.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |   mld_type    |      Code     |           Checksum            |  | ICMPv6 header &
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | this type
/// |                         raw_bytes_4_7                         |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// .                                                               .  |
/// .                       ..............                          .  | ICMPv6 payload
/// .                                                               .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownHeader {
    /// Unknown type
    pub mld_type: u8,

    /// Raw byte values after the checksum (bytes 4-7 of the ICMPv6 header).
    pub raw_bytes_4_7: [u8; 4],
}

impl UnknownHeader {
    /// Number of bytes/octets the fixed part of an unknown MLD message
    /// takes up in serialized form (the 8 byte ICMPv6 header).
    pub const LEN: usize = 8;

    /// Number of bytes/octets of the ICMPv6 payload (the bytes after the 8
    /// byte ICMPv6 header) the fixed part of an unknown MLD message takes
    /// up (zero, as nothing is known about the payload).
    pub const PAYLOAD_LEN: usize = Self::LEN - 8;
}

#[cfg(test)]
// the `clone_eq_debug` test deliberately exercises `Clone` even though
// the type is `Copy`.
#[allow(clippy::clone_on_copy)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    /// An unknown MLD message is just the 8 byte ICMPv6 header, so `LEN`
    /// must be 8 and `PAYLOAD_LEN` (`LEN - 8`) must be zero.
    #[test]
    fn constants() {
        assert_eq!(8, UnknownHeader::LEN);
        assert_eq!(0, UnknownHeader::PAYLOAD_LEN);
    }

    proptest! {
        /// `Clone`, `PartialEq` & `Debug` must be derived and hold for any
        /// type id & raw byte combination.
        #[test]
        fn clone_eq_debug(
            mld_type in any::<u8>(),
            raw_bytes_4_7 in any::<[u8;4]>(),
        ) {
            let value = UnknownHeader { mld_type, raw_bytes_4_7 };
            prop_assert_eq!(value, value.clone());
            let dbg = format!("{:?}", value);
            prop_assert!(dbg.starts_with("UnknownHeader"), "{}", dbg);
        }
    }
}
