use crate::mld::MulticastAddress;

/// MLDv1 "Multicast Listener Report" message type.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 131   |      Code     |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Unused             |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-                      Multicast Address                      -+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastListenerReportV1Type {
    /// The multicast address to which the sender is listening on the
    /// interface from which the report is sent.
    pub multicast_address: MulticastAddress,
}

impl MulticastListenerReportV1Type {
    /// Number of bytes/octets a complete MLDv1 "Multicast Listener Report"
    /// message takes up in serialized form (including the 8 byte ICMPv6
    /// header).
    pub const LEN: usize = 24;

    /// Number of bytes/octets of the ICMPv6 payload (the bytes after the 8
    /// byte ICMPv6 header) an MLDv1 "Multicast Listener Report" takes up.
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

    /// An MLDv1 "Multicast Listener Report" is 24 octets: the 8 byte ICMPv6
    /// header followed by the 16 byte multicast address.
    #[test]
    fn constants() {
        assert_eq!(24, MulticastListenerReportV1Type::LEN);
    }

    proptest! {
        /// `Clone`, `PartialEq` & `Debug` must be derived and hold for any
        /// multicast address.
        #[test]
        fn clone_eq_debug(multicast_address in any::<[u8;16]>()) {
            let value = MulticastListenerReportV1Type {
                multicast_address: multicast_address.into(),
            };
            prop_assert_eq!(value, value.clone());
            let dbg = format!("{:?}", value);
            prop_assert!(dbg.starts_with("MulticastListenerReportV1Type"), "{}", dbg);
        }
    }
}
