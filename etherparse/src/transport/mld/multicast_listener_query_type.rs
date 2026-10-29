use crate::mld::MulticastAddress;

/// MLDv1 "Multicast Listener Query" message type.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type = 130   |      Code     |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Maximum Response Delay     |           Reserved            |
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
pub struct MulticastListenerQueryType {
    /// The maximum response delay for the multicast listener report.
    ///
    /// Specifies the maximum allowed delay before sending a responding
    /// report in units of milliseconds.
    pub max_response_delay: u16,

    /// The multicast address being queried.
    ///
    /// Set to zero for general queries, to learn which multicast
    /// addresses have listeners on an attached link. Filled for multicast
    /// address specific queries, to learn if a particular multicast
    /// address has listeners on an attached link.
    pub multicast_address: MulticastAddress,
}

impl MulticastListenerQueryType {
    /// Number of bytes/octets a complete MLDv1 "Multicast Listener Query"
    /// message takes up in serialized form (including the 8 byte ICMPv6
    /// header).
    ///
    /// This is the length [RFC 9777 §8.1](
    /// https://datatracker.ietf.org/doc/html/rfc9777#section-8.1) uses to
    /// identify a query as MLDv1.
    pub const LEN: usize = 24;

    /// Number of bytes/octets of the ICMPv6 payload (the bytes after the 8
    /// byte ICMPv6 header) an MLDv1 "Multicast Listener Query" takes up.
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

    /// An MLDv1 "Multicast Listener Query" is 24 octets: the 8 byte ICMPv6
    /// header followed by the 16 byte multicast address.
    #[test]
    fn constants() {
        assert_eq!(24, MulticastListenerQueryType::LEN);
    }

    proptest! {
        /// `Clone`, `PartialEq` & `Debug` must be derived and hold for any
        /// response delay & multicast address combination.
        #[test]
        fn clone_eq_debug(
            max_response_delay in any::<u16>(),
            multicast_address in any::<[u8;16]>(),
        ) {
            let value = MulticastListenerQueryType {
                max_response_delay,
                multicast_address: multicast_address.into(),
            };
            prop_assert_eq!(value, value.clone());
            let dbg = format!("{:?}", value);
            prop_assert!(dbg.starts_with("MulticastListenerQueryType"), "{}", dbg);
        }
    }
}
