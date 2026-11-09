/// A multicast address in an MLD packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastAddress {
    pub octets: [u8; 16],
}

impl MulticastAddress {
    /// Creates a multicast address from the given 16 octets.
    pub fn new(address: [u8; 16]) -> Self {
        Self { octets: address }
    }

    /// Returns true if all 16 octets are zero.
    ///
    /// The unspecified address is what a "general query" carries in the
    /// multicast address field (see RFC 9777 section 5.1.11).
    pub fn is_zero(&self) -> bool {
        [0u8; 16] == self.octets
    }
}

impl From<MulticastAddress> for [u8; 16] {
    /// Unwraps the address into its 16 octets.
    fn from(value: MulticastAddress) -> Self {
        value.octets
    }
}

impl From<[u8; 16]> for MulticastAddress {
    /// Wraps the given 16 octets as a multicast address.
    fn from(value: [u8; 16]) -> Self {
        MulticastAddress { octets: value }
    }
}

impl From<core::net::Ipv6Addr> for MulticastAddress {
    /// Converts the IPv6 address into a multicast address (no check that
    /// the address is actually in the multicast range is performed).
    fn from(value: core::net::Ipv6Addr) -> Self {
        MulticastAddress {
            octets: value.octets(),
        }
    }
}

impl From<MulticastAddress> for core::net::Ipv6Addr {
    /// Converts the multicast address into an [`core::net::Ipv6Addr`].
    fn from(value: MulticastAddress) -> Self {
        core::net::Ipv6Addr::from(value.octets)
    }
}

#[cfg(test)]
// the `clone_eq_hash_debug` test deliberately exercises `Clone` even
// though the type is `Copy`.
#[allow(clippy::clone_on_copy)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    /// `is_zero` must only hold for the all zero address, so a single set
    /// octet in any position must make it false.
    #[test]
    fn test_is_zero() {
        assert!(MulticastAddress::new([0u8; 16]).is_zero());
        for i in 0..16 {
            let mut octets = [0u8; 16];
            octets[i] = 1;
            assert!(!MulticastAddress::new(octets).is_zero());
        }
    }

    proptest! {
        /// Converting to & from `[u8;16]` must preserve the octets in order.
        #[test]
        fn from_array_to_multicast_address_roundtrip(octets in any::<[u8;16]>()) {
            let addr = MulticastAddress::from(octets);
            prop_assert_eq!(addr.octets, octets);

            let back: [u8;16] = addr.into();
            prop_assert_eq!(back, octets);
        }
    }

    proptest! {
        /// Converting to & from [`core::net::Ipv6Addr`] must preserve the
        /// address.
        #[test]
        fn from_ipv6_addr_roundtrip(octets in any::<[u8;16]>()) {
            let ip = core::net::Ipv6Addr::from(octets);
            let addr = MulticastAddress::from(ip);
            prop_assert_eq!(addr.octets, octets);

            let back: core::net::Ipv6Addr = addr.into();
            prop_assert_eq!(back, ip);
        }
    }

    proptest! {
        /// `new` must store the octets unmodified.
        #[test]
        fn new_accessor(octets in any::<[u8;16]>()) {
            prop_assert_eq!(MulticastAddress::new(octets).octets, octets);
        }
    }

    proptest! {
        /// `Clone`, `PartialEq`, `Hash` & `Debug` must be derived and hold
        /// for any address.
        #[test]
        fn clone_eq_hash_debug(octets in any::<[u8;16]>()) {
            use core::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;

            let value = MulticastAddress::new(octets);
            prop_assert_eq!(value, value.clone());

            let hash_a = {
                let mut hasher = DefaultHasher::new();
                value.hash(&mut hasher);
                hasher.finish()
            };
            let hash_b = {
                let mut hasher = DefaultHasher::new();
                value.clone().hash(&mut hasher);
                hasher.finish()
            };
            prop_assert_eq!(hash_a, hash_b);

            let dbg = format!("{:?}", value);
            prop_assert!(dbg.starts_with("MulticastAddress"), "{}", dbg);
        }
    }
}
