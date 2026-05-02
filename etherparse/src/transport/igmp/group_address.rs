/// A group address in an IGMP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupAddress {
    pub octets: [u8; 4],
}

impl GroupAddress {
    pub fn new(address: [u8; 4]) -> Self {
        Self { octets: address }
    }

    pub fn is_zero(&self) -> bool {
        [0, 0, 0, 0] == self.octets
    }
}

impl From<GroupAddress> for [u8; 4] {
    fn from(value: GroupAddress) -> Self {
        value.octets
    }
}

impl From<[u8; 4]> for GroupAddress {
    fn from(value: [u8; 4]) -> Self {
        GroupAddress { octets: value }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<std::net::Ipv4Addr> for GroupAddress {
    fn from(value: std::net::Ipv4Addr) -> Self {
        GroupAddress {
            octets: value.octets(),
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<GroupAddress> for std::net::Ipv4Addr {
    fn from(value: GroupAddress) -> Self {
        std::net::Ipv4Addr::new(
            value.octets[0],
            value.octets[1],
            value.octets[2],
            value.octets[3],
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    #[test]
    fn test_is_zero() {
        assert!(GroupAddress::new([0, 0, 0, 0]).is_zero());
        assert!(!GroupAddress::new([1, 0, 0, 0]).is_zero());
        assert!(!GroupAddress::new([0, 1, 0, 0]).is_zero());
        assert!(!GroupAddress::new([0, 0, 1, 0]).is_zero());
        assert!(!GroupAddress::new([0, 0, 0, 1]).is_zero());
    }

    proptest! {
        #[test]
        fn from_array_to_group_address_roundtrip(octets in any::<[u8;4]>()) {
            let addr = GroupAddress::from(octets);
            prop_assert_eq!(addr.octets, octets);

            let back: [u8;4] = addr.into();
            prop_assert_eq!(back, octets);
        }
    }

    proptest! {
        #[test]
        fn from_group_address_to_array_roundtrip(octets in any::<[u8;4]>()) {
            let addr = GroupAddress { octets };
            let arr: [u8;4] = addr.into();
            prop_assert_eq!(arr, octets);

            let back = GroupAddress::from(arr);
            prop_assert_eq!(back, addr);
        }
    }

    #[cfg(feature = "std")]
    proptest! {
        #[test]
        fn from_ipv4addr_to_group_address_roundtrip(octets in any::<[u8;4]>()) {
            let ip = std::net::Ipv4Addr::from(octets);
            let addr = GroupAddress::from(ip);
            prop_assert_eq!(addr.octets, octets);

            let back: std::net::Ipv4Addr = addr.into();
            prop_assert_eq!(back.octets(), octets);
        }
    }
}
