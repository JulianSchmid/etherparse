/// Represents an "Ethertype" present in a Ethernet II header.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: EtherType = Self(0x0800);
    pub const IPV6: EtherType = Self(0x86dd);
    pub const ARP: EtherType = Self(0x0806);
    pub const WAKE_ON_LAN: EtherType = Self(0x0842);
    pub const VLAN_TAGGED_FRAME: EtherType = Self(0x8100);
    pub const PROVIDER_BRIDGING: EtherType = Self(0x88A8);
    pub const VLAN_DOUBLE_TAGGED_FRAME: EtherType = Self(0x9100);
}

impl From<u16> for EtherType {
    fn from(val: u16) -> Self {
        EtherType(val)
    }
}

impl From<EtherType> for u16 {
    fn from(val: EtherType) -> Self {
        val.0
    }
}

impl core::fmt::Debug for EtherType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::IPV4 => write!(f, "Ipv4({:#06X})", self.0),
            Self::IPV6 => write!(f, "Ipv6({:#06X})", self.0),
            Self::ARP => write!(f, "Arp({:#06X})", self.0),
            Self::WAKE_ON_LAN => write!(f, "WakeOnLan({:#06X})", self.0),
            Self::VLAN_TAGGED_FRAME => write!(f, "VlanTaggedFrame({:#06X})", self.0),
            Self::PROVIDER_BRIDGING => write!(f, "ProviderBridging({:#06X})", self.0),
            Self::VLAN_DOUBLE_TAGGED_FRAME => write!(f, "VlanDoubleTaggedFrame({:#06X})", self.0),
            _ => write!(f, "UnknownType({:#06X})", self.0),
        }
    }
}

/// `u16` constants for the most used `ether_type` values.
///
/// `ether_type` values are used in the Ethernet II header and the
/// vlan headers to identify the next header type.
///
/// Although there is a [`EtherType`] representation for every u16 value,
/// the constants in this module are limited to the known values supported
/// by the current implementation.
/// 
/// 
/// ```
/// use etherparse::{ether_type, EtherType};
///
/// assert_eq!(ether_type::IPV4, EtherType::IPV4.0);
/// assert_eq!(ether_type::IPV4, u16::from(EtherType::IPV4));
/// ```
pub mod ether_type {
    use super::EtherType;

    pub const IPV4: u16 = EtherType::IPV4.0;
    pub const IPV6: u16 = EtherType::IPV6.0;
    pub const ARP: u16 = EtherType::ARP.0;
    pub const WAKE_ON_LAN: u16 = EtherType::WAKE_ON_LAN.0;
    pub const VLAN_TAGGED_FRAME: u16 = EtherType::VLAN_TAGGED_FRAME.0;
    pub const PROVIDER_BRIDGING: u16 = EtherType::PROVIDER_BRIDGING.0;
    pub const VLAN_DOUBLE_TAGGED_FRAME: u16 = EtherType::VLAN_DOUBLE_TAGGED_FRAME.0;
}

#[cfg(test)]
mod test {

    #[test]
    fn to_u16() {
        use crate::EtherType;
        assert_eq!(0x0800, u16::from(EtherType::IPV4));
        assert_eq!(0x86dd, u16::from(EtherType::IPV6));
        assert_eq!(0x0806, u16::from(EtherType::ARP));
        assert_eq!(0x0842, u16::from(EtherType::WAKE_ON_LAN));
        assert_eq!(0x8100, u16::from(EtherType::VLAN_TAGGED_FRAME));
        assert_eq!(0x88A8, u16::from(EtherType::PROVIDER_BRIDGING));
        assert_eq!(0x9100, u16::from(EtherType::VLAN_DOUBLE_TAGGED_FRAME));
    }

    #[test]
    fn from_u16() {
        use crate::EtherType;
        assert_eq!(EtherType::from(0x0800), EtherType::IPV4);
        assert_eq!(EtherType::from(0x86dd), EtherType::IPV6);
        assert_eq!(EtherType::from(0x0806), EtherType::ARP);
        assert_eq!(EtherType::from(0x0842), EtherType::WAKE_ON_LAN);
        assert_eq!(EtherType::from(0x8100), EtherType::VLAN_TAGGED_FRAME);
        assert_eq!(EtherType::from(0x88A8), EtherType::PROVIDER_BRIDGING);
        assert_eq!(EtherType::from(0x9100), EtherType::VLAN_DOUBLE_TAGGED_FRAME);
        assert_eq!(EtherType::from(0x1234), EtherType(0x1234));
    }

    #[test]
    fn constants() {
        use crate::ether_type::*;
        use crate::EtherType;
        let pairs = &[
            (EtherType::IPV4, IPV4),
            (EtherType::IPV6, IPV6),
            (EtherType::ARP, ARP),
            (EtherType::WAKE_ON_LAN, WAKE_ON_LAN),
            (EtherType::VLAN_TAGGED_FRAME, VLAN_TAGGED_FRAME),
            (EtherType::PROVIDER_BRIDGING, PROVIDER_BRIDGING),
            (EtherType::VLAN_DOUBLE_TAGGED_FRAME, VLAN_DOUBLE_TAGGED_FRAME),
        ];

        for (ether_type, constant) in pairs {
            assert_eq!(u16::from(ether_type.clone()), *constant);
        }
    }

    #[test]
    fn dbg() {
        use crate::EtherType;
        let pairs = &[
            (EtherType::IPV4, "Ipv4(0x0800)"),
            (EtherType::IPV6, "Ipv6(0x86DD)"),
            (EtherType::ARP, "Arp(0x0806)"),
            (EtherType::WAKE_ON_LAN, "WakeOnLan(0x0842)"),
            (EtherType::VLAN_TAGGED_FRAME, "VlanTaggedFrame(0x8100)"),
            (EtherType::PROVIDER_BRIDGING, "ProviderBridging(0x88A8)"),
            (EtherType::VLAN_DOUBLE_TAGGED_FRAME, "VlanDoubleTaggedFrame(0x9100)"),
        ];

        for (ether_type, str_value) in pairs {
            assert_eq!(str_value, &format!("{:?}", ether_type));
        }
    }

    #[test]
    fn clone_eq() {
        use crate::EtherType;
        let values = &[
            EtherType::IPV4,
            EtherType::IPV6,
            EtherType::ARP,
            EtherType::WAKE_ON_LAN,
            EtherType::VLAN_TAGGED_FRAME,
            EtherType::PROVIDER_BRIDGING,
            EtherType::VLAN_DOUBLE_TAGGED_FRAME,
        ];

        // clone
        for v in values {
            assert_eq!(v, &v.clone());
        }

        // eq
        for (a_pos, a) in values.iter().enumerate() {
            for (b_pos, b) in values.iter().enumerate() {
                assert_eq!(a_pos == b_pos, a == b);
                assert_eq!(a_pos != b_pos, a != b);
            }
        }
    }
}
