/// Ether type enum present in ethernet II header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100,
}

impl EtherType {
    /// Tries to convert a raw ether type value to the enum. Returns None if the value does not exist in the enum.
    pub fn from_u16(value: u16) -> Option<EtherType> {
        use self::EtherType::*;
        match value {
            0x0800 => Some(Ipv4),
            0x86dd => Some(Ipv6),
            0x0806 => Some(Arp),
            0x0842 => Some(WakeOnLan),
            0x88A8 => Some(ProviderBridging),
            0x8100 => Some(VlanTaggedFrame),
            0x9100 => Some(VlanDoubleTaggedFrame),
            _ => None,
        }
    }
}

/// `u16` constants for the most used `ether_type` values.
///
/// `ether_type` values are used in the Ethernet II header and the
/// vlan headers to identify the next header type.
///
/// The constants are equivalent if values of the enum type [`EtherType`] get cast
/// to a u16 value.
///
/// ```
/// use etherparse::{ether_type, EtherType};
///
/// assert_eq!(ether_type::IPV4, EtherType::Ipv4 as u16);
/// ```
pub mod ether_type {
    use crate::EtherType::*;
    pub const IPV4: u16 = Ipv4 as u16;
    pub const IPV6: u16 = Ipv6 as u16;
    pub const ARP: u16 = Arp as u16;
    pub const WAKE_ON_LAN: u16 = WakeOnLan as u16;
    pub const VLAN_TAGGED_FRAME: u16 = VlanTaggedFrame as u16;
    pub const PROVIDER_BRIDGING: u16 = ProviderBridging as u16;
    pub const VLAN_DOUBLE_TAGGED_FRAME: u16 = VlanDoubleTaggedFrame as u16;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_u16() {
        use crate::EtherType::*;
        assert_eq!(0x0800, Ipv4 as u16);
        assert_eq!(0x86dd, Ipv6 as u16);
        assert_eq!(0x0806, Arp as u16);
        assert_eq!(0x0842, WakeOnLan as u16);
        assert_eq!(0x8100, VlanTaggedFrame as u16);
        assert_eq!(0x88A8, ProviderBridging as u16);
        assert_eq!(0x9100, VlanDoubleTaggedFrame as u16);
    }

    #[test]
    fn from_u16() {
        use crate::EtherType::*;
        assert_eq!(EtherType::from_u16(0x0800), Some(Ipv4));
        assert_eq!(EtherType::from_u16(0x86dd), Some(Ipv6));
        assert_eq!(EtherType::from_u16(0x0806), Some(Arp));
        assert_eq!(EtherType::from_u16(0x0842), Some(WakeOnLan));
        assert_eq!(EtherType::from_u16(0x8100), Some(VlanTaggedFrame));
        assert_eq!(EtherType::from_u16(0x88A8), Some(ProviderBridging));
        assert_eq!(EtherType::from_u16(0x9100), Some(VlanDoubleTaggedFrame));
        assert_eq!(EtherType::from_u16(0x1234), None);
    }

    #[test]
    fn constants() {
        use crate::ether_type::*;
        use crate::EtherType::*;
        let pairs = &[
            (Ipv4, IPV4),
            (Ipv6, IPV6),
            (Arp, ARP),
            (WakeOnLan, WAKE_ON_LAN),
            (VlanTaggedFrame, VLAN_TAGGED_FRAME),
            (ProviderBridging, PROVIDER_BRIDGING),
            (VlanDoubleTaggedFrame, VLAN_DOUBLE_TAGGED_FRAME),
        ];

        for (enum_value, constant) in pairs {
            assert_eq!(enum_value.clone() as u16, *constant);
        }
    }

    #[test]
    fn dbg() {
        use crate::EtherType::*;
        let pairs = &[
            (Ipv4, "Ipv4"),
            (Ipv6, "Ipv6"),
            (Arp, "Arp"),
            (WakeOnLan, "WakeOnLan"),
            (VlanTaggedFrame, "VlanTaggedFrame"),
            (ProviderBridging, "ProviderBridging"),
            (VlanDoubleTaggedFrame, "VlanDoubleTaggedFrame"),
        ];

        for (enum_value, str_value) in pairs {
            assert_eq!(str_value, &format!("{:?}", enum_value));
        }
    }

    #[test]
    fn clone_eq() {
        use crate::EtherType::*;
        let values = &[
            Ipv4,
            Ipv6,
            Arp,
            WakeOnLan,
            VlanTaggedFrame,
            ProviderBridging,
            VlanDoubleTaggedFrame,
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