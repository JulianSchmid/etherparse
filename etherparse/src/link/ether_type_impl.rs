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
