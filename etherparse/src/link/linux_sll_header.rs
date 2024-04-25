use crate::EtherType;

use super::{arp_hardware_id::ArpHardwareId, linux_sll_packet_type::LinuxSllPacketType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxSllProtocolType {
    /// The protocol type does not have relevant information
    Ignored,
    /// Netlink protocol type for the associated Netlink payload
    NetlinkProtocolType(u16),
    /// Generic Routing Encapsulation protocol type
    GenericRoutingEncapsulationProtocolType(u16),
    /// The associated payload is a Novell 802.3 frame without an 802.2 LLC header
    Novel802_3Frame,
    /// The protocol type value is "0x0003", which is possibly an error on the 
    /// capture, but it is not known the specific cause
    Unknown,
    /// The associated payload begins with a 802.2 LLC header.
    LLC,
    /// The associated payload is a CAN bus frame
    CANBusFrame,
    /// The associated payload is a CAN FD (CAN with Flexible Data-Rate) frame
    CANFDFrame,
    /// The associated payload's ether type
    EtherType(EtherType)
}

/// Linux SLL Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSllHeader {
    /// Type of the captured packet
    pub packet_type: LinuxSllPacketType,
    /// ARPHRD_ value for the link-layer device type
    pub arp_hrd_type: ArpHardwareId,
    /// The size of the adress that is valid
    pub sender_address_valid_length: u16,
    /// The link-layer adress of the sender of the packet, with the meaningful 
    /// bytes specified by `sender_address_valid_length`. If the original is 
    /// larger, the value on the packet is truncated to the first 8 bytes. If 
    /// the original is smaller, the remaining bytes will be filled with 0s.
    pub sender_address: [u8; 8],
    /// The protocol type of the encapsulated packet
    pub protocol_type: LinuxSllProtocolType,
}
