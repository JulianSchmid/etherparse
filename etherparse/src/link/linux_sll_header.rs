use crate::{EtherType, LinuxNonstandardEtherType};

use super::{arp_hardware_id::ArpHardwareId, linux_sll_packet_type::LinuxSllPacketType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxSllProtocolType {
    /// The protocol type should be ignored
    Ignored(u16),
    /// Netlink protocol type of the encapsulated payload
    NetlinkProtocolType(u16),
    /// Generic Routing Encapsulation protocol type for the encapsulated payload
    GenericRoutingEncapsulationProtocolType(u16),
    /// EtherType of the encapsulated payload
    EtherType(EtherType),
    /// Non-standard ether types of the encapsulated payload
    LinuxNonstandardEtherType(LinuxNonstandardEtherType),
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
