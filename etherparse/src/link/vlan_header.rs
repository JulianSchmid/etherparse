use crate::*;

/// IEEE 802.1Q VLAN Tagging Header (can be single or double tagged).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanHeader {
    /// IEEE 802.1Q VLAN Tagging Header
    Single(SingleVlanHeader),
    /// IEEE 802.1Q double VLAN Tagging Header
    Double(DoubleVlanHeader),
}

impl VlanHeader {
    /// All ether types that identify a vlan header.
    pub const VLAN_ETHER_TYPES: [u16; 3] = [
        ether_type::VLAN_TAGGED_FRAME,
        ether_type::PROVIDER_BRIDGING,
        ether_type::VLAN_DOUBLE_TAGGED_FRAME,
    ];

    /// Write the IEEE 802.1Q VLAN single or double tagging header
    #[inline]
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use VlanHeader::*;
        match &self {
            Single(header) => header.write(writer),
            Double(header) => header.write(writer),
        }
    }

    /// Length of the serialized header(s) in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        use VlanHeader::*;
        match &self {
            Single(_) => SingleVlanHeader::SERIALIZED_SIZE,
            Double(_) => DoubleVlanHeader::SERIALIZED_SIZE,
        }
    }
}
