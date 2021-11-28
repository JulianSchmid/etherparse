use super::*;
use std::slice::from_raw_parts;

#[derive(Clone, Debug, Eq, PartialEq)]
/// There are many other possible hardware types, but
/// this library focuses on Ethernet.
pub enum ArpHardwareType {
    Ethernet = 0x0001,
}

pub mod arp_hardware_type {
    use super::ArpHardwareType;
    pub const ETHERNET: u16 = ArpHardwareType::Ethernet as u16;
}

impl ArpHardwareType {
    pub fn from_u16(value: u16) -> Option<ArpHardwareType> {
        use self::ArpHardwareType::*;
        match value {
            0x0001 => Some(Ethernet),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArpOpcode {
    Request = 0x0001,
    Reply = 0x0002,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub opcode: u16,
}

impl SerializedSize for ArpHeader {
    ///Size of the header itself in bytes.
    const SERIALIZED_SIZE: usize = 8;
}

impl ArpHeader {
    /// Creates an arp header for ethernet & IPv4 with the given opcode.
    pub fn new_ipv4(
        opcode: ArpOpcode,
    ) -> Self {
        ArpHeader {
            hardware_type: arp_hardware_type::ETHERNET,
            protocol_type: ether_type::IPV4,
            hardware_len: 3,
            protocol_len: 4,
            opcode: opcode as u16,
        }
    }

    pub fn header_len(&self) -> usize {
        ArpHeader::SERIALIZED_SIZE
    }

    pub fn total_len(&self) -> usize {
        let payload_len = 2 * (self.hardware_len + self.protocol_len);
        ArpHeader::SERIALIZED_SIZE + (payload_len as usize)
    }

    pub fn from_slice(slice: &[u8]) -> Result<(ArpHeader, &[u8]), ReadError> {
        let header = ArpHeaderSlice::from_slice(slice)?.to_header();
        let rest = &slice[header.header_len()..];
        Ok((header, rest))
    }

    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<ArpHeader, ReadError> {
        let mut buffer : [u8;ArpHeader::SERIALIZED_SIZE] = [0;ArpHeader::SERIALIZED_SIZE];
        reader.read_exact(&mut buffer)?;
        Ok(
            // SAFETY: Safe as the buffer has the required size `ArpHeader::SERIALIZED_SIZE`.
            unsafe {
                ArpHeaderSlice::from_slice_unchecked(&buffer).to_header()
            }
        )
    }
}

///A slice containing an arp header of a network packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> ArpHeaderSlice<'a> {
    /// Creates a slice containing an arp header.
    pub fn from_slice(slice: &'a [u8]) -> Result<ArpHeaderSlice<'a>, ReadError> {
        // check len
        use crate::ReadError::*;
        if slice.len() < ArpHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(ArpHeader::SERIALIZED_SIZE));
        }

        Ok(ArpHeaderSlice {
            slice: &slice[..ArpHeader::SERIALIZED_SIZE],
        })
    }

    /// Creates a arp header slice from a slice (assumes slice size & content was validated before).
    ///
    /// # Safety
    ///
    /// This method assumes that the slice was previously validated to contain
    /// a valid arp header. This means the slice length must at least be at least 8.
    /// The data that the slice points must also be valid (meaning no nullptr or alike allowed).
    ///
    /// If these precondtions are not fullfilled the behavior of this function
    /// and the methods of the return ArpHeaderSlice will be undefined.
    pub unsafe fn from_slice_unchecked(slice: &'a[u8]) -> ArpHeaderSlice<'a> {
        ArpHeaderSlice{
            slice: from_raw_parts(
                slice.as_ptr(),
                ArpHeader::SERIALIZED_SIZE
            )
        }
    }

    /// Returns the slice containing the arp header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the "hardware type" field of the ARP header (should usually be 1 for Ethernet)
    #[inline]
    pub fn hardware_type(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (8) in the constructor.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr())
        }
    }

    /// Read the "protocol type" field of the ARP header (should be 0x0800 for IPv4, or 0x86DD for IPv6).
    #[inline]
    pub fn protocol_type(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (8) in the constructor.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    /// Read the "hardware length" field of the ARP header (should be 3 for Ethernet).
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (8) in the constructor.
        unsafe {
            *self.slice.get_unchecked(4)
        }
    }

    /// Read the "protocol length" field of the ARP header (should be 4 for IPv4, or 16 for IPv6).
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (8) in the constructor.
        unsafe {
            *self.slice.get_unchecked(5)
        }
    }

    /// Read the opcode field of the ARP header
    #[inline]
    pub fn opcode(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (8) in the constructor.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(6))
        }
    }

    pub fn total_len(&self) -> usize {
        let payload_len = 2 * (usize::from(self.hardware_len()) + usize::from(self.protocol_len()));
        ArpHeader::SERIALIZED_SIZE + (payload_len as usize)
    }

    pub fn to_header(&self) -> ArpHeader {
        ArpHeader {
            hardware_type: self.hardware_type(),
            protocol_type: self.protocol_type(),
            hardware_len: self.hardware_len(),
            protocol_len: self.protocol_len(),
            opcode: self.opcode(),
        }
    }
}
