use super::super::*;

use std::slice::from_raw_parts;
use std::io;

///Ether type enum present in ethernet II header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100
}

impl EtherType {
    ///Tries to convert a raw ether type value to the enum. Returns None if the value does not exist in the enum.
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
            _ => None
        }
    }
}

/// Module containing the u16 constants for the most used ether type values
/// present in ethernet II header.
///
/// The constants are equivalt if values of the enum type `EtherType` get cast
/// to a u16 value.
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

///Ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ethernet2Header {
    pub source: [u8;6],
    pub destination: [u8;6],
    pub ether_type: u16
}

impl SerializedSize for Ethernet2Header {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 14;
}

impl Ethernet2Header {

    ///Read an Ethernet2Header from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ethernet2Header, &[u8]), ReadError> {
        Ok((
            Ethernet2HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Ethernet2Header::SERIALIZED_SIZE..]
        ))
    }

    ///Reads an Ethernet-II header from the current position of the read argument.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ethernet2Header, io::Error> {

        let buffer = {
            let mut buffer = [0;Ethernet2Header::SERIALIZED_SIZE];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(Ethernet2HeaderSlice{
            slice: &buffer
        }.to_header())
    }

    ///Serialize the header to a given slice. Returns the unused part of the slice.
    pub fn write_to_slice<'a>(&self, slice: &'a mut [u8]) -> Result<&'a mut [u8], WriteError> {
        use self::WriteError::*;
        //length check
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            Err(SliceTooSmall(Ethernet2Header::SERIALIZED_SIZE))
        } else {
            self.write_to_slice_unchecked(slice);
            Ok(&mut slice[Ethernet2Header::SERIALIZED_SIZE..])
        }
    }

    ///Writes a given Ethernet-II header to the current position of the write argument.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), io::Error> {
        let mut buffer: [u8;Ethernet2Header::SERIALIZED_SIZE] = Default::default();
        self.write_to_slice_unchecked(&mut buffer);
        writer.write_all(&buffer)
    }

    ///Write the header to a slice without checking the slice length
    fn write_to_slice_unchecked(&self, slice: &mut [u8]) {
        slice[..6].copy_from_slice(&self.destination);
        slice[6..12].copy_from_slice(&self.source);
        slice[12..14].copy_from_slice(&self.ether_type.to_be_bytes());
    }
}

///A slice containing an ethernet 2 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ethernet2HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Ethernet2HeaderSlice<'a> {
    ///Creates a ethernet slice from an other slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<Ethernet2HeaderSlice<'a>, ReadError>{
        //check length
        use crate::ReadError::*;
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Ethernet2Header::SERIALIZED_SIZE));
        }

        //all done
        Ok(Ethernet2HeaderSlice {
            // SAFETY:
            // Safe as slice length is checked to be at least
            // Ethernet2Header::SERIALIZED_SIZE (14) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    Ethernet2Header::SERIALIZED_SIZE
                )
            }
        })
    }

    ///Returns the slice containing the ethernet 2 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the destination mac address
    #[inline]
    pub fn destination(&self) -> [u8;6] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe {
            get_unchecked_6_byte_array(self.slice.as_ptr())
        }
    }

    ///Read the source mac address
    #[inline]
    pub fn source(&self) -> [u8;6] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe {
            get_unchecked_6_byte_array(self.slice.as_ptr().add(6))
        }
    }

    ///Read the ether_type field of the header (in system native byte order).
    #[inline]
    pub fn ether_type(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(12))
        }
    }

    ///Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ethernet2Header {
        Ethernet2Header {
            source: self.source(),
            destination: self.destination(),
            ether_type: self.ether_type()
        }
    }
}