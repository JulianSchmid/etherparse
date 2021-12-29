use super::super::*;

use std::slice::from_raw_parts;
use std::io;
use error::de::UnexpectedEndOfSliceError;

/// Ether type enum present in ethernet II header.
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

    /// Creates a ethernet slice from an other slice.
    #[deprecated(
        since = "0.10.1",
        note = "Use Ethernet2Header::from_slice instead."
    )]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ethernet2Header, &[u8]), UnexpectedEndOfSliceError> {
        Ethernet2Header::from_slice(slice)
    }

    /// Read an Ethernet2Header from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Ethernet2Header, &[u8]), UnexpectedEndOfSliceError> {
        Ok((
            Ethernet2HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Ethernet2Header::SERIALIZED_SIZE..]
        ))
    }

    /// Read an Ethernet2Header from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8;14]) -> Ethernet2Header {
        Ethernet2Header{
            destination: [
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                bytes[4],
                bytes[5],
            ],
            source: [
                bytes[6],
                bytes[7],
                bytes[8],
                bytes[9],
                bytes[10],
                bytes[11],
            ],
            ether_type: u16::from_be_bytes(
                [
                    bytes[12],
                    bytes[13],
                ]
            )
        }
    }

    /// Reads an Ethernet-II header from the current position of the read argument.
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

    /// Serialize the header to a given slice. Returns the unused part of the slice.
    pub fn write_to_slice<'a>(&self, slice: &'a mut [u8]) -> Result<&'a mut [u8], WriteError> {
        use self::WriteError::*;
        //length check
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            Err(SliceTooSmall(Ethernet2Header::SERIALIZED_SIZE))
        } else {
            slice[..Ethernet2Header::SERIALIZED_SIZE].copy_from_slice(&self.to_bytes());
            Ok(&mut slice[Ethernet2Header::SERIALIZED_SIZE..])
        }
    }

    /// Writes a given Ethernet-II header to the current position of the write argument.
    #[inline]
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        14
    }

    /// Returns the serialized form of the header as a statically
    /// sized byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8;14] {
        let ether_type_be = self.ether_type.to_be_bytes();
        [
            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
            self.destination[4],
            self.destination[5],
            self.source[0],
            self.source[1],
            self.source[2],
            self.source[3],
            self.source[4],
            self.source[5],
            ether_type_be[0],
            ether_type_be[1],
        ]
    }
}

///A slice containing an ethernet 2 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ethernet2HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Ethernet2HeaderSlice<'a> {

    /// Creates a ethernet slice from an other slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<Ethernet2HeaderSlice<'a>, UnexpectedEndOfSliceError>{
        //check length
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSliceError{
                expected_min_len: Ethernet2Header::SERIALIZED_SIZE,
                actual_len: slice.len(),
            });
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

    /// Returns the slice containing the ethernet 2 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the destination mac address
    #[inline]
    pub fn destination(&self) -> [u8;6] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe {
            get_unchecked_6_byte_array(self.slice.as_ptr())
        }
    }

    /// Read the source mac address
    #[inline]
    pub fn source(&self) -> [u8;6] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe {
            get_unchecked_6_byte_array(self.slice.as_ptr().add(6))
        }
    }

    /// Read the ether_type field of the header (in system native byte order).
    #[inline]
    pub fn ether_type(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(12))
        }
    }

    /// Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ethernet2Header {
        Ethernet2Header {
            source: self.source(),
            destination: self.destination(),
            ether_type: self.ether_type()
        }
    }
}