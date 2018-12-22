use super::super::*;

extern crate byteorder;
use self::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

///Ether type enum present in ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    ///Reads an Ethernet-II header from the current position of the read argument.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ethernet2Header, io::Error> {
        fn read_mac_address<T: io::Read>(read: &mut T) -> Result<[u8;6], io::Error> {
            let mut result: [u8;6] = [0;6];
            read.read_exact(&mut result)?;
            Ok(result)
        }

        Ok(Ethernet2Header {
            destination: read_mac_address(reader)?,
            source: read_mac_address(reader)?,
            ether_type: reader.read_u16::<BigEndian>()?
        })
    }
    ///Writes a given Ethernet-II header to the current position of the write argument.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), io::Error> {
        writer.write_all(&self.destination)?;
        writer.write_all(&self.source)?;
        writer.write_u16::<BigEndian>(self.ether_type)?;
        Ok(())
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
            slice: &slice[..14]
        })
    }

    ///Returns the slice containing the ethernet 2 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the destination mac address
    pub fn destination(&self) -> &'a [u8] {
        &self.slice[..6]
    }

    ///Read the source mac address
    pub fn source(&self) -> &'a [u8] {
        &self.slice[6..12]
    }

    ///Read the ether_type field of the header (in system native byte order).
    pub fn ether_type(&self) -> u16 {
        use self::byteorder::ByteOrder;
        BigEndian::read_u16(&self.slice[12..14])
    }

    ///Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ethernet2Header {
        Ethernet2Header {
            source: {
                let mut result: [u8;6] = Default::default();
                result.copy_from_slice(self.source());
                result
            },
            destination: {
                let mut result: [u8;6] = Default::default();
                result.copy_from_slice(self.destination());
                result
            },
            ether_type: self.ether_type()
        }
    }
}