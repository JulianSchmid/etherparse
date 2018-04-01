use super::super::*;

extern crate byteorder;
use self::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

///Ether type enum present in ethernet II header.
#[derive(Debug, PartialEq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
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
            0x8100 => Some(VlanTaggedFrame),
            0x9100 => Some(VlanDoubleTaggedFrame),
            _ => None
        }
    }
}

///Ethernet II header.
#[derive(Debug, PartialEq)]
pub struct Ethernet2Header {
    pub destination: [u8;6],
    pub source: [u8;6],
    pub ether_type: u16
}

impl SerializedSize for Ethernet2Header {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 14;
}

impl Ethernet2Header {
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
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), io::Error> {
        writer.write_all(&self.destination)?;
        writer.write_all(&self.source)?;
        writer.write_u16::<BigEndian>(self.ether_type)?;
        Ok(())
    }
}
