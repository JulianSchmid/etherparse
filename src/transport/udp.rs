use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

///Udp header according to rfc768.
#[derive(Debug, PartialEq)]
pub struct UdpHeader {
    ///Source port of the packet (optional).
    pub source_port: u16,
    ///Destination port of the packet.
    pub destination_port: u16,
    ///Length of the packet (includes the udp header length of 8 bytes).
    pub length: u16,
    ///The checksum of the packet. The checksum is calculated from a pseudo header, the udp header and the payload. The pseudo header is composed of source and destination address, protocol number 
    pub checksum: u16
}

impl UdpHeader {

    ///Returns an udp header for the given parameters
    pub fn without_checksum(source_port: u16, destination_port: u16, payload_length: usize) -> Result<UdpHeader, ValueError> {
        //TODO check payload size

        Ok(UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: (8 + payload_length) as u16, //payload plus udp header
            checksum: 0
        })
    }

    ///Calculate an udp header given an ipv4 header and the payload
    pub fn with_ipv4_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv4Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {
        //TODO check that the payload length is not too big
        let mut result = UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: 8 + payload.len() as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv4(ip_header, payload)?;
        Ok(result)
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, ip_header.protocol, payload)
    }
    
    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4_raw(&self, source: &[u8;4], destination: &[u8;4], protocol: u8, payload: &[u8]) -> Result<u16, ValueError> {

        //TODO check that the payload length is not too big

        let mut sum = BigEndian::read_u16(&source[0..2]) as u32 + //pseudo header
                      BigEndian::read_u16(&source[2..4]) as u32 +
                      BigEndian::read_u16(&destination[0..2]) as u32 +
                      BigEndian::read_u16(&destination[2..4]) as u32 +
                      protocol as u32 +
                      self.length as u32 +
                      //udp header start
                      self.source_port as u32 + //udp header start
                      self.destination_port as u32 +
                      self.length as u32;

        for i in 0..(payload.len()/2) {
            sum += BigEndian::read_u16(&payload[i*2..i*2 + 2]) as u32;
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += BigEndian::read_u16(&[*payload.last().unwrap(), 0]) as u32;
        }
        let carry_add = (sum & 0xffff) + (sum >> 16);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        if result == 0xffff {
            Ok(result) //avoid the transmition of an all 0 checksum as this value is reserved by "checksum disabled" (see rfc)
        } else {
            Ok(!result)
        }
    }

    ///Tries to read an udp header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<UdpHeader, io::Error> {
        Ok(UdpHeader{
            source_port: reader.read_u16::<BigEndian>()?,
            destination_port: reader.read_u16::<BigEndian>()?,
            length: reader.read_u16::<BigEndian>()?,
            checksum: reader.read_u16::<BigEndian>()?
        })
    }

    ///Write the udp header without recalculating the checksum or length.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_u16::<BigEndian>(self.source_port)?;
        writer.write_u16::<BigEndian>(self.destination_port)?;
        writer.write_u16::<BigEndian>(self.length)?;
        writer.write_u16::<BigEndian>(self.checksum)?;
        Ok(())
    }
}

impl SerializedSize for UdpHeader {
    ///Size of the header itself
    const SERIALIZED_SIZE: usize = 8;
}