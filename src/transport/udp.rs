use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

///Udp header according to rfc768.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
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
    pub fn without_ipv4_checksum(source_port: u16, destination_port: u16, payload_length: usize) -> Result<UdpHeader, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload_length {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload_length));
        }

        Ok(UdpHeader{
            source_port,
            destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload_length) as u16, //payload plus udp header
            checksum: 0
        })
    }

    ///Calculate an udp header given an ipv4 header and the payload
    pub fn with_ipv4_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv4Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {

        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        let mut result = UdpHeader{
            source_port,
            destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv4_internal(ip_header.source, ip_header.destination, ip_header.protocol, payload);
        Ok(result)
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, ip_header.protocol, payload)
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4_raw(&self, source: [u8;4], destination: [u8;4], protocol: u8, payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv4_internal(source, destination, protocol, payload))
    }
    
    ///Calculates the upd header checksum based on a ipv4 header.
    fn calc_checksum_ipv4_internal(&self, source: [u8;4], destination: [u8;4], protocol: u8, payload: &[u8]) -> u16 {
        self.calc_checksum_post_ip(u64::from( BigEndian::read_u16(&source[0..2]) ) + //pseudo header
                                   u64::from( BigEndian::read_u16(&source[2..4]) ) +
                                   u64::from( BigEndian::read_u16(&destination[0..2]) ) +
                                   u64::from( BigEndian::read_u16(&destination[2..4]) ) +
                                   u64::from( protocol ) +
                                   u64::from( self.length ), 
                                   payload)
    }

    ///Calculate an udp header given an ipv6 header and the payload
    pub fn with_ipv6_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv6Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {

        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        let mut result = UdpHeader{
            source_port,
            destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv6_internal(ip_header.source, ip_header.destination, payload);
        Ok(result)
    }

    ///Calculates the checksum of the current udp header given an ipv6 header and the payload.
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, payload)
    }

    ///Calculates the checksum of the current udp header given an ipv6 source & destination address plus the payload.
    pub fn calc_checksum_ipv6_raw(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv6_internal(source, destination, payload))
    }

    fn calc_checksum_ipv6_internal(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> u16 {
        fn calc_sum(value: [u8;16]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i*2;
                result += u64::from( BigEndian::read_u16(&value[index..(index + 2)]) );
            }
            result
        }
        self.calc_checksum_post_ip(calc_sum(source) +
                                   calc_sum(destination) +
                                   ip_number::UDP as u64 +
                                   u64::from( self.length ),
                                   payload)
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {
        let mut sum = ip_pseudo_header_sum +
                      u64::from( self.source_port ) + //udp header start
                      u64::from( self.destination_port ) +
                      u64::from( self.length );

        for i in 0..(payload.len()/2) {
            sum += u64::from( BigEndian::read_u16(&payload[i*2..i*2 + 2]) );
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += u64::from( BigEndian::read_u16(&[*payload.last().unwrap(), 0]));
        }
        let carry_add = (sum & 0xffff) + 
                        ((sum >> 16) & 0xffff) +
                        ((sum >> 32) & 0xffff) +
                        ((sum >> 48) & 0xffff);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        if 0xffff == result {
            result //avoid the transmition of an all 0 checksum as this value is reserved by "checksum disabled" (see rfc)
        } else {
            !result
        }
    }

    ///Reads a udp header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(UdpHeader, &[u8]), ReadError> {
        Ok((
            UdpHeaderSlice::from_slice(slice)?.to_header(),
            &slice[UdpHeader::SERIALIZED_SIZE..]
        ))
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

///A slice containing an udp header of a network package. Struct allows the selective read of fields in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> UdpHeaderSlice<'a> {

    ///Creates a slice containing an udp header.
    pub fn from_slice(slice: &'a[u8]) -> Result<UdpHeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < UdpHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(UdpHeader::SERIALIZED_SIZE));
        }

        //done
        Ok(UdpHeaderSlice{
            slice: &slice[..UdpHeader::SERIALIZED_SIZE]
        })
    }

    ///Returns the slice containing the udp header
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Reads the "udp source port" from the slice.
    pub fn source_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice[..2])
    }

    ///Reads the "udp destination port" from the slice.
    pub fn destination_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice[2..4])
    }

    ///Reads the "length" from the slice.
    pub fn length(&self) -> u16 {
        BigEndian::read_u16(&self.slice[4..6])
    }

    ///Reads the "checksum" from the slice.
    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.slice[6..8])
    }

    ///Decode all the fields and copy the results to a UdpHeader struct
    pub fn to_header(&self) -> UdpHeader {
        UdpHeader {
            source_port: self.source_port(),
            destination_port: self.destination_port(),
            length: self.length(),
            checksum: self.checksum()
        }
    }
}
