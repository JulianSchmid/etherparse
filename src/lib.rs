extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

///Ether type enum present in ethernet II header.
#[derive(Debug, PartialEq)]
pub enum EtherType {
    Ipv4, //0x0800
    Ipv6, //0x86dd
    Arp,  //0x0806
    WakeOnLan, //0x0842
    VlanTaggedFrame, //0x8100
    VlanDoubleTaggedFrame, //0x9100
    Unknown(u16)
}

impl EtherType {
    pub fn to_u16(&self) -> u16 {
        use EtherType::*;
        match *self {
            Ipv4 => 0x0800,
            Ipv6 => 0x86dd,
            Arp  => 0x0806,
            WakeOnLan => 0x0842,
            VlanTaggedFrame => 0x8100,
            VlanDoubleTaggedFrame => 0x9100,
            Unknown(value) => value
        }
    }
    pub fn from_u16(value: u16) -> EtherType {
        use EtherType::*;
        match value {
            0x0800 => Ipv4,
            0x86dd => Ipv6,
            0x0806 => Arp,
            0x0842 => WakeOnLan,
            0x8100 => VlanTaggedFrame,
            0x9100 => VlanDoubleTaggedFrame,
            value => Unknown(value)
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

///IPv4 header without options.
#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    pub header_length: u8,
    pub differentiated_services_code_point: u8,
    pub explicit_congestion_notification: u8,
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragments_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: [u8;4],
    pub destination: [u8;4]
}

///IPv6 header according to rfc8200.
#[derive(Debug, PartialEq)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: [u8;16],
    pub destination: [u8;16]
}

///Internet protocol headers
#[derive(Debug, PartialEq)]
pub enum IpHeader {
    Version4(Ipv4Header),
    Version6(Ipv6Header)
}

///Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    IoError(io::Error),
    IpUnsupportedVersion(u8),
    Ipv4UnexpectedVersion(u8),
    Ipv6UnexpectedVersion(u8)
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

///Errors that can occur when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(io::Error),
    ValueU8TooLarge{value: u8, max: u8, field: ErrorField},
    ValueU16TooLarge{value: u16, max: u16, field: ErrorField},
    ValueU32TooLarge{value: u32, max: u32, field: ErrorField}
}

impl From<io::Error> for WriteError {
    fn from(err: io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

///Fields that can produce errors when serialized.
#[derive(Debug)]
pub enum ErrorField {
    Ipv4HeaderLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset,

    Ipv6FlowLabel
}

///Helper for writing headers.
///Import this for adding write functions to every struct that implements the trait Read.
pub trait WriteEtherExt: io::Write {
    fn write_ethernet2_header(&mut self, value: &Ethernet2Header) -> Result<(), io::Error> {
        self.write_all(&value.destination)?;
        self.write_all(&value.source)?;
        self.write_u16::<BigEndian>(value.ether_type)?;
        Ok(())
    }

    fn write_ipv4_header(&mut self, value: &Ipv4Header) -> Result<(), WriteError> {
        use WriteError::*;
        use ErrorField::*;
        fn max_check_u8(value: u8, max: u8, field: ErrorField) -> Result<(), WriteError> {
            if value <= max {
                Ok(())
            } else {
                Err(ValueU8TooLarge{ value: value, max: max, field: field })
            }
        };
        fn max_check_u16(value: u16, max: u16, field: ErrorField) -> Result<(), WriteError> {
            if value <= max {
                Ok(())
            } else {
                Err(ValueU16TooLarge{ value: value, max: max, field: field })
            }
        };
        //version & header_length
        max_check_u8(value.header_length, 0xf, Ipv4HeaderLength)?;
        self.write_u8(4 | (value.header_length << 4))?;

        //dscp & ecn
        max_check_u8(value.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(value.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        self.write_u8(value.differentiated_services_code_point | (value.explicit_congestion_notification << 6))?;

        //total length & id 
        self.write_u16::<BigEndian>(value.total_length)?;
        self.write_u16::<BigEndian>(value.identification)?;

        //flags & fragmentation offset
        max_check_u16(value.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;
        {
            let mut buf: [u8;2] = [0;2];
            BigEndian::write_u16(&mut buf, value.fragments_offset);
            let flags = {
                let mut result = 0;
                if value.dont_fragment {
                    result = result | 2;
                }
                if value.more_fragments {
                    result = result | 4;
                }
                result
            };
            self.write_u8(
                (flags & 0x7) |
                (buf[0] << 3),
            )?;
            self.write_u8(
                (buf[0] >> 5) |
                (buf[1] << 3)
            )?;
        }

        //rest
        self.write_u8(value.time_to_live)?;
        self.write_u8(value.protocol)?;
        self.write_u16::<BigEndian>(value.header_checksum)?;
        self.write_all(&value.source)?;
        self.write_all(&value.destination)?;

        Ok(())
    }
    fn write_ipv6_header(&mut self, value: &Ipv6Header) -> Result<(), WriteError> {
        use WriteError::*;
        use ErrorField::*;
        fn max_check_u32(value: u32, max: u32, field: ErrorField) -> Result<(), WriteError> {
            if value <= max {
                Ok(())
            } else {
                Err(ValueU32TooLarge{ value: value, max: max, field: field })
            }
        };

        //version & traffic class p0
        self.write_u8(6 | (value.traffic_class << 4))?;

        //flow label
        max_check_u32(value.flow_label, 0xfffff, Ipv6FlowLabel)?;
        {
            //write as a u32 to a buffer and write only the "lower bytes"
            let mut buffer: [u8; 4] = [0;4];
            byteorder::BigEndian::write_u32(&mut buffer, value.flow_label);
            //add the traffic_class
            buffer[1] = (buffer[1] << 4) | (value.traffic_class >> 4);
            //skip "highest" byte of big endian
            self.write_all(&buffer[1..])?;
        }

        //rest
        self.write_u16::<BigEndian>(value.payload_length)?;
        self.write_u8(value.next_header)?;
        self.write_u8(value.hop_limit)?;
        self.write_all(&value.source)?;
        self.write_all(&value.destination)?;

        Ok(())
    }
}

impl<W: io::Write + ?Sized> WriteEtherExt for W {}

pub trait ReadEtherExt: io::Read + io::Seek {
    fn read_ethernet2_header(&mut self) -> Result<Ethernet2Header, io::Error> {
        Ok(Ethernet2Header {
            destination: self.read_mac_address()?,
            source: self.read_mac_address()?,
            ether_type: self.read_u16::<BigEndian>()?
        })
    }

    fn read_ip_header(&mut self) -> Result<IpHeader, ReadError> {
        let value = self.read_u8()?;
        match value & 0xf {
            4 => Ok(IpHeader::Version4(self.read_ipv4_header_without_version(value >> 4)?)),
            6 => Ok(IpHeader::Version6(self.read_ipv6_header_without_version(value >> 4)?)),
            version => Err(ReadError::IpUnsupportedVersion(version))
        }
    }

    fn read_ipv4_header(&mut self) -> Result<Ipv4Header, ReadError> {
        let value = self.read_u8()?;
        let version = value & 0xf;
        if 4 != version {
            return Err(ReadError::Ipv4UnexpectedVersion(version));
        }
        self.read_ipv4_header_without_version(value >> 4)
    }

    fn read_ipv4_header_without_version(&mut self, version_rest: u8) -> Result<Ipv4Header, ReadError> {
        let ihl = version_rest;
        let (dscp, ecn) = {
            let value = self.read_u8()?;
            (value & 0x3f, (value >> 6))
        };
        let total_length = self.read_u16::<BigEndian>()?;
        let identification = self.read_u16::<BigEndian>()?;
        let (dont_fragment, more_fragments, fragments_offset) = {
            let mut values: [u8; 2] = [0;2];
            self.read_exact(&mut values)?;
            (0 != (values[0] & 0x2),
             0 != (values[0] & 0x4),
             {
                let shifted = [(values[0] >> 3) | ((values[1] << 5) & 0xE0),
                               (values[1] >> 3)];
                let mut cursor = io::Cursor::new(&shifted);
                cursor.read_u16::<BigEndian>()?
             })
        };
        Ok(Ipv4Header{
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            total_length: total_length,
            identification: identification,
            dont_fragment: dont_fragment,
            more_fragments: more_fragments,
            fragments_offset: fragments_offset,
            time_to_live: self.read_u8()?,
            protocol: self.read_u8()?,
            header_checksum: self.read_u16::<BigEndian>()?,
            source: {
                let mut values: [u8;4] = [0;4];
                self.read_exact(&mut values)?;
                values
            },
            destination: {
                let mut values: [u8;4] = [0;4];
                self.read_exact(&mut values)?;
                values
            },
            header_length: ihl
        })
    }

    fn read_ipv6_header(&mut self) -> Result<Ipv6Header, ReadError> {
        let value = self.read_u8()?;
        let version = value & 0xf;
        if 6 != version {
            return Err(ReadError::Ipv6UnexpectedVersion(version));
        }
        self.read_ipv6_header_without_version(value >> 4)
    }

    fn read_ipv6_header_without_version(&mut self, version_rest: u8) -> Result<Ipv6Header, ReadError> {
        let (traffic_class, flow_label) = {
            //read 4 bytes
            let mut buffer: [u8; 4] = [0;4];
            self.read_exact(&mut buffer[1..])?;

            //extract class
            let traffic_class = version_rest | (buffer[1] << 4);

            //remove traffic class from buffer & read flow_label
            buffer[1] = buffer[1] >> 4;
            (traffic_class, byteorder::BigEndian::read_u32(&buffer))
        };
        
        Ok(Ipv6Header{
            traffic_class: traffic_class,
            flow_label: flow_label,
            payload_length: self.read_u16::<BigEndian>()?,
            next_header: self.read_u8()?,
            hop_limit: self.read_u8()?,
            source: {
                let mut buffer: [u8; 16] = [0;16];
                self.read_exact(&mut buffer)?;
                buffer
            },
            destination: {
                let mut buffer: [u8; 16] = [0;16];
                self.read_exact(&mut buffer)?;
                buffer
            }
        })
    }

    ///Skips the ipv6 header extension "next header" identification
    fn skip_ipv6_header_extension(&mut self) -> Result<u8, ReadError> {
        let next_header = self.read_u8()?;
        //read the length
        //Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
        let rest_length = ((self.read_u8()? as i64)*8) + 8 - 2;
        self.seek(io::SeekFrom::Current(rest_length))?;
        Ok(next_header)
    }

    fn read_mac_address(&mut self) -> Result<[u8;6], io::Error> {
        let mut result: [u8;6] = [0;6];
        self.read_exact(&mut result)?;
        Ok(result)
    }
}

impl<W: io::Read + io::Seek + ?Sized> ReadEtherExt for W {}

#[cfg(test)]
mod tests {
    #[test]
    fn ether_test_convert() {
        use super::*;
        use EtherType::*;
        [(0x0800, Ipv4),
         (0x86dd, Ipv6),
         (0x0806, Arp),
         (0x0842, WakeOnLan),
         (0x8100, VlanTaggedFrame),
         (0x9100, VlanDoubleTaggedFrame),
         (0x1234, Unknown(0x1234))
        ].iter().for_each(|&(ref raw_value, ref enum_value)| {
            assert_eq!(*raw_value, enum_value.to_u16());
            assert_eq!(*enum_value, EtherType::from_u16(*raw_value));
        });
    }
    #[test]
    fn readwrite_ethernet2_header() {
        use super::*;
        use std::io::Cursor;
        
        let input = Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [10,11,12,13,14,15],
            ether_type: 0x0800
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        buffer.write_ethernet2_header(&input).unwrap();
        //deserialize
        let result = {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ethernet2_header().unwrap()
        };
        //check equivalence
        assert_eq!(input, result);
    }
    
    #[test]
    fn read_ip_header_ipv4() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv4Header {
            header_length: 10,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 2345,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv4_header(&input).unwrap();
        //deserialize
        match {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ip_header().unwrap()
        } {
            IpHeader::Version4(result) => assert_eq!(input, result),
            value => assert!(false, format!("Expected IpHeaderV4 but received {:?}", value))
        }
    }
    #[test]
    fn read_ip_header_ipv6() {
        use super::*;
        use std::io::Cursor;
        let input = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv6_header(&input).unwrap();
        //deserialize
        match {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ip_header().unwrap()
        } {
            IpHeader::Version6(result) => assert_eq!(input, result),
            value => assert!(false, format!("Expected IpHeaderV6 but received {:?}", value))
        }
    }
    #[test]
    fn readwrite_ipv4_header() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv4Header {
            header_length: 10,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 2345,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv4_header(&input).unwrap();
        //deserialize
        let result = {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ipv4_header().unwrap()
        };
        //check equivalence
        assert_eq!(input, result);
    }
    #[test]
    fn write_ipv4_header_errors() {
        use super::*;
        use super::WriteError::*;
        use super::ErrorField::*;
        fn base() -> Ipv4Header {
            Ipv4Header{
                header_length: 10,
                differentiated_services_code_point: 42,
                explicit_congestion_notification: 3,
                total_length: 1234,
                identification: 4321,
                dont_fragment: true,
                more_fragments: false,
                fragments_offset: 4367,
                time_to_live: 8,
                protocol: 1,
                header_checksum: 2345,
                source: [192, 168, 1, 1],
                destination: [212, 10, 11, 123]
            }
        };

        fn test_write(input: &Ipv4Header) -> Result<(), WriteError> {
            let mut buffer: Vec<u8> = Vec::with_capacity(20);
            buffer.write_ipv4_header(input)
        };
        //header_length
        match test_write(&{
            let mut value = base();
            value.header_length = 0x1f;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x1f, max: 0xf, field: Ipv4HeaderLength}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
        //dscp
        match test_write(&{
            let mut value = base();
            value.differentiated_services_code_point = 0x40;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x40, max: 0x3f, field: Ipv4Dscp}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
        //ecn
        match test_write(&{
            let mut value = base();
            value.explicit_congestion_notification = 0x4;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x4, max: 0x3, field: Ipv4Ecn}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
        //fragmentation offset
        match test_write(&{
            let mut value = base();
            value.fragments_offset = 0x2000;
            value
        }) {
            Err(ValueU16TooLarge{value: 0x2000, max: 0x1FFF, field: Ipv4FragmentsOffset}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
    }
    #[test]
    fn read_ipv4_error_header() {
        use super::*;
        let buffer: [u8;20] = [0;20];
        let mut cursor = io::Cursor::new(&buffer);
        let result = cursor.read_ipv4_header();
        match result {
            Err(ReadError::Ipv4UnexpectedVersion(0)) => {},
            _ => assert!(false, format!("Expected ipv 4 version error but received {:?}", result))
        }
    } 
    #[test]
    fn readwrite_ipv6_header() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        buffer.write_ipv6_header(&input).unwrap();
        //deserialize
        let result = {
            let mut cursor = Cursor::new(&buffer);
            cursor.read_ipv6_header().unwrap()
        };
        //check equivalence
        assert_eq!(input, result);
    }
    #[test]
    fn write_ipv6_header_errors() {
        use super::*;
        use super::WriteError::*;
        use super::ErrorField::*;
        fn base() -> Ipv6Header {
            Ipv6Header {
                traffic_class: 1,
                flow_label: 0x201806,
                payload_length: 0x8021,
                next_header: 30,
                hop_limit: 40,
                source: [1, 2, 3, 4, 5, 6, 7, 8,
                         9,10,11,12,13,14,15,16],
                destination: [21,22,23,24,25,26,27,28,
                              29,30,31,32,33,34,35,36]
            }
        };

        fn test_write(input: &Ipv6Header) -> Result<(), WriteError> {
            let mut buffer: Vec<u8> = Vec::with_capacity(20);
            buffer.write_ipv6_header(input)
        };
        //flow label
        match test_write(&{
            let mut value = base();
            value.flow_label = 0x100000;
            value
        }) {
            Err(ValueU32TooLarge{value: 0x100000, max: 0xFFFFF, field: Ipv6FlowLabel}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
    }
    #[test]
    fn read_ipv6_error_header() {
        use super::*;
        let buffer: [u8;20] = [0;20];
        let mut cursor = io::Cursor::new(&buffer);
        let result = cursor.read_ipv6_header();
        match result {
            Err(ReadError::Ipv6UnexpectedVersion(0)) => {},
            _ => assert!(false, format!("Expected ipv 6 version error but received {:?}", result))
        }
    }
    #[test]
    fn skip_ipv6_header_extension() {
        use super::*;
        use std::io::Cursor;
        {
            let buffer: [u8; 8] = [0;8];
            let mut cursor = Cursor::new(&buffer);
            match cursor.skip_ipv6_header_extension() {
                Ok(0) => {},
                value => assert!(false, format!("Expected Ok(0) but received {:?}", value))
            }
            assert_eq!(8, cursor.position());
        }
        {
            let buffer: [u8; 8*3] = [
                4,2,0,0, 0,0,0,0,
                0,0,0,0, 0,0,0,0,
                0,0,0,0, 0,0,0,0,
            ];
            let mut cursor = Cursor::new(&buffer);
            match cursor.skip_ipv6_header_extension() {
                Ok(4) => {},
                value => assert!(false, format!("Expected Ok(4) but received {:?}", value))
            }
            assert_eq!(8*3, cursor.position());
        }
    }
}
