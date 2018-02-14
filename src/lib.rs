extern crate byteorder;

use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

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

#[derive(Debug, PartialEq)]
pub struct Ethernet2Header {
    pub destination: [u8;6],
    pub source: [u8;6],
    pub ether_type: u16
}

#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    pub version: u8,
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
    //note options are skipped
}

///Error when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(io::Error),
    ValueU8TooLarge{value: u8, max: u8, field: ErrorField},
    ValueU16TooLarge{value: u16, max: u16, field: ErrorField}
}

impl From<io::Error> for WriteError {
    fn from(err: io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

///Fields that can produce errors when serialized
#[derive(Debug)]
pub enum ErrorField {
    Ipv4Version,
    Ipv4HeaderLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset
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
        max_check_u8(value.version, 0xf, Ipv4Version)?;
        max_check_u8(value.header_length, 0xf, Ipv4HeaderLength)?;
        self.write_u8(value.version | (value.header_length << 4))?;

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
}

impl<W: io::Write + ?Sized> WriteEtherExt for W {}

pub trait ReadEtherExt: io::Read {
    fn read_ethernet2_header(&mut self) -> Result<Ethernet2Header, io::Error> {
        Ok(Ethernet2Header {
            destination: self.read_mac_address()?,
            source: self.read_mac_address()?,
            ether_type: self.read_u16::<BigEndian>()?
        })
    }

    fn read_ipv4_header(&mut self) -> Result<Ipv4Header, io::Error> {
        let (version, ihl) = {
            let value = self.read_u8()?;
            //println!("sup {} => {}", value, (value >> 4));
            (value & 0xf, (value >> 4))
        };
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
            version: version,
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

    fn read_mac_address(&mut self) -> Result<[u8;6], io::Error> {
        let mut result: [u8;6] = [0;6];
        self.read_exact(&mut result)?;
        Ok(result)
    }
}

impl<W: io::Read + ?Sized> ReadEtherExt for W {}

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
    fn readwrite_ipv4_header() {
        use super::*;
        use std::io::Cursor;

        let input = Ipv4Header {
            version: 4,
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
                version: 4,
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
        //version
        match test_write(&{
            let mut value = base();
            value.version = 0x1f;
            value
        }) {
            Err(ValueU8TooLarge{value: 0x1f, max: 0xf, field: Ipv4Version}) => {}, //all good
            value => assert!(false, format!("Expected a range error but received {:?}", value))
        }
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
}
