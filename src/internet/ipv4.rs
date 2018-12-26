use super::super::*;

use std::net::Ipv4Addr;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

///IPv4 header without options.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv4Header {
    ///Length of the header in 4 bytes (often also called IHL - Internet Header Lenght). 
    ///
    ///The minimum allowed length of a header is 5 (= 20 bytes) and the maximum length is 15 (= 60 bytes).
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
    pub destination: [u8;4],
}


impl SerializedSize for Ipv4Header {
    ///Size of the header itself (without options) in bytes.
    const SERIALIZED_SIZE:usize = 20;
}

impl Ipv4Header {
    ///Constructs an Ipv4Header with standard values for non specified values.
    ///Note: This header calculates the checksum assuming that there are no ipv4 options. In case there are calculate the checksum using the "calc_header_checksum" method.
    pub fn new(payload_and_options_length: usize, time_to_live: u8, protocol: IpTrafficClass, source: [u8;4], destination: [u8;4]) -> Result<Ipv4Header, ValueError> {
        
        //check that the total length fits into the field
        const MAX_PAYLOAD_AND_OPTIONS_LENGTH: usize = (std::u16::MAX as usize) - Ipv4Header::SERIALIZED_SIZE;
        if MAX_PAYLOAD_AND_OPTIONS_LENGTH < payload_and_options_length {
            return Err(ValueError::Ipv4PayloadAndOptionsLengthTooLarge(payload_and_options_length));
        }

        Ok(Ipv4Header {
            header_length: 0,
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            total_length: (payload_and_options_length + 20) as u16,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live,
            protocol: protocol as u8,
            header_checksum: 0,
            source,
            destination,
        })
    }

    ///Read an Ipv4Header from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv4Header, &[u8]), ReadError> {
        Ok((
            Ipv4HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Ipv4Header::SERIALIZED_SIZE..]
        ))
    }

    ///Reads an IPv4 header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv4Header, ReadError> {
        let value = reader.read_u8()?;
        let version = value >> 4;
        if 4 != version {
            return Err(ReadError::Ipv4UnexpectedVersion(version));
        }
        match Ipv4Header::read_without_version(reader, value & 0xf) {
            Ok(value) => Ok(value),
            Err(err) => Err(ReadError::IoError(err))
        }
    }

    ///Reads an IPv4 header assuming the version & ihl field have already been read.
    pub fn read_without_version<T: io::Read + io::Seek + Sized>(reader: &mut T, version_rest: u8) -> Result<Ipv4Header, io::Error> {
        let ihl = version_rest;
        let (dscp, ecn) = {
            let value = reader.read_u8()?;
            (value >> 2, value & 0x3)
        };
        let total_length = reader.read_u16::<BigEndian>()?;
        let identification = reader.read_u16::<BigEndian>()?;
        let (dont_fragment, more_fragments, fragments_offset) = {
            let mut values: [u8; 2] = [0;2];
            reader.read_exact(&mut values)?;
            (0 != (values[0] & 0x40),
             0 != (values[0] & 0x20),
             {
                let buf = [values[0] & 0x1f, values[1]];
                let mut cursor = io::Cursor::new(&buf);
                cursor.read_u16::<BigEndian>()?
             })
        };
        Ok(Ipv4Header{
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            total_length,
            identification,
            dont_fragment,
            more_fragments,
            fragments_offset,
            time_to_live: reader.read_u8()?,
            protocol: reader.read_u8()?,
            header_checksum: reader.read_u16::<BigEndian>()?,
            source: {
                let mut values: [u8;4] = [0;4];
                reader.read_exact(&mut values)?;
                values
            },
            destination: {
                let mut values: [u8;4] = [0;4];
                reader.read_exact(&mut values)?;
                values
            },
            header_length: ihl
        })
    }

    ///Skips the ipv4 header options based on the header length.
    pub fn skip_options<T: io::Read + io::Seek + Sized>(&self, reader: &mut T) -> Result<(), ReadError> {
        //return an error if the provided header length is too small (smaller then the header itself)
        if self.header_length < 5 {
            use crate::ReadError::*;
            return Err(Ipv4HeaderLengthBad(self.header_length));
        }

        let skip = i64::from(self.header_length - 5)*4;
        if skip > 0 {
            //seek does not return an error, when the end is reached
            //to ensure this still happens an read_exact is added at the end
            //that throws an error
            if skip > 4 {
                use std::io::SeekFrom;
                reader.seek(SeekFrom::Current(skip - 4))?;
            }
            let mut buffer: [u8;4] = [0;4];
            reader.read_exact(&mut buffer)?;
        }
        Ok(())
    }

    ///Writes a given IPv4 header to the current position (this method automatically calculates the header length and checksum).
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T, options: &[u8]) -> Result<(), WriteError> {
        use crate::ErrorField::*;
        
        //check ranges
        max_check_u8(self.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(self.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        max_check_u16(self.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;
        if options.len() > 10*4 || options.len() % 4 != 0 {
            return Err(
                WriteError::ValueError(
                    ValueError::Ipv4OptionsLengthBad(
                        options.len())));
        }

        //write with recalculations
        let header_legnth = 5 + (options.len()/4) as u8;
        self.write_ipv4_header_internal(writer, options, header_legnth, self.calc_header_checksum_unchecked(header_legnth, options))
    }

    ///Writes a given IPv4 header to the current position (this method just writes the specified checksum and header_length and does note compute it).
    pub fn write_raw<T: io::Write + Sized>(&self, writer: &mut T, options: &[u8]) -> Result<(), WriteError> {
        use crate::ErrorField::*;
        
        //check ranges
        max_check_u8(self.header_length, 0xf, Ipv4HeaderLength)?;
        max_check_u8(self.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(self.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        max_check_u16(self.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;
        if options.len() > 10*4 || options.len() % 4 != 0 {
            return Err(
                WriteError::ValueError(
                    ValueError::Ipv4OptionsLengthBad(
                        options.len())));
        }

        //write
        self.write_ipv4_header_internal(writer, options, self.header_length, self.header_checksum)
    }

    ///Write the given header with the  checksum and header length specified in the seperate arguments
    fn write_ipv4_header_internal<T: io::Write>(&self, write: &mut T, options: &[u8], header_length: u8, header_checksum: u16) -> Result<(), WriteError> {
        //version & header_length
        write.write_u8((4 << 4) | header_length)?;

        //dscp & ecn        
        write.write_u8((self.differentiated_services_code_point << 2) | self.explicit_congestion_notification)?;

        //total length & id 
        write.write_u16::<BigEndian>(self.total_length)?;
        write.write_u16::<BigEndian>(self.identification)?;

        //flags & fragmentation offset
        {
            let mut buf: [u8;2] = [0;2];
            BigEndian::write_u16(&mut buf, self.fragments_offset);
            let flags = {
                let mut result = 0;
                if self.dont_fragment {
                    result |= 64;
                }
                if self.more_fragments {
                    result |= 32;
                }
                result
            };
            write.write_u8(
                flags |
                (buf[0] & 0x1f),
            )?;
            write.write_u8(
                buf[1]
            )?;
        }

        //rest
        write.write_u8(self.time_to_live)?;
        write.write_u8(self.protocol)?;
        write.write_u16::<BigEndian>(header_checksum)?;
        write.write_all(&self.source)?;
        write.write_all(&self.destination)?;
        //options
        write.write_all(&options)?;
        Ok(())
    }

    ///Calculate header checksum of the current ipv4 header.
    pub fn calc_header_checksum(&self, options: &[u8]) -> Result<u16, ValueError> {
        use crate::ErrorField::*;
        use crate::ValueError::Ipv4OptionsLengthBad;

        //check ranges
        max_check_u8(self.header_length, 0xf, Ipv4HeaderLength)?;
        max_check_u8(self.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(self.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        max_check_u16(self.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;
        if options.len() > 10*4 || options.len() % 4 != 0 {
            return Err(Ipv4OptionsLengthBad(options.len()));
        }

        //calculate the checksum
        Ok(self.calc_header_checksum_unchecked(self.header_length, options))
    }

    ///Calculate the header checksum under the assumtion that all value ranges in the header are correct
    fn calc_header_checksum_unchecked(&self, header_length: u8, options: &[u8]) -> u16 {
        //version & header_length
        let mut sum: u32 = [
            BigEndian::read_u16(&[ (4 << 4) | header_length,
                                (self.differentiated_services_code_point << 2) | self.explicit_congestion_notification ]),
            self.total_length,
            self.identification,
            //flags & fragmentation offset
            {
                let mut buf: [u8;2] = [0;2];
                BigEndian::write_u16(&mut buf, self.fragments_offset);
                let flags = {
                    let mut result = 0;
                    if self.dont_fragment {
                        result |= 64;
                    }
                    if self.more_fragments {
                        result |= 32;
                    }
                    result
                };
                BigEndian::read_u16(&[flags | (buf[0] & 0x1f), buf[1]])
            },
            BigEndian::read_u16(&[self.time_to_live, self.protocol]),
            //skip checksum (for obvious reasons)
            BigEndian::read_u16(&self.source[0..2]),
            BigEndian::read_u16(&self.source[2..4]),
            BigEndian::read_u16(&self.destination[0..2]),
            BigEndian::read_u16(&self.destination[2..4])
        ].into_iter().map(|x| u32::from(*x)).sum();
        for i in 0..(options.len()/2) {
            sum += u32::from( BigEndian::read_u16(&options[i*2..i*2 + 2]) );
        }

        let carry_add = (sum & 0xffff) + (sum >> 16);
        !( ((carry_add & 0xffff) + (carry_add >> 16)) as u16 )
    }

    ///Sets the field total_length based on the size of the payload and the options. Returns an error if the payload is too big to fit.
    pub fn set_payload_and_options_length(&mut self, size: usize) -> Result<(), ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_AND_OPTIONS_LENGTH: usize = (std::u16::MAX as usize) - Ipv4Header::SERIALIZED_SIZE;
        if MAX_PAYLOAD_AND_OPTIONS_LENGTH < size {
            return Err(ValueError::Ipv4PayloadAndOptionsLengthTooLarge(size));
        }

        self.total_length = (size + Ipv4Header::SERIALIZED_SIZE) as u16;
        Ok(())
    }
}

///A slice containing an ipv4 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Ipv4HeaderSlice<'a> {

    ///Creates a slice containing an ipv4 header (including header options).
    pub fn from_slice(slice: &'a[u8]) -> Result<Ipv4HeaderSlice<'a>, ReadError> {

        //check length
        use crate::ReadError::*;
        if slice.len() < Ipv4Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Ipv4Header::SERIALIZED_SIZE));
        }

        //read version & ihl
        let (version, ihl) = {
            let value = slice[0];
            (value >> 4, value & 0xf)
        };

        //check version
        if 4 != version {
            return Err(Ipv4UnexpectedVersion(version));
        }

        //check that the ihl is correct
        if ihl < 5 {
            use crate::ReadError::*;
            return Err(Ipv4HeaderLengthBad(ihl));
        }

        //check that the slice contains enough data for the entire header + options
        let total_length = (ihl as usize)*4;
        if slice.len() < total_length {
            return Err(UnexpectedEndOfSlice(total_length));
        }

        //all good
        Ok(Ipv4HeaderSlice {
            slice: &slice[..total_length]
        })
    }

    ///Returns the slice containing the ipv4 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the "version" field of the IPv4 header (should be 4).
    pub fn version(&self) -> u8 {
        self.slice[0] >> 4
    }

    ///Read the "ip header length" (length of the ipv4 header + options in multiples of 4 bytes).
    pub fn ihl(&self) -> u8 {
        self.slice[0] & 0xf
    }

    ///Read the "differentiated_services_code_point" from the slice.
    pub fn dcp(&self) -> u8 {
        self.slice[1] >> 2
    }

    ///Read the "explicit_congestion_notification" from the slice.
    pub fn ecn(&self) -> u8 {
        self.slice[1] & 0x3
    }

    ///Read the "total length" from the slice (total length of ip header + payload).
    pub fn total_length(&self) -> u16 {
        BigEndian::read_u16(&self.slice[2..4])
    }

    ///Read the "identification" field from the slice.
    pub fn identification(&self) -> u16 {
        BigEndian::read_u16(&self.slice[4..6])
    }

    ///Read the "dont fragment" flag from the slice.
    pub fn dont_fragment(&self) -> bool {
        0 != (self.slice[6] & 0x40)
    }

    ///Read the "more fragments" flag from the slice.
    pub fn more_fragments(&self) -> bool {
        0 != (self.slice[6] & 0x20)
    }

    ///Read the "fragment_offset" field from the slice.
    pub fn fragments_offset(&self) -> u16 {
        let buf = [self.slice[6] & 0x1f, self.slice[7]];
        BigEndian::read_u16(&buf[..])
    }

    ///Read the "time_to_live" field from the slice.
    pub fn ttl(&self) -> u8 {
        self.slice[8]
    }

    ///Read the "protocol" field from the slice.
    pub fn protocol(&self) -> u8 {
        self.slice[9]
    }

    ///Read the "header checksum" field from the slice.
    pub fn header_checksum(&self) -> u16 {
        BigEndian::read_u16(&self.slice[10..12])
    }
    
    ///Returns a slice containing the ipv4 source address.
    pub fn source(&self) -> &'a [u8] {
        &self.slice[12..16]
    }

    ///Return the ipv4 source address as an std::net::Ipv4Addr
    pub fn source_addr(&self) -> Ipv4Addr {
        let mut result: [u8; 4] = Default::default();
        result.copy_from_slice(self.source());
        Ipv4Addr::from(result)
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn destination(&self) -> &'a [u8] {
        &self.slice[16..20]
    }

    ///Return the ipv4 destination address as an std::net::Ipv4Addr
    pub fn destination_addr(&self) -> Ipv4Addr {
        let mut result: [u8; 4] = Default::default();
        result.copy_from_slice(self.destination());
        Ipv4Addr::from(result)
    }

    ///Returns a slice containing the ipv4 header options (empty when there are no options).
    pub fn options(&self) -> &'a [u8] {
        &self.slice[20..]
    }

    ///Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ipv4Header {
        Ipv4Header {
            header_length: self.ihl(),
            differentiated_services_code_point: self.dcp(),
            explicit_congestion_notification: self.ecn(),
            total_length: self.total_length(),
            identification: self.identification(),
            dont_fragment: self.dont_fragment(),
            more_fragments: self.more_fragments(),
            fragments_offset: self.fragments_offset(),
            time_to_live: self.ttl(),
            protocol: self.protocol(),
            header_checksum: self.header_checksum(),
            source: {
                let mut result: [u8; 4] = Default::default();
                result.copy_from_slice(self.source());
                result
            },
            destination: {
                let mut result: [u8; 4] = Default::default();
                result.copy_from_slice(self.destination());
                result
            },
        }
    }
}
