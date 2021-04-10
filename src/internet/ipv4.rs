use super::super::*;

use std::net::Ipv4Addr;
use std::fmt::{Debug, Formatter};

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

///IPv4 header without options.
#[derive(Clone)]
pub struct Ipv4Header {
    pub differentiated_services_code_point: u8,
    pub explicit_congestion_notification: u8,
    ///Length of the payload of the ipv4 packet in bytes (does not contain the options).
    ///
    ///This field does not directly exist in an ipv4 header but instead is decoded from
    /// & encoded to the total_size field together with the options length (using the ihl).
    ///If the total_length field in a ipv4 header is smaller then 
    pub payload_len: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragments_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: [u8;4],
    pub destination: [u8;4],
    ///Length of the options in the options_buffer in bytes.
    options_len: u8,
    options_buffer: [u8;40]
}

impl SerializedSize for Ipv4Header {
    ///Size of the header itself (without options) in bytes.
    const SERIALIZED_SIZE:usize = 20;
}

const IPV4_MAX_OPTIONS_LENGTH: usize = 10*4;

impl Ipv4Header {
    ///Constructs an Ipv4Header with standard values for non specified values.
    pub fn new(payload_len: u16, time_to_live: u8, protocol: IpNumber, source: [u8;4], destination: [u8;4]) -> Ipv4Header {
        Ipv4Header {
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            payload_len,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live,
            protocol: protocol as u8,
            header_checksum: 0,
            source,
            destination,
            options_len: 0,
            options_buffer: [0;40]
        }
    }

    ///Length of the header in 4 bytes (often also called IHL - Internet Header Lenght). 
    ///
    ///The minimum allowed length of a header is 5 (= 20 bytes) and the maximum length is 15 (= 60 bytes).
    pub fn ihl(&self) -> u8 {
        (self.options_len/4) + 5
    }

    ///Returns a slice to the options part of the header (empty if no options are present).
    pub fn options(&self) -> &[u8] {
        &self.options_buffer[..usize::from(self.options_len)]
    }

    ///Length of the header (includes options) in bytes.
    pub fn header_len(&self) -> usize {
        Ipv4Header::SERIALIZED_SIZE + usize::from(self.options_len)
    }

    ///Returns the total length of the header + payload in bytes.
    pub fn total_len(&self) -> u16 {
        self.payload_len + (Ipv4Header::SERIALIZED_SIZE as u16) + u16::from(self.options_len)
    }

    ///Sets the payload length if the value is not too big. Otherwise an error is returned.
    pub fn set_payload_len(&mut self, value: usize) -> Result<(), ValueError> {
        if usize::from(self.max_payload_len()) < value {
            use crate::ValueError::*;
            Err(Ipv4PayloadLengthTooLarge(value))
        } else {
            self.payload_len = value as u16;
            Ok(())
        }
    }

    ///Returns the maximum payload size based on the current options size.
    pub fn max_payload_len(&self) -> u16 {
        std::u16::MAX - u16::from(self.options_len) - (Ipv4Header::SERIALIZED_SIZE as u16)
    }

    ///Sets the options & header_length based on the provided length.
    ///The length of the given slice must be a multiple of 4 and maximum 40 bytes.
    ///If the length is not fullfilling these constraints, no data is set and
    ///an error is returned.
    pub fn set_options(&mut self, data: &[u8]) -> Result<(), ValueError> {
        use crate::ValueError::*;

        //check that the options length is within bounds
        if (IPV4_MAX_OPTIONS_LENGTH < data.len()) ||
           (0 != data.len() % 4)
        {
            Err(Ipv4OptionsLengthBad(data.len()))
        } else {
            //copy the data to the buffer
            self.options_buffer[..data.len()].copy_from_slice(data);

            //set the header length
            self.options_len = data.len() as u8;
            Ok(())
        }
    }

    ///Read an Ipv4Header from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv4Header, &[u8]), ReadError> {
        let header = Ipv4HeaderSlice::from_slice(slice)?.to_header();
        let rest = &slice[header.header_len()..];
        Ok((
            header,
            rest
        ))
    }

    ///Reads an IPv4 header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv4Header, ReadError> {
        let value = reader.read_u8()?;
        let version = value >> 4;
        if 4 != version {
            return Err(ReadError::Ipv4UnexpectedVersion(version));
        }
        Ipv4Header::read_without_version(reader, value & 0xf)
    }

    ///Reads an IPv4 header assuming the version & ihl field have already been read.
    pub fn read_without_version<T: io::Read + io::Seek + Sized>(reader: &mut T, version_rest: u8) -> Result<Ipv4Header, ReadError> {
        let ihl = version_rest;
        if ihl < 5 {
            use crate::ReadError::*;
            return Err(Ipv4HeaderLengthBad(ihl));
        }
        let (dscp, ecn) = {
            let value = reader.read_u8()?;
            (value >> 2, value & 0x3)
        };
        let header_length = u16::from(ihl)*4;
        let total_length = reader.read_u16::<BigEndian>()?;
        if total_length < header_length {
            use crate::ReadError::*;
            return Err(Ipv4TotalLengthTooSmall(total_length));
        }
        let identification = reader.read_u16::<BigEndian>()?;
        let (dont_fragment, more_fragments, fragments_offset) = {
            let mut values: [u8; 2] = [0;2];
            reader.read_exact(&mut values)?;
            (
                0 != (values[0] & 0b0100_0000),
                0 != (values[0] & 0b0010_0000),
                u16::from_be_bytes(
                    [values[0] & 0b0001_1111, values[1]]
                )
            )
        };
        Ok(Ipv4Header{
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            payload_len: total_length - header_length,
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
            options_len: (ihl - 5)*4,
            options_buffer: {
                let mut values: [u8;40] = [0;40];
                
                let options_len = usize::from(ihl - 5)*4;
                if options_len > 0 {
                    reader.read_exact(&mut values[..options_len])?;
                }
                values
            },
        })
    }

    ///Checks if the values in this header are valid values for an ipv4 header.
    ///
    ///Specifically it will be checked, that:
    /// * payload_len + options_len is not too big to be encoded in the total_size header field
    /// * differentiated_services_code_point is not greater then 0x3f
    /// * explicit_congestion_notification is not greater then 0x3
    /// * fragments_offset is not greater then 0x1fff
    pub fn check_ranges(&self) -> Result<(), ValueError> {
        use crate::ErrorField::*;
        
        //check ranges
        max_check_u8(self.differentiated_services_code_point, 0x3f, Ipv4Dscp)?;
        max_check_u8(self.explicit_congestion_notification, 0x3, Ipv4Ecn)?;
        max_check_u16(self.fragments_offset, 0x1fff, Ipv4FragmentsOffset)?;
        max_check_u16(self.payload_len, self.max_payload_len(), Ipv4PayloadLength)?;

        Ok(())
    }

    ///Writes a given IPv4 header to the current position (this method automatically calculates the header length and checksum).
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        //check ranges
        self.check_ranges()?;

        //write with recalculations
        self.write_ipv4_header_internal(writer, self.calc_header_checksum_unchecked())
    }

    ///Writes a given IPv4 header to the current position (this method just writes the specified checksum and does note compute it).
    pub fn write_raw<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        //check ranges
        self.check_ranges()?;

        //write
        self.write_ipv4_header_internal(writer, self.header_checksum)
    }

    ///Write the given header with the  checksum and header length specified in the seperate arguments
    fn write_ipv4_header_internal<T: io::Write>(&self, write: &mut T, header_checksum: u16) -> Result<(), WriteError> {
        //version & header_length
        write.write_u8((4 << 4) | self.ihl())?;

        //dscp & ecn        
        write.write_u8((self.differentiated_services_code_point << 2) | self.explicit_congestion_notification)?;

        //total length & id 
        write.write_u16::<BigEndian>(self.total_len())?;
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
        write.write_all(&self.options())?;

        //done
        Ok(())
    }

    ///Calculate header checksum of the current ipv4 header.
    pub fn calc_header_checksum(&self) -> Result<u16, ValueError> {

        //check ranges
        self.check_ranges()?;

        //calculate the checksum
        Ok(self.calc_header_checksum_unchecked())
    }

    ///Calculate the header checksum under the assumtion that all value ranges in the header are correct
    fn calc_header_checksum_unchecked(&self) -> u16 {
        //version & header_length
        let mut sum: u32 = [
            BigEndian::read_u16(&[ (4 << 4) | self.ihl(),
                                (self.differentiated_services_code_point << 2) | self.explicit_congestion_notification ]),
            self.total_len(),
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
        ].iter().map(|x| u32::from(*x)).sum();
        let options = self.options();
        for i in 0..(options.len()/2) {
            sum += u32::from( BigEndian::read_u16(&options[i*2..i*2 + 2]) );
        }

        let carry_add = (sum & 0xffff) + (sum >> 16);
        !( ((carry_add & 0xffff) + (carry_add >> 16)) as u16 )
    }
}

//NOTE: I would have prefered to NOT write my own Default, Debug & PartialEq implementation but there are no
//      default implementations availible for [u8;40] and the alternative of using [u32;10] would lead
//      to unsafe casting. Writing impl Debug for [u8;40] in a crate is also illegal as it could lead 
//      to an implementation collision between crates.
//      So the only option left to me was to write an implementation myself and deal with the added complexity
//      and potential added error source.

impl Default for Ipv4Header {
    fn default() -> Ipv4Header {
        Ipv4Header {
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            payload_len: 0,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live: 0,
            protocol: 0,
            header_checksum: 0,
            source: [0;4],
            destination: [0;4],
            options_len: 0,
            options_buffer: [0;40]
        }
    }
}

impl Debug for Ipv4Header {
    fn fmt(&self, fotmatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(fotmatter, "Ipv4Header {{ ihl: {}, differentiated_services_code_point: {}, explicit_congestion_notification: {}, payload_len: {}, identification: {}, dont_fragment: {}, more_fragments: {}, fragments_offset: {}, time_to_live: {}, protocol: {}, header_checksum: {}, source: {:?}, destination: {:?}, options: {:?} }}", 
            self.ihl(),
            self.differentiated_services_code_point,
            self.explicit_congestion_notification,
            self.payload_len,
            self.identification,
            self.dont_fragment,
            self.more_fragments,
            self.fragments_offset,
            self.time_to_live,
            self.protocol,
            self.header_checksum,
            self.source,
            self.destination,
            self.options())
    }
}

impl std::cmp::PartialEq for Ipv4Header {
    fn eq(&self, other: &Ipv4Header) -> bool {
        self.differentiated_services_code_point == other.differentiated_services_code_point &&
        self.explicit_congestion_notification == other.explicit_congestion_notification &&
        self.payload_len == other.payload_len &&
        self.identification == other.identification &&
        self.dont_fragment == other.dont_fragment &&
        self.more_fragments == other.more_fragments &&
        self.fragments_offset == other.fragments_offset &&
        self.time_to_live == other.time_to_live &&
        self.protocol == other.protocol &&
        self.header_checksum == other.header_checksum &&
        self.source == other.source &&
        self.destination == other.destination &&
        self.options_len == other.options_len &&
        self.options() == other.options()
    }
}

impl std::cmp::Eq for Ipv4Header {}

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
        let header_length = (usize::from(ihl))*4;
        if slice.len() < header_length {
            return Err(UnexpectedEndOfSlice(header_length));
        }

        //check the total_length can contain the header
        let total_length = BigEndian::read_u16(&slice[2..4]);
        if total_length < header_length as u16 {
            return Err(Ipv4TotalLengthTooSmall(total_length))
        }

        //all good
        Ok(Ipv4HeaderSlice {
            slice: &slice[..header_length]
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
    pub fn total_len(&self) -> u16 {
        BigEndian::read_u16(&self.slice[2..4])
    }

    ///Determine the payload length based on the ihl & total_length field of the header.
    pub fn payload_len(&self) -> u16 {
        self.total_len() - u16::from(self.ihl())*4
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
    pub fn source(&self) -> [u8;4] {
        let s = &self.slice[12..16];
        [s[0], s[1], s[2], s[3]]
    }

    ///Return the ipv4 source address as an std::net::Ipv4Addr
    pub fn source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.source())
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn destination(&self) -> [u8;4] {
        let d = &self.slice[16..20];
        [d[0], d[1], d[2], d[3]]
    }

    ///Return the ipv4 destination address as an std::net::Ipv4Addr
    pub fn destination_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.destination())
    }

    ///Returns a slice containing the ipv4 header options (empty when there are no options).
    pub fn options(&self) -> &'a [u8] {
        &self.slice[20..]
    }

    ///Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ipv4Header {
        let options = self.options();
        Ipv4Header {
            differentiated_services_code_point: self.dcp(),
            explicit_congestion_notification: self.ecn(),
            payload_len: self.payload_len(),
            identification: self.identification(),
            dont_fragment: self.dont_fragment(),
            more_fragments: self.more_fragments(),
            fragments_offset: self.fragments_offset(),
            time_to_live: self.ttl(),
            protocol: self.protocol(),
            header_checksum: self.header_checksum(),
            source: self.source(),
            destination: self.destination(),
            options_len: options.len() as u8,
            options_buffer: {
                let mut result: [u8;40] = [0;40];
                result[..options.len()].copy_from_slice(options);
                result
            }
        }
    }
}
