use super::super::*;

use std::net::Ipv6Addr;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

///IPv6 header according to rfc8200.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    ///If non 0 serves as a hint to router and switches with multiple outbound paths that these packets should stay on the same path, so that they will not be reordered.
    pub flow_label: u32,
    ///The length of the payload and extension headers in bytes (0 in case of jumbo payloads).
    pub payload_length: u16,
    ///Specifies what the next header or transport layer protocol is (see IpTrafficClass for a definitions of ids).
    pub next_header: u8,
    ///The number of hops the packet can take before it is discarded.
    pub hop_limit: u8,
    ///IPv6 source address
    pub source: [u8;16],
    ///IPv6 destination address
    pub destination: [u8;16]
}

impl SerializedSize for Ipv6Header {
    ///Size of the header itself in bytes.
    const SERIALIZED_SIZE:usize = 40;
}

impl Ipv6Header {

    ///Read an Ipv6Header from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv6Header, &[u8]), ReadError> {
        Ok((
            Ipv6HeaderSlice::from_slice(slice)?.to_header(), 
            &slice[Ipv6Header::SERIALIZED_SIZE..]
        ))
    }

    ///Reads an IPv6 header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv6Header, ReadError> {
        let value = reader.read_u8()?;
        let version = value >> 4;
        if 6 != version {
            return Err(ReadError::Ipv6UnexpectedVersion(version));
        }
        match Ipv6Header::read_without_version(reader, value & 0xf) {
            Ok(value) => Ok(value),
            Err(err) => Err(ReadError::IoError(err))
        }
    }

    ///Reads an IPv6 header assuming the version & flow_label field have already been read.
    pub fn read_without_version<T: io::Read + io::Seek + Sized>(reader: &mut T, version_rest: u8) -> Result<Ipv6Header, io::Error> {
        let (traffic_class, flow_label) = {
            //read 4 bytes
            let mut buffer: [u8; 4] = [0;4];
            reader.read_exact(&mut buffer[1..])?;

            //extract class
            let traffic_class = (version_rest << 4) | (buffer[1] >> 4);

            //remove traffic class from buffer & read flow_label
            buffer[1] &= 0xf;
            (traffic_class, byteorder::BigEndian::read_u32(&buffer))
        };
        
        Ok(Ipv6Header{
            traffic_class,
            flow_label,
            payload_length: reader.read_u16::<BigEndian>()?,
            next_header: reader.read_u8()?,
            hop_limit: reader.read_u8()?,
            source: {
                let mut buffer: [u8; 16] = [0;16];
                reader.read_exact(&mut buffer)?;
                buffer
            },
            destination: {
                let mut buffer: [u8; 16] = [0;16];
                reader.read_exact(&mut buffer)?;
                buffer
            }
        })
    }

    ///Takes a slice and skips an ipv6 header extensions and returns the next_header ip number & the slice past the header.
    pub fn skip_header_extension_in_slice(slice: &[u8], next_header: u8) -> Result<(u8, &[u8]), ReadError> {
        use crate::ip_number::*;

        if slice.len() >= 2 {
            //determine the length
            let len = match next_header {
                IPV6_FRAG => 8,
                AUTH => (usize::from(slice[1]) + 2)*4,
                IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => {
                    (usize::from(slice[1]) + 1)*8
                },
                // not a ipv6 header extension that can be skipped
                _ => return Ok((next_header, slice))
            };

            if slice.len() < len {
                Err(ReadError::UnexpectedEndOfSlice(len))
            } else {
                Ok((slice[0], &slice[len..]))
            }
        } else {
            Err(ReadError::UnexpectedEndOfSlice(2))
        }
    }

    /// Returns true if the given ip protocol number is a skippable header extension.
    ///
    /// A skippable header extension is an extension header for which it is known how 
    /// to determine the protocol number of the following header as well as how many 
    /// octets have to be skipped to reach the start of the following header.
    pub fn is_skippable_header_extension(ip_protocol_number: u8) -> bool {
        use crate::ip_number::*;
        //Note: EncapsulatingSecurityPayload & ExperimentalAndTesting0 can not be skipped
        match ip_protocol_number {
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_FRAG | AUTH | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => true,
            _ => false
        }
    }

    ///Takes a slice & ip protocol number (identifying the first header type) and returns next_header id & the slice past after all ipv6 header extensions.
    pub fn skip_all_header_extensions_in_slice(slice: &[u8], next_header: u8) -> Result<(u8, &[u8]), ReadError> {

        let mut next_header = next_header;
        let mut rest = slice;
        
        for _i in 0..IPV6_MAX_NUM_HEADER_EXTENSIONS {

            let (n_id, n_rest) = Ipv6Header::skip_header_extension_in_slice(rest, next_header)?;

            if n_rest.len() == rest.len() {
                return Ok((next_header, rest))
            } else {
                next_header = n_id;
                rest = n_rest;
            }
        }

        // final check
        if Ipv6Header::is_skippable_header_extension(next_header) {
            Err(ReadError::Ipv6TooManyHeaderExtensions)
        } else {
            Ok((next_header, rest))
        }
    }

    ///Skips the ipv6 header extension and returns the next ip protocol number
    pub fn skip_header_extension<T: io::Read + io::Seek + Sized>(reader: &mut T, next_header: u8) -> Result<u8, io::Error> {
        use crate::ip_number::*;

        let (next_header, rest_length) = match next_header {
            IPV6_FRAG => (reader.read_u8()?, 7),
            AUTH => (
                reader.read_u8()?,
                i64::from(reader.read_u8()?)*4 + 6
            ),
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => (
                reader.read_u8()?,
                i64::from(reader.read_u8()?)*8 + 6
            ),
            // not a ipv6 header extension that can be skipped
            _ => return Ok(next_header)
        };

        //Sadly seek does not return an error if the seek could not be fullfilled.
        //Some implementations do not even truncate the returned position to the
        //last valid one. std::io::Cursor for example just moves the position
        //over the border of the given slice (e.g. returns position 15 even when
        //the given slice contains only 1 element).
        //The only option, to detect that we are in an invalid state, is to move the
        //seek offset to one byte before the end and then execute a normal read to
        //trigger an error.
        reader.seek(io::SeekFrom::Current(rest_length - 1))?;
        reader.read_u8()?;
        Ok(next_header)
    }

    ///Skips all ipv6 header extensions and returns the next ip protocol number
    pub fn skip_all_header_extensions<T: io::Read + io::Seek + Sized>(reader: &mut T, next_header: u8) -> Result<u8, ReadError> {

        let mut next_header = next_header;

        for _i in 0..IPV6_MAX_NUM_HEADER_EXTENSIONS {
            if Ipv6Header::is_skippable_header_extension(next_header)
            {
                next_header = Ipv6Header::skip_header_extension(reader, next_header)?;
            } else {
                return Ok(next_header);
            }
        }

        //final check
        if Ipv6Header::is_skippable_header_extension(next_header) {
            Err(ReadError::Ipv6TooManyHeaderExtensions)
        } else {
            Ok(next_header)
        }
    }

    ///Writes a given IPv6 header to the current position.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::ErrorField::*;
        fn max_check_u32(value: u32, max: u32, field: ErrorField) -> Result<(), WriteError> {
            if value <= max {
                Ok(())
            } else {
                Err(
                    WriteError::ValueError(
                        ValueError::U32TooLarge{
                            value, 
                            max, 
                            field }))
            }
        }

        //version & traffic class p0
        writer.write_u8((6 << 4) | (self.traffic_class >> 4))?;

        //flow label
        max_check_u32(self.flow_label, 0xfffff, Ipv6FlowLabel)?;
        {
            //write as a u32 to a buffer and write only the "lower bytes"
            let mut buffer: [u8; 4] = [0;4];
            byteorder::BigEndian::write_u32(&mut buffer, self.flow_label);
            //add the traffic_class
            buffer[1] |= self.traffic_class << 4;
            //skip "highest" byte of big endian
            writer.write_all(&buffer[1..])?;
        }

        //rest
        writer.write_u16::<BigEndian>(self.payload_length)?;
        writer.write_u8(self.next_header)?;
        writer.write_u8(self.hop_limit)?;
        writer.write_all(&self.source)?;
        writer.write_all(&self.destination)?;

        Ok(())
    }

    ///Sets the field total_length based on the size of the payload and the options. Returns an error if the payload is too big to fit.
    pub fn set_payload_length(&mut self, size: usize) -> Result<(), ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = std::u16::MAX as usize;
        if MAX_PAYLOAD_LENGTH < size {
            return Err(ValueError::Ipv6PayloadLengthTooLarge(size));
        }

        self.payload_length = size as u16;
        Ok(())
    }
}

///A slice containing an ipv6 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Ipv6HeaderSlice<'a, > {

    ///Creates a slice containing an ipv6 header (without header extensions).
    pub fn from_slice(slice: &'a[u8]) -> Result<Ipv6HeaderSlice<'a>, ReadError> {

        //check length
        use crate::ReadError::*;
        if slice.len() < Ipv6Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Ipv6Header::SERIALIZED_SIZE));
        }

        //read version & ihl
        let version = slice[0] >> 4;

        //check version
        if 6 != version {
            return Err(Ipv6UnexpectedVersion(version));
        }

        //all good
        Ok(Ipv6HeaderSlice {
            slice: &slice[..Ipv6Header::SERIALIZED_SIZE]
        })
    }

    ///Returns the slice containing the ipv6 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the "version" field from the slice (should be 6).
    pub fn version(&self) -> u8 {
        self.slice[0] >> 4
    }

    ///Read the "traffic class" field from the slice.
    pub fn traffic_class(&self) -> u8 {
        (self.slice[0] << 4) | (self.slice[1] >> 4)
    }

    ///Read the "flow label" field from the slice.
    pub fn flow_label(&self) -> u32 {
        byteorder::BigEndian::read_u32(&[0, self.slice[1] & 0xf, self.slice[2], self.slice[3]])
    }

    ///Read the "payload length" field from  the slice. The length should contain the length of all extension headers and payload.
    pub fn payload_length(&self) -> u16 {
        byteorder::BigEndian::read_u16(&self.slice[4..6])
    }

    ///Read the "next header" field from the slice. The next header value specifies what the next header or transport layer protocol is (see IpTrafficClass for a definitions of ids).
    pub fn next_header(&self) -> u8 {
        self.slice[6]
    }

    ///Read the "hop limit" field from the slice. The hop limit specifies the number of hops the packet can take before it is discarded.
    pub fn hop_limit(&self) -> u8 {
        self.slice[7]
    }

    ///Returns a slice containing the IPv6 source address.
    pub fn source(&self) -> [u8;16] {
        let s = &self.slice[8..8+16];
        [ s[ 0], s[ 1], s[ 2], s[ 3],
          s[ 4], s[ 5], s[ 6], s[ 7],
          s[ 8], s[ 9], s[10], s[11],
          s[12], s[13], s[14], s[15] ]
    }

    ///Return the ipv6 source address as an std::net::Ipv6Addr
    pub fn source_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.source())
    }

    ///Returns a slice containing the IPv6 destination address.
    pub fn destination(&self) -> [u8;16] {
        let d = &self.slice[24..24+16];
        [ d[ 0], d[ 1], d[ 2], d[ 3],
          d[ 4], d[ 5], d[ 6], d[ 7],
          d[ 8], d[ 9], d[10], d[11],
          d[12], d[13], d[14], d[15] ]
    }

    ///Return the ipv6 destination address as an std::net::Ipv6Addr
    pub fn destination_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.destination())
    }

    ///Decode all the fields and copy the results to a Ipv6Header struct
    pub fn to_header(&self) -> Ipv6Header {
        Ipv6Header {
            traffic_class: self.traffic_class(),
            flow_label: self.flow_label(),
            payload_length: self.payload_length(),
            next_header: self.next_header(),
            hop_limit: self.hop_limit(),
            source: self.source(),
            destination: self.destination()
        }
    }
}
