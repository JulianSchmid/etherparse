use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

///Internet protocol headers version 4 & 6
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpHeader {
    Version4(Ipv4Header),
    Version6(Ipv6Header)
}

impl IpHeader {
    ///Reads an IP (v4 or v6) header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<IpHeader, ReadError> {
        let value = reader .read_u8()?;
        match value >> 4 {
            4 => Ok(IpHeader::Version4(Ipv4Header::read_without_version(reader, value & 0xf)?)),
            6 => Ok(IpHeader::Version6(Ipv6Header::read_without_version(reader, value & 0xf)?)),
            version => Err(ReadError::IpUnsupportedVersion(version))
        }
    }
    ///Writes an IP (v4 or v6) header to the current position
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use IpHeader::*;
        match *self {
            Version4(ref value) => value.write(writer, &[]),
            Version6(ref value) => value.write(writer)
        }
    }
}

///IPv4 header without options.
#[derive(Clone, Debug, Eq, PartialEq)]
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
            time_to_live: time_to_live,
            protocol: protocol as u8,
            header_checksum: 0,
            source: source,
            destination: destination
        })
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
            total_length: total_length,
            identification: identification,
            dont_fragment: dont_fragment,
            more_fragments: more_fragments,
            fragments_offset: fragments_offset,
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
            use ReadError::*;
            return Err(Ipv4HeaderLengthBad(self.header_length));
        }

        let skip = ((self.header_length - 5) as i64)*4;
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
        use ErrorField::*;
        
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
        use ErrorField::*;
        
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
                    result = result | 64;
                }
                if self.more_fragments {
                    result = result | 32;
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
        use ErrorField::*;
        use ValueError::Ipv4OptionsLengthBad;

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
        let mut sum = [
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
                        result = result | 64;
                    }
                    if self.more_fragments {
                        result = result | 32;
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
        ].iter().fold(0, |a: u32, x: &u16| a + (*x as u32));
        for i in 0..(options.len()/2) {
            sum += BigEndian::read_u16(&options[i*2..i*2 + 2]) as u32;
        }

        let carry_add = (sum & 0xffff) + (sum >> 16);
        !(((carry_add & 0xffff) + (carry_add >> 16)) as u16)
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

///IPv6 header according to rfc8200.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    ///If non 0 serves as a hint to router and switches with multiple outbound paths that these packets should stay on the same path, so that they will not be reordered.
    pub flow_label: u32,
    ///The length of the payload and extension headers in 
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
            buffer[1] = buffer[1] & 0xf;
            (traffic_class, byteorder::BigEndian::read_u32(&buffer))
        };
        
        Ok(Ipv6Header{
            traffic_class: traffic_class,
            flow_label: flow_label,
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

    ///Skips the ipv6 header extension and returns the traffic_class
    pub fn skip_header_extension<T: io::Read + io::Seek + Sized>(reader: &mut T, traffic_class: u8) -> Result<u8, io::Error> {
        let next_header = reader.read_u8()?;
        //determine the length (fragmentation header has a fixed length & the rest a length field)
        const FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;
        let rest_length = if traffic_class == FRAG {
            //fragmentation header has the fixed length of 64bits (one already read)
            7
        } else {
            //Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
            (((reader.read_u8()? as i64) + 1)*8) - 2
        };
        reader.seek(io::SeekFrom::Current(rest_length))?;
        Ok(next_header)
    }

    ///Skips all ipv6 header extensions and returns the last traffic_class
    pub fn skip_all_header_extensions<T: io::Read + io::Seek + Sized>(reader: &mut T, traffic_class: u8) -> Result<u8, ReadError> {
        use IpTrafficClass::*;
        const HOP_BY_HOP: u8 = IPv6HeaderHopByHop as u8;
        const ROUTE: u8 = IPv6RouteHeader as u8;
        const FRAG: u8 = IPv6FragmentationHeader as u8;
        const OPTIONS: u8 = IPv6DestinationOptions as u8;
        const AUTH: u8 = IPv6AuthenticationHeader as u8;
        const ENCAP_SEC: u8 = IPv6EncapSecurityPayload as u8;

        let mut next_traffic_class = traffic_class;
        for _i in 0..IPV6_MAX_NUM_HEADER_EXTENSIONS {
            match next_traffic_class {
                HOP_BY_HOP | ROUTE | FRAG | OPTIONS | AUTH | ENCAP_SEC => {
                    next_traffic_class = Ipv6Header::skip_header_extension(reader, next_traffic_class)?;
                },
                _ => return Ok(next_traffic_class)
            }
        }
        match next_traffic_class {
            HOP_BY_HOP | ROUTE | FRAG | OPTIONS | AUTH | ENCAP_SEC => Err(ReadError::Ipv6TooManyHeaderExtensions),
            value => Ok(value)
        }
    }

    ///Writes a given IPv6 header to the current position.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use ErrorField::*;
        fn max_check_u32(value: u32, max: u32, field: ErrorField) -> Result<(), WriteError> {
            if value <= max {
                Ok(())
            } else {
                Err(
                    WriteError::ValueError(
                        ValueError::U32TooLarge{
                            value: value, 
                            max: max, 
                            field: field }))
            }
        };

        //version & traffic class p0
        writer.write_u8((6 << 4) | (self.traffic_class >> 4))?;

        //flow label
        max_check_u32(self.flow_label, 0xfffff, Ipv6FlowLabel)?;
        {
            //write as a u32 to a buffer and write only the "lower bytes"
            let mut buffer: [u8; 4] = [0;4];
            byteorder::BigEndian::write_u32(&mut buffer, self.flow_label);
            //add the traffic_class
            buffer[1] = buffer[1] | (self.traffic_class << 4);
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

impl<'a> Slice<'a, Ipv4Header> {

    ///Creates a slice containing an ipv4 header (including header options).
    pub fn from_slice(slice: &'a[u8]) -> Result<Slice<'a, Ipv4Header>, ReadError> {

        //check length
        use std::io::ErrorKind::UnexpectedEof;
        use std::io::Error;
        use ReadError::*;
        if slice.len() < Ipv4Header::SERIALIZED_SIZE {
            return Err(IoError(Error::from(UnexpectedEof)));
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
            use ReadError::*;
            return Err(Ipv4HeaderLengthBad(ihl));
        }

        //check that the slice contains enough data for the entire header + options
        let total_length = (ihl as usize)*4;
        if slice.len() < total_length {
            return Err(IoError(Error::from(UnexpectedEof)));
        }

        //all good
        Ok(Slice {
            slice: &slice[..total_length],
            phantom: std::marker::PhantomData{}
        })
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
    pub fn source(&self) -> [u8;4] {
        let mut result: [u8; 4] = Default::default();
        result.copy_from_slice(&self.slice[12..16]);
        result
    }

    ///Returns a slice containing the ipv4 source address.
    pub fn destination(&self) -> [u8;4] {
        let mut result: [u8; 4] = Default::default();
        result.copy_from_slice(&self.slice[16..20]);
        result
    }

    ///Returns a slice containing the ipv4 header options (empty when there are no options).
    pub fn options(&self) -> &'a [u8] {
        &self.slice[20..]
    }
}

impl<'a> Slice<'a, Ipv6Header> {

    ///Creates a slice containing an ipv6 header (without header extensions).
    pub fn from_slice(slice: &'a[u8]) -> Result<Slice<'a, Ipv6Header>, ReadError> {

        //check length
        use std::io::ErrorKind::UnexpectedEof;
        use std::io::Error;
        use ReadError::*;
        if slice.len() < Ipv6Header::SERIALIZED_SIZE {
            return Err(IoError(Error::from(UnexpectedEof)));
        }

        //read version & ihl
        let version = slice[0] >> 4;

        //check version
        if 6 != version {
            return Err(Ipv6UnexpectedVersion(version));
        }

        //all good
        Ok(Slice {
            slice: &slice[..Ipv6Header::SERIALIZED_SIZE],
            phantom: std::marker::PhantomData{}
        })
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
    pub fn source(&self) -> &'a[u8] {
        &self.slice[8..8+16]
    }

    ///Returns a slice containing the IPv6 destination address.
    pub fn destination(&self) -> &'a[u8] {
        &self.slice[24..24+16]
    }
}

///Maximum number of header extensions allowed (according to the ipv6 rfc8200).
pub const IPV6_MAX_NUM_HEADER_EXTENSIONS: usize = 7;

///Dummy struct for ipv6 header extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionHeader {}

impl<'a> Slice<'a, Ipv6ExtensionHeader> {
    ///Creates a slice containing an ipv6 header extension.
    pub fn from_slice(header_type: u8, slice: &'a[u8]) -> Result<Slice<'a, Ipv6ExtensionHeader>, ReadError> {

        //check length
        use std::io::ErrorKind::UnexpectedEof;
        use std::io::Error;
        use ReadError::*;
        if slice.len() < 8 {
            return Err(IoError(Error::from(UnexpectedEof)));
        }

        //check length
        const FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;
        let len = if FRAG == header_type {
            8
        } else {
            ((slice[1] as usize) + 1)*8
        };

        //check the length again now that the expected length is known
        if slice.len() < len {
            return Err(IoError(Error::from(UnexpectedEof)));
        }

        //all good
        Ok(Slice {
            slice: &slice[..len],
            phantom: std::marker::PhantomData{}
        })
    }

    ///Returns the id of the next header (see IpTrafficClass for a definition of all ids).
    pub fn next_header(&self) -> u8 {
        self.slice[0]
    }
}

///Identifiers for the traffic_class field in ipv6 headers and protocol field in ipv4 headers.
#[derive(Debug, PartialEq, Eq)]
pub enum IpTrafficClass {
    ///IPv6 Hop-by-Hop Option [RFC8200]
    IPv6HeaderHopByHop = 0,
    ///Internet Control Message [RFC792]
    Icmp = 1,
    ///Internet Group Management [RFC1112]
    Igmp = 2,
    ///Gateway-to-Gateway [RFC823]
    Ggp = 3,
    ///IPv4 encapsulation [RFC2003]
    IPv4 = 4,
    ///Stream [RFC1190][RFC1819]
    Stream = 5,
    ///Transmission Control [RFC793]
    Tcp = 6,
    ///CBT [Tony_Ballardie]
    Cbt = 7,
    ///Exterior Gateway Protocol [RFC888][David_Mills]
    Egp = 8,
    ///any private interior gateway (used by Cisco for their IGRP) [Internet_Assigned_Numbers_Authority]
    Igp = 9,
    ///BBN RCC Monitoring [Steve_Chipman]
    BbnRccMon = 10,
    ///Network Voice Protocol [RFC741][Steve_Casner]
    NvpII = 11,
    ///PUP
    Pup = 12,
    ///ARGUS (deprecated) [Robert_W_Scheifler]
    Argus = 13,
    ///EMCON [<mystery contact>]
    Emcon = 14,
    ///Cross Net Debugger [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.][Jack_Haverty]
    Xnet = 15,
    ///Chaos [J_Noel_Chiappa]
    Chaos = 16,
    ///User Datagram [RFC768][Jon_Postel]
    Udp = 17,
    ///Multiplexing [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.][Jon_Postel]
    Mux = 18,
    ///DCN Measurement Subsystems [David_Mills]
    DcnMeas = 19,
    ///Host Monitoring [RFC869][Bob_Hinden]
    Hmp = 20,
    ///Packet Radio Measurement [Zaw_Sing_Su]
    Prm = 21,
    ///XEROX NS IDP
    XnsIdp = 22,
    ///Trunk-1 [Barry_Boehm]
    Trunk1 = 23,
    ///Trunk-2 [Barry_Boehm]
    Trunk2 = 24,
    ///Leaf-1 [Barry_Boehm]
    Leaf1 = 25,
    ///Leaf-2 [Barry_Boehm]
    Leaf2 = 26,
    ///Reliable Data Protocol [RFC908][Bob_Hinden]
    Rdp = 27,
    ///Internet Reliable Transaction [RFC938][Trudy_Miller]
    Irtp = 28,
    ///ISO Transport Protocol Class 4 [RFC905][<mystery contact>]
    IsoTp4 = 29,
    ///Bulk Data Transfer Protocol [RFC969][David_Clark]
    NetBlt = 30,
    ///MFE Network Services Protocol [Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.][Barry_Howard]
    MfeNsp = 31,
    ///MERIT Internodal Protocol [Hans_Werner_Braun]
    MeritInp = 32,
    ///Datagram Congestion Control Protocol [RFC4340]
    Dccp = 33,
    ///Third Party Connect Protocol [Stuart_A_Friedberg]
    ThirdPartyConnectProtocol = 34,
    ///Inter-Domain Policy Routing Protocol [Martha_Steenstrup]
    Idpr = 35,
    ///XTP [Greg_Chesson]
    Xtp = 36,
    ///Datagram Delivery Protocol [Wesley_Craig]
    Ddp = 37,
    ///IDPR Control Message Transport Proto [Martha_Steenstrup]
    IdprCmtp = 38,
    ///TP++ Transport Protocol [Dirk_Fromhein]
    TpPlusPlus = 39,
    ///IL Transport Protocol [Dave_Presotto]
    Il = 40,
    ///IPv6 encapsulation [RFC2473]
    Ipv6 = 41,
    ///Source Demand Routing Protocol [Deborah_Estrin]
    Sdrp = 42,
    ///Routing Header for IPv6 [Steve_Deering]
    IPv6RouteHeader = 43,
    ///Fragment Header for IPv6 [Steve_Deering]
    IPv6FragmentationHeader = 44,
    ///Inter-Domain Routing Protocol [Sue_Hares]
    Idrp = 45,
    ///Reservation Protocol [RFC2205][RFC3209][Bob_Braden]
    Rsvp = 46,
    ///Generic Routing Encapsulation [RFC2784][Tony_Li]
    Gre = 47,
    ///Dynamic Source Routing Protocol [RFC4728]
    Dsr = 48,
    ///BNA [Gary Salamon]
    Bna = 49,
    ///Encap Security Payload [RFC4303]
    IPv6EncapSecurityPayload = 50,
    ///Authentication Header [RFC4302]
    IPv6AuthenticationHeader = 51,
    ///Integrated Net Layer Security  TUBA [K_Robert_Glenn]
    Inlsp = 52,
    ///IP with Encryption (deprecated) [John_Ioannidis]
    Swipe = 53,
    ///NBMA Address Resolution Protocol [RFC1735]
    Narp = 54,
    ///IP Mobility [Charlie_Perkins]
    Mobile = 55,
    ///Transport Layer Security Protocol using Kryptonet key management [Christer_Oberg]
    Tlsp = 56,
    ///SKIP [Tom_Markson]
    Skip = 57,
    ///ICMP for IPv6 [RFC8200]
    IPv6Icmp = 58,
    ///No Next Header for IPv6 [RFC8200]
    IPv6NoNextHeader = 59,
    ///Destination Options for IPv6 [RFC8200]
    IPv6DestinationOptions = 60,
    ///any host internal protocol [Internet_Assigned_Numbers_Authority]
    AnyHostInternalProtocol = 61,
    ///CFTP [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.][Harry_Forsdick]
    Cftp = 62,
    ///any local network [Internet_Assigned_Numbers_Authority]
    AnyLocalNetwork = 63,
    ///SATNET and Backroom EXPAK [Steven_Blumenthal]
    SatExpak = 64,
    ///Kryptolan [Paul Liu]
    Krytolan = 65,
    ///MIT Remote Virtual Disk Protocol [Michael_Greenwald]
    Rvd = 66,
    ///Internet Pluribus Packet Core [Steven_Blumenthal]
    Ippc = 67,
    ///any distributed file system [Internet_Assigned_Numbers_Authority]
    AnyDistributedFileSystem = 68,
    ///SATNET Monitoring [Steven_Blumenthal]
    SatMon = 69,
    ///VISA Protocol [Gene_Tsudik]
    Visa = 70,
    ///Internet Packet Core Utility [Steven_Blumenthal]
    Ipcv = 71,
    ///Computer Protocol Network Executive [David Mittnacht]
    Cpnx = 72,
    ///Computer Protocol Heart Beat [David Mittnacht]
    Cphb = 73,
    ///Wang Span Network [Victor Dafoulas]
    Wsn = 74,
    ///Packet Video Protocol [Steve_Casner]
    Pvp = 75,
    ///Backroom SATNET Monitoring [Steven_Blumenthal]
    BrSatMon = 76,
    ///SUN ND PROTOCOL-Temporary [William_Melohn]
    SunNd = 77,
    ///WIDEBAND Monitoring [Steven_Blumenthal]
    WbMon = 78,
    ///WIDEBAND EXPAK [Steven_Blumenthal]
    WbExpak = 79,
    ///ISO Internet Protocol [Marshall_T_Rose]
    IsoIp = 80,
    ///VMTP [Dave_Cheriton]
    Vmtp = 81,
    ///SECURE-VMTP [Dave_Cheriton]
    SecureVmtp = 82,
    ///VINES [Brian Horn]
    Vines = 83,
    ///Transaction Transport Protocol or Internet Protocol Traffic Manager [Jim_Stevens]
    TtpOrIptm = 84,
    ///NSFNET-IGP [Hans_Werner_Braun]
    NsfnetIgp = 85,
    ///Dissimilar Gateway Protocol [M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.][Mike_Little]
    Dgp = 86,
    ///TCF [Guillermo_A_Loyola]
    Tcf = 87,
    ///EIGRP [RFC7868]
    Eigrp = 88,
    ///OSPFIGP [RFC1583][RFC2328][RFC5340][John_Moy]
    Ospfigp = 89,
    ///Sprite RPC Protocol [Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.][Bruce Willins]
    SpriteRpc = 90,
    ///Locus Address Resolution Protocol [Brian Horn]
    Larp = 91,
    ///Multicast Transport Protocol [Susie_Armstrong]
    Mtp = 92,
    ///AX.25 Frames [Brian_Kantor]
    Ax25 = 93,
    ///IP-within-IP Encapsulation Protocol [John_Ioannidis]
    Ipip = 94,
    ///Mobile Internetworking Control Pro. (deprecated) [John_Ioannidis]
    Micp = 95,
    ///Semaphore Communications Sec. Pro. [Howard_Hart]
    SccSp = 96,
    ///Ethernet-within-IP Encapsulation [RFC3378]
    EtherIp = 97,
    ///Encapsulation Header [RFC1241][Robert_Woodburn]
    Encap = 98,
    ///GMTP [[RXB5]]
    Gmtp = 100,
    ///Ipsilon Flow Management Protocol [Bob_Hinden][November 1995, 1997.]
    Ifmp = 101,
    ///PNNI over IP [Ross_Callon]
    Pnni = 102,
    ///Protocol Independent Multicast [RFC7761][Dino_Farinacci]
    Pim = 103,
    ///ARIS [Nancy_Feldman]
    Aris = 104,
    ///SCPS [Robert_Durst]
    Scps = 105,
    ///QNX [Michael_Hunter]
    Qnx = 106,
    ///Active Networks [Bob_Braden]
    ActiveNetworks = 107,
    ///IP Payload Compression Protocol [RFC2393]
    IpComp = 108,
    ///Sitara Networks Protocol [Manickam_R_Sridhar]
    SitraNetworksProtocol = 109,
    ///Compaq Peer Protocol [Victor_Volpe]
    CompaqPeer = 110,
    ///IPX in IP [CJ_Lee]
    IpxInIp = 111,
    ///Virtual Router Redundancy Protocol [RFC5798]
    Vrrp = 112,
    ///PGM Reliable Transport Protocol [Tony_Speakman]
    Pgm = 113,
    ///any 0-hop protocol [Internet_Assigned_Numbers_Authority]
    AnyZeroHopProtocol = 114,
    ///Layer Two Tunneling Protocol [RFC3931][Bernard_Aboba]
    Layer2TunnelingProtocol = 115,
    ///D-II Data Exchange (DDX) [John_Worley]
    Ddx = 116,
    ///Interactive Agent Transfer Protocol [John_Murphy]
    Iatp = 117,
    ///Schedule Transfer Protocol [Jean_Michel_Pittet]
    Stp = 118,
    ///SpectraLink Radio Protocol [Mark_Hamilton]
    Srp = 119,
    ///UTI [Peter_Lothberg]
    Uti = 120,
    ///Simple Message Protocol [Leif_Ekblad]
    SimpleMessageProtocol = 121,
    ///Simple Multicast Protocol (deprecated) [Jon_Crowcroft][draft-perlman-simple-multicast]
    Sm = 122,
    ///Performance Transparency Protocol [Michael_Welzl]
    Ptp = 123,
    ///ISIS over IPv4 [Tony_Przygienda]
    IsisOverIpv4 = 124,
    ///FIRE [Criag_Partridge]
    Fire = 125,
    ///Combat Radio Transport Protocol [Robert_Sautter]
    Crtp = 126,
    ///Combat Radio User Datagram [Robert_Sautter]
    Crudp = 127,
    ///SSCOPMCE [Kurt_Waber]
    Sscopmce = 128,
    ///IPLT [[Hollbach]]
    Iplt = 129,
    ///Secure Packet Shield [Bill_McIntosh]
    Sps = 130,
    ///Private IP Encapsulation within IP [Bernhard_Petri]
    Pipe = 131,
    ///Stream Control Transmission Protocol [Randall_R_Stewart]
    Sctp = 132,
    ///Fibre Channel [Murali_Rajagopal][RFC6172]
    Fc = 133,
    ///RSVP-E2E-IGNORE [RFC3175]
    RsvpE2eIgnore = 134,
    ///MobilityHeader [RFC6275]
    MobilityHeader = 135,
    ///UDPLite [RFC3828]
    UdpLite = 136,
    /// [RFC4023]
    MplsInIp = 137,
    ///MANET Protocols [RFC5498]
    Manet = 138,
    ///Host Identity Protocol [RFC7401]
    Hip = 139,
    ///Shim6 Protocol [RFC5533]
    Shim6 = 140,
    ///Wrapped Encapsulating Security Payload [RFC5840]
    Wesp = 141,
    ///Robust Header Compression [RFC5858]
    Rohc = 142
}
