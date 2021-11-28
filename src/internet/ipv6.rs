use super::super::*;

use std::net::Ipv6Addr;
use std::slice::from_raw_parts;

///IPv6 header according to rfc8200.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    ///If non 0 serves as a hint to router and switches with multiple outbound paths that these packets should stay on the same path, so that they will not be reordered.
    pub flow_label: u32,
    ///The length of the payload and extension headers in bytes (0 in case of jumbo payloads).
    pub payload_length: u16,
    /// IP protocol number specifying the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definitions of ids.
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

    /// Renamed to `Ipv6Header::from_slice`
    #[deprecated(
        since = "0.10.0",
        note = "Renamed to `Ipv6Header::from_slice`"
    )]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv6Header, &[u8]), ReadError> {
        Ipv6Header::from_slice(slice)
    }

    /// Read an Ipv6Header from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Ipv6Header, &[u8]), ReadError> {
        Ok((
            Ipv6HeaderSlice::from_slice(slice)?.to_header(), 
            &slice[Ipv6Header::SERIALIZED_SIZE..]
        ))
    }

    ///Reads an IPv6 header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv6Header, ReadError> {
        let mut value : [u8;1] = [0;1];
        reader.read_exact(&mut value)?;
        let version = value[0] >> 4;
        if 6 != version {
            return Err(ReadError::Ipv6UnexpectedVersion(version));
        }
        match Ipv6Header::read_without_version(reader, value[0] & 0xf) {
            Ok(value) => Ok(value),
            Err(err) => Err(ReadError::IoError(err))
        }
    }

    ///Reads an IPv6 header assuming the version & flow_label field have already been read.
    pub fn read_without_version<T: io::Read + io::Seek + Sized>(reader: &mut T, version_rest: u8) -> Result<Ipv6Header, io::Error> {

        let mut buffer : [u8;8+32-1] = [0;8+32-1];
        reader.read_exact(&mut buffer[..])?;

        Ok(Ipv6Header{
            traffic_class: (version_rest << 4) | (buffer[0] >> 4),
            flow_label: u32::from_be_bytes([0, buffer[0] & 0xf, buffer[1], buffer[2]]),
            payload_length: u16::from_be_bytes([buffer[3], buffer[4]]),
            next_header: buffer[5],
            hop_limit: buffer[6],
            source: [
                buffer[7],  buffer[8],  buffer[9],  buffer[10],
                buffer[11], buffer[12], buffer[13], buffer[14],
                buffer[15], buffer[16], buffer[17], buffer[18],
                buffer[19], buffer[20], buffer[21], buffer[22],
            ],
            destination: [
                buffer[23], buffer[24], buffer[25], buffer[26],
                buffer[27], buffer[28], buffer[29], buffer[30],
                buffer[31], buffer[32], buffer[33], buffer[34],
                buffer[35], buffer[36], buffer[37], buffer[38],
            ]
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
        matches!(ip_protocol_number, IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_FRAG | AUTH | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6)
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
            IPV6_FRAG => {
                let mut buf = [0; 1];
                reader.read_exact(&mut buf)?;
                (buf[0], 7)
            },
            AUTH => {
                let mut buf = [0; 2];
                reader.read_exact(&mut buf)?;
                (buf[0], i64::from(buf[1])*4 + 6)
            },
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => {
                let mut buf = [0; 2];
                reader.read_exact(&mut buf)?;
                (buf[0],i64::from(buf[1])*8 + 6)
            },
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
        {
            let mut buf = [0; 1];
            reader.read_exact(&mut buf)?;
        }
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
                            field
                        }
                    )
                )
            }
        }

        // check value ranges
        max_check_u32(self.flow_label, 0xfffff, Ipv6FlowLabel)?;

        // serialize header
        let flow_label_be = self.flow_label.to_be_bytes();
        let payload_len_be = self.payload_length.to_be_bytes();

        let header_raw = [
            (6 << 4) | (self.traffic_class >> 4), 
            (self.traffic_class << 4) | flow_label_be[1],
            flow_label_be[2],
            flow_label_be[3],

            payload_len_be[0],
            payload_len_be[1],
            self.next_header,
            self.hop_limit,

            self.source[0], self.source[1], self.source[2], self.source[3],
            self.source[4], self.source[5], self.source[6], self.source[7],
            self.source[8], self.source[9], self.source[10], self.source[11],
            self.source[12], self.source[13], self.source[14], self.source[15],

            self.destination[0], self.destination[1], self.destination[2], self.destination[3],
            self.destination[4], self.destination[5], self.destination[6], self.destination[7],
            self.destination[8], self.destination[9], self.destination[10], self.destination[11],
            self.destination[12], self.destination[13], self.destination[14], self.destination[15],
        ];
        writer.write_all(&header_raw)?;

        Ok(())
    }

    /// Length of the serialized header in bytes.
    ///
    /// The function always returns the constant Ipv6Header::SERIALIZED_SIZE
    /// and exists to keep the methods consistent with other headers. 
    #[inline]
    pub fn header_len(&self) -> usize {
        Ipv6Header::SERIALIZED_SIZE
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

    /// Creates a slice containing an ipv6 header (without header extensions).
    pub fn from_slice(slice: &'a[u8]) -> Result<Ipv6HeaderSlice<'a>, ReadError> {

        // check length
        use crate::ReadError::*;
        if slice.len() < Ipv6Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Ipv6Header::SERIALIZED_SIZE));
        }

        // read version & ihl
        //
        // SAFETY:
        // This is safe as the slice len is checked to be
        // at least 40 bytes at the start of the function.
        let version = unsafe {
            slice.get_unchecked(0) >> 4
        };

        // check version
        if 6 != version {
            return Err(Ipv6UnexpectedVersion(version));
        }

        // all good
        Ok(Ipv6HeaderSlice {
            // SAFETY:
            // This is safe as the slice length is checked to be
            // at least Ipv6Header::SERIALIZED_SIZE (40)
            // at the start of the function.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    Ipv6Header::SERIALIZED_SIZE
                )
            }
        })
    }

    ///Returns the slice containing the ipv6 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the "version" field from the slice (should be 6).
    #[inline]
    pub fn version(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            *self.slice.get_unchecked(0) >> 4
        }
    }

    ///Read the "traffic class" field from the slice.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            (self.slice.get_unchecked(0) << 4) | 
            (self.slice.get_unchecked(1) >> 4)
        }
    }

    ///Read the "flow label" field from the slice.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        u32::from_be_bytes(
            // SAFETY:
            // Safe as the slice length is set to
            // Ipv6Header::SERIALIZED_SIZE (40) during construction
            // of the struct.
            unsafe {
                [
                    0,
                    *self.slice.get_unchecked(1) & 0xf,
                    *self.slice.get_unchecked(2),
                    *self.slice.get_unchecked(3)
                ]
            }
        )
    }

    ///Read the "payload length" field from  the slice. The length should contain the length of all extension headers and payload.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(4))
        }
    }

    /// Read the "next header" field from the slice.
    ///
    /// The next header value specifies what the next header or transport
    /// layer protocol is (see [IpNumber] or [ip_number] for a definitions of ids).
    #[inline]
    pub fn next_header(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            *self.slice.get_unchecked(6)
        }
    }

    ///Read the "hop limit" field from the slice. The hop limit specifies the number of hops the packet can take before it is discarded.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            *self.slice.get_unchecked(7)
        }
    }

    ///Returns a slice containing the IPv6 source address.
    #[inline]
    pub fn source(&self) -> [u8;16] {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            get_unchecked_16_byte_array(self.slice.as_ptr().add(8))
        }
    }

    ///Return the ipv6 source address as an std::net::Ipv6Addr
    pub fn source_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.source())
    }

    ///Returns a slice containing the IPv6 destination address.
    #[inline]
    pub fn destination(&self) -> [u8;16] {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::SERIALIZED_SIZE (40) during construction
        // of the struct.
        unsafe {
            get_unchecked_16_byte_array(self.slice.as_ptr().add(24))
        }
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
