use super::super::*;

extern crate byteorder;
use self::byteorder::{WriteBytesExt, ReadBytesExt};
use std::fmt::{Debug, Formatter};

///Maximum number of header extensions allowed (according to the ipv6 rfc8200, & iana protocol numbers).
pub const IPV6_MAX_NUM_HEADER_EXTENSIONS: usize = 12;

/// IPv6 extension header with only minimal data interpretation. NOTE only ipv6 header
/// extensions with the first two bytes representing the next header and the header length
/// in 8-octets (- 8 octets) can be represented with this struct. This excludes the "Authentication 
/// Header" (AH) and "Encapsulating Security Payload" (ESP).
///
/// The following headers can be represented in a `Ipv6GenericExtensionHeader`:
/// * Hop by Hop
/// * Destination Options
/// * Routing 
/// * Mobility
/// * Host Identity Protocol
/// * Shim6 Protocol
#[derive(Clone)]
pub struct Ipv6GenericExtensionHeader {
    /// Internet protocol number of the content after this header
    pub next_header: u8,
    /// Length of the extension header in 8 octets (minus the first 8 octets).
    header_length: u8,
    //// The data contained in the extension header (excluding next_header & hdr length).
    payload_buffer: [u8;0xff * 8 + 6],
}

impl Debug for Ipv6GenericExtensionHeader {
    fn fmt(&self, fotmatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(fotmatter, "Ipv6GenericExtensionHeader {{ next_header: {}, payload: {:?} }}", 
            self.next_header,
            self.payload())
    }
}

impl PartialEq for Ipv6GenericExtensionHeader {
    fn eq(&self, other: &Self) -> bool {
        self.next_header == other.next_header &&
        self.payload() == other.payload()
    }
}

impl Eq for Ipv6GenericExtensionHeader {}

impl Ipv6GenericExtensionHeader {

    /// Minimum length of the payload
    const MIN_PAYLOAD_LEN: usize = 6;

    /// Maximum length of the payload
    const MAX_PAYLOAD_LEN: usize = 0xff*8 + 6;

    /// Returns true if the given header type ip number can be represented in an `Ipv6ExtensionHeader`.
    pub fn header_type_supported(next_header: u8) -> bool {
        use crate::ip_number::*;
        match next_header {
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => true,
            _ => false
        }
    }

    /// Creates an generic IPv6 extension header with the given data.
    ///
    /// # Arguments
    ///
    /// * `next_header` - type of content after this header (protocol number)
    /// * `payload` - slice containing the data of the header. This must NOT contain the `next header` and `extended header length` fields of the header.
    ///
    /// Note that `payload` must have at least the length of 6 bytes and only supports
    /// length increases in steps of 8. This measn that the following expression must be true `(payload.len() + 2) % 8 == 0`.
    /// The maximum length of the payload is `2046` bytes (`Ipv6GenericExtensionHeader::MAX_PAYLOAD_LEN`).
    ///
    /// If a payload with a non supported length is provided a `ValueError` is returned.
    pub fn new_raw(next_header: u8, payload: &[u8]) -> Result<Ipv6GenericExtensionHeader, ValueError> {
        use ValueError::*;
        if payload.len() < Self::MIN_PAYLOAD_LEN {
            Err(Ipv6ExtensionPayloadTooSmall(payload.len()))
        } else if payload.len() > Self::MAX_PAYLOAD_LEN {
            Err(Ipv6ExtensionPayloadTooLarge(payload.len()))
        } else if 0 != (payload.len() + 2) % 8 {
            Err(Ipv6ExtensionPayloadLengthUnaligned(payload.len()))
        } else {
            let mut result = Ipv6GenericExtensionHeader {
                next_header,
                header_length: ((payload.len() - 6) / 8) as u8,
                payload_buffer: [0;Self::MAX_PAYLOAD_LEN]
            };
            result.payload_buffer[..payload.len()].copy_from_slice(payload);
            Ok(result)
        }
    }

    /// Read an Ipv6ExtensionHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv6GenericExtensionHeader, &[u8]), ReadError> {
        let s = Ipv6GenericExtensionHeaderSlice::from_slice(slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((
            header, 
            rest
        ))
    }

    /// Return a slice containing the current payload. This does NOT contain 
    /// the `next_header` and `header_length` fields. But everything after these
    /// two fields.
    pub fn payload(&self) -> &[u8] {
        &self.payload_buffer[..(6 + usize::from(self.header_length)*8)]
    }

    /// Sets the payload (content of the header after the `next_header` & `header_length` fields).
    ///
    /// Note that `payload` must have at least the length of 6 bytes and only supports
    /// length increases in steps of 8. This measn that the following expression must be true `(payload.len() + 2) % 8 == 0`.
    /// The maximum length of the payload is `2046` bytes (`Ipv6GenericExtensionHeader::MAX_PAYLOAD_LEN`).
    ///
    /// If a payload with a non supported length is provided a `ValueError` is returned and the payload of the header is not changed.
    pub fn set_payload(&mut self, payload: &[u8]) -> Result<(), ValueError> {
        use ValueError::*;
        if payload.len() < Self::MIN_PAYLOAD_LEN {
            Err(Ipv6ExtensionPayloadTooSmall(payload.len()))
        } else if payload.len() > Self::MAX_PAYLOAD_LEN {
            Err(Ipv6ExtensionPayloadTooLarge(payload.len()))
        } else if 0 != (payload.len() + 2) % 8 {
            Err(Ipv6ExtensionPayloadLengthUnaligned(payload.len()))
        } else {
            self.payload_buffer[..payload.len()].copy_from_slice(payload);
            self.header_length = ((payload.len() - 6) / 8) as u8;
            Ok(())
        }
    }

    /// Read an fragment header from the current reader position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv6GenericExtensionHeader, ReadError> {
        let next_header = reader.read_u8()?;
        let header_length = reader.read_u8()?;

        Ok(Ipv6GenericExtensionHeader {
            next_header,
            header_length,
            payload_buffer: {
                let mut buffer = [0;0xff * 8 + 6];
                reader.read_exact(&mut buffer[..usize::from(header_length)*8 + 6])?;
                buffer
            },
        })
    }

    /// Writes a given IPv6 extension header to the current position.
    pub fn write<W: io::Write + Sized>(&self, writer: &mut W) -> Result<(), WriteError> {
        writer.write_u8(self.next_header)?;
        writer.write_u8(self.header_length)?;
        writer.write_all(self.payload())?;
        Ok(())
    }

    ///Length of the header in bytes.
    pub fn header_len(&self) -> usize {
        2 + (6 + usize::from(self.header_length)*8)
    }
}

/// Slice containing an IPv6 extension header with only minimal data interpretation. NOTE only ipv6 header
/// extensions with the first two bytes representing the next header and the header length
/// in 8-octets (- 8 octets) can be represented with this struct. This excludes the "Authentication 
/// Header" (AH) and "Encapsulating Security Payload" (ESP).
///
/// The following headers can be represented in a Ipv6ExtensionHeaderSlice:
/// * HopbyHop
/// * Destination Options
/// * Routing 
/// * Mobility
/// * Host Identity Protocol
/// * Shim6 Protocol
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6GenericExtensionHeaderSlice<'a> {
    /// Slice containing the packet data.
    slice: &'a [u8],
}

impl<'a> Ipv6GenericExtensionHeaderSlice<'a> {

    /// Returns true if the given header type ip number can be represented in an `Ipv6ExtensionHeaderSlice`.
    pub fn header_type_supported(next_header: u8) -> bool {
        Ipv6GenericExtensionHeader::header_type_supported(next_header)
    }

    /// Creates a generic ipv6 extension header slice from a slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<Ipv6GenericExtensionHeaderSlice<'a>, ReadError> {

        //check length
        use crate::ReadError::*;
        if slice.len() < 8 {
            return Err(UnexpectedEndOfSlice(8));
        }

        //check length
        let len = ((slice[1] as usize) + 1)*8;

        //check the length again now that the expected length is known
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(len));
        }

        //all good
        Ok(Ipv6GenericExtensionHeaderSlice {
            slice: &slice[..len]
        })
    }

    /// Returns the slice containing the ipv6 extension header
    #[inline]
    pub fn slice(&self) -> &'a[u8] {
        self.slice
    }

    /// Returns the id of the next header (see IpTrafficClass for a definition of all ids).
    pub fn next_header(&self) -> u8 {
        self.slice[0]
    }

    /// Returns a slice containing the payload data of the header.
    /// This contains all the data after the header length field
    /// until the end of the header (length specified by the
    /// hdr ext length field).
    pub fn payload(&self) -> &'a[u8] {
        &self.slice[2..]
    }

    /// Decode some of the fields and copy the results to a 
    /// Ipv6ExtensionHeader struct together with a slice pointing
    /// to the non decoded parts.
    pub fn to_header(&self) -> Ipv6GenericExtensionHeader {
        Ipv6GenericExtensionHeader::new_raw(
            self.next_header(),
            self.payload()
        ).unwrap()
    }
}
