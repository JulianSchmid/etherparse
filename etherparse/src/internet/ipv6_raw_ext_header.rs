use super::super::*;

use std::fmt::{Debug, Formatter};
use std::slice::from_raw_parts;

/// Raw IPv6 extension header (undecoded payload).
///
/// IPv6 extension header with only minimal data interpretation. NOTE only ipv6 header
/// extensions with the first two bytes representing the next header and the header length
/// in 8-octets (- 8 octets) can be represented with this struct. This excludes the "Authentication
/// Header" (AH) and "Encapsulating Security Payload" (ESP).
///
/// The following headers can be represented in a `Ipv6RawExtensionHeader`:
/// * Hop by Hop
/// * Destination Options
/// * Routing
/// * Mobility
/// * Host Identity Protocol
/// * Shim6 Protocol
#[derive(Clone)]
pub struct Ipv6RawExtensionHeader {
    /// IP protocol number specifying the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definition of the known values.
    pub next_header: u8,
    /// Length of the extension header in 8 octets (minus the first 8 octets).
    header_length: u8,
    //// The data contained in the extension header (excluding next_header & hdr length).
    payload_buffer: [u8; 0xff * 8 + 6],
}

impl Debug for Ipv6RawExtensionHeader {
    fn fmt(&self, fotmatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            fotmatter,
            "Ipv6RawExtensionHeader {{ next_header: {}, payload: {:?} }}",
            self.next_header,
            self.payload()
        )
    }
}

impl PartialEq for Ipv6RawExtensionHeader {
    fn eq(&self, other: &Self) -> bool {
        self.next_header == other.next_header && self.payload() == other.payload()
    }
}

impl Eq for Ipv6RawExtensionHeader {}

impl Ipv6RawExtensionHeader {
    /// Minimum length of an raw IPv6 extension header in bytes/octets.
    pub const MIN_LEN: usize = 8;

    /// Maximum length of an raw IPv6 extension header in bytes/octets.
    ///
    /// This number is calculated by multiplying the maximum "hdr ext len"
    /// (0xff) with 8 and adding 8. As RFC8200 states that "hdr ext len" is
    /// defined as "8-bit unsigned integer. Length of the Hop-by-Hop Options
    /// header in 8-octet units, not including the first 8 octets."
    pub const MAX_LEN: usize = 8 + (8 * 0xff);

    /// Minimum length of a [Ipv6RawExtensionHeader] payload
    pub const MIN_PAYLOAD_LEN: usize = 6;

    /// Maximum length of a [Ipv6RawExtensionHeader] the payload
    pub const MAX_PAYLOAD_LEN: usize = 0xff * 8 + 6;

    /// Returns true if the given header type ip number can be represented in an `Ipv6ExtensionHeader`.
    pub fn header_type_supported(next_header: u8) -> bool {
        use crate::ip_number::*;
        matches!(
            next_header,
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6
        )
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
    /// The maximum length of the payload is `2046` bytes (`Ipv6RawExtensionHeader::MAX_PAYLOAD_LEN`).
    ///
    /// If a payload with a non supported length is provided a `ValueError` is returned.
    pub fn new_raw(next_header: u8, payload: &[u8]) -> Result<Ipv6RawExtensionHeader, ValueError> {
        use ValueError::*;
        if payload.len() < Self::MIN_PAYLOAD_LEN {
            Err(Ipv6ExtensionPayloadTooSmall(payload.len()))
        } else if payload.len() > Self::MAX_PAYLOAD_LEN {
            Err(Ipv6ExtensionPayloadTooLarge(payload.len()))
        } else if 0 != (payload.len() + 2) % 8 {
            Err(Ipv6ExtensionPayloadLengthUnaligned(payload.len()))
        } else {
            let mut result = Ipv6RawExtensionHeader {
                next_header,
                header_length: ((payload.len() - 6) / 8) as u8,
                payload_buffer: [0; Self::MAX_PAYLOAD_LEN],
            };
            result.payload_buffer[..payload.len()].copy_from_slice(payload);
            Ok(result)
        }
    }

    /// Read an Ipv6ExtensionHeader from a slice and return the header & unused parts of the slice.
    pub fn from_slice(slice: &[u8]) -> Result<(Ipv6RawExtensionHeader, &[u8]), ReadError> {
        let s = Ipv6RawExtensionHeaderSlice::from_slice(slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((header, rest))
    }

    /// Return a slice containing the current payload. This does NOT contain
    /// the `next_header` and `header_length` fields. But everything after these
    /// two fields.
    pub fn payload(&self) -> &[u8] {
        &self.payload_buffer[..(6 + usize::from(self.header_length) * 8)]
    }

    /// Sets the payload (content of the header after the `next_header` & `header_length` fields).
    ///
    /// Note that `payload` must have at least the length of 6 bytes and only supports
    /// length increases in steps of 8. This measn that the following expression must be true `(payload.len() + 2) % 8 == 0`.
    /// The maximum length of the payload is `2046` bytes (`Ipv6RawExtensionHeader::MAX_PAYLOAD_LEN`).
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
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<Ipv6RawExtensionHeader, ReadError> {
        let (next_header, header_length) = {
            let mut d: [u8; 2] = [0; 2];
            reader.read_exact(&mut d)?;
            (d[0], d[1])
        };

        Ok(Ipv6RawExtensionHeader {
            next_header,
            header_length,
            payload_buffer: {
                let mut buffer = [0; 0xff * 8 + 6];
                reader.read_exact(&mut buffer[..usize::from(header_length) * 8 + 6])?;
                buffer
            },
        })
    }

    /// Writes a given IPv6 extension header to the current position.
    pub fn write<W: io::Write + Sized>(&self, writer: &mut W) -> Result<(), WriteError> {
        writer.write_all(&[self.next_header, self.header_length])?;
        writer.write_all(self.payload())?;
        Ok(())
    }

    /// Length of the header in bytes.
    pub fn header_len(&self) -> usize {
        2 + (6 + usize::from(self.header_length) * 8)
    }
}
