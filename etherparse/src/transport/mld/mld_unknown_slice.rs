use crate::mld::*;

/// Zero-copy slice of the ICMPv6 payload of an MLD message with a type
/// unknown to etherparse.
///
/// See [`UnknownHeader`] for the field layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MldUnknownSlice<'a> {
    /// The ICMPv6 type byte.
    type_u8: u8,
    /// Bytes 4-7 of the ICMPv6 header.
    bytes5to8: [u8; 4],
    /// The ICMPv6 payload.
    slice: &'a [u8],
}

impl<'a> MldUnknownSlice<'a> {
    /// Creates a slice from the ICMPv6 payload.
    ///
    /// Nothing is known about the message, so the payload may be of any
    /// length (including empty).
    #[inline]
    pub(crate) fn new(type_u8: u8, bytes5to8: [u8; 4], slice: &'a [u8]) -> MldUnknownSlice<'a> {
        MldUnknownSlice {
            type_u8,
            bytes5to8,
            slice,
        }
    }

    /// Returns the "type" byte value of the ICMPv6 header.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        self.type_u8
    }

    /// Returns bytes 4-7 of the ICMPv6 header.
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        self.bytes5to8
    }

    /// Decodes the fixed fields into an owned [`UnknownHeader`].
    #[inline]
    pub fn to_header(&self) -> UnknownHeader {
        UnknownHeader {
            mld_type: self.type_u8,
            raw_bytes_4_7: self.bytes5to8,
        }
    }

    /// Returns the complete ICMPv6 payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the slice containing the ICMPv6 payload of the MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
