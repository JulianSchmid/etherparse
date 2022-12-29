use crate::*;
use core::slice::from_raw_parts;

/// Slice containing an IPv6 extension header without specific decoding methods (fallback in case no specific implementation is available).
///
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
pub struct Ipv6RawExtensionHeaderSlice<'a> {
    /// Slice containing the packet data.
    slice: &'a [u8],
}

impl<'a> Ipv6RawExtensionHeaderSlice<'a> {
    /// Returns true if the given header type ip number can be represented in an `Ipv6ExtensionHeaderSlice`.
    pub fn header_type_supported(next_header: u8) -> bool {
        Ipv6RawExtensionHeader::header_type_supported(next_header)
    }

    /// Creates a generic ipv6 extension header slice from a slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<Ipv6RawExtensionHeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < 8 {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: 8,
                actual_len: slice.len(),
                layer: err::Layer::Ipv6ExtHeader,
            }));
        }

        //check length
        let len = ((slice[1] as usize) + 1) * 8;

        //check the length again now that the expected length is known
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: len,
                actual_len: slice.len(),
                layer: err::Layer::Ipv6ExtHeader,
            }));
        }

        //all good
        Ok(Ipv6RawExtensionHeaderSlice {
            // SAFETY:
            // Safe as the slice has been checked in the previous if
            // to have at least the the length of the variable len.
            slice: unsafe { from_raw_parts(slice.as_ptr(), len) },
        })
    }

    /// Creates a raw ipv6 extension header slice from a slice (assumes slice
    /// size & content was validated before).
    ///
    /// # Safety
    ///
    /// This method assumes that the slice was previously validated to contain
    /// a valid & supported raw ipv6 extension header. This means the slice length
    /// must at least be at least 8 and `(slice[1] + 1)*8`. The data that the
    /// slice points must also be valid (meaning no nullptr or alike allowed).
    ///
    /// If these precondtions are not fullfilled the behavior of this function
    /// and the methods of the return [`IpAuthHeaderSlice`] will be undefined.
    pub unsafe fn from_slice_unchecked(slice: &'a [u8]) -> Ipv6RawExtensionHeaderSlice<'a> {
        Ipv6RawExtensionHeaderSlice {
            slice: from_raw_parts(slice.as_ptr(), ((*slice.get_unchecked(1) as usize) + 1) * 8),
        }
    }

    /// Returns the slice containing the ipv6 extension header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the IP protocol number of the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definition of the known values.
    #[inline]
    pub fn next_header(&self) -> u8 {
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns a slice containing the payload data of the header.
    ///
    /// This contains all the data after the header length field
    /// until the end of the header (length specified by the
    /// hdr ext length field).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        unsafe { from_raw_parts(self.slice.as_ptr().add(2), self.slice.len() - 2) }
    }

    /// Convert the slice to an [Ipv6RawExtensionHeader].
    ///
    /// Decode some of the fields and copy the results to a
    /// [Ipv6RawExtensionHeader] struct together with a slice pointing
    /// to the non decoded parts.
    pub fn to_header(&self) -> Ipv6RawExtensionHeader {
        Ipv6RawExtensionHeader::new_raw(self.next_header(), self.payload()).unwrap()
    }
}
