use crate::*;
use core::slice::from_raw_parts;

/// Deprecated use [IpAuthHeaderSlice] instead.
#[deprecated(
    since = "0.14.0",
    note = "Please use the type IpAuthHeaderSlice instead"
)]
pub type IpAuthenticationHeaderSlice<'a> = IpAuthHeaderSlice<'a>;

/// A slice containing an IP Authentication Header (rfc4302)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpAuthHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IpAuthHeaderSlice<'a> {
    /// Creates a ip authentication header slice from a slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<IpAuthHeaderSlice<'a>, err::ip_auth::HeaderSliceError> {
        use err::ip_auth::{HeaderError::*, HeaderSliceError::*};

        // check slice length
        if slice.len() < IpAuthHeader::LEN_MIN {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: IpAuthHeader::LEN_MIN,
                actual_len: slice.len(),
                layer: err::Layer::IpAuthHeader,
            }));
        }

        // SAFETY:
        // Safe the slice length gets checked to be at least 12 beforehand.
        let payload_len_enc = unsafe { *slice.get_unchecked(1) };

        // check header length minimum size
        if payload_len_enc < 1 {
            return Err(Content(ZeroPayloadLen));
        }

        // check length
        // note: The unit is different then all other ipv6 extension headers.
        //       In the other headers the lenth is in 8 octets, but for authentication
        //       headers the length is in 4 octets.
        let len = ((payload_len_enc as usize) + 2) * 4;
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: len,
                actual_len: slice.len(),
                layer: err::Layer::IpAuthHeader,
            }));
        }

        // all good
        Ok(IpAuthHeaderSlice {
            // SAFETY:
            // Safe as slice len is checked to be at last len above.
            slice: unsafe { from_raw_parts(slice.as_ptr(), len) },
        })
    }

    /// Creates a ip authentication header slice from a slice (assumes slice size & content was validated before).
    ///
    /// # Safety
    ///
    /// This method assumes that the slice was previously validated to contain
    /// a valid authentification header. This means the slice length must at
    /// least be at least 8 and `(slice[1] + 2)*4`. The data that the
    /// slice points must also be valid (meaning no nullptr or alike allowed).
    ///
    /// If these precondtions are not fullfilled the behavior of this function
    /// and the methods of the return IpAuthHeaderSlice will be undefined.
    pub unsafe fn from_slice_unchecked(slice: &'a [u8]) -> IpAuthHeaderSlice<'a> {
        IpAuthHeaderSlice {
            slice: from_raw_parts(slice.as_ptr(), ((*slice.get_unchecked(1) as usize) + 2) * 4),
        }
    }

    /// Returns the slice containing the authentification header.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the IP protocol number of the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definition of the known values.
    #[inline]
    pub fn next_header(&self) -> u8 {
        // SAFETY:
        // Safe as slice length is checked in the constructor
        // to be at least 12.
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Read the security parameters index from the slice
    #[inline]
    pub fn spi(&self) -> u32 {
        // SAFETY:
        // Safe as slice length is checked in the constructor
        // to be at least 12.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(4)) }
    }

    /// This unsigned 32-bit field contains a counter value that
    /// increases by one for each packet sent.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        // SAFETY:
        // Safe as slice length is checked in the constructor
        // to be at least 12.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(8)) }
    }

    /// Return a slice with the raw integrity check value
    pub fn raw_icv(&self) -> &'a [u8] {
        &self.slice[12..]
    }

    /// Decode some of the fields and copy the results to a
    /// Ipv6ExtensionHeader struct together with a slice pointing
    /// to the non decoded parts.
    pub fn to_header(&self) -> IpAuthHeader {
        IpAuthHeader::new(
            self.next_header(),
            self.spi(),
            self.sequence_number(),
            self.raw_icv(),
        )
        .unwrap()
    }
}
