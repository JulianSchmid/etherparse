use crate::*;
use std::slice::from_raw_parts;

///A slice containing an ethernet 2 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ethernet2HeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Ethernet2HeaderSlice<'a> {
    /// Creates a ethernet slice from an other slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<Ethernet2HeaderSlice<'a>, err::UnexpectedEndOfSliceError> {
        //check length
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            return Err(err::UnexpectedEndOfSliceError {
                expected_min_len: Ethernet2Header::SERIALIZED_SIZE,
                actual_len: slice.len(),
                layer: err::Layer::Ethernet2Header,
            });
        }

        //all done
        Ok(Ethernet2HeaderSlice {
            // SAFETY:
            // Safe as slice length is checked to be at least
            // Ethernet2Header::SERIALIZED_SIZE (14) before this.
            slice: unsafe { from_raw_parts(slice.as_ptr(), Ethernet2Header::SERIALIZED_SIZE) },
        })
    }

    /// Converts the given slice into a ethernet 2 header slice WITHOUT any
    /// checks to ensure that the data present is an ethernet 2 header or that the
    /// slice length is matching the header length.
    ///
    /// If you are not sure what this means, use [`Ethernet2HeaderSlice::from_slice`]
    /// instead.
    ///
    /// # Safety
    ///
    /// The caller must ensured that the given slice has the length of
    /// [`Ethernet2Header::SERIALIZED_SIZE`]
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &[u8]) -> Ethernet2HeaderSlice {
        Ethernet2HeaderSlice { slice }
    }

    /// Returns the slice containing the ethernet 2 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the destination mac address
    #[inline]
    pub fn destination(&self) -> [u8; 6] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe { get_unchecked_6_byte_array(self.slice.as_ptr()) }
    }

    /// Read the source mac address
    #[inline]
    pub fn source(&self) -> [u8; 6] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe { get_unchecked_6_byte_array(self.slice.as_ptr().add(6)) }
    }

    /// Read the ether_type field of the header (in system native byte order).
    #[inline]
    pub fn ether_type(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Ethernet2Header::SERIALIZED_SIZE (14).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(12)) }
    }

    /// Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> Ethernet2Header {
        Ethernet2Header {
            source: self.source(),
            destination: self.destination(),
            ether_type: self.ether_type(),
        }
    }
}
