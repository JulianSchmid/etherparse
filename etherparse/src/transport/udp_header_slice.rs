use crate::*;
use core::slice::from_raw_parts;

///A slice containing an udp header of a network package. Struct allows the selective read of fields in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> UdpHeaderSlice<'a> {
    /// Creates a slice containing an udp header.
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<UdpHeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < UdpHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: UdpHeader::SERIALIZED_SIZE,
                actual_len: slice.len(),
                layer: err::Layer::UdpHeader,
            }));
        }

        //done
        Ok(UdpHeaderSlice {
            // SAFETY:
            // Safe as slice length is checked to be at least
            // UdpHeader::SERIALIZED_SIZE (8) before this.
            slice: unsafe { from_raw_parts(slice.as_ptr(), UdpHeader::SERIALIZED_SIZE) },
        })
    }

    /// Returns the slice containing the udp header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Reads the "udp source port" from the slice.
    #[inline]
    pub fn source_port(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr()) }
    }

    /// Reads the "udp destination port" from the slice.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Reads the "length" from the slice.
    #[inline]
    pub fn length(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) }
    }

    /// Reads the "checksum" from the slice.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(6)) }
    }

    /// Decode all the fields and copy the results to a UdpHeader struct
    #[inline]
    pub fn to_header(&self) -> UdpHeader {
        UdpHeader {
            source_port: self.source_port(),
            destination_port: self.destination_port(),
            length: self.length(),
            checksum: self.checksum(),
        }
    }
}
