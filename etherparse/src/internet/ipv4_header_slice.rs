use std::{slice::from_raw_parts, net::Ipv4Addr};

use crate::*;

/// A slice containing an ipv4 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Ipv4HeaderSlice<'a> {

    /// Creates a slice containing an ipv4 header (including header options).
    pub fn from_slice(slice: &'a[u8]) -> Result<Ipv4HeaderSlice<'a>, ReadError> {

        //check length
        use crate::ReadError::*;
        if slice.len() < Ipv4Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(
                err::UnexpectedEndOfSliceError{
                    expected_min_len: Ipv4Header::SERIALIZED_SIZE,
                    actual_len: slice.len(),
                    layer: err::Layer::Ipv4Header,
                }
            ));
        }

        //read version & ihl
        let (version, ihl) = unsafe {
            let value = slice.get_unchecked(0);
            (value >> 4, value & 0xf)
        };

        //check version
        if 4 != version {
            return Err(Ipv4UnexpectedVersion(version));
        }

        //check that the ihl is correct
        if ihl < 5 {
            use crate::ReadError::*;
            return Err(Ipv4HeaderLengthBad(ihl));
        }

        //check that the slice contains enough data for the entire header + options
        let header_length = (usize::from(ihl))*4;
        if slice.len() < header_length {
            return Err(UnexpectedEndOfSlice(
                err::UnexpectedEndOfSliceError{
                    expected_min_len: header_length,
                    actual_len: slice.len(),
                    layer: err::Layer::Ipv4Header,
                }
            ));
        }

        // check the total_length can contain the header
        //
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) at the start.
        let total_length = unsafe {
            get_unchecked_be_u16(slice.as_ptr().add(2))
        };

        if total_length < header_length as u16 {
            return Err(Ipv4TotalLengthTooSmall(total_length))
        }

        //all good
        Ok(Ipv4HeaderSlice {
            // SAFETY:
            // Safe as the slice length is checked to be at least
            // header_length or greater above.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    header_length
                )
            }
        })
    }

    /// Converts the given slice into a ipv4 header slice WITHOUT any
    /// checks to ensure that the data present is an ipv4 header or that the
    /// slice length is matching the header length.
    /// 
    /// If you are not sure what this means, use [`Ipv4HeaderSlice::from_slice`]
    /// instead.
    /// 
    /// # Safety
    /// 
    /// It must ensured that the slice exactly contains the IPv4 header
    /// and the ihl (intra header length) & total length must be consistent.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &[u8]) -> Ipv4HeaderSlice {
        Ipv4HeaderSlice {
            slice,
        }
    }

    /// Returns the slice containing the ipv4 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the "version" field of the IPv4 header (should be 4).
    #[inline]
    pub fn version(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            *self.slice.get_unchecked(0) >> 4
        }
    }

    /// Read the "ip header length" (length of the ipv4 header + options in multiples of 4 bytes).
    #[inline]
    pub fn ihl(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            *self.slice.get_unchecked(0) & 0xf
        }
    }

    /// Read the "differentiated_services_code_point" from the slice.
    #[inline]
    pub fn dcp(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            *self.slice.get_unchecked(1) >> 2
        }
    }

    /// Read the "explicit_congestion_notification" from the slice.
    #[inline]
    pub fn ecn(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            *self.slice.get_unchecked(1) & 0x3
        }
    }

    /// Read the "total length" from the slice (total length of ip header + payload).
    #[inline]
    pub fn total_len(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    /// Determine the payload length based on the ihl & total_length field of the header.
    #[inline]
    pub fn payload_len(&self) -> u16 {
        self.total_len() - u16::from(self.ihl())*4
    }

    /// Read the "identification" field from the slice.
    #[inline]
    pub fn identification(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(4))
        }
    }

    /// Read the "dont fragment" flag from the slice.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            0 != (*self.slice.get_unchecked(6) & 0x40)
        }
    }

    /// Read the "more fragments" flag from the slice.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            0 != (*self.slice.get_unchecked(6) & 0x20)
        }
    }

    /// Read the "fragment_offset" field from the slice.
    #[inline]
    pub fn fragments_offset(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Safe as the slice length is checked to be at least
            // SERIALIZED_SIZE (20) in the constructor.
            unsafe {
                [
                    *self.slice.get_unchecked(6) & 0x1f,
                    *self.slice.get_unchecked(7)
                ]
            }
        )
    }

    /// Read the "time_to_live" field from the slice.
    #[inline]
    pub fn ttl(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            *self.slice.get_unchecked(8)
        }
    }

    /// Read the "protocol" field from the slice.
    #[inline]
    pub fn protocol(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            *self.slice.get_unchecked(9)
        }
    }

    /// Read the "header checksum" field from the slice.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(10))
        }
    }
    
    /// Returns a slice containing the ipv4 source address.
    #[inline]
    pub fn source(&self) -> [u8;4] {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            get_unchecked_4_byte_array(self.slice.as_ptr().add(12))
        }
    }

    /// Return the ipv4 source address as an std::net::Ipv4Addr
    pub fn source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.source())
    }

    /// Returns a slice containing the ipv4 source address.
    #[inline]
    pub fn destination(&self) -> [u8;4] {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            get_unchecked_4_byte_array(self.slice.as_ptr().add(16))
        }
    }

    /// Return the ipv4 destination address as an std::net::Ipv4Addr
    pub fn destination_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.destination())
    }

    /// Returns a slice containing the ipv4 header options (empty when there are no options).
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // SERIALIZED_SIZE (20) in the constructor.
        unsafe {
            from_raw_parts(
                self.slice.as_ptr().add(20),
                self.slice.len() - 20
            )
        }
    }

    /// Returns true if the payload is fragmented.
    ///
    /// Either data is missing (more_fragments set) or there is
    /// an fragment offset.
    #[inline]
    pub fn is_fragmenting_payload(&self) -> bool {
        self.more_fragments() ||
        (0 != self.fragments_offset())
    }

    /// Decode all the fields and copy the results to a Ipv4Header struct
    #[inline]
    pub fn to_header(&self) -> Ipv4Header {
        Ipv4Header::from_ipv4_slice(self)
    }
}
