use crate::*;
use core::slice::from_raw_parts;

/// A slice containing an ipv6 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6HeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Ipv6HeaderSlice<'a> {
    /// Creates a slice containing an ipv6 header (without header extensions).
    pub fn from_slice(slice: &'a [u8]) -> Result<Ipv6HeaderSlice<'a>, ReadError> {
        // check length
        use crate::ReadError::*;
        if slice.len() < Ipv6Header::LEN {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: Ipv6Header::LEN,
                actual_len: slice.len(),
                layer: err::Layer::Ipv6Header,
            }));
        }

        // read version & ihl
        //
        // SAFETY:
        // This is safe as the slice len is checked to be
        // at least 40 bytes at the start of the function.
        let version = unsafe { slice.get_unchecked(0) >> 4 };

        // check version
        if 6 != version {
            return Err(Ipv6UnexpectedVersion(version));
        }

        // all good
        Ok(Ipv6HeaderSlice {
            // SAFETY:
            // This is safe as the slice length is checked to be
            // at least Ipv6Header::LEN (40)
            // at the start of the function.
            slice: unsafe { from_raw_parts(slice.as_ptr(), Ipv6Header::LEN) },
        })
    }

    /// Returns the slice containing the ipv6 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the "version" field from the slice (should be 6).
    #[inline]
    pub fn version(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { *self.slice.get_unchecked(0) >> 4 }
    }

    /// Read the "traffic class" field from the slice.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { (self.slice.get_unchecked(0) << 4) | (self.slice.get_unchecked(1) >> 4) }
    }

    /// Read the "flow label" field from the slice.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        u32::from_be_bytes(
            // SAFETY:
            // Safe as the slice length is set to
            // Ipv6Header::LEN (40) during construction
            // of the struct.
            unsafe {
                [
                    0,
                    *self.slice.get_unchecked(1) & 0xf,
                    *self.slice.get_unchecked(2),
                    *self.slice.get_unchecked(3),
                ]
            },
        )
    }

    /// Read the "payload length" field from  the slice. The length should contain the length of all extension headers and payload.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) }
    }

    /// Read the "next header" field from the slice.
    ///
    /// The next header value specifies what the next header or transport
    /// layer protocol is (see [IpNumber] or [ip_number] for a definitions of ids).
    #[inline]
    pub fn next_header(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { *self.slice.get_unchecked(6) }
    }

    /// Read the "hop limit" field from the slice. The hop limit specifies the number of hops the packet can take before it is discarded.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { *self.slice.get_unchecked(7) }
    }

    /// Returns a slice containing the IPv6 source address.
    #[inline]
    pub fn source(&self) -> [u8; 16] {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { get_unchecked_16_byte_array(self.slice.as_ptr().add(8)) }
    }

    /// Return the ipv6 source address as an std::net::Ipv6Addr
    #[inline]
    pub fn source_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.source())
    }

    /// Returns a slice containing the IPv6 destination address.
    #[inline]
    pub fn destination(&self) -> [u8; 16] {
        // SAFETY:
        // Safe as the slice length is set to
        // Ipv6Header::LEN (40) during construction
        // of the struct.
        unsafe { get_unchecked_16_byte_array(self.slice.as_ptr().add(24)) }
    }

    /// Return the ipv6 destination address as an std::net::Ipv6Addr
    #[inline]
    pub fn destination_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.destination())
    }

    /// Decode all the fields and copy the results to a Ipv6Header struct
    pub fn to_header(&self) -> Ipv6Header {
        Ipv6Header {
            traffic_class: self.traffic_class(),
            flow_label: self.flow_label(),
            payload_length: self.payload_length(),
            next_header: self.next_header(),
            hop_limit: self.hop_limit(),
            source: self.source(),
            destination: self.destination(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{*, test_gens::*};
    use proptest::*;

    #[test]
    fn debug() {
        let header: Ipv6Header = Default::default();
        let bytes = header.to_bytes().unwrap();
        let slice = Ipv6HeaderSlice::from_slice(&bytes).unwrap();
        assert_eq!(
            format!("{:?}", slice),
            format!("Ipv6HeaderSlice {{ slice: {:?} }}", &bytes[..])
        );
    }

    proptest!{
        #[test]
        fn clone_eq(header in ipv6_any()) {
            let bytes = header.to_bytes().unwrap();
            let slice = Ipv6HeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice.clone(), slice);
        }
    }
}