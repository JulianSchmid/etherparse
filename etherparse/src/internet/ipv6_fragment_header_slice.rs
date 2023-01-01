use crate::*;
use core::slice::from_raw_parts;

/// Slice containing an IPv6 fragment header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6FragmentHeaderSlice<'a> {
    /// Slice containing the packet data.
    slice: &'a [u8],
}

impl<'a> Ipv6FragmentHeaderSlice<'a> {
    /// Creates a hop by hop header slice from a slice.
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<Ipv6FragmentHeaderSlice<'a>, err::SliceLenError> {
        // the fragmentation header has the exact size of 8 bytes
        if slice.len() < 8 {
            Err(err::SliceLenError {
                expected_min_len: 8,
                actual_len: slice.len(),
                layer: err::Layer::Ipv6FragHeader,
            })
        } else {
            Ok(Ipv6FragmentHeaderSlice {
                // SAFETY:
                // Safe as slice length is checked to be at least 8 before this
                // code can be reached.
                slice: unsafe { from_raw_parts(slice.as_ptr(), 8) },
            })
        }
    }

    /// Creates a hop by hop header slice from a slice (assumes slice size & content was validated before).
    ///
    /// # Safety
    ///
    /// This function assumes that the passed slice has at least the length
    /// of 8. If a slice with length less then 8 is passed to this function
    /// the behavior will be undefined.
    pub unsafe fn from_slice_unchecked(slice: &'a [u8]) -> Ipv6FragmentHeaderSlice<'a> {
        debug_assert!(slice.len() >= Ipv6FragmentHeader::LEN);
        // the fragmentation header has the exact size of 8 bytes
        Ipv6FragmentHeaderSlice {
            slice: from_raw_parts(slice.as_ptr(), Ipv6FragmentHeader::LEN),
        }
    }

    /// Returns the slice containing the ipv6 fragment header.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the IP protocol number of the next header.
    ///
    /// See [IpNumber] or [ip_number] for a definition of the known values.
    #[inline]
    pub fn next_header(&self) -> u8 {
        // SAFETY:
        // Slice size checked to be at least 8 bytes in constructor.
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Fragment offset in 8 octets.
    ///
    /// Note: In the header only 13 bits are used, so the allowed range
    /// of the value is between 0 and 0x1FFF (inclusive).
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Slice size checked to be at least 8 bytes in constructor.
            unsafe {
                [
                    (*self.slice.get_unchecked(2) >> 3) & 0b0001_1111u8,
                    ((*self.slice.get_unchecked(2) << 5) & 0b1110_0000u8)
                        | (*self.slice.get_unchecked(3) & 0b0001_1111u8),
                ]
            },
        )
    }

    /// True if more fragment packets will follow. False if this is the last packet.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        // SAFETY:
        // Slice size checked to be at least 8 bytes in constructor.
        unsafe { 0 != *self.slice.get_unchecked(3) & 0b1000_0000u8 }
    }

    /// Identifcation value generated by the source
    pub fn identification(&self) -> u32 {
        // SAFETY:
        // Slice size checked to be at least 8 bytes in constructor.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(4)) }
    }

    /// Checks if the fragment header actually fragments the packet.
    ///
    /// Returns false if the fragment offset is 0 and the more flag
    /// is not set. Otherwise returns true.
    ///
    /// [RFC8200](https://datatracker.ietf.org/doc/html/rfc8200) explicitly
    /// states that fragment headers that don't fragment the packet payload are
    /// allowed. See the following quote from
    /// RFC8200 page 32:
    ///
    /// > Revised the text to handle the case of fragments that are whole
    /// > datagrams (i.e., both the Fragment Offset field and the M flag
    /// > are zero).  If received, they should be processed as a
    /// > reassembled packet.  Any other fragments that match should be
    /// > processed independently.  The Fragment creation process was
    /// > modified to not create whole datagram fragments (Fragment
    /// > Offset field and the M flag are zero).  See
    /// > [RFC6946](https://datatracker.ietf.org/doc/html/6946) and
    /// > [RFC8021](https://datatracker.ietf.org/doc/html/rfc8021) for more
    /// > information."
    ///
    /// ```
    /// use etherparse::Ipv6FragmentHeaderSlice;
    ///
    /// {
    ///     let slice = Ipv6FragmentHeaderSlice::from_slice(&[
    ///         0, 0, 0, 0, // offset 0 & more_fragments not set
    ///         1, 2, 3, 4,
    ///     ]).unwrap();
    ///     assert!(false == slice.is_fragmenting_payload());
    /// }
    ///
    /// {
    ///     let slice = Ipv6FragmentHeaderSlice::from_slice(&[
    ///         0, 0, 0, 0b1000_0000u8, // more_fragments set
    ///         1, 2, 3, 4,
    ///     ]).unwrap();
    ///     assert!(slice.is_fragmenting_payload());
    /// }
    ///
    /// {
    ///     let slice = Ipv6FragmentHeaderSlice::from_slice(&[
    ///         0, 0, 1, 0, // non zero offset
    ///         1, 2, 3, 4,
    ///     ]).unwrap();
    ///     assert!(slice.is_fragmenting_payload());
    /// }
    /// ```
    #[inline]
    pub fn is_fragmenting_payload(&self) -> bool {
        // SAFETY:
        // Slice size checked to be at least 8 bytes in constructor.
        unsafe {
            0 != *self.slice.get_unchecked(2) || 0 != (*self.slice.get_unchecked(3) & 0b1001_1111u8)
            // exclude the reserved bytes
        }
    }

    /// Decode some of the fields and copy the results to a
    /// Ipv6FragmentHeader struct.
    pub fn to_header(&self) -> Ipv6FragmentHeader {
        Ipv6FragmentHeader {
            next_header: self.next_header(),
            fragment_offset: self.fragment_offset(),
            more_fragments: self.more_fragments(),
            identification: self.identification(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{*, test_gens::*};
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn debug(input in ipv6_fragment_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(
                &bytes
            ).unwrap();
            assert_eq!(
                &format!(
                    "Ipv6FragmentHeaderSlice {{ slice: {:?} }}",
                    slice.slice()
                ),
                &format!("{:?}", slice)
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in ipv6_fragment_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(
                &bytes
            ).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            input in ipv6_fragment_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(slice.slice(), &buffer[..8]);
            }

            // call with not enough data in the slice
            for len in 0..Ipv6FragmentHeader::LEN {
                assert_eq!(
                    Ipv6FragmentHeaderSlice::from_slice(&buffer[0..len]).unwrap_err(),
                    err::SliceLenError{
                        expected_min_len: 8,
                        actual_len: len,
                        layer: err::Layer::Ipv6FragHeader,
                    }
                );
            }
        }
    }
    
    proptest! {
        #[test]
        fn from_slice_unchecked(
            input in ipv6_fragment_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
                        // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            unsafe {
                let slice = Ipv6FragmentHeaderSlice::from_slice_unchecked(&buffer[..]);
                assert_eq!(slice.slice(), &buffer[..8]);
            }
        }
    }
    
    proptest! {
        #[test]
        fn getters(input in ipv6_fragment_any()) {
            let buffer = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(input.next_header, slice.next_header());
            assert_eq!(input.fragment_offset, slice.fragment_offset());
            assert_eq!(input.more_fragments, slice.more_fragments());
            assert_eq!(input.identification, slice.identification());
        }
    }
    
    proptest! {
        #[test]
        fn is_fragmenting_payload(
            non_zero_offset in 1u16..0b0001_1111_1111_1111u16,
            identification in any::<u32>(),
            next_header in any::<u8>(),
        ) {
            // negative case
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: 0,
                    more_fragments: false,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(false == slice.is_fragmenting_payload());
            }
            // positive case (non zero offset)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: non_zero_offset,
                    more_fragments: false,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(slice.is_fragmenting_payload());
            }

            // positive case (more fragments)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: 0,
                    more_fragments: true,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(slice.is_fragmenting_payload());
            }

            // positive case (non zero offset & more fragments)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: non_zero_offset,
                    more_fragments: true,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(slice.is_fragmenting_payload());
            }
        }
    }

    proptest! {
        #[test]
        fn to_header(input in ipv6_fragment_any()) {
            let buffer = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }
}
