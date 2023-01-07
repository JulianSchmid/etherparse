use std::{net::Ipv4Addr, slice::from_raw_parts};

use crate::*;

/// A slice containing an ipv4 header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4HeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> Ipv4HeaderSlice<'a> {
    /// Creates a slice containing an ipv4 header (including header options).
    pub fn from_slice(slice: &'a [u8]) -> Result<Ipv4HeaderSlice<'a>, err::ipv4::HeaderSliceError> {
        use err::ipv4::HeaderError::*;
        use err::ipv4::HeaderSliceError::*;

        //check length
        if slice.len() < Ipv4Header::MIN_LEN {
            return Err(Len(err::LenError {
                required_len: Ipv4Header::MIN_LEN,
                len: slice.len(),
                len_source: err::LenSource::Slice,
                layer: err::Layer::Ipv4Header,
                layer_start_offset: 0,
            }));
        }

        //read version & ihl
        let (version_number, ihl) = unsafe {
            let value = slice.get_unchecked(0);
            (value >> 4, value & 0xf)
        };

        //check version
        if 4 != version_number {
            return Err(Content(UnexpectedVersion { version_number }));
        }

        //check that the ihl is correct
        if ihl < 5 {
            return Err(Content(HeaderLengthSmallerThanHeader { ihl }));
        }

        //check that the slice contains enough data for the entire header + options
        let header_length = (usize::from(ihl)) * 4;
        if slice.len() < header_length {
            return Err(Len(err::LenError {
                required_len: header_length,
                len: slice.len(),
                len_source: err::LenSource::Slice,
                layer: err::Layer::Ipv4Header,
                layer_start_offset: 0,
            }));
        }

        // check the total_length can contain the header
        //
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) at the start.
        let total_length = unsafe { get_unchecked_be_u16(slice.as_ptr().add(2)) };

        if total_length < header_length as u16 {
            return Err(Content(TotalLengthSmallerThanHeader {
                total_length,
                min_expected_length: header_length as u16,
            }));
        }

        //all good
        Ok(Ipv4HeaderSlice {
            // SAFETY:
            // Safe as the slice length is checked to be at least
            // header_length or greater above.
            slice: unsafe { from_raw_parts(slice.as_ptr(), header_length) },
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
        Ipv4HeaderSlice { slice }
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
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { *self.slice.get_unchecked(0) >> 4 }
    }

    /// Read the "ip header length" (length of the ipv4 header + options in multiples of 4 bytes).
    #[inline]
    pub fn ihl(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { *self.slice.get_unchecked(0) & 0xf }
    }

    /// Read the "differentiated_services_code_point" from the slice.
    #[inline]
    pub fn dcp(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { *self.slice.get_unchecked(1) >> 2 }
    }

    /// Read the "explicit_congestion_notification" from the slice.
    #[inline]
    pub fn ecn(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { *self.slice.get_unchecked(1) & 0x3 }
    }

    /// Read the "total length" from the slice (total length of ip header + payload).
    #[inline]
    pub fn total_len(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Determine the payload length based on the ihl & total_length field of the header.
    #[inline]
    pub fn payload_len(&self) -> u16 {
        self.total_len() - u16::from(self.ihl()) * 4
    }

    /// Read the "identification" field from the slice.
    #[inline]
    pub fn identification(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) }
    }

    /// Read the "dont fragment" flag from the slice.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { 0 != (*self.slice.get_unchecked(6) & 0x40) }
    }

    /// Read the "more fragments" flag from the slice.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { 0 != (*self.slice.get_unchecked(6) & 0x20) }
    }

    /// Read the "fragment_offset" field from the slice.
    #[inline]
    pub fn fragments_offset(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Safe as the slice length is checked to be at least
            // Ipv4Header::MIN_LEN (20) in the constructor.
            unsafe {
                [
                    *self.slice.get_unchecked(6) & 0x1f,
                    *self.slice.get_unchecked(7),
                ]
            },
        )
    }

    /// Read the "time_to_live" field from the slice.
    #[inline]
    pub fn ttl(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { *self.slice.get_unchecked(8) }
    }

    /// Read the "protocol" field from the slice.
    #[inline]
    pub fn protocol(&self) -> u8 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { *self.slice.get_unchecked(9) }
    }

    /// Read the "header checksum" field from the slice.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(10)) }
    }

    /// Returns a slice containing the ipv4 source address.
    #[inline]
    pub fn source(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { get_unchecked_4_byte_array(self.slice.as_ptr().add(12)) }
    }

    /// Return the ipv4 source address as an std::net::Ipv4Addr
    pub fn source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.source())
    }

    /// Returns a slice containing the ipv4 source address.
    #[inline]
    pub fn destination(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the slice length is checked to be at least
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { get_unchecked_4_byte_array(self.slice.as_ptr().add(16)) }
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
        // Ipv4Header::MIN_LEN (20) in the constructor.
        unsafe { from_raw_parts(self.slice.as_ptr().add(20), self.slice.len() - 20) }
    }

    /// Returns true if the payload is fragmented.
    ///
    /// Either data is missing (more_fragments set) or there is
    /// an fragment offset.
    #[inline]
    pub fn is_fragmenting_payload(&self) -> bool {
        self.more_fragments() || (0 != self.fragments_offset())
    }

    /// Decode all the fields and copy the results to a Ipv4Header struct
    #[inline]
    pub fn to_header(&self) -> Ipv4Header {
        let options = self.options();
        Ipv4Header {
            differentiated_services_code_point: self.dcp(),
            explicit_congestion_notification: self.ecn(),
            payload_len: self.payload_len(),
            identification: self.identification(),
            dont_fragment: self.dont_fragment(),
            more_fragments: self.more_fragments(),
            fragments_offset: self.fragments_offset(),
            time_to_live: self.ttl(),
            protocol: self.protocol(),
            header_checksum: self.header_checksum(),
            source: self.source(),
            destination: self.destination(),
            options_len: options.len() as u8,
            options_buffer: {
                let mut result: [u8; 40] = [0; 40];
                result[..options.len()].copy_from_slice(options);
                result
            },
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{test_gens::*, *};
    use arrayvec::ArrayVec;
    use proptest::prelude::*;

    #[test]
    fn debug() {
        let buffer = {
            let header: Ipv4Header = Default::default();
            header.to_bytes().unwrap()
        };
        let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(
            format!("{:?}", slice),
            format!("Ipv4HeaderSlice {{ slice: {:?} }}", slice.slice())
        );
    }

    proptest! {
        #[test]
        fn clone_eq(header in ipv4_any()) {
            let buffer = header.to_bytes().unwrap();
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(slice.clone(), slice);
        }
    }

    proptest! {
        #[test]
        fn from_slice(header in ipv4_any()) {
            use err::ipv4::HeaderError::*;
            use err::ipv4::HeaderSliceError::*;

            // ok
            {
                let mut buffer = ArrayVec::<u8, { Ipv4Header::MAX_LEN + 1 }>::new();
                buffer.try_extend_from_slice(&header.to_bytes().unwrap()).unwrap();
                buffer.try_extend_from_slice(&[1]).unwrap();

                let actual_slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
                assert_eq!(actual_slice.to_header(), header);
                assert_eq!(actual_slice.slice(), &buffer[..header.header_len()]);
            }

            // unexpected end of slice
            {
                let buffer = header.to_bytes().unwrap();
                for len in 0..header.header_len() {
                    assert_eq!(
                        Ipv4HeaderSlice::from_slice(&buffer[..len]),
                        Err(Len(err::LenError{
                            required_len: if len < Ipv4Header::MIN_LEN {
                                Ipv4Header::MIN_LEN
                            } else {
                                header.header_len()
                            },
                            len: len,
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv4Header,
                            layer_start_offset: 0,
                        }))
                    );
                }
            }

            // version error
            for version_number in 0u8..0b1111u8 {
                if 4 != version_number {
                    let mut buffer = header.to_bytes().unwrap();
                    // inject the bad ihl
                    buffer[0] = (version_number << 4) | (buffer[0] & 0b1111);
                    // expect an error
                    assert_eq!(
                        Ipv4HeaderSlice::from_slice(&buffer).unwrap_err(),
                        Content(UnexpectedVersion{
                            version_number,
                        })
                    );
                }
            }

            // ihl too small error
            for ihl in 0u8..5u8 {
                let mut buffer = header.to_bytes().unwrap();
                // inject the bad ihl
                buffer[0] = (4 << 4) | ihl;
                // expect an error
                assert_eq!(
                    Ipv4HeaderSlice::from_slice(&buffer).unwrap_err(),
                    Content(HeaderLengthSmallerThanHeader{
                        ihl,
                    })
                );
            }

            // total length too small error
            for total_length in 0..header.header_len() {
                let mut buffer = header.to_bytes().unwrap();
                // inject total length smaller then the header length
                let tl_be = (total_length as u16).to_be_bytes();
                buffer[2] = tl_be[0];
                buffer[3] = tl_be[1];
                // expect an error
                assert_eq!(
                    Ipv4HeaderSlice::from_slice(&buffer).unwrap_err(),
                    Content(TotalLengthSmallerThanHeader{
                        total_length: total_length as u16,
                        min_expected_length: header.header_len() as u16,
                    })
                );
            }
        }
    }

    #[test]
    fn from_slice_unchecked() {
        let buffer = [0u8; 4];
        let slice = unsafe { Ipv4HeaderSlice::from_slice_unchecked(&buffer) };
        assert_eq!(slice.slice(), &buffer);
    }

    proptest! {
        #[test]
        fn getters(header in ipv4_any()) {
            use std::net::Ipv4Addr;

            let buffer = header.to_bytes().unwrap();
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();

            assert_eq!(slice.slice(), &buffer[..]);
            assert_eq!(slice.version(), 4);
            assert_eq!(slice.ihl(), header.ihl());
            assert_eq!(slice.dcp(), header.differentiated_services_code_point);
            assert_eq!(slice.ecn(), header.explicit_congestion_notification);
            assert_eq!(slice.total_len(), header.total_len());
            assert_eq!(slice.payload_len(), header.payload_len);
            assert_eq!(slice.identification(), header.identification);
            assert_eq!(slice.dont_fragment(), header.dont_fragment);
            assert_eq!(slice.more_fragments(), header.more_fragments);
            assert_eq!(slice.fragments_offset(), header.fragments_offset);
            assert_eq!(slice.ttl(), header.time_to_live);
            assert_eq!(slice.protocol(), header.protocol);
            assert_eq!(slice.header_checksum(), header.header_checksum);
            assert_eq!(slice.source(), header.source);
            assert_eq!(slice.source_addr(), Ipv4Addr::from(header.source));
            assert_eq!(slice.destination(), header.destination);
            assert_eq!(slice.destination_addr(), Ipv4Addr::from(header.destination));
            assert_eq!(slice.options(), header.options());
        }
    }

    #[test]
    fn is_fragmenting_payload() {
        // not fragmenting
        {
            let buffer = {
                let mut header: Ipv4Header = Default::default();
                header.fragments_offset = 0;
                header.more_fragments = false;
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(false, slice.is_fragmenting_payload());
        }

        // fragmenting based on offset
        {
            let buffer = {
                let mut header: Ipv4Header = Default::default();
                header.fragments_offset = 1;
                header.more_fragments = false;
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert!(slice.is_fragmenting_payload());
        }

        // fragmenting based on more_fragments
        {
            let buffer = {
                let mut header: Ipv4Header = Default::default();
                header.fragments_offset = 0;
                header.more_fragments = true;
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert!(slice.is_fragmenting_payload());
        }
    }

    proptest! {
        #[test]
        fn to_header(header in ipv4_any()) {
            let buffer = header.to_bytes().unwrap();
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(slice.to_header(), header);
        }
    }
}
