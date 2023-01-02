use crate::*;

/// A slice containing an tcp header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> TcpHeaderSlice<'a> {
    /// Creates a slice containing an tcp header.
    pub fn from_slice(slice: &'a [u8]) -> Result<TcpHeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < TcpHeader::MIN_LEN {
            return Err(SliceLen(err::SliceLenError {
                expected_min_len: TcpHeader::MIN_LEN,
                actual_len: slice.len(),
                layer: err::Layer::TcpHeader,
            }));
        }

        // SAFETY:
        // Safe as it is checked at the start of the function that the
        // length of the slice is at least TcpHeader::MIN_LEN (20).
        let data_offset = unsafe { (*slice.get_unchecked(12) & 0xf0) >> 4 };
        let len = data_offset as usize * 4;

        if data_offset < TcpHeader::MIN_DATA_OFFSET {
            Err(ReadError::TcpDataOffsetTooSmall(data_offset))
        } else if slice.len() < len {
            Err(SliceLen(err::SliceLenError {
                expected_min_len: len,
                actual_len: slice.len(),
                layer: err::Layer::TcpHeader,
            }))
        } else {
            //done
            Ok(TcpHeaderSlice::<'a> {
                // SAFETY:
                // Safe as there is a check above that the slice length
                // is at least len.
                slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), len) },
            })
        }
    }
    /// Returns the slice containing the tcp header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the destination port number.
    #[inline]
    pub fn source_port(&self) -> u16 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr()) }
    }

    /// Read the destination port number.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Read the sequence number of the first data octet in this segment (except when SYN is present).
    ///
    /// If SYN is present the sequence number is the initial sequence number (ISN)
    /// and the first data octet is ISN+1.
    /// \[copied from RFC 793, page 16\]
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(4)) }
    }

    /// Reads the acknowledgment number.
    ///
    /// If the ACK control bit is set this field contains the value of the
    /// next sequence number the sender of the segment is expecting to
    /// receive.
    ///
    /// Once a connection is established this is always sent.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(8)) }
    }

    /// Read the number of 32 bit words in the TCP Header.
    ///
    /// This indicates where the data begins.  The TCP header (even one including options) is an
    /// integral number of 32 bits long.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { (*self.slice.get_unchecked(12) & 0b1111_0000) >> 4 }
    }

    /// ECN-nonce - concealment protection (experimental: see RFC 3540)
    #[inline]
    pub fn ns(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(12) & 0b0000_0001) }
    }

    /// Read the fin flag (no more data from sender).
    #[inline]
    pub fn fin(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_0001) }
    }

    /// Reads the syn flag (synchronize sequence numbers).
    #[inline]
    pub fn syn(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_0010) }
    }

    /// Reads the rst flag (reset the connection).
    #[inline]
    pub fn rst(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_0100) }
    }

    /// Reads the psh flag (push function).
    #[inline]
    pub fn psh(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0000_1000) }
    }

    /// Reads the ack flag (acknowledgment field significant).
    #[inline]
    pub fn ack(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0001_0000) }
    }

    /// Reads the urg flag (Urgent Pointer field significant).
    #[inline]
    pub fn urg(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0010_0000) }
    }

    /// Read the ECN-Echo flag (RFC 3168).
    #[inline]
    pub fn ece(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b0100_0000) }
    }

    /// Reads the cwr flag (Congestion Window Reduced).
    ///
    /// This flag is set by the sending host to indicate that it received a TCP
    /// segment with the ECE flag set and had responded in congestion control
    /// mechanism (added to header by RFC 3168).
    #[inline]
    pub fn cwr(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe { 0 != (*self.slice.get_unchecked(13) & 0b1000_0000) }
    }

    /// The number of data octets beginning with the one indicated in the
    /// acknowledgment field which the sender of this segment is willing to
    /// accept.
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe { [*self.slice.get_unchecked(14), *self.slice.get_unchecked(15)] },
        )
    }

    /// Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe { [*self.slice.get_unchecked(16), *self.slice.get_unchecked(17)] },
        )
    }

    /// This field communicates the current value of the urgent pointer as a
    /// positive offset from the sequence number in this segment.
    ///
    /// The urgent pointer points to the sequence number of the octet following
    /// the urgent data.  This field is only be interpreted in segments with
    /// the URG control bit set.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe { [*self.slice.get_unchecked(18), *self.slice.get_unchecked(19)] },
        )
    }

    /// Options of the header
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.slice[TcpHeader::MIN_LEN..self.data_offset() as usize * 4]
    }

    /// Returns an iterator that allows to iterate through all known TCP header options.
    #[inline]
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator::from_slice(self.options())
    }

    /// Decode all the fields and copy the results to a TcpHeader struct
    pub fn to_header(&self) -> TcpHeader {
        TcpHeader {
            source_port: self.source_port(),
            destination_port: self.destination_port(),
            sequence_number: self.sequence_number(),
            acknowledgment_number: self.acknowledgment_number(),
            _data_offset: self.data_offset(),
            ns: self.ns(),
            fin: self.fin(),
            syn: self.syn(),
            rst: self.rst(),
            psh: self.psh(),
            ack: self.ack(),
            ece: self.ece(),
            urg: self.urg(),
            cwr: self.cwr(),
            window_size: self.window_size(),
            checksum: self.checksum(),
            urgent_pointer: self.urgent_pointer(),
            options_buffer: {
                let options = self.options();
                let mut result: [u8; 40] = [0; 40];
                if !options.is_empty() {
                    result[..options.len()].clone_from_slice(options);
                }
                result
            },
        }
    }

    /// Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(
        &self,
        ip_header: &Ipv4HeaderSlice,
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source(), ip_header.destination(), payload)
    }

    /// Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(
        &self,
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        let tcp_length = self.slice.len() + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        //calculate the checksum
        Ok(self.calc_checksum_post_ip(
            checksum::Sum16BitWords::new()
                .add_4bytes(source_ip)
                .add_4bytes(destination_ip)
                .add_2bytes([0, ip_number::TCP])
                .add_2bytes((tcp_length as u16).to_be_bytes()),
            payload,
        ))
    }

    /// Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(
        &self,
        ip_header: &Ipv6HeaderSlice,
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source(), ip_header.destination(), payload)
    }

    /// Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(
        &self,
        source: [u8; 16],
        destination: [u8; 16],
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        let tcp_length = (self.data_offset() as usize) * 4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        Ok(self.calc_checksum_post_ip(
            checksum::Sum16BitWords::new()
                .add_16bytes(source)
                .add_16bytes(destination)
                .add_2bytes([0, ip_number::TCP])
                .add_4bytes((tcp_length as u32).to_be_bytes()),
            payload,
        ))
    }

    /// This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(
        &self,
        ip_pseudo_header_sum: checksum::Sum16BitWords,
        payload: &[u8],
    ) -> u16 {
        ip_pseudo_header_sum
            .add_slice(&self.slice[..16]) //until checksum
            .add_slice(&self.slice[18..self.slice.len()])
            .add_slice(payload)
            .ones_complement()
            .to_be()
    }
}
