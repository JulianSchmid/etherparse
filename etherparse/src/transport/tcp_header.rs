use super::super::*;

/// Deprecated use [`TcpHeader::MIN_LEN`] instead.
#[deprecated(since = "0.14.0", note = "Use `TcpHeader::MIN_LEN` instead")]
pub const TCP_MINIMUM_HEADER_SIZE: usize = 5 * 4;

/// Deprecated use [`TcpHeader::MIN_DATA_OFFSET`] instead.
#[deprecated(since = "0.14.0", note = "Use `TcpHeader::MIN_DATA_OFFSET` instead")]
pub const TCP_MINIMUM_DATA_OFFSET: u8 = 5;

/// Deprecated use [`TcpHeader::MAX_DATA_OFFSET`] instead.
#[deprecated(since = "0.14.0", note = "Use `TcpHeader::MAX_DATA_OFFSET` instead")]
pub const TCP_MAXIMUM_DATA_OFFSET: u8 = 0xf;

/// TCP header according to rfc 793.
///
/// Field descriptions copied from RFC 793 page 15++
#[derive(Clone)]
pub struct TcpHeader {
    /// The source port number.
    pub source_port: u16,
    /// The destination port number.
    pub destination_port: u16,
    /// The sequence number of the first data octet in this segment (except when SYN is present).
    ///
    /// If SYN is present the sequence number is the initial sequence number (ISN)
    /// and the first data octet is ISN+1.
    /// [copied from RFC 793, page 16]
    pub sequence_number: u32,
    /// If the ACK control bit is set this field contains the value of the
    /// next sequence number the sender of the segment is expecting to
    /// receive.
    ///
    /// Once a connection is established this is always sent.
    pub acknowledgment_number: u32,
    /// The number of 32 bit words in the TCP Header.
    ///
    /// This indicates where the data begins.  The TCP header (even one including options) is an
    /// integral number of 32 bits long.
    pub (crate) _data_offset: u8,
    /// ECN-nonce - concealment protection (experimental: see RFC 3540)
    pub ns: bool,
    /// No more data from sender
    pub fin: bool,
    /// Synchronize sequence numbers
    pub syn: bool,
    /// Reset the connection
    pub rst: bool,
    /// Push Function
    pub psh: bool,
    /// Acknowledgment field significant
    pub ack: bool,
    /// Urgent Pointer field significant
    pub urg: bool,
    /// ECN-Echo (RFC 3168)
    pub ece: bool,
    /// Congestion Window Reduced (CWR) flag
    ///
    /// This flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    pub cwr: bool,
    /// The number of data octets beginning with the one indicated in the
    /// acknowledgment field which the sender of this segment is willing to
    /// accept.
    pub window_size: u16,
    /// Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    pub checksum: u16,
    /// This field communicates the current value of the urgent pointer as a
    /// positive offset from the sequence number in this segment.
    ///
    /// The urgent pointer points to the sequence number of the octet following
    /// the urgent data.  This field is only be interpreted in segments with
    /// the URG control bit set.
    pub urgent_pointer: u16,
    /// Buffer containing the options of the header (note that the data_offset defines the actual length). Use the options() method if you want to get a slice that has the actual length of the options.
    pub(crate) options_buffer: [u8; 40],
}

impl TcpHeader {
    /// Minimum length of a TCP header in bytes/octets.
    pub const MIN_LEN: usize = 5 * 4;

    /// Maximum length of a TCP header in bytes/octets.
    ///
    /// The length is obtained by multiplying the maximum value
    /// that "data offset" can take (it is a 4 bit number so the max
    /// is 0b1111) and multiplying it by 4 as it describes the offset
    /// to the data in 4-bytes words.
    pub const MAX_LEN: usize = 0b1111 * 4;

    /// The minimum data offset size (size of the tcp header itself).
    pub const MIN_DATA_OFFSET: u8 = 5;

    /// The maximum allowed value for the data offset (it is a 4 bit value).
    pub const MAX_DATA_OFFSET: u8 = 0xf;

    /// Creates a TcpHeader with the given values and the rest initialized with default values.
    pub fn new(
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        window_size: u16,
    ) -> TcpHeader {
        TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number: 0,
            _data_offset: TcpHeader::MIN_DATA_OFFSET,
            ns: false,
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            ece: false,
            urg: false,
            cwr: false,
            window_size,
            checksum: 0,
            urgent_pointer: 0,
            options_buffer: [0; 40],
        }
    }

    /// The number of 32 bit words in the TCP Header.
    ///
    /// This indicates where the data begins.  The TCP header (even one including options) is an
    /// integral number of 32 bits long.
    pub fn data_offset(&self) -> u8 {
        self._data_offset
    }

    /// Returns the length of the header including the options.
    pub fn header_len(&self) -> u16 {
        u16::from(self._data_offset) * 4
    }

    /// Returns the options size in bytes based on the currently set data_offset. Returns None if the data_offset is smaller then the minimum size or bigger then the maximum supported size.
    pub fn options_len(&self) -> usize {
        debug_assert!(TcpHeader::MIN_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TcpHeader::MAX_DATA_OFFSET);
        (self._data_offset - TcpHeader::MIN_DATA_OFFSET) as usize * 4
    }

    /// Returns a slice containing the options of the header (size is determined via the data_offset field.
    pub fn options(&self) -> &[u8] {
        &self.options_buffer[..self.options_len()]
    }

    /// Sets the options (overwrites the current options) or returns an error when there is not enough space.
    pub fn set_options(&mut self, options: &[TcpOptionElement]) -> Result<(), TcpOptionWriteError> {
        //calculate the required size of the options
        use crate::TcpOptionElement::*;
        let required_length = options.iter().fold(0, |acc, ref x| {
            acc + match x {
                Noop => 1,
                MaximumSegmentSize(_) => 4,
                WindowScale(_) => 3,
                SelectiveAcknowledgementPermitted => 2,
                SelectiveAcknowledgement(_, rest) => rest.iter().fold(10, |acc2, ref y| match y {
                    None => acc2,
                    Some(_) => acc2 + 8,
                }),
                Timestamp(_, _) => 10,
            }
        });

        if self.options_buffer.len() < required_length {
            Err(TcpOptionWriteError::NotEnoughSpace(required_length))
        } else {
            //reset the options to null
            self.options_buffer = [0; 40];
            self._data_offset = TcpHeader::MIN_DATA_OFFSET;

            //write the options to the buffer
            //note to whoever: I would have prefered to use std::io::Cursor as it would be less error
            //                 prone. But just in case that "no std" support is added later lets
            //                 not not rewrite it just yet with cursor.
            use tcp_option::*;
            let mut i = 0;
            for element in options {
                match element {
                    Noop => {
                        self.options_buffer[i] = KIND_NOOP;
                        i += 1;
                    }
                    MaximumSegmentSize(value) => {
                        // determine insertion area
                        let insert = &mut self.options_buffer[i..i + 4];
                        i += 4;

                        // write data
                        insert[0] = KIND_MAXIMUM_SEGMENT_SIZE;
                        insert[1] = 4;
                        insert[2..4].copy_from_slice(&value.to_be_bytes());
                    }
                    WindowScale(value) => {
                        // determine insertion area
                        let insert = &mut self.options_buffer[i..i + 3];
                        i += 3;

                        // write data
                        insert[0] = KIND_WINDOW_SCALE;
                        insert[1] = 3;
                        insert[2] = *value;
                    }
                    SelectiveAcknowledgementPermitted => {
                        // determine insertion area
                        let insert = &mut self.options_buffer[i..i + 2];
                        i += 2;

                        // write data
                        insert[0] = KIND_SELECTIVE_ACK_PERMITTED;
                        insert[1] = 2;
                    }
                    SelectiveAcknowledgement(first, rest) => {
                        //write guranteed data
                        {
                            let insert = &mut self.options_buffer[i..i + 10];
                            i += 10;

                            insert[0] = KIND_SELECTIVE_ACK;
                            //write the length
                            insert[1] = rest.iter().fold(10, |acc, ref y| match y {
                                None => acc,
                                Some(_) => acc + 8,
                            });
                            // write first
                            insert[2..6].copy_from_slice(&first.0.to_be_bytes());
                            insert[6..10].copy_from_slice(&first.1.to_be_bytes());
                        }
                        //write the rest
                        for v in rest {
                            match v {
                                None => {}
                                Some((a, b)) => {
                                    // determine insertion area
                                    let insert = &mut self.options_buffer[i..i + 8];
                                    i += 8;

                                    // insert
                                    insert[0..4].copy_from_slice(&a.to_be_bytes());
                                    insert[4..8].copy_from_slice(&b.to_be_bytes());
                                }
                            }
                        }
                    }
                    Timestamp(a, b) => {
                        let insert = &mut self.options_buffer[i..i + 10];
                        i += 10;

                        insert[0] = KIND_TIMESTAMP;
                        insert[1] = 10;
                        insert[2..6].copy_from_slice(&a.to_be_bytes());
                        insert[6..10].copy_from_slice(&b.to_be_bytes());
                    }
                }
            }
            //set the new data offset
            if i > 0 {
                self._data_offset = (i / 4) as u8 + TcpHeader::MIN_DATA_OFFSET;
                if i % 4 != 0 {
                    self._data_offset += 1;
                }
            }
            //done
            Ok(())
        }
    }

    /// Sets the options to the data given.
    pub fn set_options_raw(&mut self, data: &[u8]) -> Result<(), TcpOptionWriteError> {
        //check length
        if self.options_buffer.len() < data.len() {
            Err(TcpOptionWriteError::NotEnoughSpace(data.len()))
        } else {
            //reset all to zero to ensure padding
            self.options_buffer = [0; 40];

            //set data & data_offset
            self.options_buffer[..data.len()].copy_from_slice(data);
            self._data_offset = (data.len() / 4) as u8 + TcpHeader::MIN_DATA_OFFSET;
            if data.len() % 4 != 0 {
                self._data_offset += 1;
            }
            Ok(())
        }
    }

    /// Returns an iterator that allows to iterate through all known TCP header options.
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator {
            options: &self.options_buffer[..self.options_len()],
        }
    }

    /// Renamed to `TcpHeader::from_slice`
    #[deprecated(since = "0.10.1", note = "Use TcpHeader::from_slice instead.")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), ReadError> {
        TcpHeader::from_slice(slice)
    }

    /// Reads a tcp header from a slice
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), ReadError> {
        let h = TcpHeaderSlice::from_slice(slice)?;
        Ok((h.to_header(), &slice[h.slice().len()..]))
    }

    /// Read a tcp header from the current position
    pub fn read<T: io::Read + Sized>(reader: &mut T) -> Result<TcpHeader, ReadError> {
        let raw = {
            let mut raw: [u8; 20] = [0; 20];
            reader.read_exact(&mut raw)?;
            raw
        };
        let source_port = u16::from_be_bytes([raw[0], raw[1]]);
        let destination_port = u16::from_be_bytes([raw[2], raw[3]]);
        let sequence_number = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let acknowledgment_number = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let (data_offset, ns) = {
            let value = raw[12];
            ((value & 0xf0) >> 4, 0 != value & 1)
        };
        let flags = raw[13];

        Ok(TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            ns,
            fin: 0 != flags & 1,
            syn: 0 != flags & 2,
            rst: 0 != flags & 4,
            psh: 0 != flags & 8,
            ack: 0 != flags & 16,
            urg: 0 != flags & 32,
            ece: 0 != flags & 64,
            cwr: 0 != flags & 128,
            window_size: u16::from_be_bytes([raw[14], raw[15]]),
            checksum: u16::from_be_bytes([raw[16], raw[17]]),
            urgent_pointer: u16::from_be_bytes([raw[18], raw[19]]),
            options_buffer: {
                if data_offset < TcpHeader::MIN_DATA_OFFSET {
                    return Err(ReadError::TcpDataOffsetTooSmall(data_offset));
                } else {
                    let mut buffer: [u8; 40] = [0; 40];
                    //convert to bytes minus the tcp header size itself
                    let len = ((data_offset - TcpHeader::MIN_DATA_OFFSET) as usize) * 4;
                    if len > 0 {
                        reader.read_exact(&mut buffer[..len])?;
                    }
                    buffer
                }
            },
            _data_offset: data_offset,
        })
    }

    /// Write the tcp header to a stream (does NOT calculate the checksum).
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        //check that the data offset is within range
        debug_assert!(TcpHeader::MIN_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TcpHeader::MAX_DATA_OFFSET);

        let src_be = self.source_port.to_be_bytes();
        let dst_be = self.destination_port.to_be_bytes();
        let seq_be = self.sequence_number.to_be_bytes();
        let ack_be = self.acknowledgment_number.to_be_bytes();
        let window_be = self.window_size.to_be_bytes();
        let checksum_be = self.checksum.to_be_bytes();
        let urg_ptr_be = self.urgent_pointer.to_be_bytes();

        writer.write_all(&[
            src_be[0],
            src_be[1],
            dst_be[0],
            dst_be[1],
            seq_be[0],
            seq_be[1],
            seq_be[2],
            seq_be[3],
            ack_be[0],
            ack_be[1],
            ack_be[2],
            ack_be[3],
            {
                let value = (self._data_offset << 4) & 0xF0;
                if self.ns {
                    value | 1
                } else {
                    value
                }
            },
            {
                let mut value = 0;
                if self.fin {
                    value |= 1;
                }
                if self.syn {
                    value |= 2;
                }
                if self.rst {
                    value |= 4;
                }
                if self.psh {
                    value |= 8;
                }
                if self.ack {
                    value |= 16;
                }
                if self.urg {
                    value |= 32;
                }
                if self.ece {
                    value |= 64;
                }
                if self.cwr {
                    value |= 128;
                }
                value
            },
            window_be[0],
            window_be[1],
            checksum_be[0],
            checksum_be[1],
            urg_ptr_be[0],
            urg_ptr_be[1],
        ])?;

        //write options if the data_offset is large enough
        if self._data_offset > TcpHeader::MIN_DATA_OFFSET {
            let len = ((self._data_offset - TcpHeader::MIN_DATA_OFFSET) as usize) * 4;
            writer.write_all(&self.options_buffer[..len])?;
        }
        Ok(())
    }

    /// Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(
        &self,
        ip_header: &Ipv4Header,
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, payload)
    }

    /// Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(
        &self,
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize) * 4 + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        // calculate the checksum
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
        ip_header: &Ipv6Header,
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, payload)
    }

    /// Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(
        &self,
        source: [u8; 16],
        destination: [u8; 16],
        payload: &[u8],
    ) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize) * 4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        Ok(self.calc_checksum_post_ip(
            checksum::Sum16BitWords::new()
                .add_16bytes(source)
                .add_16bytes(destination)
                .add_4bytes((tcp_length as u32).to_be_bytes())
                .add_2bytes([0, ip_number::TCP]),
            payload,
        ))
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(
        &self,
        ip_pseudo_header_sum: checksum::Sum16BitWords,
        payload: &[u8],
    ) -> u16 {
        ip_pseudo_header_sum
            .add_2bytes(self.source_port.to_be_bytes())
            .add_2bytes(self.destination_port.to_be_bytes())
            .add_4bytes(self.sequence_number.to_be_bytes())
            .add_4bytes(self.acknowledgment_number.to_be_bytes())
            .add_2bytes([
                {
                    let value = (self._data_offset << 4) & 0xF0;
                    if self.ns {
                        value | 1
                    } else {
                        value
                    }
                },
                {
                    let mut value = 0;
                    if self.fin {
                        value |= 1;
                    }
                    if self.syn {
                        value |= 2;
                    }
                    if self.rst {
                        value |= 4;
                    }
                    if self.psh {
                        value |= 8;
                    }
                    if self.ack {
                        value |= 16;
                    }
                    if self.urg {
                        value |= 32;
                    }
                    if self.ece {
                        value |= 64;
                    }
                    if self.cwr {
                        value |= 128;
                    }
                    value
                },
            ])
            .add_2bytes(self.window_size.to_be_bytes())
            .add_2bytes(self.urgent_pointer.to_be_bytes())
            .add_slice(&self.options_buffer[..self.options_len()])
            .add_slice(payload)
            .ones_complement()
            .to_be()
    }
}

impl Default for TcpHeader {
    fn default() -> TcpHeader {
        TcpHeader {
            source_port: 0,
            destination_port: 0,
            sequence_number: 0,
            acknowledgment_number: 0,
            _data_offset: 5,
            ns: false,
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            options_buffer: [0; 40],
        }
    }
}

//NOTE: I would have prefered to NOT write my own Debug & PartialEq implementation but there are no
//      default implementations availible for [u8;40] and the alternative of using [u32;10] would lead
//      to unsafe casting. Writing impl Debug for [u8;40] in a crate is also illegal as it could lead
//      to an implementation collision between crates.
//      So the only option left to me was to write an implementation myself and deal with the added complexity
//      and potential added error source.
impl core::fmt::Debug for TcpHeader {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("TcpHeader")
            .field("source_port", &self.source_port)
            .field("destination_port", &self.destination_port)
            .field("sequence_number", &self.sequence_number)
            .field("acknowledgment_number", &self.acknowledgment_number)
            .field("data_offset", &self._data_offset)
            .field("ns", &self.ns)
            .field("fin", &self.fin)
            .field("syn", &self.syn)
            .field("rst", &self.rst)
            .field("psh", &self.psh)
            .field("ack", &self.ack)
            .field("urg", &self.urg)
            .field("ece", &self.ece)
            .field("cwr", &self.cwr)
            .field("window_size", &self.window_size)
            .field("checksum", &self.checksum)
            .field("urgent_pointer", &self.urgent_pointer)
            .field("options", &self.options_iterator())
            .finish()
    }
}

impl core::cmp::PartialEq for TcpHeader {
    fn eq(&self, other: &TcpHeader) -> bool {
        self.source_port == other.source_port
            && self.destination_port == other.destination_port
            && self.sequence_number == other.sequence_number
            && self.acknowledgment_number == other.acknowledgment_number
            && self._data_offset == other._data_offset
            && self.ns == other.ns
            && self.fin == other.fin
            && self.syn == other.syn
            && self.rst == other.rst
            && self.psh == other.psh
            && self.ack == other.ack
            && self.urg == other.urg
            && self.ece == other.ece
            && self.cwr == other.cwr
            && self.window_size == other.window_size
            && self.checksum == other.checksum
            && self.urgent_pointer == other.urgent_pointer
            && self.options() == other.options()
    }
}

impl core::cmp::Eq for TcpHeader {}
