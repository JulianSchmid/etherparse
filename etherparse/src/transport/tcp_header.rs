use arrayvec::ArrayVec;

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
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self._data_offset
    }

    /// Returns the length of the header including the options.
    #[inline]
    pub fn header_len(&self) -> u16 {
        u16::from(self._data_offset) * 4
    }

    /// Returns the options size in bytes based on the currently set data_offset. Returns None if the data_offset is smaller then the minimum size or bigger then the maximum supported size.
    #[inline]
    pub fn options_len(&self) -> usize {
        debug_assert!(TcpHeader::MIN_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TcpHeader::MAX_DATA_OFFSET);
        (self._data_offset - TcpHeader::MIN_DATA_OFFSET) as usize * 4
    }

    /// Returns a slice containing the options of the header (size is determined via the data_offset field.
    #[inline]
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
    pub fn read_from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), err::tcp::HeaderSliceError> {
        TcpHeader::from_slice(slice)
    }

    /// Reads a tcp header from a slice
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), err::tcp::HeaderSliceError> {
        let h = TcpHeaderSlice::from_slice(slice)?;
        Ok((h.to_header(), &slice[h.slice().len()..]))
    }

    /// Read a tcp header from the current position
    pub fn read<T: io::Read + Sized>(reader: &mut T) -> Result<TcpHeader, err::tcp::HeaderReadError> {
        use err::tcp::{HeaderError::*, HeaderReadError::*};

        let raw = {
            let mut raw: [u8; 20] = [0; 20];
            reader.read_exact(&mut raw).map_err(Io)?;
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
                    return Err(Content(DataOffsetTooSmall{ data_offset }));
                } else {
                    let mut buffer: [u8; 40] = [0; 40];
                    //convert to bytes minus the tcp header size itself
                    let len = ((data_offset - TcpHeader::MIN_DATA_OFFSET) as usize) * 4;
                    if len > 0 {
                        reader.read_exact(&mut buffer[..len]).map_err(Io)?;
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

    /// Returns the serialized header.
    pub fn to_bytes(&self) -> ArrayVec<u8, { TcpHeader::MAX_LEN }> {

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

        let mut result = ArrayVec::new();

        // write base header data
        result.extend([
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
        ]);

        // add the options
        result.extend(self.options_buffer);
        // SAFETY: Safe as the header len can not exceed the maximum length
        // of the header.
        unsafe {
            result.set_len(self.header_len() as usize);
        }

        result
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

#[cfg(test)]
mod test {
    use crate::{
        *,
        test_gens::*,
        tcp_option::*,
        TcpOptionElement::*,
        err::tcp::{HeaderError::*, HeaderSliceError::*}
    };
    use proptest::prelude::*;
    use std::io::Cursor;

    #[test]
    fn default() {
        let default: TcpHeader = Default::default();

        assert_eq!(0, default.source_port);
        assert_eq!(0, default.destination_port);
        assert_eq!(0, default.sequence_number);
        assert_eq!(0, default.acknowledgment_number);
        assert_eq!(5, default.data_offset());
        assert_eq!(false, default.ns);
        assert_eq!(false, default.fin);
        assert_eq!(false, default.syn);
        assert_eq!(false, default.rst);
        assert_eq!(false, default.psh);
        assert_eq!(false, default.ack);
        assert_eq!(false, default.ece);
        assert_eq!(false, default.urg);
        assert_eq!(false, default.cwr);
        assert_eq!(0, default.window_size);
        assert_eq!(0, default.checksum);
        assert_eq!(0, default.urgent_pointer);
        assert_eq!(&[0; 40][0..0], &default.options()[..]);
    }

    proptest! {
        #[test]
        fn debug(header in tcp_any()) {

            // normal debug printing
            assert_eq!(
                format!(
                    "TcpHeader {{ source_port: {}, destination_port: {}, sequence_number: {}, acknowledgment_number: {}, data_offset: {}, ns: {}, fin: {}, syn: {}, rst: {}, psh: {}, ack: {}, urg: {}, ece: {}, cwr: {}, window_size: {}, checksum: {}, urgent_pointer: {}, options: {:?} }}", 
                    header.source_port,
                    header.destination_port,
                    header.sequence_number,
                    header.acknowledgment_number,
                    header.data_offset(),
                    header.ns,
                    header.fin,
                    header.syn,
                    header.rst,
                    header.psh,
                    header.ack,
                    header.urg,
                    header.ece,
                    header.cwr,
                    header.window_size,
                    header.checksum,
                    header.urgent_pointer,
                    header.options_iterator()
                ),
                format!("{:?}", header)
            );

            // multi line debug printing
            {
                let mut header = header.clone();
                // lets exclude options for now, as I am not quiet sure
                // how to introduce additional indentation and the options
                // part is already checked by the previous test
                header.set_options(&[]).unwrap();
                assert_eq!(
                    format!(
                        "TcpHeader {{
    source_port: {},
    destination_port: {},
    sequence_number: {},
    acknowledgment_number: {},
    data_offset: {},
    ns: {},
    fin: {},
    syn: {},
    rst: {},
    psh: {},
    ack: {},
    urg: {},
    ece: {},
    cwr: {},
    window_size: {},
    checksum: {},
    urgent_pointer: {},
    options: {:?},
}}",
                        header.source_port,
                        header.destination_port,
                        header.sequence_number,
                        header.acknowledgment_number,
                        header.data_offset(),
                        header.ns,
                        header.fin,
                        header.syn,
                        header.rst,
                        header.psh,
                        header.ack,
                        header.urg,
                        header.ece,
                        header.cwr,
                        header.window_size,
                        header.checksum,
                        header.urgent_pointer,
                        header.options_iterator()
                    ),
                    format!("{:#?}", header)
                );
            }
        }
    }

    #[test]
    fn eq() {
        let options = [
            TcpOptionElement::Timestamp(0x00102030, 0x01112131), //10
            TcpOptionElement::SelectiveAcknowledgement(
                (0x02122232, 0x03132333),
                [None, None, None],
            ), //20
            TcpOptionElement::Timestamp(0x04142434, 0x05152535), //30
            TcpOptionElement::Timestamp(0x06162636, 0x07172737), //40
        ];

        let base: TcpHeader = {
            let mut base: TcpHeader = Default::default();
            base.source_port = 1;
            base.destination_port = 2;
            base.sequence_number = 3;
            base.acknowledgment_number = 4;
            base.window_size = 6;
            base.checksum = 7;
            base.urgent_pointer = 8;
            base.set_options(&options[..]).unwrap();

            base
        };

        //equal
        {
            let other = base.clone();
            assert_eq!(other, base);
        }
        //change every field anc check for neq
        //source_port
        {
            let mut other = base.clone();
            other.source_port = 10;
            assert_ne!(other, base);
        }
        //destination_port
        {
            let mut other = base.clone();
            other.destination_port = 10;
            assert_ne!(other, base);
        }
        //sequence_number
        {
            let mut other = base.clone();
            other.sequence_number = 10;
            assert_ne!(other, base);
        }
        //acknowledgment_number
        {
            let mut other = base.clone();
            other.acknowledgment_number = 10;
            assert_ne!(other, base);
        }
        //data_offset
        {
            let mut other = base.clone();
            other
                .set_options(&[TcpOptionElement::MaximumSegmentSize(16)])
                .unwrap();
            assert_ne!(other, base);
        }
        //ns
        {
            let mut other = base.clone();
            other.ns = true;
            assert_ne!(other, base);
        }
        //fin
        {
            let mut other = base.clone();
            other.fin = true;
            assert_ne!(other, base);
        }
        //syn
        {
            let mut other = base.clone();
            other.syn = true;
            assert_ne!(other, base);
        }
        //rst
        {
            let mut other = base.clone();
            other.rst = true;
            assert_ne!(other, base);
        }
        //psh
        {
            let mut other = base.clone();
            other.psh = true;
            assert_ne!(other, base);
        }
        //ack
        {
            let mut other = base.clone();
            other.ack = true;
            assert_ne!(other, base);
        }
        //ece
        {
            let mut other = base.clone();
            other.ece = true;
            assert_ne!(other, base);
        }
        //urg
        {
            let mut other = base.clone();
            other.urg = true;
            assert_ne!(other, base);
        }
        //cwr
        {
            let mut other = base.clone();
            other.cwr = true;
            assert_ne!(other, base);
        }
        //window_size
        {
            let mut other = base.clone();
            other.window_size = 10;
            assert_ne!(other, base);
        }
        //checksum
        {
            let mut other = base.clone();
            other.checksum = 10;
            assert_ne!(other, base);
        }
        //urgent_pointer
        {
            let mut other = base.clone();
            other.urgent_pointer = 10;
            assert_ne!(other, base);
        }
        //options (first element different)
        {
            let mut other = base.clone();
            other
                .set_options(&{
                    let mut other_options = options.clone();
                    other_options[0] = TcpOptionElement::Timestamp(0x00102039, 0x01112131);
                    other_options
                })
                .unwrap();

            assert_ne!(other, base);
        }
        //options (last element)
        {
            let mut other = base.clone();
            other.set_options(&options).unwrap();

            let mut other2 = base.clone();
            other2
                .set_options(&{
                    let mut options2 = options.clone();
                    options2[3] = TcpOptionElement::Timestamp(0x06162636, 0x97172737);
                    options2
                })
                .unwrap();

            assert_ne!(other, other2);
        }
        //options (check only relevant data is compared)
        {
            let mut other = base.clone();
            other.set_options(&options).unwrap();

            let mut other2 = base.clone();
            other2
                .set_options(&{
                    let mut options2 = options.clone();
                    options2[3] = TcpOptionElement::Timestamp(0x06162636, 0x97172737);
                    options2
                })
                .unwrap();

            // reset the data
            let new_options = [TcpOptionElement::Timestamp(0x00102030, 0x01112131)];
            other.set_options(&new_options).unwrap();
            other2.set_options(&new_options).unwrap();

            assert_eq!(other, other2);
        }
    }

    proptest! {
        #[test]
        fn new(
            source_port in any::<u16>(),
            destination_port in any::<u16>(),
            sequence_number in any::<u32>(),
            window_size in any::<u16>()
        ) {
            let header = TcpHeader::new(
                source_port,
                destination_port,
                sequence_number,
                window_size
            );
            assert_eq!(header.source_port, source_port);
            assert_eq!(header.destination_port, destination_port);
            assert_eq!(header.sequence_number, sequence_number);
            assert_eq!(header.acknowledgment_number, 0);
            assert_eq!(header._data_offset, 5);
            assert_eq!(header.ns, false);
            assert_eq!(header.fin, false);
            assert_eq!(header.syn, false);
            assert_eq!(header.rst, false);
            assert_eq!(header.psh, false);
            assert_eq!(header.ack, false);
            assert_eq!(header.urg, false);
            assert_eq!(header.ece, false);
            assert_eq!(header.cwr, false);
            assert_eq!(header.window_size, window_size);
            assert_eq!(header.checksum, 0);
            assert_eq!(header.urgent_pointer, 0);
            assert_eq!(header.options_buffer, [0u8;40]);
        }
    }

    proptest! {
        #[test]
        fn data_offset(header in tcp_any()) {
            assert_eq!(header.options().len()/4 + 5, header.data_offset().into());
        }
    }

    proptest! {
        #[test]
        fn header_len(header in tcp_any()) {
            assert_eq!(
                header.header_len(),
                (20 + header.options().len()) as u16
            );
        }
    }

    proptest! {
        #[test]
        fn options_len(header in tcp_any()) {
            assert_eq!(
                header.options_len(),
                header.to_bytes().len() - 20
            );
        }
    }

    proptest! {
        #[test]
        fn options(header in tcp_any()) {
            assert_eq!(
                header.options(),
                &header.to_bytes()[20..]
            );
        }
    }

    proptest! {
        #[test]
        #[rustfmt::skip]
        fn set_options(
            header in tcp_any(),
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
            ack_args in proptest::collection::vec(any::<u32>(), 4*2),
            arg0_u32 in any::<u32>(),
            arg1_u32 in any::<u32>()
        ) {
            use crate::TcpOptionElement::*;

            // maximum segment size
            {
                let mut header = header.clone();
                header.set_options(
                    &[Noop, Noop, MaximumSegmentSize(arg_u16), Noop]
                ).unwrap();
                assert_eq!(
                    header.options(),
                    &{
                        let arg_be = arg_u16.to_be_bytes();
                        [
                            KIND_NOOP, KIND_NOOP, KIND_MAXIMUM_SEGMENT_SIZE, 4,
                            arg_be[0], arg_be[1], KIND_NOOP, KIND_END
                        ]
                    }
                );
            }

            // window scale
            {
                let mut header = header.clone();
                header.set_options(
                    &[Noop, Noop, WindowScale(arg_u8), Noop]
                ).unwrap();
                assert_eq!(
                    header.options(),
                    &[
                        KIND_NOOP, KIND_NOOP, KIND_WINDOW_SCALE, 3,
                        arg_u8, KIND_NOOP, KIND_END, 0
                    ]
                );
            }

            // selective ack permitted
            {
                let mut header = header.clone();
                header.set_options(
                    &[Noop, Noop, SelectiveAcknowledgementPermitted, Noop]
                ).unwrap();
                assert_eq!(
                    header.options(),
                    &[
                        KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK_PERMITTED, 2,
                        KIND_NOOP, KIND_END, 0, 0
                    ]
                );
            }

            // selective ack
            {
                let args_be : Vec<[u8;4]> = ack_args.iter().map(|v| v.to_be_bytes()).collect();

                //1
                {
                    let mut header = header.clone();
                    header.set_options(
                        &[Noop, Noop, SelectiveAcknowledgement((ack_args[0], ack_args[1]), [None, None, None]), Noop]
                    ).unwrap();
                    assert_eq!(
                        header.options(),
                        &[
                            KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 10,
                            args_be[0][0], args_be[0][1], args_be[0][2], args_be[0][3],
                            args_be[1][0], args_be[1][1], args_be[1][2], args_be[1][3],
                            KIND_NOOP, KIND_END, 0, 0
                        ]
                    );
                }

                //2
                {
                    let mut header = header.clone();
                    header.set_options(
                        &[
                            Noop,
                            Noop,
                            SelectiveAcknowledgement(
                                (ack_args[0], ack_args[1]),
                                [Some((ack_args[2], ack_args[3])), None, None]
                            ),
                            Noop
                        ]
                    ).unwrap();
                    assert_eq!(
                        header.options(),
                        [
                            KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 18,
                            args_be[0][0], args_be[0][1], args_be[0][2], args_be[0][3],
                            args_be[1][0], args_be[1][1], args_be[1][2], args_be[1][3],
                            args_be[2][0], args_be[2][1], args_be[2][2], args_be[2][3],
                            args_be[3][0], args_be[3][1], args_be[3][2], args_be[3][3],
                            KIND_NOOP, KIND_END, 0, 0
                        ]
                    );
                }

                //3
                {
                    let mut header = header.clone();
                    header.set_options(
                        &[
                            Noop,
                            Noop,
                            SelectiveAcknowledgement(
                                (ack_args[0], ack_args[1]),
                                [
                                    Some((ack_args[2], ack_args[3])),
                                    Some((ack_args[4], ack_args[5])),
                                    None
                                ]
                            ),
                            Noop
                        ]
                    ).unwrap();
                    assert_eq!(
                        header.options(),
                        &[
                            KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 26,
                            args_be[0][0], args_be[0][1], args_be[0][2], args_be[0][3],
                            args_be[1][0], args_be[1][1], args_be[1][2], args_be[1][3],
                            args_be[2][0], args_be[2][1], args_be[2][2], args_be[2][3],
                            args_be[3][0], args_be[3][1], args_be[3][2], args_be[3][3],
                            args_be[4][0], args_be[4][1], args_be[4][2], args_be[4][3],
                            args_be[5][0], args_be[5][1], args_be[5][2], args_be[5][3],
                            KIND_NOOP, KIND_END, 0, 0
                        ]
                    );
                }

                //4
                {
                    let mut header = header.clone();
                    header.set_options(
                        &[
                            Noop,
                            Noop,
                            SelectiveAcknowledgement(
                                (ack_args[0], ack_args[1]),
                                [
                                    Some((ack_args[2], ack_args[3])),
                                    Some((ack_args[4], ack_args[5])),
                                    Some((ack_args[6], ack_args[7]))
                                ]
                            ),
                            Noop
                        ]
                    ).unwrap();
                    assert_eq!(
                        header.options(),
                        &[
                            KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 34,
                            args_be[0][0], args_be[0][1], args_be[0][2], args_be[0][3],
                            args_be[1][0], args_be[1][1], args_be[1][2], args_be[1][3],
                            args_be[2][0], args_be[2][1], args_be[2][2], args_be[2][3],
                            args_be[3][0], args_be[3][1], args_be[3][2], args_be[3][3],
                            args_be[4][0], args_be[4][1], args_be[4][2], args_be[4][3],
                            args_be[5][0], args_be[5][1], args_be[5][2], args_be[5][3],
                            args_be[6][0], args_be[6][1], args_be[6][2], args_be[6][3],
                            args_be[7][0], args_be[7][1], args_be[7][2], args_be[7][3],
                            KIND_NOOP, KIND_END, 0, 0
                        ]
                    );
                }
            }

            // timestamp
            {
                let mut header = header.clone();
                header.set_options(
                    &[Noop, Noop, Timestamp(arg0_u32, arg1_u32), Noop]
                ).unwrap();
                assert_eq!(
                    header.options(),
                    &{
                        let arg0_be = arg0_u32.to_be_bytes();
                        let arg1_be = arg1_u32.to_be_bytes();
                        [
                            KIND_NOOP, KIND_NOOP, KIND_TIMESTAMP, 10,
                            arg0_be[0], arg0_be[1], arg0_be[2], arg0_be[3],
                            arg1_be[0], arg1_be[1], arg1_be[2], arg1_be[3],
                            KIND_NOOP, KIND_END, 0, 0
                        ]
                    }
                );
            }

            // check for padding
            {
                let mut header = header.clone();
                header.set_options(&[
                    MaximumSegmentSize(1400),          // 4
                    SelectiveAcknowledgementPermitted, // 2
                    Timestamp(2661445915, 0),          // 10
                    Noop,                              // 1
                    WindowScale(7),                    // 3
                ]).unwrap(); // total 20
                // + header 20 = 40 byte
                assert_eq!(40, header.header_len());
            }

            // not enough memory error
            {
                let mut header = header.clone();
                assert_eq!(
                    Err(TcpOptionWriteError::NotEnoughSpace(41)),
                    header.set_options(&[
                        MaximumSegmentSize(1),                                        //4
                        WindowScale(2),                                               //+3 = 7
                        SelectiveAcknowledgementPermitted,                            //+2 = 9
                        SelectiveAcknowledgement((3, 4), [Some((5, 6)), None, None]), // + 18 = 27
                        Timestamp(5, 6),                                              // + 10 = 37
                        Noop,
                        Noop,
                        Noop,
                        Noop // + 4
                    ])
                );
                //test with all fields filled of the selective ack
                assert_eq!(
                    Err(TcpOptionWriteError::NotEnoughSpace(41)),
                    header.set_options(&[
                        Noop,                                                                         // 1
                        SelectiveAcknowledgement((3, 4), [Some((5, 6)), Some((5, 6)), Some((5, 6))]), // + 34 = 35
                        MaximumSegmentSize(1), // + 4 = 39
                        Noop,
                        Noop // + 2 = 41
                    ])
                );
        
                //test with all fields filled of the selective ack
                assert_eq!(
                    Err(TcpOptionWriteError::NotEnoughSpace(41)),
                    header.set_options(&[
                        Noop,                                                 // 1
                        SelectiveAcknowledgement((3, 4), [None, None, None]), // + 10 = 11
                        Timestamp(1, 2),                                      // + 10 = 21
                        Timestamp(1, 2),                                      // + 10 = 31
                        MaximumSegmentSize(1),                                // + 4 = 35
                        Noop,
                        Noop,
                        Noop,
                        Noop,
                        Noop,
                        Noop // + 6 = 41
                    ])
                );
            }
        }
    }

    proptest! {
        #[test]
        fn set_options_raw(header in tcp_any()) {
            let base: TcpHeader = Default::default();

            let dummy = [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
            ];

            //ok size -> expect output based on options size
            for i in 0..40 {
                let mut header = header.clone();
                //set the options
                header.set_options_raw(&dummy[..i]).unwrap();

                //determine the expected options length
                let mut options_length = i / 4;
                if i % 4 != 0 {
                    options_length += 1;
                }
                options_length = options_length * 4;

                //expecetd data
                let mut expected_options = [0; 40];
                expected_options[..i].copy_from_slice(&dummy[..i]);

                assert_eq!(options_length, header.options_len());
                assert_eq!(
                    (options_length / 4) as u8 + TcpHeader::MIN_DATA_OFFSET,
                    header.data_offset()
                );
                assert_eq!(&expected_options[..options_length], header.options());
            }

            //too big -> expect error
            let mut header = base.clone();
            use crate::TcpOptionWriteError::*;
            assert_eq!(
                Err(NotEnoughSpace(dummy.len())),
                header.set_options_raw(&dummy[..])
            );
        }
    }

    #[test]
    fn options_iterator() {
        let options = [
            TcpOptionElement::Timestamp(0x00102030, 0x01112131), //10
            TcpOptionElement::SelectiveAcknowledgement((0x02122232, 0x03132333), [None, None, None]), //20
            TcpOptionElement::Timestamp(0x04142434, 0x05152535), //30
            TcpOptionElement::Timestamp(0x06162636, 0x07172737), //40
        ];

        let base: TcpHeader = {
            let mut base: TcpHeader = Default::default();
            base.set_options(&options[..]).unwrap();
            base
        };

        assert_eq!(
            &options[..],
            &base
                .options_iterator()
                .map(|x| x.unwrap())
                .collect::<Vec<TcpOptionElement>>()[..]
        );
    }

    proptest! {
        #[test]
        #[allow(deprecated)]
        fn read_from_slice(header in tcp_any()) {
            // ok case
            {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes.try_extend_from_slice(
                        &([0u8;TcpHeader::MAX_LEN])[..bytes.remaining_capacity()]
                    ).unwrap();
                    bytes
                };
                
                let (actual_header, actual_rest) = TcpHeader::read_from_slice(&bytes[..]).unwrap();
                assert_eq!(actual_header, header);
                assert_eq!(actual_rest, &bytes[header.header_len() as usize..]);
            }

            // data offset error
            for data_offset in 0..TcpHeader::MIN_DATA_OFFSET {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes[12] = (bytes[12] & 0xf) | ((data_offset << 4) & 0xf0);
                    bytes
                };
                assert_eq!(
                    TcpHeader::read_from_slice(&bytes[..]),
                    Err(Content(DataOffsetTooSmall{ data_offset }))
                );
            }

            // length error
            {
                let bytes = header.to_bytes();
                for len in 0..(header.header_len() as usize) {
                    assert_eq!(
                        TcpHeader::read_from_slice(&bytes[..len])
                            .unwrap_err(),
                        SliceLen(err::SliceLenError {
                            expected_min_len: if len < TcpHeader::MIN_LEN {
                                TcpHeader::MIN_LEN
                            } else {
                                header.header_len() as usize
                            },
                            actual_len: len,
                            layer: err::Layer::TcpHeader,
                        })
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn from_slice(header in tcp_any()) {
            // ok case
            {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes.try_extend_from_slice(
                        &([0u8;TcpHeader::MAX_LEN])[..bytes.remaining_capacity()]
                    ).unwrap();
                    bytes
                };
                
                let (actual_header, actual_rest) = TcpHeader::from_slice(&bytes[..]).unwrap();
                assert_eq!(actual_header, header);
                assert_eq!(actual_rest, &bytes[header.header_len() as usize..]);
            }

            // data offset error
            for data_offset in 0..TcpHeader::MIN_DATA_OFFSET {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes[12] = (bytes[12] & 0xf) | ((data_offset << 4) & 0xf0);
                    bytes
                };
                assert_eq!(
                    TcpHeader::from_slice(&bytes[..]),
                    Err(Content(DataOffsetTooSmall{ data_offset }))
                );
            }

            // length error
            {
                let bytes = header.to_bytes();
                for len in 0..(header.header_len() as usize) {
                    assert_eq!(
                        TcpHeader::from_slice(&bytes[..len])
                            .unwrap_err(),
                        SliceLen(err::SliceLenError {
                            expected_min_len: if len < TcpHeader::MIN_LEN {
                                TcpHeader::MIN_LEN
                            } else {
                                header.header_len() as usize
                            },
                            actual_len: len,
                            layer: err::Layer::TcpHeader,
                        })
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn read(header in tcp_any()) {
            // ok case
            {
                let bytes = header.to_bytes();
                let mut cursor = Cursor::new(&bytes[..]);
                let actual = TcpHeader::read(&mut cursor).unwrap();
                assert_eq!(header.header_len() as u64, cursor.position());
                assert_eq!(header, actual);
            }

            // data offset error
            for data_offset in 0..TcpHeader::MIN_DATA_OFFSET {
                let bytes = {
                    let mut bytes = header.to_bytes();
                    bytes[12] = (bytes[12] & 0xf) | ((data_offset << 4) & 0xf0);
                    bytes
                };
                assert_eq!(
                    TcpHeader::read(&mut Cursor::new(&bytes[..]))
                        .unwrap_err()
                        .content_error()
                        .unwrap(),
                    DataOffsetTooSmall{ data_offset }
                );
            }

            // length error
            {
                let bytes = header.to_bytes();
                for len in 0..(header.header_len() as usize) {
                    let mut cursor = Cursor::new(&bytes[..len]);
                    let err = TcpHeader::read(&mut cursor).unwrap_err();
                    assert!(err.io_error().is_some());
                }
            }
        }
    }

    proptest! {
        #[test]
        fn write(header in tcp_any()) {
            // ok
            {
                let mut bytes = [0u8;TcpHeader::MAX_LEN];
                let len = {
                    let mut cursor = Cursor::new(&mut bytes[..]);
                    header.write(&mut cursor).unwrap();
                    
                    cursor.position() as usize
                };
                assert_eq!(header.header_len() as usize, len);
                assert_eq!(
                    header,
                    TcpHeader::from_slice(&bytes[..len]).unwrap().0
                );
            }
            // length error
            for len in 0..header.header_len() {
                let mut bytes = [0u8;TcpHeader::MAX_LEN];
                let mut cursor = Cursor::new(&mut bytes[..len as usize]);
                let result = header.write(&mut cursor);
                assert!(result.is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn to_bytes(header in tcp_any()) {
            let bytes = header.to_bytes();
            let actual = TcpHeader::from_slice(&bytes).unwrap().0;
            assert_eq!(actual, header);
        }
    }

    #[test]
    fn calc_checksum_ipv4() {
        use crate::TcpOptionElement::*;

        // checksum == 0xf (no carries) (aka sum == 0xffff)
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];
            //write the tcp header
            let tcp = TcpHeader::new(0, 0, 40905, 0);
            let ip_header = Ipv4Header::new(
                //payload length
                tcp.header_len() + (tcp_payload.len() as u16),
                //time to live
                0,
                ip_number::TCP,
                //source ip address
                [0; 4],
                //destination ip address
                [0; 4],
            );
            assert_eq!(Ok(0x0), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
            assert_eq!(
                Ok(0x0),
                tcp.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &tcp_payload)
            );
        }

        //a header with options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            let ip_header = Ipv4Header::new(
                //payload length
                tcp.header_len() + (tcp_payload.len() as u16),
                //time to live
                20,
                //contained protocol is udp
                ip_number::TCP,
                //source ip address
                [192, 168, 1, 42],
                //destination ip address
                [192, 168, 1, 1],
            );

            //check checksum
            assert_eq!(Ok(0xdeeb), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        }

        //a header with an uneven number of options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            let ip_header = Ipv4Header::new(
                //payload length
                tcp.header_len() + (tcp_payload.len() as u16),
                //time to live
                20,
                //contained protocol is udp
                ip_number::TCP,
                //source ip address
                [192, 168, 1, 42],
                //destination ip address
                [192, 168, 1, 1],
            );

            //check checksum
            assert_eq!(Ok(0xd5ea), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        }

        // value error
        {
            // write the udp header
            let tcp: TcpHeader = Default::default();
            let len = (std::u16::MAX - tcp.header_len()) as usize + 1;
            let mut tcp_payload = Vec::with_capacity(len);
            tcp_payload.resize(len, 0);
            let ip_header = Ipv4Header::new(0, 0, ip_number::TCP, [0; 4], [0; 4]);
            assert_eq!(
                Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)),
                tcp.calc_checksum_ipv4(&ip_header, &tcp_payload)
            );
        }
    }


    #[test]
    fn calc_checksum_ipv4_raw() {

        // checksum == 0xf (no carries) (aka sum == 0xffff)
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];
            //write the tcp header
            let tcp = TcpHeader::new(0, 0, 40905, 0);
            assert_eq!(
                Ok(0x0),
                tcp.calc_checksum_ipv4_raw([0; 4], [0; 4], &tcp_payload)
            );
        }

        // a header with options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // check checksum
            assert_eq!(
                Ok(0xdeeb),
                tcp.calc_checksum_ipv4_raw([192, 168, 1, 42], [192, 168, 1, 1], &tcp_payload)
            );
        }

        // a header with an uneven number of options
        {
            let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9];

            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;
            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // check checksum
            assert_eq!(
                Ok(0xd5ea),
                tcp.calc_checksum_ipv4_raw([192, 168, 1, 42], [192, 168, 1, 1], &tcp_payload)
            );
        }

        // value error
        {
            // write the udp header
            let tcp: TcpHeader = Default::default();
            let len = (std::u16::MAX - tcp.header_len()) as usize + 1;
            let mut tcp_payload = Vec::with_capacity(len);
            tcp_payload.resize(len, 0);
            assert_eq!(
                Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)),
                tcp.calc_checksum_ipv4_raw([0; 4], [0; 4], &tcp_payload)
            );
        }
    }

    #[test]
    fn calc_checksum_ipv6() {
        
        // ok case
        {
            let tcp_payload = [51, 52, 53, 54, 55, 56, 57, 58];

            // setup tcp header
            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;

            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            use crate::TcpOptionElement::*;
            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            let ip_header = Ipv6Header {
                traffic_class: 1,
                flow_label: 0x81806,
                payload_length: tcp_payload.len() as u16 + tcp.header_len(),
                next_header: ip_number::TCP,
                hop_limit: 40,
                source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                destination: [
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                ],
            };
            // check checksum
            assert_eq!(Ok(0x786e), tcp.calc_checksum_ipv6(&ip_header, &tcp_payload));
        }

        // error
        #[cfg(target_pointer_width = "64")]
        {
            //write the udp header
            let tcp: TcpHeader = Default::default();
            let len = (std::u32::MAX - tcp.header_len() as u32) as usize + 1;

            //lets create a slice of that size that points to zero
            //(as most systems can not allocate blocks of the size of u32::MAX)
            let tcp_payload = unsafe {
                //NOTE: The pointer must be initialized with a non null value
                //      otherwise a key constraint of slices is not fullfilled
                //      which can lead to crashes in release mode.
                use core::ptr::NonNull;
                core::slice::from_raw_parts(NonNull::<u8>::dangling().as_ptr(), len)
            };
            let ip_header = Ipv6Header {
                traffic_class: 1,
                flow_label: 0x81806,
                payload_length: 0, //lets assume jumbograms behavior (set to 0, as bigger then u16)
                next_header: ip_number::TCP,
                hop_limit: 40,
                source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                destination: [
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
                ],
            };

            assert_eq!(
                Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)),
                tcp.calc_checksum_ipv6(&ip_header, &tcp_payload)
            );
        }
    }

    #[test]
    fn calc_checksum_ipv6_raw() {
        
        // ok case
        {
            let tcp_payload = [51, 52, 53, 54, 55, 56, 57, 58];

            //write the tcp header
            let mut tcp = TcpHeader::new(69, 42, 0x24900448, 0x3653);
            tcp.urgent_pointer = 0xE26E;

            tcp.ns = true;
            tcp.fin = true;
            tcp.syn = true;
            tcp.rst = true;
            tcp.psh = true;
            tcp.ack = true;
            tcp.ece = true;
            tcp.urg = true;
            tcp.cwr = true;

            use crate::TcpOptionElement::*;
            tcp.set_options(&[Noop, Noop, Noop, Noop, Timestamp(0x4161008, 0x84161708)])
                .unwrap();

            // check checksum
            assert_eq!(
                Ok(0x786e),
                tcp.calc_checksum_ipv6_raw(
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], 
                    [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,],
                    &tcp_payload
                )
            );
        }

        // error
        #[cfg(target_pointer_width = "64")]
        {
            //write the udp header
            let tcp: TcpHeader = Default::default();
            let len = (std::u32::MAX - tcp.header_len() as u32) as usize + 1;

            //lets create a slice of that size that points to zero
            //(as most systems can not allocate blocks of the size of u32::MAX)
            let tcp_payload = unsafe {
                //NOTE: The pointer must be initialized with a non null value
                //      otherwise a key constraint of slices is not fullfilled
                //      which can lead to crashes in release mode.
                use core::ptr::NonNull;
                core::slice::from_raw_parts(NonNull::<u8>::dangling().as_ptr(), len)
            };

            assert_eq!(
                Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)),
                tcp.calc_checksum_ipv6_raw(
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,],
                    &tcp_payload
                )
            );
        }
    }
}