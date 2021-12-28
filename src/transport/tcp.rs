use super::super::*;

use std::fmt::{Debug, Formatter};
use std::slice::from_raw_parts;

///The minimum size of the tcp header in bytes
pub const TCP_MINIMUM_HEADER_SIZE: usize = 5*4;
///The minimum data offset size (size of the tcp header itself).
pub const TCP_MINIMUM_DATA_OFFSET: u8 = 5;
///The maximum allowed value for the data offset (it is a 4 bit value).
pub const TCP_MAXIMUM_DATA_OFFSET: u8 = 0xf;

///TCP header according to rfc 793.
///
///Field descriptions copied from RFC 793 page 15++
#[derive(Clone)]
pub struct TcpHeader {
    ///The source port number.
    pub source_port: u16,
    ///The destination port number.
    pub destination_port: u16,
    ///The sequence number of the first data octet in this segment (except when SYN is present).
    ///
    ///If SYN is present the sequence number is the initial sequence number (ISN) 
    ///and the first data octet is ISN+1.
    ///[copied from RFC 793, page 16]
    pub sequence_number: u32,
    ///If the ACK control bit is set this field contains the value of the
    ///next sequence number the sender of the segment is expecting to
    ///receive.
    ///
    ///Once a connection is established this is always sent.
    pub acknowledgment_number: u32,
    ///The number of 32 bit words in the TCP Header.
    ///
    ///This indicates where the data begins.  The TCP header (even one including options) is an
    ///integral number of 32 bits long.
    _data_offset: u8,
    ///ECN-nonce - concealment protection (experimental: see RFC 3540)
    pub ns: bool,
    ///No more data from sender
    pub fin: bool,
    ///Synchronize sequence numbers
    pub syn: bool,
    ///Reset the connection
    pub rst: bool,
    ///Push Function
    pub psh: bool,
    ///Acknowledgment field significant
    pub ack: bool,
    ///Urgent Pointer field significant
    pub urg: bool,
    ///ECN-Echo (RFC 3168)
    pub ece: bool,
    ///Congestion Window Reduced (CWR) flag 
    ///
    ///This flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    pub cwr: bool,
    ///The number of data octets beginning with the one indicated in the
    ///acknowledgment field which the sender of this segment is willing to
    ///accept.
    pub window_size: u16,
    ///Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    pub checksum: u16,
    ///This field communicates the current value of the urgent pointer as a
    ///positive offset from the sequence number in this segment.
    ///
    ///The urgent pointer points to the sequence number of the octet following
    ///the urgent data.  This field is only be interpreted in segments with
    ///the URG control bit set.
    pub urgent_pointer: u16,
    ///Buffer containing the options of the header (note that the data_offset defines the actual length). Use the options() method if you want to get a slice that has the actual length of the options.
    options_buffer: [u8;40]
}

impl TcpHeader {

    ///Creates a TcpHeader with the given values and the rest initialized with default values.
    pub fn new(source_port: u16, destination_port: u16, sequence_number: u32, window_size: u16) -> TcpHeader {
        TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number: 0,
            _data_offset: TCP_MINIMUM_DATA_OFFSET,
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
            options_buffer: [0;40]
        }
    }

    ///The number of 32 bit words in the TCP Header.
    ///
    ///This indicates where the data begins.  The TCP header (even one including options) is an
    ///integral number of 32 bits long.
    pub fn data_offset(&self) -> u8 {
        self._data_offset
    }

    ///Returns the length of the header including the options.
    pub fn header_len(&self) -> u16 {
        u16::from(self._data_offset) * 4
    }

    ///Returns the options size in bytes based on the currently set data_offset. Returns None if the data_offset is smaller then the minimum size or bigger then the maximum supported size.
    pub fn options_len(&self) -> usize {
        debug_assert!(TCP_MINIMUM_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TCP_MAXIMUM_DATA_OFFSET);
        (self._data_offset - TCP_MINIMUM_DATA_OFFSET) as usize * 4
    }

    ///Returns a slice containing the options of the header (size is determined via the data_offset field.
    pub fn options(&self) -> &[u8] {
        &self.options_buffer[..self.options_len()]
    }

    ///Sets the options (overwrites the current options) or returns an error when there is not enough space.
    pub fn set_options(&mut self, options: &[TcpOptionElement]) -> Result<(), TcpOptionWriteError> {

        //calculate the required size of the options
        use crate::TcpOptionElement::*;
        let required_length = options.iter().fold(0, |acc, ref x| {
            acc + match x {
                Noop => 1,
                MaximumSegmentSize(_) => 4,
                WindowScale(_) => 3,
                SelectiveAcknowledgementPermitted => 2,
                SelectiveAcknowledgement(_, rest) => {
                    rest.iter().fold(10, |acc2, ref y| {
                        match y {
                            None => acc2,
                            Some(_) => acc2 + 8
                        }
                    })
                },
                Timestamp(_, _) => 10,
            }
        });

        if self.options_buffer.len() < required_length {
            Err(TcpOptionWriteError::NotEnoughSpace(required_length))
        } else {

            //reset the options to null
            self.options_buffer = [0;40];
            self._data_offset = TCP_MINIMUM_DATA_OFFSET;

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
                    },
                    MaximumSegmentSize(value) => {
                        // determine insertion area
                        let insert = &mut self.options_buffer[i..i+4];
                        i += 4;

                        // write data
                        insert[0] = KIND_MAXIMUM_SEGMENT_SIZE;
                        insert[1] = 4;
                        insert[2..4].copy_from_slice(&value.to_be_bytes());
                    },
                    WindowScale(value) => {
                        // determine insertion area
                        let insert = &mut self.options_buffer[i..i+3];
                        i += 3;

                        // write data
                        insert[0] = KIND_WINDOW_SCALE;
                        insert[1] = 3;
                        insert[2] = *value;
                    },
                    SelectiveAcknowledgementPermitted => {
                        // determine insertion area
                        let insert = &mut self.options_buffer[i..i+2];
                        i += 2;

                        // write data
                        insert[0] = KIND_SELECTIVE_ACK_PERMITTED;
                        insert[1] = 2;
                    },
                    SelectiveAcknowledgement(first, rest) => {
                        //write guranteed data
                        {
                            let insert = &mut self.options_buffer[i..i + 10];
                            i += 10;

                            insert[0] = KIND_SELECTIVE_ACK;
                            //write the length
                            insert[1] = rest.iter().fold(10, |acc, ref y| {
                                match y {
                                    None => acc,
                                    Some(_) => acc + 8
                                }
                            });
                            // write first
                            insert[2..6].copy_from_slice(&first.0.to_be_bytes());
                            insert[6..10].copy_from_slice(&first.1.to_be_bytes());
                        }
                        //write the rest
                        for v in rest {
                            match v {
                                None => {},
                                Some((a,b)) => {
                                    // determine insertion area
                                    let insert = &mut self.options_buffer[i..i + 8];
                                    i += 8;

                                    // insert
                                    insert[0..4].copy_from_slice(&a.to_be_bytes());
                                    insert[4..8].copy_from_slice(&b.to_be_bytes());
                                }
                            }
                        }
                    },
                    Timestamp(a, b) =>  {
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
                self._data_offset = (i / 4) as u8 + TCP_MINIMUM_DATA_OFFSET;
                if i % 4 != 0 {
                    self._data_offset += 1;
                }
            }
            //done
            Ok(())
        }
    }

    ///Sets the options to the data given.
    pub fn set_options_raw(&mut self, data: &[u8]) -> Result<(), TcpOptionWriteError> {
        //check length
        if self.options_buffer.len() < data.len() {
            Err(TcpOptionWriteError::NotEnoughSpace(data.len()))
        } else {
            //reset all to zero to ensure padding
            self.options_buffer = [0;40];

            //set data & data_offset
            self.options_buffer[..data.len()].copy_from_slice(data);
            self._data_offset = (data.len() / 4) as u8 + TCP_MINIMUM_DATA_OFFSET;
            if data.len() % 4 != 0 {
                self._data_offset += 1;
            }
            Ok(())
        }
    }

    /// Returns an iterator that allows to iterate through all known TCP header options.
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator {
            options: &self.options_buffer[..self.options_len()]
        }
    }

    /// Renamed to `TcpHeader::from_slice`
    #[deprecated(
        since = "0.10.1",
        note = "Use TcpHeader::from_slice instead."
    )]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), ReadError> {
        TcpHeader::from_slice(slice)
    }

    /// Reads a tcp header from a slice
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), ReadError> {
        let h = TcpHeaderSlice::from_slice(slice)?;
        Ok((
            h.to_header(),
            &slice[h.slice().len()..]
        ))
    }

    /// Read a tcp header from the current position
    pub fn read<T: io::Read + Sized>(reader: &mut T) -> Result<TcpHeader, ReadError> {
        let raw = {
            let mut raw : [u8;20] = [0;20];
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

        Ok(TcpHeader{
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
                if data_offset < TCP_MINIMUM_DATA_OFFSET {
                    return Err(ReadError::TcpDataOffsetTooSmall(data_offset));
                } else {
                    let mut buffer: [u8;40] = [0;40];
                    //convert to bytes minus the tcp header size itself
                    let len = ((data_offset - TCP_MINIMUM_DATA_OFFSET) as usize)*4;
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
        debug_assert!(TCP_MINIMUM_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TCP_MAXIMUM_DATA_OFFSET);

        let src_be = self.source_port.to_be_bytes();
        let dst_be = self.destination_port.to_be_bytes();
        let seq_be = self.sequence_number.to_be_bytes();
        let ack_be = self.acknowledgment_number.to_be_bytes();
        let window_be = self.window_size.to_be_bytes();
        let checksum_be = self.checksum.to_be_bytes();
        let urg_ptr_be = self.urgent_pointer.to_be_bytes();

        writer.write_all(
            &[
                src_be[0], src_be[1], dst_be[0], dst_be[1],
                seq_be[0], seq_be[1], seq_be[2], seq_be[3],
                ack_be[0], ack_be[1], ack_be[2], ack_be[3],
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
                window_be[0], window_be[1],
                checksum_be[0], checksum_be[1], urg_ptr_be[0], urg_ptr_be[1]
            ]
        )?;

        //write options if the data_offset is large enough
        if self._data_offset > TCP_MINIMUM_DATA_OFFSET {
            let len = ((self._data_offset - TCP_MINIMUM_DATA_OFFSET) as usize)*4;
            writer.write_all(&self.options_buffer[..len])?;
        }
        Ok(())
    }

    /// Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, payload)
    }

    /// Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(&self, source_ip: [u8;4], destination_ip: [u8;4], payload: &[u8]) -> Result<u16, ValueError> {
        
        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize)*4 + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        // calculate the checksum
        Ok(
            self.calc_checksum_post_ip(
                checksum::Sum16BitWords::new()
                .add_4bytes(source_ip)
                .add_4bytes(destination_ip)
                .add_2bytes([0, ip_number::TCP])
                .add_2bytes((tcp_length as u16).to_be_bytes()),
                payload
            )
        )
    }

    /// Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, payload)
    }

    /// Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize)*4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        Ok(self.calc_checksum_post_ip(
            checksum::Sum16BitWords::new()
            .add_16bytes(source)
            .add_16bytes(destination)
            .add_4bytes((tcp_length as u32).to_be_bytes())
            .add_2bytes([0, ip_number::TCP]),
            payload))
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: checksum::Sum16BitWords, payload: &[u8]) -> u16 {
        ip_pseudo_header_sum
        .add_2bytes(self.source_port.to_be_bytes())
        .add_2bytes(self.destination_port.to_be_bytes())
        .add_4bytes(self.sequence_number.to_be_bytes())
        .add_4bytes(self.acknowledgment_number.to_be_bytes())
        .add_2bytes(
            [
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
                }
            ]
        )
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
            ns: false, fin: false, syn: false, rst: false,
            psh: false, ack: false, urg: false, ece: false,
            cwr: false,
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            options_buffer: [0;40]
        }
    }
}

//NOTE: I would have prefered to NOT write my own Debug & PartialEq implementation but there are no
//      default implementations availible for [u8;40] and the alternative of using [u32;10] would lead
//      to unsafe casting. Writing impl Debug for [u8;40] in a crate is also illegal as it could lead 
//      to an implementation collision between crates.
//      So the only option left to me was to write an implementation myself and deal with the added complexity
//      and potential added error source.
impl Debug for TcpHeader {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), std::fmt::Error> {
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

impl std::cmp::PartialEq for TcpHeader {
    fn eq(&self, other: &TcpHeader) -> bool {
        self.source_port == other.source_port &&
        self.destination_port == other.destination_port &&
        self.sequence_number == other.sequence_number &&
        self.acknowledgment_number == other.acknowledgment_number &&
        self._data_offset == other._data_offset &&
        self.ns == other.ns &&
        self.fin == other.fin &&
        self.syn == other.syn &&
        self.rst == other.rst &&
        self.psh == other.psh &&
        self.ack == other.ack &&  
        self.urg == other.urg &&
        self.ece == other.ece &&
        self.cwr == other.cwr &&
        self.window_size == other.window_size &&
        self.checksum == other.checksum &&
        self.urgent_pointer  == other.urgent_pointer &&
        self.options() == other.options()
    }
}

impl std::cmp::Eq for TcpHeader {}

///A slice containing an tcp header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> TcpHeaderSlice<'a> {

    ///Creates a slice containing an tcp header.
    pub fn from_slice(slice: &'a[u8]) -> Result<TcpHeaderSlice<'a>, ReadError> {
        //check length
        if slice.len() < TCP_MINIMUM_HEADER_SIZE {
            return Err(
                UnexpectedEndOfSliceError{
                    expected_min_len: TCP_MINIMUM_HEADER_SIZE,
                    actual_len: slice.len(),
                }.into()
            );
        }

        // SAFETY:
        // Safe as it is checked at the start of the function that the
        // length of the slice is at least TCP_MINIMUM_HEADER_SIZE (20).
        let data_offset = unsafe {
            (*slice.get_unchecked(12) & 0xf0) >> 4
        };
        let len = data_offset as usize * 4;

        if data_offset < TCP_MINIMUM_DATA_OFFSET {
            Err(ReadError::TcpDataOffsetTooSmall(data_offset))
        } else if slice.len() < len {
            Err(
                UnexpectedEndOfSliceError{
                    expected_min_len: len,
                    actual_len: slice.len(),
                }.into()
            )
        } else {
            //done
            Ok(TcpHeaderSlice::<'a>{
                // SAFETY:
                // Safe as there is a check above that the slice length
                // is at least len.
                slice: unsafe {
                    from_raw_parts(slice.as_ptr(), len)
                },
            })
        }
    }
    ///Returns the slice containing the tcp header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the destination port number.
    #[inline]
    pub fn source_port(&self) -> u16 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr())
        }
    }

    ///Read the destination port number.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    ///Read the sequence number of the first data octet in this segment (except when SYN is present).
    ///
    ///If SYN is present the sequence number is the initial sequence number (ISN) 
    ///and the first data octet is ISN+1.
    ///\[copied from RFC 793, page 16\]
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            get_unchecked_be_u32(self.slice.as_ptr().add(4))
        }
    }

    ///Reads the acknowledgment number.
    ///
    ///If the ACK control bit is set this field contains the value of the
    ///next sequence number the sender of the segment is expecting to
    ///receive.
    ///
    ///Once a connection is established this is always sent.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            get_unchecked_be_u32(self.slice.as_ptr().add(8))
        }
    }

    ///Read the number of 32 bit words in the TCP Header.
    ///
    ///This indicates where the data begins.  The TCP header (even one including options) is an
    ///integral number of 32 bits long.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            (*self.slice.get_unchecked(12) & 0b1111_0000) >> 4
        }
    }

    ///ECN-nonce - concealment protection (experimental: see RFC 3540)
    #[inline]
    pub fn ns(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(12) & 0b0000_0001)
        }
    }

    ///Read the fin flag (no more data from sender).
    #[inline]
    pub fn fin(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0000_0001)
        }
    }

    ///Reads the syn flag (synchronize sequence numbers).
    #[inline]
    pub fn syn(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0000_0010)
        }
    }

    ///Reads the rst flag (reset the connection).
    #[inline]
    pub fn rst(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0000_0100)
        }
    }

    ///Reads the psh flag (push function).
    #[inline]
    pub fn psh(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0000_1000)
        }
    }

    ///Reads the ack flag (acknowledgment field significant).
    #[inline]
    pub fn ack(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0001_0000)
        }
    }

    ///Reads the urg flag (Urgent Pointer field significant).
    #[inline]
    pub fn urg(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0010_0000)
        }
    }

    ///Read the ECN-Echo flag (RFC 3168).
    #[inline]
    pub fn ece(&self) -> bool {
        // SAFETY:
        // Constructor checks that the slice has at least the length
        // of 20.
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b0100_0000)
        }
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
        unsafe {
            0 != (*self.slice.get_unchecked(13) & 0b1000_0000)
        }
    }

    ///The number of data octets beginning with the one indicated in the
    ///acknowledgment field which the sender of this segment is willing to
    ///accept.
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe {
                [
                    *self.slice.get_unchecked(14),
                    *self.slice.get_unchecked(15),
                ]
            }
        )
    }

    ///Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe {
                [
                    *self.slice.get_unchecked(16),
                    *self.slice.get_unchecked(17),
                ]
            }
        )
    }

    ///This field communicates the current value of the urgent pointer as a
    ///positive offset from the sequence number in this segment.
    ///
    ///The urgent pointer points to the sequence number of the octet following
    ///the urgent data.  This field is only be interpreted in segments with
    ///the URG control bit set.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Constructor checks that the slice has at least the length
            // of 20.
            unsafe {
                [
                    *self.slice.get_unchecked(18),
                    *self.slice.get_unchecked(19),
                ]
            }
        )
    }

    ///Options of the header
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.slice[TCP_MINIMUM_HEADER_SIZE..self.data_offset() as usize*4]
    }

    ///Returns an iterator that allows to iterate through all known TCP header options.
    #[inline]
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator::from_slice(self.options())
    }

    ///Decode all the fields and copy the results to a TcpHeader struct
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
                let mut result: [u8;40] = [0;40];
                if !options.is_empty() {
                    result[..options.len()].clone_from_slice(options);
                }
                result
            }
        }
    }

    ///Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4HeaderSlice, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source(), ip_header.destination(), payload)
    }

    ///Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(&self, source_ip: [u8;4], destination_ip: [u8;4], payload: &[u8]) -> Result<u16, ValueError> {
        
        //check that the total length fits into the field
        let tcp_length = self.slice.len() + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        //calculate the checksum
        Ok(
            self.calc_checksum_post_ip(
                checksum::Sum16BitWords::new()
                .add_4bytes(source_ip)
                .add_4bytes(destination_ip)
                .add_2bytes([0, ip_number::TCP])
                .add_2bytes((tcp_length as u16).to_be_bytes()),
                payload
            )
        )
    }

    ///Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6HeaderSlice, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source(), ip_header.destination(), payload)
    }

    ///Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = (self.data_offset() as usize)*4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        Ok(
            self.calc_checksum_post_ip(
                checksum::Sum16BitWords::new()
                .add_16bytes(source)
                .add_16bytes(destination)
                .add_2bytes([0, ip_number::TCP])
                .add_4bytes((tcp_length as u32).to_be_bytes()),
                payload
            )
        )
    }

    /// This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: checksum::Sum16BitWords, payload: &[u8]) -> u16 {
        ip_pseudo_header_sum
        .add_slice(&self.slice[..16]) //until checksum
        .add_slice(&self.slice[18..self.slice.len()])
        .add_slice(payload)
        .ones_complement()
        .to_be()
    }
}

/// Different kinds of options that can be present in the options part of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionElement {
    /// "No-Operation" option.
    ///
    /// Description from RFC 793:
    ///
    /// This option code may be used between options, for example, to
    /// align the beginning of a subsequent option on a word boundary.
    /// There is no guarantee that senders will use this option, so
    /// receivers must be prepared to process options even if they do
    /// not begin on a word boundary.
    Noop,
    /// "Maximum Segment Size" option.
    ///
    /// Description from RFC 793:
    ///
    /// If this option is present, then it communicates the maximum
    /// receive segment size at the TCP which sends this segment.
    /// This field must only be sent in the initial connection request
    /// (i.e., in segments with the SYN control bit set).  If this
    //// option is not used, any segment size is allowed.
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SelectiveAcknowledgementPermitted,
    SelectiveAcknowledgement((u32,u32), [Option<(u32,u32)>;3]),
    ///Timestamp & echo (first number is the sender timestamp, the second the echo timestamp)
    Timestamp(u32, u32),
}

///Allows iterating over the options after a TCP header.
#[derive(Clone, Eq, PartialEq)]
pub struct TcpOptionsIterator<'a> {
    options: &'a [u8]
}

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_END instead"
)]
/// Deprecated please use [tcp_option::KIND_END] instead.
pub const TCP_OPTION_ID_END: u8 = 0;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_NOOP instead"
)]
/// Deprecated please use [tcp_option::KIND_NOOP] instead.
pub const TCP_OPTION_ID_NOP: u8 = 1;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_MAXIMUM_SEGMENT_SIZE instead"
)]
/// Deprecated please use [tcp_option::KIND_MAXIMUM_SEGMENT_SIZE] instead.
pub const TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE: u8 = 2;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_WINDOW_SCALE instead"
)]
/// Deprecated please use [tcp_option::KIND_WINDOW_SCALE] instead.
pub const TCP_OPTION_ID_WINDOW_SCALE: u8 = 3;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_SELECTIVE_ACK_PERMITTED instead"
)]
/// Deprecated please use [tcp_option::KIND_SELECTIVE_ACK_PERMITTED] instead.
pub const TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED: u8 = 4;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_SELECTIVE_ACK instead"
)]
/// Deprecated please use [tcp_option::KIND_SELECTIVE_ACK] instead.
pub const TCP_OPTION_ID_SELECTIVE_ACK: u8 = 5;

#[deprecated(
    since = "0.10.1",
    note = "Please use tcp_option::KIND_TIMESTAMP instead"
)]
/// Deprecated please use [tcp_option::KIND_TIMESTAMP] instead.
pub const TCP_OPTION_ID_TIMESTAMP: u8 = 8;

/// Module containing the constants for tcp options (id number & sizes).
pub mod tcp_option {
    /// `u8` identifying the "end of options list" in the tcp option.
    pub const KIND_END: u8 = 0;
    /// `u8` identifying a "no operation" tcp option.
    pub const KIND_NOOP: u8 = 1;
    /// `u8` identifying a "maximum segment size" tcp option.
    pub const KIND_MAXIMUM_SEGMENT_SIZE: u8 = 2;
    /// `u8` identifying a "window scaling" tcp option.
    pub const KIND_WINDOW_SCALE: u8 = 3;
    /// `u8` identifying a "selective acknowledgement permitted" tcp option.
    pub const KIND_SELECTIVE_ACK_PERMITTED: u8 = 4;
    /// `u8` identifying a "selective acknowledgement" tcp option.
    pub const KIND_SELECTIVE_ACK: u8 = 5;
    /// `u8` identifying a "timestamp and echo of previous timestamp" tcp option.
    pub const KIND_TIMESTAMP: u8 = 8;
    /// Length in octets/bytes of the "end" tcp option (includes kind value).
    pub const LEN_END: u8 = 1;
    /// Length in octets/bytes of the "no operation" tcp option (includes kind value).
    pub const LEN_NOOP: u8 = 1;
    /// Length in octets/bytes of the "maximum segment size" tcp option (includes kind value).
    pub const LEN_MAXIMUM_SEGMENT_SIZE: u8 = 4;
    /// Length in octets/bytes of the "window scaling" tcp option (includes kind value).
    pub const LEN_WINDOW_SCALE: u8 = 3;
    /// Length in octets/bytes of the "selective acknowledgement permitted" tcp option (includes kind value).
    pub const LEN_SELECTIVE_ACK_PERMITTED: u8 = 2;
    /// Length in octets/bytes of the "timestamp and echo of previous timestamp" tcp option (includes kind value).
    pub const LEN_TIMESTAMP: u8 = 10;
}

impl<'a> TcpOptionsIterator<'a> {
    ///Creates an options iterator from a slice containing encoded tcp options.
    pub fn from_slice(options: &'a [u8]) -> TcpOptionsIterator<'a> {
        TcpOptionsIterator{ options }
    }

    ///Returns the non processed part of the options slice.
    pub fn rest(&self) -> &'a [u8] {
        self.options
    }
}

impl<'a> Iterator for TcpOptionsIterator<'a> {
    type Item = Result<TcpOptionElement, TcpOptionReadError>;

    fn next(&mut self) -> Option<Self::Item> {

        use crate::TcpOptionReadError::*;
        use crate::TcpOptionElement::*;

        let expect_specific_size = |expected_size: u8, slice: &[u8]| -> Result<(), TcpOptionReadError> {
            let id = slice[0];
            if slice.len() < expected_size as usize {
                Err(
                    UnexpectedEndOfSlice{
                        option_id: id, 
                        expected_len: expected_size, 
                        actual_len: slice.len()
                    },
                )
            } else if slice[1] != expected_size {
                Err(UnexpectedSize{
                    option_id: slice[0],
                    size: slice[1] 
                })
            } else {
                Ok(())
            }
        };

        if self.options.is_empty() {
            None
        } else {
            //first determine the result
            use tcp_option::*;
            let result = match self.options[0] {
                //end
                KIND_END => {
                    None
                },
                KIND_NOOP => {
                    self.options = &self.options[1..];
                    Some(Ok(Noop))
                },
                KIND_MAXIMUM_SEGMENT_SIZE => {
                    match expect_specific_size(LEN_MAXIMUM_SEGMENT_SIZE, self.options) {
                        Err(value) => {
                            Some(Err(value))
                        },
                        _ => {
                            // SAFETY:
                            // Safe as the slice size is checked beforehand to be at
                            // least of size LEN_MAXIMUM_SEGMENT_SIZE (4).
                            let value = unsafe {
                                get_unchecked_be_u16(self.options.as_ptr().add(2))
                            };
                            self.options = &self.options[4..];
                            Some(Ok(MaximumSegmentSize(value)))
                        }
                    }
                },
                KIND_WINDOW_SCALE => {
                    match expect_specific_size(LEN_WINDOW_SCALE, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            let value = self.options[2];
                            self.options = &self.options[3..];
                            Some(Ok(WindowScale(value)))
                        }
                    }
                },
                KIND_SELECTIVE_ACK_PERMITTED => {
                    match expect_specific_size(LEN_SELECTIVE_ACK_PERMITTED, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            self.options = &self.options[2..];
                            Some(Ok(SelectiveAcknowledgementPermitted))
                        }
                    }
                },
                KIND_SELECTIVE_ACK => {
                    //check that the length field can be read
                    if self.options.len() < 2 {
                        Some(
                            Err(
                                UnexpectedEndOfSlice {
                                    option_id: self.options[0], 
                                    expected_len: 2, 
                                    actual_len: self.options.len()
                                }
                            )
                        )
                    } else {
                        //check that the length is an allowed one for this option
                        let len = self.options[1];
                        if len != 10 && len != 18 && len != 26 && len != 34 {
                            Some(Err(UnexpectedSize{
                                option_id: self.options[0],
                                size: len 
                            }))
                        } else if self.options.len() < (len as usize) {
                            Some(
                                Err(
                                    UnexpectedEndOfSlice {
                                        option_id: self.options[0], 
                                        expected_len: len, 
                                        actual_len: self.options.len()
                                    }
                                )
                            )
                        } else {
                            let mut acks: [Option<(u32,u32)>;3] = [None;3];
                            // SAFETY:
                            // This is safe as above the len is checked
                            // to be at least 10 and the slice len is
                            // checked to be at least len bytes.
                            let first = unsafe {
                                (
                                    get_unchecked_be_u32(self.options.as_ptr().add(2)),
                                    get_unchecked_be_u32(self.options.as_ptr().add(6)),
                                )
                            };
                            for (i, item) in acks.iter_mut()
                                                 .enumerate()
                                                 .take(3)
                            {
                                let offset = 2 + 8 + (i*8);
                                // SAFETY:
                                // len can only be 10, 18, 26 or 34
                                // therefore if the offset is smaller then the
                                // len, then at least 8 bytes can be read.
                                unsafe {
                                    if offset < (len as usize) {
                                        *item = Some(
                                            (
                                                get_unchecked_be_u32(self.options.as_ptr().add(offset)),
                                                get_unchecked_be_u32(self.options.as_ptr().add(offset + 4)),
                                            )
                                        );
                                    }
                                }
                            }
                            //iterate the options
                            self.options = &self.options[len as usize..];
                            Some(Ok(SelectiveAcknowledgement(first, acks)))
                        }
                    }
                },
                KIND_TIMESTAMP => {
                    match expect_specific_size(LEN_TIMESTAMP, self.options) {
                        Err(value) => Some(Err(value)),
                        
                        _ => unsafe {
                            let t = Timestamp(
                                // SAFETY:
                                // Safe as the len first gets checked to be equal
                                // LEN_TIMESTAMP (10).
                                get_unchecked_be_u32(self.options.as_ptr().add(2)),
                                get_unchecked_be_u32(self.options.as_ptr().add(6)),
                            );
                            self.options = &self.options[10..];
                            Some(Ok(t))
                        }
                    }
                },

                //unknown id
                _ => {
                    Some(Err(UnknownId(self.options[0])))
                },
            };

            //in case the result was an error or the end move the slice to an end position
            match result {
                None | Some(Err(_)) => {
                    let len = self.options.len();
                    self.options = &self.options[len..len];
                },
                _ => {}
            }

            //finally return the result
            result
        }
    }
}

impl<'a> Debug for TcpOptionsIterator<'a> {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), std::fmt::Error> {
        let mut list = fmt.debug_list();

        // create a copy and iterate over all elements
        for it in self.clone() {
            match it {
                Ok(e) => { list.entry(&e); },
                Err(e) => {
                    list.entry(&Result::<(), TcpOptionReadError>::Err(e.clone()));
                }
            }
        }

        list.finish()
    }
}
