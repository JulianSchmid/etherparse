use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt::{Debug, Formatter};

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
                        self.options_buffer[i] = KIND_MAXIMUM_SEGMENT_SIZE;
                        i += 1;
                        self.options_buffer[i] = 4;
                        i += 1;
                        BigEndian::write_u16(&mut self.options_buffer[i..i + 2], *value);
                        i += 2;
                    },
                    WindowScale(value) => {
                        self.options_buffer[i] = KIND_WINDOW_SCALE;
                        i += 1;
                        self.options_buffer[i] = 3;
                        i += 1;
                        self.options_buffer[i] = *value;
                        i += 1;
                    },
                    SelectiveAcknowledgementPermitted => {
                        self.options_buffer[i] = KIND_SELECTIVE_ACK_PERMITTED;
                        i += 1;
                        self.options_buffer[i] = 2;
                        i += 1;
                    },
                    SelectiveAcknowledgement(first, rest) => {
                        self.options_buffer[i] = KIND_SELECTIVE_ACK;
                        i += 1;

                        //write the length
                        self.options_buffer[i] = rest.iter().fold(10, |acc, ref y| {
                            match y {
                                None => acc,
                                Some(_) => acc + 8
                            }
                        });
                        i += 1;

                        //write first
                        BigEndian::write_u32(&mut self.options_buffer[i..i + 4], first.0);
                        i += 4;
                        BigEndian::write_u32(&mut self.options_buffer[i..i + 4], first.1);
                        i += 4;

                        //write the rest
                        for v in rest {
                            match v {
                                None => {},
                                Some((a,b)) => {
                                    BigEndian::write_u32(&mut self.options_buffer[i..i + 4], *a);
                                    i += 4;
                                    BigEndian::write_u32(&mut self.options_buffer[i..i + 4], *b);
                                    i += 4;
                                }
                            }
                        }
                    },
                    Timestamp(a, b) =>  {
                        self.options_buffer[i] = KIND_TIMESTAMP;
                        i += 1;
                        self.options_buffer[i] = 10;
                        i += 1;
                        BigEndian::write_u32(&mut self.options_buffer[i..i + 4], *a);
                        i += 4;
                        BigEndian::write_u32(&mut self.options_buffer[i..i + 4], *b);
                        i += 4;
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

    ///Returns an iterator that allows to iterate through all known TCP header options.
    pub fn options_iterator(&self) -> TcpOptionsIterator {
        TcpOptionsIterator {
            options: &self.options_buffer[..self.options_len()]
        }
    }

    ///Reads a tcp header from a slice
    pub fn read_from_slice(slice: &[u8]) -> Result<(TcpHeader, &[u8]), ReadError> {
        let h = TcpHeaderSlice::from_slice(slice)?;
        Ok((
            h.to_header(),
            &slice[h.slice().len()..]
        ))
    }

    ///Read a tcp header from the current position
    pub fn read<T: io::Read + Sized>(reader: &mut T) -> Result<TcpHeader, ReadError> {
        let source_port = reader.read_u16::<BigEndian>()?;
        let destination_port = reader.read_u16::<BigEndian>()?;
        let sequence_number = reader.read_u32::<BigEndian>()?;
        let acknowledgment_number = reader.read_u32::<BigEndian>()?;
        let (data_offset, ns) = {
            let value = reader.read_u8()?;
            ((value & 0xf0) >> 4, 0 != value & 1)
        };
        let flags = reader.read_u8()?;

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
            window_size: reader.read_u16::<BigEndian>()?,
            checksum: reader.read_u16::<BigEndian>()?,
            urgent_pointer: reader.read_u16::<BigEndian>()?,
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

    ///Write the tcp header to a stream (does NOT calculate the checksum).
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {

        //check that the data offset is within range
        debug_assert!(TCP_MINIMUM_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TCP_MAXIMUM_DATA_OFFSET);

        writer.write_u16::<BigEndian>(self.source_port)?;
        writer.write_u16::<BigEndian>(self.destination_port)?;
        writer.write_u32::<BigEndian>(self.sequence_number)?;
        writer.write_u32::<BigEndian>(self.acknowledgment_number)?;
        writer.write_u8({
            let value = (self._data_offset << 4) & 0xF0;
            if self.ns {
                value | 1
            } else {
                value
            }
        })?;
        writer.write_u8({
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
        })?;
        writer.write_u16::<BigEndian>(self.window_size)?;
        writer.write_u16::<BigEndian>(self.checksum)?;
        writer.write_u16::<BigEndian>(self.urgent_pointer)?;

        //write options if the data_offset is large enough
        if self._data_offset > TCP_MINIMUM_DATA_OFFSET {
            let len = ((self._data_offset - TCP_MINIMUM_DATA_OFFSET) as usize)*4;
            writer.write_all(&self.options_buffer[..len])?;
        }
        Ok(())
    }

    ///Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, payload)
    }

    ///Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(&self, source_ip: [u8;4], destination_ip: [u8;4], payload: &[u8]) -> Result<u16, ValueError> {
        
        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize)*4 + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        //calculate the checksum
        Ok(self.calc_checksum_post_ip(u64::from( BigEndian::read_u16(&source_ip[0..2]) ) + //pseudo header
                                      u64::from( BigEndian::read_u16(&source_ip[2..4]) ) +
                                      u64::from( BigEndian::read_u16(&destination_ip[0..2]) ) +
                                      u64::from( BigEndian::read_u16(&destination_ip[2..4]) ) +
                                      u64::from( ip_number::TCP ) +
                                      tcp_length as u64,
                                      payload))
    }

    ///Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, payload)
    }

    ///Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(&self, source: [u8;16], destination: [u8;16], payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize)*4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        fn calc_sum(value: [u8;16]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i*2;
                result += u64::from( BigEndian::read_u16(&value[index..(index + 2)]) );
            }
            result
        }
        Ok(self.calc_checksum_post_ip(
            calc_sum(source) +
            calc_sum(destination) +
            u64::from( ip_number::TCP ) +
            {
                let mut buffer: [u8;4] = Default::default();
                BigEndian::write_u32(&mut buffer[..], tcp_length as u32);
                u64::from( BigEndian::read_u16(&buffer[0..2]) ) +
                u64::from( BigEndian::read_u16(&buffer[2..4]) )
            },
            payload))
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {
        fn calc_u32_checksum(value: u32) -> u64 {
            let mut buffer: [u8;4] = [0;4];
            BigEndian::write_u32(&mut buffer, value);
            u64::from( BigEndian::read_u16(&buffer[..2]) ) + 
            u64::from( BigEndian::read_u16(&buffer[2..]) )
        }
        let mut sum = 
            ip_pseudo_header_sum +
            u64::from( self.source_port ) + //udp header start
            u64::from( self.destination_port ) +
            calc_u32_checksum(self.sequence_number) +
            calc_u32_checksum(self.acknowledgment_number) +
            u64::from( BigEndian::read_u16(&[
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
            ]) ) +
            u64::from( self.window_size ) +
            u64::from( self.urgent_pointer );

        //add the options
        let options_len = self.options_len();
        for i in RangeStep::new(0, options_len, 2) {
            sum += u64::from( BigEndian::read_u16(&self.options_buffer[i..i + 2]) );
        }

        //payload
        for i in RangeStep::new(0, payload.len()/2*2, 2) {
            sum += u64::from( BigEndian::read_u16(&payload[i..i + 2]) );
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += u64::from( BigEndian::read_u16(&[*payload.last().unwrap(), 0]) );
        }
        let carry_add = (sum & 0xffff) + 
                        ((sum >> 16) & 0xffff) +
                        ((sum >> 32) & 0xffff) +
                        ((sum >> 48) & 0xffff);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        !result
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
        use crate::ReadError::*;
        if slice.len() < TCP_MINIMUM_HEADER_SIZE {
            return Err(UnexpectedEndOfSlice(TCP_MINIMUM_HEADER_SIZE));
        }

        //read data offset
        let data_offset = (slice[12] & 0xf0) >> 4;
        let len = data_offset as usize * 4;

        if data_offset < TCP_MINIMUM_DATA_OFFSET {
            Err(ReadError::TcpDataOffsetTooSmall(data_offset))
        } else if slice.len() < len {
            Err(UnexpectedEndOfSlice(len))
        } else {
            //done
            Ok(TcpHeaderSlice::<'a>{
                slice: &slice[..len],
            })
        }
    }
    ///Returns the slice containing the tcp header
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the destination port number.
    pub fn source_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice[..2])
    }

    ///Read the destination port number.
    pub fn destination_port(&self) -> u16 {
        BigEndian::read_u16(&self.slice[2..4])
    }

    ///Read the sequence number of the first data octet in this segment (except when SYN is present).
    ///
    ///If SYN is present the sequence number is the initial sequence number (ISN) 
    ///and the first data octet is ISN+1.
    ///[copied from RFC 793, page 16]
    pub fn sequence_number(&self) -> u32 {
        BigEndian::read_u32(&self.slice[4..8])
    }

    ///Reads the acknowledgment number.
    ///
    ///If the ACK control bit is set this field contains the value of the
    ///next sequence number the sender of the segment is expecting to
    ///receive.
    ///
    ///Once a connection is established this is always sent.
    pub fn acknowledgment_number(&self) -> u32 {
        BigEndian::read_u32(&self.slice[8..12])
    }

    ///Read the number of 32 bit words in the TCP Header.
    ///
    ///This indicates where the data begins.  The TCP header (even one including options) is an
    ///integral number of 32 bits long.
    pub fn data_offset(&self) -> u8 {
        (self.slice[12] & 0xf0) >> 4
    }

    ///ECN-nonce - concealment protection (experimental: see RFC 3540)
    pub fn ns(&self) -> bool {
        0 != (self.slice[12] & 1)
    }

    ///Read the fin flag (no more data from sender).
    pub fn fin(&self) -> bool {
        0 != (self.slice[13] & 1)
    }

    ///Reads the syn flag (synchronize sequence numbers).
    pub fn syn(&self) -> bool {
        0 != (self.slice[13] & 2)
    }

    ///Reads the rst flag (reset the connection).
    pub fn rst(&self) -> bool {
        0 != (self.slice[13] & 4)
    }

    ///Reads the psh flag (push function).
    pub fn psh(&self) -> bool {
        0 != (self.slice[13] & 8)
    }

    ///Reads the ack flag (acknowledgment field significant).
    pub fn ack(&self) -> bool {
        0 != (self.slice[13] & 16)
    }

    ///Reads the urg flag (Urgent Pointer field significant).
    pub fn urg(&self) -> bool {
        0 != (self.slice[13] & 32)
    }

    ///Read the ECN-Echo flag (RFC 3168).
    pub fn ece(&self) -> bool {
        0 != (self.slice[13] & 64)
    }

    ///Reads the cwr flag (Congestion Window Reduced). 
    ///
    ///This flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    pub fn cwr(&self) -> bool {
        0 != (self.slice[13] & 128)
    }

    ///The number of data octets beginning with the one indicated in the
    ///acknowledgment field which the sender of this segment is willing to
    ///accept.
    pub fn window_size(&self) -> u16 {
        BigEndian::read_u16(&self.slice[14..16])
    }

    ///Checksum (16 bit one's complement) of the pseudo ip header, this tcp header and the payload.
    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.slice[16..18])
    }

    ///This field communicates the current value of the urgent pointer as a
    ///positive offset from the sequence number in this segment.
    ///
    ///The urgent pointer points to the sequence number of the octet following
    ///the urgent data.  This field is only be interpreted in segments with
    ///the URG control bit set.
    pub fn urgent_pointer(&self) -> u16 {
        BigEndian::read_u16(&self.slice[18..20])
    }

    ///Options of the header
    pub fn options(&self) -> &[u8] {
        &self.slice[TCP_MINIMUM_HEADER_SIZE..self.data_offset() as usize*4]
    }

    ///Returns an iterator that allows to iterate through all known TCP header options.
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
                    result[..options.len()].clone_from_slice(&options);
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
        Ok(self.calc_checksum_post_ip(u64::from( BigEndian::read_u16(&source_ip[0..2]) ) + //pseudo header
                                      u64::from( BigEndian::read_u16(&source_ip[2..4]) ) +
                                      u64::from( BigEndian::read_u16(&destination_ip[0..2]) ) +
                                      u64::from( BigEndian::read_u16(&destination_ip[2..4]) ) +
                                      u64::from( ip_number::TCP ) +
                                      tcp_length as u64,
                                      payload))
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

        fn calc_addr_sum(value: [u8;16]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i*2;
                result += u64::from( BigEndian::read_u16(&value[index..(index + 2)]) );
            }
            result
        }
        Ok(self.calc_checksum_post_ip(
            calc_addr_sum(source) +
            calc_addr_sum(destination) +
            u64::from( ip_number::TCP ) +
            {
                let mut buffer: [u8;4] = Default::default();
                BigEndian::write_u32(&mut buffer[..], tcp_length as u32);
                u64::from( BigEndian::read_u16(&buffer[0..2]) ) +
                u64::from( BigEndian::read_u16(&buffer[2..4]) )
            },
            payload))
    }

    ///This method takes the sum of the pseudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {

        let mut sum = ip_pseudo_header_sum;

        //until checksum
        for i in RangeStep::new(0, 16, 2) {
            sum += u64::from( BigEndian::read_u16(&self.slice[i..i + 2]) );
        }
        //after checksum
        for i in RangeStep::new(18, self.slice.len(), 2) {
            sum += u64::from( BigEndian::read_u16(&self.slice[i..i + 2]) );
        }
        //payload
        for i in RangeStep::new(0, payload.len()/2*2, 2) {
            sum += u64::from( BigEndian::read_u16(&payload[i..i + 2]) );
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += u64::from( BigEndian::read_u16(&[*payload.last().unwrap(), 0]) );
        }
        let carry_add = (sum & 0xffff) + 
                        ((sum >> 16) & 0xffff) +
                        ((sum >> 32) & 0xffff) +
                        ((sum >> 48) & 0xffff);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        !result
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

///Errors that can occour while reading the options of a TCP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionReadError {
    ///Returned if an option id was read, but there was not enough memory in the options left to completely read it.
    UnexpectedEndOfSlice(u8),

    ///Returned if the option as an unexpected size argument (e.g. != 4 for maximum segment size).
    UnexpectedSize{option_id: u8, size: u8 },

    ///Returned if an unknown tcp header option is encountered.
    ///
    ///The first element is the identifier and the slice contains the rest of data left in the options.
    UnknownId(u8),
}

///Errors that can occour when setting the options of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionWriteError {
    ///There is not enough memory to store all options in the options section of the header (maximum 40 bytes).
    ///
    ///The options size is limited by the 4 bit data_offset field in the header which describes
    ///the total tcp header size in multiple of 4 bytes. This leads to a maximum size for the options
    ///part of the header of 4*(15 - 5) (minus 5 for the size of the tcp header itself). 
    NotEnoughSpace(usize)
}

///Allows iterating over the options after a TCP header.
#[derive(Clone, Eq, PartialEq)]
pub struct TcpOptionsIterator<'a> {
    options: &'a [u8]
}

#[deprecated(
    since = "0.10.0",
    note = "Please use tcp_option::KIND_END instead"
)]
/// Deprecated please use [tcp_option::KIND_END] instead.
pub const TCP_OPTION_ID_END: u8 = 0;

#[deprecated(
    since = "0.10.0",
    note = "Please use tcp_option::KIND_NOOP instead"
)]
/// Deprecated please use [tcp_option::KIND_NOOP] instead.
pub const TCP_OPTION_ID_NOP: u8 = 1;

#[deprecated(
    since = "0.10.0",
    note = "Please use tcp_option::KIND_MAXIMUM_SEGMENT_SIZE instead"
)]
/// Deprecated please use [tcp_option::KIND_MAXIMUM_SEGMENT_SIZE] instead.
pub const TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE: u8 = 2;

#[deprecated(
    since = "0.10.0",
    note = "Please use tcp_option::KIND_WINDOW_SCALE instead"
)]
/// Deprecated please use [tcp_option::KIND_WINDOW_SCALE] instead.
pub const TCP_OPTION_ID_WINDOW_SCALE: u8 = 3;

#[deprecated(
    since = "0.10.0",
    note = "Please use tcp_option::KIND_SELECTIVE_ACK_PERMITTED instead"
)]
/// Deprecated please use [tcp_option::KIND_SELECTIVE_ACK_PERMITTED] instead.
pub const TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED: u8 = 4;

#[deprecated(
    since = "0.10.0",
    note = "Please use tcp_option::KIND_SELECTIVE_ACK instead"
)]
/// Deprecated please use [tcp_option::KIND_SELECTIVE_ACK] instead.
pub const TCP_OPTION_ID_SELECTIVE_ACK: u8 = 5;

#[deprecated(
    since = "0.10.0",
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
                Err(UnexpectedEndOfSlice(id))
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
                            let value = BigEndian::read_u16(&self.options[2..4]);
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
                        Some(Err(UnexpectedEndOfSlice(self.options[0])))
                    } else {
                        //check that the length is an allowed one for this option
                        let len = self.options[1];
                        if len != 10 && len != 18 && len != 26 && len != 34 {
                            Some(Err(UnexpectedSize{
                                option_id: self.options[0],
                                size: len 
                            }))
                        } else if self.options.len() < (len as usize) {
                            Some(Err(UnexpectedEndOfSlice(self.options[0])))
                        } else {
                            let mut acks: [Option<(u32,u32)>;3] = [None;3];
                            let first = (BigEndian::read_u32(&self.options[2..2 + 4]),
                                         BigEndian::read_u32(&self.options[2 + 4..2 + 8]));
                            for (i, item) in acks.iter_mut()
                                                 .enumerate()
                                                 .take(3)
                            {
                                let offset = 2 + 8 + (i*8);
                                if offset < (len as usize) {
                                    *item = Some((
                                        BigEndian::read_u32(&self.options[offset..offset + 4]),
                                        BigEndian::read_u32(&self.options[offset + 4..offset + 8]))
                                    );
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
                        _ => {
                            let t = Timestamp(
                                BigEndian::read_u32(&self.options[2..6]),
                                BigEndian::read_u32(&self.options[6..10])
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
        let mut clone = self.clone();
        while let Some(it) = clone.next() {
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
