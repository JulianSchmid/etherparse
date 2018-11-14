use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt::{Debug, Formatter};

//TODO checksum calculation

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
            source_port: source_port,
            destination_port: destination_port,
            sequence_number: sequence_number,
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
            window_size: window_size,
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
        self._data_offset as u16 * 4
    }

    ///Returns the options size in bytes based on the currently set data_offset. Returns None if the data_offset is smaller then the minimum size or bigger then the maximum supported size.
    pub fn options_len(&self) -> usize {
        debug_assert!(TCP_MINIMUM_DATA_OFFSET <= self._data_offset);
        debug_assert!(self._data_offset <= TCP_MAXIMUM_DATA_OFFSET);
        (self._data_offset - TCP_MINIMUM_DATA_OFFSET) as usize * 4
    }

    ///Returns a slice containing the options of the header (size is determined via the data_offset field.
    pub fn options<'a>(&'a self) -> &'a[u8] {
        &self.options_buffer[..self.options_len()]
    }

    ///Sets the options (overwrites the current options) or returns an error when there is not enough space.
    pub fn set_options(&mut self, options: &[TcpOptionElement]) -> Result<(), TcpOptionWriteError> {

        //calculate the required size of the options
        use TcpOptionElement::*;
        let required_length = options.iter().fold(0, |acc, ref x| {
            acc + match x {
                Nop => 1,
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
        }) + 1; //+1 for end option

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
            let mut i = 0;
            for element in options {
                match element {
                    Nop => {
                        self.options_buffer[i] = TCP_OPTION_ID_NOP;
                        i += 1;
                    },
                    MaximumSegmentSize(value) => {
                        self.options_buffer[i] = TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE;
                        i += 1;
                        self.options_buffer[i] = 4;
                        i += 1;
                        BigEndian::write_u16(&mut self.options_buffer[i..i + 2], *value);
                        i += 2;
                    },
                    WindowScale(value) => {
                        self.options_buffer[i] = TCP_OPTION_ID_WINDOW_SCALE;
                        i += 1;
                        self.options_buffer[i] = 3;
                        i += 1;
                        self.options_buffer[i] = *value;
                        i += 1;
                    },
                    SelectiveAcknowledgementPermitted => {
                        self.options_buffer[i] = TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED;
                        i += 1;
                        self.options_buffer[i] = 2;
                        i += 1;
                    },
                    SelectiveAcknowledgement(first, rest) => {
                        self.options_buffer[i] = TCP_OPTION_ID_SELECTIVE_ACK;
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
                        self.options_buffer[i] = TCP_OPTION_ID_TIMESTAMP;
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
    pub fn options_iterator<'a>(&'a self) -> TcpOptionsIterator<'a> {
        TcpOptionsIterator {
            options: &self.options_buffer[..self.options_len()]
        }
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
            source_port: source_port,
            destination_port: destination_port,
            sequence_number: sequence_number,
            acknowledgment_number: acknowledgment_number,
            ns: ns,
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
                value = value | 1;
            }
            if self.syn {
                value = value | 2;
            }
            if self.rst {
                value = value | 4;
            }
            if self.psh {
                value = value | 8;
            }
            if self.ack {
                value = value | 16;
            }
            if self.urg {
                value = value | 32;
            }
            if self.ece {
                value = value | 64;
            }
            if self.cwr {
                value = value | 128;
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
        self.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, payload)
    }

    ///Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(&self, source_ip: &[u8;4], destination_ip: &[u8;4], payload: &[u8]) -> Result<u16, ValueError> {
        
        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize)*4 + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        //calculate the checksum
        Ok(self.calc_checksum_post_ip(BigEndian::read_u16(&source_ip[0..2]) as u64 + //pseudo header
                                      BigEndian::read_u16(&source_ip[2..4]) as u64 +
                                      BigEndian::read_u16(&destination_ip[0..2]) as u64 +
                                      BigEndian::read_u16(&destination_ip[2..4]) as u64 +
                                      IpTrafficClass::Tcp as u64 +
                                      tcp_length as u64,
                                      payload))
    }

    ///Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(&ip_header.source, &ip_header.destination, payload)
    }

    ///Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(&self, source: &[u8;16], destination: &[u8;16], payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = (self._data_offset as usize)*4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        fn calc_sum(value: &[u8;16]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i*2;
                result += BigEndian::read_u16(&value[index..(index + 2)]) as u64;
            }
            result
        }
        Ok(self.calc_checksum_post_ip(
            calc_sum(source) +
            calc_sum(destination) +
            IpTrafficClass::Tcp as u64 +
            {
                let mut buffer: [u8;4] = Default::default();
                BigEndian::write_u32(&mut buffer[..], tcp_length as u32);
                BigEndian::read_u16(&buffer[0..2]) as u64 +
                BigEndian::read_u16(&buffer[2..4]) as u64
            },
            payload))
    }

    ///This method takes the sum of the preudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {
        fn calc_u32_checksum(value: u32) -> u64 {
            let mut buffer: [u8;4] = [0;4];
            BigEndian::write_u32(&mut buffer, value);
            (BigEndian::read_u16(&buffer[..2]) as u64) + 
            (BigEndian::read_u16(&buffer[2..]) as u64)
        }
        let mut sum = 
            ip_pseudo_header_sum +
            self.source_port as u64 + //udp header start
            self.destination_port as u64 +
            calc_u32_checksum(self.sequence_number) +
            calc_u32_checksum(self.acknowledgment_number) +
            BigEndian::read_u16(&[
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
                        value = value | 1;
                    }
                    if self.syn {
                        value = value | 2;
                    }
                    if self.rst {
                        value = value | 4;
                    }
                    if self.psh {
                        value = value | 8;
                    }
                    if self.ack {
                        value = value | 16;
                    }
                    if self.urg {
                        value = value | 32;
                    }
                    if self.ece {
                        value = value | 64;
                    }
                    if self.cwr {
                        value = value | 128;
                    }
                    value
                }
            ]) as u64 +
            self.window_size as u64 +
            self.urgent_pointer as u64;

        //add the options
        let options_len = self.options_len();
        for i in RangeStep::new(0, options_len, 2) {
            sum += BigEndian::read_u16(&self.options_buffer[i..i + 2]) as u64;
        }

        //payload
        for i in RangeStep::new(0, payload.len()/2*2, 2) {
            sum += BigEndian::read_u16(&payload[i..i + 2]) as u64;
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += BigEndian::read_u16(&[*payload.last().unwrap(), 0]) as u64;
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
    fn fmt(&self, fotmatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        // TODO add printing of decoded options
        write!(fotmatter, "TcpHeader {{ source_port: {}, destination_port: {}, sequence_number: {}, acknowledgment_number: {}, data_offset: {}, ns: {}, fin: {}, syn: {}, rst: {}, psh: {}, ack: {}, urg: {}, ece: {}, cwr: {}, window_size: {}, checksum: {}, urgent_pointer: {} }}", 
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.acknowledgment_number,
            self._data_offset,
            self.ns,
            self.fin,
            self.syn,
            self.rst,
            self.psh,
            self.ack,
            self.urg,
            self.ece,
            self.cwr,
            self.window_size,
            self.checksum,
            self.urgent_pointer)
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
        self.options_buffer[..] == other.options_buffer[..]
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
        use std::io::ErrorKind::UnexpectedEof;
        use std::io::Error;
        use ReadError::*;
        if slice.len() < TCP_MINIMUM_HEADER_SIZE {
            return Err(IoError(Error::from(UnexpectedEof)));
        }

        //read data offset
        let data_offset = (slice[12] & 0xf0) >> 4;
        let len = data_offset as usize * 4;

        if data_offset < TCP_MINIMUM_DATA_OFFSET {
            Err(ReadError::TcpDataOffsetTooSmall(data_offset))
        } else if slice.len() < len {
            Err(IoError(Error::from(UnexpectedEof)))
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
    pub fn options_iterator<'b>(&'b self) -> TcpOptionsIterator<'b> {
        TcpOptionsIterator {
            options: self.options()
        }
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
                if options.len() > 0 {
                    result[..options.len()].clone_from_slice(&options);
                }
                result
            }
        }
    }


    ///Calculates the upd header checksum based on a ipv4 header and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4HeaderSlice, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(&ip_header.source(), &ip_header.destination(), payload)
    }

    ///Calculates the checksum for the current header in ipv4 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv4_raw(&self, source_ip: &[u8], destination_ip: &[u8], payload: &[u8]) -> Result<u16, ValueError> {
        
        //check that the total length fits into the field
        let tcp_length = self.slice.len() + payload.len();
        if (std::u16::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        //calculate the checksum
        Ok(self.calc_checksum_post_ip(BigEndian::read_u16(&source_ip[0..2]) as u64 + //pseudo header
                                      BigEndian::read_u16(&source_ip[2..4]) as u64 +
                                      BigEndian::read_u16(&destination_ip[0..2]) as u64 +
                                      BigEndian::read_u16(&destination_ip[2..4]) as u64 +
                                      IpTrafficClass::Tcp as u64 +
                                      tcp_length as u64,
                                      payload))
    }

    ///Calculates the upd header checksum based on a ipv6 header and returns the result. This does NOT set the checksum..
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6HeaderSlice, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(&ip_header.source(), &ip_header.destination(), payload)
    }

    ///Calculates the checksum for the current header in ipv6 mode and returns the result. This does NOT set the checksum.
    pub fn calc_checksum_ipv6_raw(&self, source: &[u8], destination: &[u8], payload: &[u8]) -> Result<u16, ValueError> {

        //check that the total length fits into the field
        let tcp_length = (self.data_offset() as usize)*4 + payload.len();
        if (std::u32::MAX as usize) < tcp_length {
            return Err(ValueError::TcpLengthTooLarge(tcp_length));
        }

        fn calc_addr_sum(value: &[u8]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i*2;
                result += BigEndian::read_u16(&value[index..(index + 2)]) as u64;
            }
            result
        }
        Ok(self.calc_checksum_post_ip(
            calc_addr_sum(source) +
            calc_addr_sum(destination) +
            IpTrafficClass::Tcp as u64 +
            {
                let mut buffer: [u8;4] = Default::default();
                BigEndian::write_u32(&mut buffer[..], tcp_length as u32);
                BigEndian::read_u16(&buffer[0..2]) as u64 +
                BigEndian::read_u16(&buffer[2..4]) as u64
            },
            payload))
    }

    ///This method takes the sum of the preudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {

        let mut sum = ip_pseudo_header_sum;

        //until checksum
        for i in RangeStep::new(0, 16, 2) {
            sum += BigEndian::read_u16(&self.slice[i..i + 2]) as u64;
        }
        //after checksum
        for i in RangeStep::new(18, self.slice.len(), 2) {
            sum += BigEndian::read_u16(&self.slice[i..i + 2]) as u64;
        }
        //payload
        for i in RangeStep::new(0, payload.len()/2*2, 2) {
            sum += BigEndian::read_u16(&payload[i..i + 2]) as u64;
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += BigEndian::read_u16(&[*payload.last().unwrap(), 0]) as u64;
        }
        let carry_add = (sum & 0xffff) + 
                        ((sum >> 16) & 0xffff) +
                        ((sum >> 32) & 0xffff) +
                        ((sum >> 48) & 0xffff);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        !result
    }
}

///Different kinds of options that can be present in the options part of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionElement {
    Nop,
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
pub struct TcpOptionsIterator<'a> {
    options: &'a [u8]
}

pub const TCP_OPTION_ID_END: u8 = 0;
pub const TCP_OPTION_ID_NOP: u8 = 1;
pub const TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE: u8 = 2;
pub const TCP_OPTION_ID_WINDOW_SCALE: u8 = 3;
pub const TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED: u8 = 4;
pub const TCP_OPTION_ID_SELECTIVE_ACK: u8 = 5;
pub const TCP_OPTION_ID_TIMESTAMP: u8 = 8;

impl<'a> Iterator for TcpOptionsIterator<'a> {
    type Item = Result<TcpOptionElement, TcpOptionReadError>;

    fn next(&mut self) -> Option<Self::Item> {

        use TcpOptionReadError::*;
        use TcpOptionElement::*;

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

        if self.options.len() == 0 {
            None
        } else {
            //first determine the result
            let result = match self.options[0] {
                //end
                TCP_OPTION_ID_END => {
                    None
                },
                TCP_OPTION_ID_NOP => {
                    self.options = &self.options[1..];
                    Some(Ok(Nop))
                },
                TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE => {
                    match expect_specific_size(4, self.options) {
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
                TCP_OPTION_ID_WINDOW_SCALE => {
                    match expect_specific_size(3, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            let value = self.options[2];
                            self.options = &self.options[3..];
                            Some(Ok(WindowScale(value)))
                        }
                    }
                },
                TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED => {
                    match expect_specific_size(2, self.options) {
                        Err(value) => Some(Err(value)),
                        _ => {
                            self.options = &self.options[2..];
                            Some(Ok(SelectiveAcknowledgementPermitted))
                        }
                    }
                },
                TCP_OPTION_ID_SELECTIVE_ACK => {
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
                                         BigEndian::read_u32(&self.options[2 + 4..2 + 8]));;
                            for i in 0usize..3 {
                                let offset = 2 + 8 + (i*8);
                                if offset < (len as usize) {
                                    acks[i] = Some((
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
                TCP_OPTION_ID_TIMESTAMP => {
                    match expect_specific_size(10, self.options) {
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

#[cfg(test)]
mod whitebox_tests {
    use super::*;
    #[test]
    pub fn options_iterator() {
        fn expect_elements(buffer: &[u8], expected: &[TcpOptionElement]) {
            let mut it = TcpOptionsIterator{ options: buffer };
            for element in expected.iter() {
                assert_eq!(element, &it.next().unwrap().unwrap());
            }
            //expect no more elements
            assert_eq!(None, it.next());
            assert_eq!(0, it.options.len());
        }

        use TcpOptionElement::*;

        //nop & max segment size
        expect_elements(&[
                TCP_OPTION_ID_NOP, 
                TCP_OPTION_ID_NOP,
                TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 4, 
                0, 1,
                TCP_OPTION_ID_WINDOW_SCALE, 3, 2,
                TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED, 2,
                TCP_OPTION_ID_SELECTIVE_ACK, 10,
                0, 0, 0, 10,
                0, 0, 0, 11,
                TCP_OPTION_ID_SELECTIVE_ACK, 18, 
                0, 0, 0, 12,
                0, 0, 0, 13,
                0, 0, 0, 14,
                0, 0, 0, 15,
                TCP_OPTION_ID_SELECTIVE_ACK, 26, 
                0, 0, 0, 16,
                0, 0, 0, 17,
                0, 0, 0, 18,
                0, 0, 0, 19,
                0, 0, 0, 20,
                0, 0, 0, 21,
                TCP_OPTION_ID_SELECTIVE_ACK, 34, 
                0, 0, 0, 22,
                0, 0, 0, 23,
                0, 0, 0, 24,
                0, 0, 0, 25,
                0, 0, 0, 26,
                0, 0, 0, 27,
                0, 0, 0, 28,
                0, 0, 0, 29,
                TCP_OPTION_ID_TIMESTAMP, 10, 
                0, 0, 0, 30, 
                0, 0, 0, 31,
                TCP_OPTION_ID_END, 0, 0, 0, 0
            ],
            &[
                Nop,
                Nop,
                MaximumSegmentSize(1),
                WindowScale(2),
                SelectiveAcknowledgementPermitted,
                SelectiveAcknowledgement((10,11), [None, None, None]),
                SelectiveAcknowledgement((12,13), [Some((14,15)), None, None]),
                SelectiveAcknowledgement((16,17), [Some((18,19)), Some((20,21)), None]),
                SelectiveAcknowledgement((22,23), [Some((24,25)), Some((26,27)), Some((28,29))]),
                Timestamp(30,31)
            ]);
    }

    #[test]
    pub fn options_iterator_unexpected_eos() {
        fn expect_unexpected_eos(slice: &[u8]) {
            for i in 1..slice.len()-1 {
                let mut it = TcpOptionsIterator{ options: &slice[..i] };
                assert_eq!(Some(Err(TcpOptionReadError::UnexpectedEndOfSlice(slice[0]))), it.next());
                //expect the iterator slice to be moved to the end
                assert_eq!(0, it.options.len());
                assert_eq!(None, it.next());
            }
        }
        expect_unexpected_eos(&[TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 4, 0, 0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_WINDOW_SCALE, 3, 0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 4, 0, 0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED, 2]);
        expect_unexpected_eos(&[TCP_OPTION_ID_SELECTIVE_ACK, 10, 0, 0, 0,
                                0, 0, 0, 0, 0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_SELECTIVE_ACK, 18, 0, 0, 0,
                                0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0,
                                0, 0, 0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_SELECTIVE_ACK, 26, 0, 0, 0,
                                0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0,
                                0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_SELECTIVE_ACK, 34, 0, 0, 0,
                                0, 0, 0, 0, 0, //10
                                0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, //20
                                0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, //30
                                0, 0, 0, 0]);
        expect_unexpected_eos(&[TCP_OPTION_ID_TIMESTAMP, 10, 0, 0, 0,
                                0, 0, 0, 0, 0]);
    }
    #[test]
    pub fn options_iterator_unexpected_length() {
        fn expect_unexpected_size(id: u8, size: u8) {
            let data = [id, size, 0, 0, 0,
                        0, 0, 0, 0, 0, //10
                        0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, //20
                        0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, //30
                        0, 0, 0, 0];
            let mut it = TcpOptionsIterator{ options: &data };
            assert_eq!(Some(Err(TcpOptionReadError::UnexpectedSize {option_id: data[0], size: data[1] })), it.next());
            //expect the iterator slice to be moved to the end
            assert_eq!(0, it.options.len());
            assert_eq!(None, it.next());
            assert_eq!(0, it.options.len());
        }
        expect_unexpected_size(TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 3);
        expect_unexpected_size(TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 5);

        expect_unexpected_size(TCP_OPTION_ID_WINDOW_SCALE, 2);
        expect_unexpected_size(TCP_OPTION_ID_WINDOW_SCALE, 4);

        expect_unexpected_size(TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 3);
        expect_unexpected_size(TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 5);

        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED, 1);
        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED, 3);

        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 9);
        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 11);

        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 17);
        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 19);

        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 25);
        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 27);

        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 33);
        expect_unexpected_size(TCP_OPTION_ID_SELECTIVE_ACK, 35);

        expect_unexpected_size(TCP_OPTION_ID_TIMESTAMP, 9);
        expect_unexpected_size(TCP_OPTION_ID_TIMESTAMP, 11);
    }

    #[test]
    pub fn options_iterator_unexpected_id() {
        let data = [255, 2, 0, 0, 0,
                    0, 0, 0, 0, 0, //10
                    0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, //20
                    0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, //30
                    0, 0, 0, 0];
        let mut it = TcpOptionsIterator{ options: &data };
        assert_eq!(Some(Err(TcpOptionReadError::UnknownId(255))), it.next());
        //expect the iterator slice to be moved to the end
        assert_eq!(0, it.options.len());
        assert_eq!(None, it.next());
        assert_eq!(0, it.options.len());
    }

    #[test]
    pub fn eq()
    {
        let base = TcpHeader {
            source_port: 1,
            destination_port: 2,
            sequence_number: 3,
            acknowledgment_number: 4,
            _data_offset: 5,
            ns: false,
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            ece: false,
            urg: false,
            cwr: false,
            window_size: 6,
            checksum: 7,
            urgent_pointer: 8,
            options_buffer: [0;40]
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
            other._data_offset = 10;
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
        //options (first element)
        {
            let mut other = base.clone();
            other.options_buffer[0] = 10;
            assert_ne!(other, base);
        }
        //options (last element)
        {
            let mut other = base.clone();
            other.options_buffer[39] = 10;
            assert_ne!(other, base);
        }
    }

    #[test]
    pub fn default() {
        let default : TcpHeader = Default::default();

        assert_eq!(0, default.source_port);
        assert_eq!(0, default.destination_port);
        assert_eq!(0, default.sequence_number);
        assert_eq!(0, default.acknowledgment_number);
        assert_eq!(5, default._data_offset);
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
        assert_eq!(&[0;40][..], &default.options_buffer[..]);
    }
}