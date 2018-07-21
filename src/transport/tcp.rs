use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt::{Debug, Formatter};

//TODO checksum calculation
//TODO options setting & interpretation

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
    pub data_offset: u8,
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
    pub options_buffer: [u8;40]
}

impl TcpHeader {
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
            data_offset: data_offset,
        })
    }

    ///Write the tcp header to a stream (does NOT calculate the checksum).
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {

        //check that the data offset is within range
        use ValueError::*;
        use WriteError::ValueError;
        if self.data_offset < TCP_MINIMUM_DATA_OFFSET {
            return Err(ValueError(U8TooSmall{
                value: self.data_offset, 
                min: TCP_MINIMUM_DATA_OFFSET, 
                field: ErrorField::TcpDataOffset
            }));
        } else if self.data_offset > TCP_MAXIMUM_DATA_OFFSET {
            return Err(ValueError(U8TooLarge{
                value: self.data_offset, 
                max: TCP_MAXIMUM_DATA_OFFSET, 
                field: ErrorField::TcpDataOffset
            }));
        } 

        writer.write_u16::<BigEndian>(self.source_port)?;
        writer.write_u16::<BigEndian>(self.destination_port)?;
        writer.write_u32::<BigEndian>(self.sequence_number)?;
        writer.write_u32::<BigEndian>(self.acknowledgment_number)?;
        writer.write_u8({
            let value = (self.data_offset << 4) & 0xF0;
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
        if self.data_offset > TCP_MINIMUM_DATA_OFFSET {
            let len = ((self.data_offset - TCP_MINIMUM_DATA_OFFSET) as usize)*4;
            writer.write(&self.options_buffer[..len])?;
        }
        Ok(())
    }

    ///Returns the options size in bytes based on the currently set data_offset. Returns None if the data_offset is smaller then the minimum size or bigger then the maximum supported size.
    pub fn options_size(&self) -> Option<usize> {
        if self.data_offset < TCP_MINIMUM_DATA_OFFSET || self.data_offset > TCP_MAXIMUM_DATA_OFFSET {
            None
        } else {
            Some((self.data_offset - TCP_MINIMUM_DATA_OFFSET) as usize * 4)
        }
    }

    pub fn options<'a>(&'a self) -> Option<&'a[u8]> {
        match self.options_size() {
            None => None,
            Some(size) => Some(&self.options_buffer[..size])
        }
    }

    ///Returns an iterator that allows to iterate through all known TCP header options.
    pub fn options_iterator<'a>(&'a self) -> Option<TcpOptionsIterator<'a>> {
        match self.options_size() {
            None => None,
            Some(size) => Some(TcpOptionsIterator {
                options: &self.options_buffer[..size]
            })
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
            self.data_offset,
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
        self.data_offset == other.data_offset &&
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

impl<'a> PacketSlice<'a, TcpHeader> {

    ///Creates a slice containing an tcp header.
    pub fn from_slice(slice: &'a[u8]) -> Result<PacketSlice<'a, TcpHeader>, ReadError> {
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
            Ok(PacketSlice{
                slice: &slice[..len],
                phantom: std::marker::PhantomData{}
            })
        }
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
            data_offset: self.data_offset(),
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
}

///Different kinds of options that can be present in the options part of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionElement {
    Nop,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SelectiveAcknowledgementPermitted,
    SelectiveAcknowledgement([Option<(u32,u32)>;4]),
    ///Timestamp & echo (first number is the sender timestamp, the second the echo timestamp)
    Timestamp(u32, u32),
}

///Errors that can occour while reading the options of a TCP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionError {
    ///Returned if an option id was read, but there was not enough memory in the options left to completely read it.
    UnexpectedEndOfSlice(u8),

    ///Returned if the option as an unexpected size argument (e.g. != 4 for maximum segment size).
    UnexpectedSize{option_id: u8, size: u8 },

    ///Returned if an unknown tcp header option is encountered.
    ///
    ///The first element is the identifier and the slice contains the rest of data left in the options.
    UnknownId(u8),
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
    type Item = Result<TcpOptionElement, TcpOptionError>;

    fn next(&mut self) -> Option<Self::Item> {

        use TcpOptionError::*;
        use TcpOptionElement::*;

        let expect_specific_size = |expected_size: u8, slice: &[u8]| -> Result<(), TcpOptionError> {
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
                            let mut acks: [Option<(u32,u32)>;4] = [None;4];
                            for i in 0usize..4 {
                                let offset = 2 + (i*8);
                                if offset < (len as usize) {
                                    acks[i] = Some((
                                        BigEndian::read_u32(&self.options[offset..offset + 4]),
                                        BigEndian::read_u32(&self.options[offset + 4..offset + 8]))
                                    );
                                }
                            }
                            //iterate the options
                            self.options = &self.options[len as usize..];
                            Some(Ok(SelectiveAcknowledgement(acks)))
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
mod tests {
    use super::*;
    #[test]
    fn options_iterator() {
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
                SelectiveAcknowledgement([Some((10,11)),None, None, None]),
                SelectiveAcknowledgement([Some((12,13)),Some((14,15)), None, None]),
                SelectiveAcknowledgement([Some((16,17)),Some((18,19)), Some((20,21)), None]),
                SelectiveAcknowledgement([Some((22,23)),Some((24,25)), Some((26,27)), Some((28,29))]),
                Timestamp(30,31)
            ]);
    }

    #[test]
    fn options_iterator_unexpected_eos() {
        fn expect_unexpected_eos(slice: &[u8]) {
            for i in 1..slice.len()-1 {
                let mut it = TcpOptionsIterator{ options: &slice[..i] };
                assert_eq!(Some(Err(TcpOptionError::UnexpectedEndOfSlice(slice[0]))), it.next());
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
    fn options_iterator_unexpected_length() {
        fn expect_unexpected_size(id: u8, size: u8) {
            let data = [id, size, 0, 0, 0,
                        0, 0, 0, 0, 0, //10
                        0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, //20
                        0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, //30
                        0, 0, 0, 0];
            let mut it = TcpOptionsIterator{ options: &data };
            assert_eq!(Some(Err(TcpOptionError::UnexpectedSize {option_id: data[0], size: data[1] })), it.next());
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
    fn options_iterator_unexpected_id() {
        let data = [255, 2, 0, 0, 0,
                    0, 0, 0, 0, 0, //10
                    0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, //20
                    0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, //30
                    0, 0, 0, 0];
        let mut it = TcpOptionsIterator{ options: &data };
        assert_eq!(Some(Err(TcpOptionError::UnknownId(255))), it.next());
        //expect the iterator slice to be moved to the end
        assert_eq!(0, it.options.len());
        assert_eq!(None, it.next());
        assert_eq!(0, it.options.len());
    }
}