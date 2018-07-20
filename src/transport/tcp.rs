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
///Field descriptions copied from RFC 793 page 15-
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
    ///Options of the header
    pub options: [u8;40]
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
            options: {
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
            writer.write(&self.options[..len])?;
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
}

///Different kinds of options that can be present in the options part of a tcp header.
pub enum TcpOptionElement<'a> {
    Nop,
    End,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SelectiveAcknowledgementPermitted,
    SelectiveAcknowledgement(&'a[u8]),
    ///Timestamp & echo (first number is the sender timestamp, the second the echo timestamp)
    Timestamp(u32, u32)
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
        self.options[..] == other.options[..]
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
            options: {
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
