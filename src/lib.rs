use std::io;

mod link;
pub use crate::link::ethernet::*;
pub use crate::link::vlan_tagging::*;

mod internet;
pub use crate::internet::ip::*;
pub use crate::internet::ipv4::*;
pub use crate::internet::ipv6::*;

mod transport;
pub use crate::transport::tcp::*;
pub use crate::transport::udp::*;
pub use crate::transport::TransportHeader;

mod packet_builder;
pub use crate::packet_builder::*;

mod packet_decoder;
pub use crate::packet_decoder::*;

mod packet_slicing;
pub use crate::packet_slicing::*;

pub mod packet_filter;

///Contains the size when serialized.
pub trait SerializedSize {
    const SERIALIZED_SIZE: usize;
}

///Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    IoError(std::io::Error),
    ///Error when an unexpected end of a slice was reached even though more data was expected to be present (expected minimum size as argument).
    UnexpectedEndOfSlice(usize),
    ///Error when a double vlan tag was expected but the tpid of the outer vlan does not contain the expected id of 0x8100.
    VlanDoubleTaggingUnexpectedOuterTpid(u16),
    ///Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    IpUnsupportedVersion(u8),
    ///Error when the ip header version field is not equal 4. The value is the version that was received.
    Ipv4UnexpectedVersion(u8),
    ///Error when the ipv4 header length is smaller then the header itself (5).
    Ipv4HeaderLengthBad(u8),
    ///Error when the total length field is too small to contain the header itself.
    Ipv4TotalLengthTooSmall(u16),
    ///Error when then ip header version field is not equal 6. The value is the version that was received.
    Ipv6UnexpectedVersion(u8),
    ///Error when more then 7 header extensions are present (according to RFC82000 this should never happen).
    Ipv6TooManyHeaderExtensions,
    ///Error given if the data_offset field in a TCP header is smaller then the minimum size of the tcp header itself.
    TcpDataOffsetTooSmall(u8),
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

///Errors that can occur when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(std::io::Error),
    ///Error in the data that was given to write
    ValueError(ValueError)
}

impl WriteError {
    pub fn value_error(self) -> Option<ValueError> {
        match self {
            WriteError::ValueError(value) => Some(value),
            _ => None
        }
    }
}

impl From<ValueError> for WriteError {
    fn from(err: ValueError) -> WriteError {
        WriteError::ValueError(err)
    }
}

///Errors in the given data
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValueError {
    ///Error when the ipv4 options length is too big or not aligned (cannot be bigger then 40 bytes and must be a multiple of 4 bytes).
    Ipv4OptionsLengthBad(usize),
    ///Error when a given payload & ipv4 header is bigger then what fits inside an ipv4 total_length field.
    Ipv4PayloadLengthTooLarge(usize),
    ///Error when a given payload & ipv6 header block is bigger then what fits inside an ipv6 payload_length field.
    Ipv6PayloadLengthTooLarge(usize),
    ///Error when a given payload is bigger then what fits inside an udp packet
    ///Note that a the maximum payload size, as far as udp is conceirned, is max_value(u16) - 8. The 8 is for the size of the udp header itself.
    UdpPayloadLengthTooLarge(usize),
    ///Error when a given payload + tcp header options is bigger then what fits inside an tcp packet
    ///Note that a the maximum size, as far as tcp is conceirned, is max_value(u16) - tcp_header.data_offset()*4. The data_offset is for the size of the udp header itself.
    TcpLengthTooLarge(usize),
    ///Error when a u8 field in a header has a larger value then supported.
    U8TooLarge{value: u8, max: u8, field: ErrorField},
    ///Error when a u16 field in a header has a larger value then supported.
    U16TooLarge{value: u16, max: u16, field: ErrorField},
    ///Error when a u32 field in a header has a larger value then supported.
    U32TooLarge{value: u32, max: u32, field: ErrorField}
}

impl From<std::io::Error> for WriteError {
    fn from(err: std::io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

///Fields that can produce errors when serialized.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ErrorField {
    Ipv4HeaderLength,
    Ipv4PayloadLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset,
    Ipv6FlowLabel,
    ///VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
    ///VlanTaggingHeader.vlan_identifier
    VlanTagVlanId,
    ///The data offset field in a tcp header
    TcpDataOffset
}

fn max_check_u8(value: u8, max: u8, field: ErrorField) -> Result<(), ValueError> {
    use crate::ValueError::U8TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U8TooLarge { 
            value, 
            max,
            field
        })
    }
}

fn max_check_u16(value: u16, max: u16, field: ErrorField) -> Result<(), ValueError> {
    use crate::ValueError::U16TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U16TooLarge{ 
            value, 
            max, 
            field
        })
    }
}

//NOTE: Replace this with std::Iterator::step_by as soon as it is in stable (see https://github.com/rust-lang/rust/issues/27741)
struct RangeStep {
    start: usize,
    end: usize,
    step: usize 
}

impl RangeStep {
    fn new(start: usize, end: usize, step: usize) -> RangeStep {
        RangeStep {
            start,
            end,
            step 
        }
    }
}

impl Iterator for RangeStep {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        if self.start < self.end {
            let result = self.start;
            self.start = result + self.step;
            Some(result)
        } else {
            None
        }
    }
}