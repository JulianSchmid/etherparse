use std::io;

mod link;
pub use link::ethernet::*;
pub use link::vlan_tagging::*;

mod internet;
pub use internet::ip::*;

mod transport;
pub use transport::udp::*;

mod write_extension;
pub use write_extension::WriteEtherExt;

mod read_extension;
pub use read_extension::ReadEtherExt;

///Contains the size when serialized.
pub trait SerializedSize {
    const SERIALIZED_SIZE: usize;
}

///Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    IoError(io::Error),
    ///Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    IpUnsupportedVersion(u8),
    ///Error when the ip header version field is not equal 4. The value is the version that was received.
    Ipv4UnexpectedVersion(u8),
    ///Error when then ip header version field is not equal 6. The value is the version that was received.
    Ipv6UnexpectedVersion(u8),
    ///Error when more then 7 header extensions are present (according to RFC82000 this should never happen).
    Ipv6TooManyHeaderExtensions
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

///Errors that can occur when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(io::Error),
    ///Error in the data that was given to write
    ValueError(ValueError)
}

impl From<ValueError> for WriteError {
    fn from(err: ValueError) -> WriteError {
        WriteError::ValueError(err)
    }
}

///Errors in the given data
#[derive(Debug, PartialEq, Eq)]
pub enum ValueError {
    ///Error when the ipv4 options length is too big (cannot be bigger then 40 bytes and must be a multiple of 4 bytes).
    Ipv4OptionsLengthBad(usize),
    ///Error when a given payload & ipv4 options block is bigger then what fits inside an ipv4 total_length field.
    Ipv4PayloadAndOptionsLengthTooLarge(usize),
    ///Error when a given payload is bigger then what fits inside an udp packet
    ///Note that a the maximum payload size, as far as udp is conceirned, is max_value(u16) - 8. The 8 is for the size of the udp header itself.
    UdpPayloadLengthTooLarge(usize),
    ///Error when a u8 field in a header has a larger value then supported.
    U8TooLarge{value: u8, max: u8, field: ErrorField},
    ///Error when a u16 field in a header has a larger value then supported.
    U16TooLarge{value: u16, max: u16, field: ErrorField},
    ///Error when a u32 field in a header has a larger value then supported.
    U32TooLarge{value: u32, max: u32, field: ErrorField}
}

impl From<io::Error> for WriteError {
    fn from(err: io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

///Fields that can produce errors when serialized.
#[derive(Debug, PartialEq, Eq)]
pub enum ErrorField {
    Ipv4HeaderLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset,

    Ipv6FlowLabel,
    ///VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
    ///VlanTaggingHeader.vlan_identifier
    VlanTagVlanId
}

fn max_check_u8(value: u8, max: u8, field: ErrorField) -> Result<(), ValueError> {
    use ValueError::U8TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U8TooLarge { 
            value: value, 
            max: max,
            field: field
        })
    }
}

fn max_check_u16(value: u16, max: u16, field: ErrorField) -> Result<(), ValueError> {
    use ValueError::U16TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U16TooLarge{ 
            value: value, 
            max: max, 
            field: field
        })
    }
}