
use super::*;

use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};

/// Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    /// Whenever an std::io::Error gets triggerd during a write it gets forwarded via this enum value.
    IoError(std::io::Error),
    /// Error when an unexpected end of a slice was reached even though more data was expected to be present.
    UnexpectedEndOfSlice(error::de::UnexpectedEndOfSliceError),
    /// Error when a double vlan tag was expected but the ether type of the the first vlan header does not an vlan header ether type.
    /// The value is the unexpected ether type value in the outer vlan header.
    DoubleVlanOuterNonVlanEtherType(u16),
    /// Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    IpUnsupportedVersion(u8),
    Ipv4(error::de::Ipv4Error),
    /// Error when then ip header version field is not equal 6. The value is the version that was received.
    Ipv6UnexpectedVersion(u8),
    /// Error if the ipv6 hop by hop header does not occur directly after the ipv6 header (see rfc8200 chapter 4.1.)
    Ipv6HopByHopHeaderNotAtStart,
    /// Error if the header length in the ip authentication header is smaller then the minimum size of 1.
    IpAuthenticationHeaderTooSmallPayloadLength(u8),
    /// Error given if the data_offset field in a TCP header is smaller then the minimum size of the tcp header itself.
    TcpDataOffsetTooSmall(u8),
}

impl ReadError {
    ///Adds an offset value to the UnexpectedEndOfSlice error.
    pub fn add_slice_offset(self, offset: usize) -> ReadError {
        use crate::ReadError::*;
        match self {
            UnexpectedEndOfSlice(err) =>
                UnexpectedEndOfSlice(err.add_slice_offset(offset)),
            value => value
        }
    }

    /// Returns the `std::io::Error` value if the `ReadError` is an `IoError`.
    /// Otherwise `None is returned.
    pub fn io_error(self) -> Option<std::io::Error> {
        match self {
            ReadError::IoError(value) => Some(value),
            _ => None
        }
    }
    /// Returns the expected minimum size if the error is an `UnexpectedEndOfSlice`.
    pub fn unexpected_end_of_slice_min_expected_size(self) -> Option<usize> {
        match self {
            ReadError::UnexpectedEndOfSlice(value) => Some(value.expected_min_len),
            _ => None
        }
    }
}

impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ReadError::*;

        match self {
            IoError(err) => err.fmt(f),
            UnexpectedEndOfSlice(err) => err.fmt(f),
            DoubleVlanOuterNonVlanEtherType(ether_type) => { //u16
                write!(f, "ReadError: Expected a double vlan header, but the ether type field value {} of the outer vlan header is a non vlan header ether type.", ether_type)
            },
            IpUnsupportedVersion(version_number) => { // u8
                write!(f, "ReadError: Unsupported IP version number. The IP header contained the unsupported version number {}.", version_number)
            },
            Ipv4(err) => err.fmt(f),
            Ipv6UnexpectedVersion(version_number) => { //u8
                write!(f, "ReadError: Unexpected IP version number. Expected an IPv6 Header but the header contained the version number {}.", version_number)
            },
            Ipv6HopByHopHeaderNotAtStart => {
                write!(f, "ReadError: Encountered an IPv6 hop-by-hop header somwhere else then directly after the IPv6 header. This is not allowed according to RFC 8200.")
            },
            IpAuthenticationHeaderTooSmallPayloadLength(length) => {
                write!(f, "ReadError: Authentication header payload size is smaller then 1 ({}) which is smaller then the minimum size of the header.", length)
            },
            TcpDataOffsetTooSmall(data_offset) => { //u8
                write!(f, "ReadError: TCP data offset too small. The data offset value {} in the tcp header is smaller then the tcp header itself.", data_offset)
            },
        }
    }
}

impl Error for ReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ReadError::IoError(ref err) => Some(err),
            ReadError::UnexpectedEndOfSlice(ref err) => Some(err),
            ReadError::Ipv4(ref err) => Some(err),
            _ => None
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

impl From<error::de::UnexpectedEndOfSliceError> for ReadError {
    fn from(err: error::de::UnexpectedEndOfSliceError) -> ReadError {
        ReadError::UnexpectedEndOfSlice(err)
    }
}

impl From<error::de::Ipv4Error> for ReadError {
    fn from(err: error::de::Ipv4Error) -> ReadError {
        ReadError::Ipv4(err)
    }
}

///Errors that can occur when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(std::io::Error),
    ///Error in the data that was given to write
    ValueError(ValueError),
    ///Error when a given slice is not big enough to serialize the data.
    SliceTooSmall(usize),
}

impl WriteError {
    /// Returns the `std::io::Error` value if the `WriteError` is an `IoError`.
    /// Otherwise `None is returned.
    pub fn io_error(self) -> Option<std::io::Error> {
        match self {
            WriteError::IoError(value) => Some(value),
            _ => None
        }
    }
    /// Returns the `std::io::Error` value if the `WriteError` is an `ValueError`.
    /// Otherwise `None` is returned.
    pub fn value_error(self) -> Option<ValueError> {
        match self {
            WriteError::ValueError(value) => Some(value),
            _ => None
        }
    }

    /// Returns the expected minimum size if the error is an `SliceTooSmall`.
    pub fn slice_too_small_size(self) -> Option<usize> {
        match self {
            WriteError::SliceTooSmall(value) => Some(value),
            _ => None
        }
    }
}

impl From<ValueError> for WriteError {
    fn from(err: ValueError) -> WriteError {
        WriteError::ValueError(err)
    }
}

impl From<std::io::Error> for WriteError {
    fn from(err: std::io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

impl Display for WriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use WriteError::*;
        match self {
            IoError(err) => err.fmt(f),
            ValueError(err) => {
                write!(f, "ValueError: {}", err)
            },
            SliceTooSmall(size) => {
                write!(f, "SliceTooSmall: The slice given to write to is too small (required to be at least {} bytes large)", size)
            }
        }
    }
}

impl Error for WriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use WriteError::*;
        match self {
            IoError(ref err) => Some(err),
            ValueError(ref err) => Some(err),
            SliceTooSmall(_) => None
        }
    }
}

/// Errors in the given data
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValueError {
    /// Error when the ipv4 options length is too big or not aligned (cannot be bigger then 40 bytes and must be a multiple of 4 bytes).
    Ipv4OptionsLengthBad(usize),
    /// Error when a given payload & ipv4 header is bigger then what fits inside an ipv4 total_length field.
    Ipv4PayloadLengthTooLarge(usize),
    /// Error when a given payload & ipv6 header block is bigger then what fits inside an ipv6 payload_length field.
    Ipv6PayloadLengthTooLarge(usize),
    /// Error when a given payload size is smaller then 6 octets which is the minimum ipv6 extended header size ([Ipv6RawExtensionHeader::MAX_PAYLOAD_LEN]).
    Ipv6ExtensionPayloadTooSmall(usize),
    /// Error when a given payload size is bigger then what fits inside an ipv6 extended header size ([Ipv6RawExtensionHeader::MAX_PAYLOAD_LEN]).
    Ipv6ExtensionPayloadTooLarge(usize),
    /// Error when a given payload length is not aligned to be a multiple of 8 octets when 6 is substracted and can not be represented by the header length field.
    Ipv6ExtensionPayloadLengthUnaligned(usize),
    /// Error when a given authentication header icv size is not a multiple of 4 bytes or bigger then 1016 bytes and therefor can not be represented in the header length field.
    IpAuthenticationHeaderBadIcvLength(usize),
    /// Error when a header in `Ipv4Extensions` is never written as it is never referenced by any of the other `next_header` fields or the initial `protocol`.
    Ipv4ExtensionNotReferenced(IpNumber),
    /// Error when a hop-by-hop header is not referenced as the first header after the ipv6 header but as a later extension header.
    Ipv6ExtensionHopByHopNotAtStart,
    /// Error when a header in `Ipv6Extensions` is never written as it is never referenced by any of the other `next_header` fields or the initial ip number.
    Ipv6ExtensionNotReferenced(IpNumber),
    /// Error when a header in `Ipv6Extensions` is referenced multiple times or is referenced and not defined.
    Ipv6ExtensionNotDefinedReference(IpNumber),
    /// Error when a given payload is bigger then what fits inside an udp packet
    /// Note that a the maximum payload size, as far as udp is conceirned, is max_value(u16) - 8. The 8 is for the size of the udp header itself.
    UdpPayloadLengthTooLarge(usize),
    /// Error when a given payload + tcp header options is bigger then what fits inside an tcp packet
    /// Note that a the maximum size, as far as tcp is conceirned, is max_value(u16) - tcp_header.data_offset()*4. The data_offset is for the size of the udp header itself.
    TcpLengthTooLarge(usize),
    /// Error when a u8 field in a header has a larger value then supported.
    U8TooLarge{value: u8, max: u8, field: ErrorField},
    /// Error when a u16 field in a header has a larger value then supported.
    U16TooLarge{value: u16, max: u16, field: ErrorField},
    /// Error when a u32 field in a header has a larger value then supported.
    U32TooLarge{value: u32, max: u32, field: ErrorField}
}

impl Error for ValueError {

}

impl Display for ValueError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ValueError::*;
        match self {
            Ipv4OptionsLengthBad(options_len) => { //usize
                write!(f, "Bad IPv4 'options_len'. The IPv4 options length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 40 bytes.", options_len)
            },
            Ipv4PayloadLengthTooLarge(total_length) => { //usize
                write!(f, "IPv4 'total_legnth' too large. The IPv4 header and payload have a larger size ({} bytes) than can be be represented by the 'total_legnth' field in the IPv4 header.", total_length)
            },
            Ipv6PayloadLengthTooLarge(size) => { //usize
                write!(f, "IPv6 'payload_length' too large. The IPv6 header block & payload size ({} bytes) is larger then what can be be represented by the 'payload_length' field in the IPv6 header.", size)
            },
            Ipv6ExtensionPayloadTooSmall(size) => {
                write!(f, "IPv6 extensions header payload length is too small. The payload size ({} bytes) is less then 6 octets which is the minimum IPv6 extension header payload size.", size)
            },
            Ipv6ExtensionPayloadTooLarge(size) => {
                write!(f, "IPv6 extensions header payload length is too large. The payload size ({} bytes) is larger then what can be be represented by the 'extended header size' field in an IPv6 extension header.", size)
            },
            Ipv6ExtensionPayloadLengthUnaligned(size) => {
                write!(f, "IPv6 extensions header 'payload length ({} bytes) + 2' is not multiple of 8 (+ 2 for the `next_header` and `header_length` fields). This is required as the header length field can only express lengths in multiple of 8 bytes.", size)
            },
            IpAuthenticationHeaderBadIcvLength(size) => {
                write!(f, "IP authentication header 'raw_icv' value has a length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 1016 bytes.", size)
            },
            Ipv4ExtensionNotReferenced(ip_protocol_number) => {
                write!(f, "IPv4 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the 'protocol' field of the IPv4 header.", ip_protocol_number)
            }
            Ipv6ExtensionHopByHopNotAtStart => {
                write!(f, "IPv6 extensions hop-by-hop is not located directly after the IPv6 header (required by IPv6).")
            },
            Ipv6ExtensionNotReferenced(ip_protocol_number) => {
                write!(f, "IPv6 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the IPv6 header.", ip_protocol_number)
            },
            Ipv6ExtensionNotDefinedReference(ip_protocol_number) => {
                write!(f, "IPv6 extensions '{:?}' is referenced by the 'next_header' field of an extension headers or the IPv6 header but is not defined in the 'Ipv6Extensions'.", ip_protocol_number)
            },
            UdpPayloadLengthTooLarge(length) => { //usize
                write!(f, "UDP 'length' too large. The UDP length ({} bytes) is larger then what can be be represented by the 'length' field in the UDP header.", length)
            }, 
            TcpLengthTooLarge(length) => {  //usize
                write!(f, "TCP length too large. The TCP packet length ({} bytes) is larger then what is supported.", length)
            },
            U8TooLarge{value, max, field} => {
                write!(f, "The value {} of the field '{}' is larger then the allowed maximum of {}.", value, field, max)
            },
            U16TooLarge{value, max, field} => {
                write!(f, "The value {} of the field '{}' is larger then the allowed maximum of {}.", value, field, max)
            },
            U32TooLarge{value, max, field} => {
                write!(f, "The value {} of the field '{}' is larger then the allowed maximum of {}.", value, field, max)
            }
        }
    }
}

///Fields that can produce errors when serialized.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ErrorField {
    Ipv4PayloadLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset,
    Ipv6FlowLabel,
    /// Ipv6 fragment header fragment offset field.
    Ipv6FragmentOffset,
    ///VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
    ///VlanTaggingHeader.vlan_identifier
    VlanTagVlanId,
}

impl Display for ErrorField {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ErrorField::*;
        match self {
            Ipv4PayloadLength => write!(f, "Ipv4Header.payload_len"),
            Ipv4Dscp => write!(f, "Ipv4Header.differentiated_services_code_point"),
            Ipv4Ecn => write!(f, "Ipv4Header.explicit_congestion_notification"),
            Ipv4FragmentsOffset => write!(f, "Ipv4Header.fragments_offset"),
            Ipv6FlowLabel => write!(f, "Ipv6Header.flow_label"),
            Ipv6FragmentOffset => write!(f, "Ipv6FragmentHeader.fragment_offset"),
            VlanTagPriorityCodePoint => write!(f, "SingleVlanHeader.priority_code_point"),
            VlanTagVlanId => write!(f, "SingleVlanHeader.vlan_identifier")
        }
    }
}


///Errors that can occour while reading the options of a TCP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionReadError {
    ///Returned if an option id was read, but there was not enough memory in the options left to completely read it.
    UnexpectedEndOfSlice{ option_id: u8, expected_len: u8, actual_len: usize },

    ///Returned if the option as an unexpected size argument (e.g. != 4 for maximum segment size).
    UnexpectedSize{ option_id: u8, size: u8 },

    ///Returned if an unknown tcp header option is encountered.
    ///
    ///The first element is the identifier and the slice contains the rest of data left in the options.
    UnknownId(u8),
}

impl Error for TcpOptionReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for TcpOptionReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TcpOptionReadError::*;
        match self {
            UnexpectedEndOfSlice{option_id, expected_len, actual_len} => {
                write!(f, "TcpOptionReadError: Not enough memory left in slice to read option of kind {} (expected at least {} bytes, only {} bytes available).", option_id, expected_len, actual_len)
            },
            UnexpectedSize{option_id, size} => {
                write!(f, "TcpOptionReadError: Length value of the option of kind {} had unexpected value {}.", option_id, size)
            },
            UnknownId(id) => {
                write!(f, "TcpOptionReadError: Unknown tcp option kind value {}.", id)
            }
        }
    }
}

/// Errors that can occour when setting the options of a tcp header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionWriteError {
    /// There is not enough memory to store all options in the options section of the header (maximum 40 bytes).
    ///
    /// The options size is limited by the 4 bit data_offset field in the header which describes
    /// the total tcp header size in multiple of 4 bytes. This leads to a maximum size for the options
    /// part of the header of 4*(15 - 5) (minus 5 for the size of the tcp header itself). 
    NotEnoughSpace(usize)
}

impl Error for TcpOptionWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for TcpOptionWriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use TcpOptionWriteError::*;
        match self {
            NotEnoughSpace(size) => {
                write!(f, "TcpOptionWriteError: Not enough memory to store all options in the options section of a tcp header (maximum 40 bytes can be stored, the options would have needed {} bytes).", size)
            },
        }
    }
}

