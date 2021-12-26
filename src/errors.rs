
use super::*;

/// Error when an unexpected end of a slice was reached even though more data was expected to be present.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnexpectedEndOfSliceError {
    /// The expected minimum amount of datat that should have been present.
    pub expected_min_len: usize,
}

impl UnexpectedEndOfSliceError {
    /// Adds an offset value to the expected_min_len and returns the result as a new UnexpectedEndOfSliceError.
    pub fn add_slice_offset(self, offset: usize) -> UnexpectedEndOfSliceError {
        UnexpectedEndOfSliceError {
            expected_min_len: self.expected_min_len + offset,
        }
    }
}

impl fmt::Display for UnexpectedEndOfSliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnexpectedEndOfSliceError: Unexpected end of slice. The given slice contained less then minimum required {} bytes.", self.expected_min_len)
    }
}

impl Error for UnexpectedEndOfSliceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    /// Whenever an std::io::Error gets triggerd during a write it gets forwarded via this enum value.
    IoError(std::io::Error),
    /// Error when an unexpected end of a slice was reached even though more data was expected to be present.
    UnexpectedEndOfSlice(UnexpectedEndOfSliceError),
    /// Error when a double vlan tag was expected but the ether type of the the first vlan header does not an vlan header ether type.
    /// The value is the unexpected ether type value in the outer vlan header.
    DoubleVlanOuterNonVlanEtherType(u16),
    /// Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    IpUnsupportedVersion(u8),
    /// Error when the ip header version field is not equal 4. The value is the version that was received.
    Ipv4UnexpectedVersion(u8),
    /// Error when the ipv4 header length is smaller then the header itself (5).
    Ipv4HeaderLengthBad(u8),
    /// Error when the total length field is too small to contain the header itself.
    Ipv4TotalLengthTooSmall(u16),
    /// Error when then ip header version field is not equal 6. The value is the version that was received.
    Ipv6UnexpectedVersion(u8),
    /// Error when more then 7 header extensions are present (according to RFC82000 this should never happen).
    Ipv6TooManyHeaderExtensions,
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

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            Ipv4UnexpectedVersion(version_number) => { //u8
                write!(f, "ReadError: Unexpected IP version number. Expected an IPv4 Header but the header contained the version number {}.", version_number)
            },
            Ipv4HeaderLengthBad(header_length) => { //u8
                write!(f, "ReadError: Bad IPv4 header length. The header length value {} in the IPv4 header is smaller then the ipv4 header.", header_length)
            },
            Ipv4TotalLengthTooSmall(total_length_field) => { //u16
                write!(f, "ReadError: Bad IPv4 total length. The total length value {} in the IPv4 header is smaller then the ipv4 header itself.", total_length_field)
            },
            Ipv6UnexpectedVersion(version_number) => { //u8
                write!(f, "ReadError: Unexpected IP version number. Expected an IPv6 Header but the header contained the version number {}.", version_number)
            },
            Ipv6TooManyHeaderExtensions => {
                write!(f, "ReadError: Too many IPv6 header extensions. There are more then 7 extension headers present, this not supported.")
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
            _ => None
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

impl From<UnexpectedEndOfSliceError> for ReadError {
    fn from(err: UnexpectedEndOfSliceError) -> ReadError {
        ReadError::UnexpectedEndOfSlice(err)
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

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl fmt::Display for ErrorField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
