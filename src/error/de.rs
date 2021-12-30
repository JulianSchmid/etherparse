use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};

/// Error when an unexpected end of a slice was reached even though more data was expected to be present.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnexpectedEndOfSliceError {
    /// The expected minimum amount of datat that should have been present.
    pub expected_min_len: usize,

    /// Actual length of the slice.
    pub actual_len: usize,
}

impl UnexpectedEndOfSliceError {
    /// Adds an offset value to the expected_min_len and returns the result as a new UnexpectedEndOfSliceError.
    pub fn add_slice_offset(self, offset: usize) -> UnexpectedEndOfSliceError {
        UnexpectedEndOfSliceError {
            expected_min_len: self.expected_min_len + offset,
            actual_len: self.actual_len + offset,
        }
    }
}

impl Display for UnexpectedEndOfSliceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "UnexpectedEndOfSliceError: Unexpected end of slice. The given slice contained less then minimum required {} bytes.", self.expected_min_len)
    }
}

impl Error for UnexpectedEndOfSliceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Error when decoding a header or packet from a slice.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FromSliceError<T : Error + Display> {
    /// Error when an unexpected end of a slice was reached even though more data was expected to be present.
    UnexpectedEndOfSlice(UnexpectedEndOfSliceError),

    /// Error caused by an invalid encoded value.
    Content(T)
}

impl<T : Error + Display> Display for FromSliceError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use FromSliceError::*;

        match self {
            UnexpectedEndOfSlice(ref err) => err.fmt(f),
            Content(ref err) => Display::fmt(&err, f),
        }
    }
}

impl<T : 'static + Error + Display> Error for FromSliceError<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use FromSliceError::*;

        match self {
            UnexpectedEndOfSlice(ref err) => Some(err),
            Content(ref err) => Some(err),
        }
    }
}

/// Errors that can be encountered when parsing an [`crate::Ipv4Header`] or [`crate::Ipv4HeaderSlice`].
///
/// Note that this error is only used if it is clear that an IPv4 header should
/// be parsed (e.g. via the ether_type number from the Ethernet II header). If the
/// parsing starts at the IP layer without prior knowledge what kind of IP header is present
/// an [`IpError`] is used instead.
///
/// The following functions return [`Ipv6Error`] errors:
///
/// * [`crate::Ipv4Header::from_slice`]
/// * [`crate::Ipv4Header::read`]
/// * [`crate::Ipv4Header::read_without_version`]
/// * [`crate::SlicedPacket::from_ethernet`] (as part of [`PacketError`])
/// * [`crate::SlicedPacket::from_ether_type`] (as part of [`PacketError`])
/// * [`crate::PacketHeaders::from_ethernet_slice`] (as part of [`PacketError`])
/// * [`crate::PacketHeaders::from_ether_type`] (as part of [`PacketError`])
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv4Error {
    /// Error when the ip header version field is not equal 4. The value is the version that was received.
    UnexpectedIpVersion(u8),
    /// Error when the ihl (Internet Header Length) header length is smaller then the ipv4 header itself (5).
    IhlTooSmall(u8),
    /// Error when the total length field is smaller then the 'ihl' (internet header length).
    TotalLengthSmallerThanIhl(Ipv4TotalLengthSmallerThanIhlError),
}

impl Display for Ipv4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Ipv4Error::*;

        match self {
            UnexpectedIpVersion(version_number) => { //u8
                write!(f, "de::Ipv4Error: Unexpected IP version number. Expected an IPv4 Header but the header contained the version number {}.", version_number)
            },
            IhlTooSmall(ihl) => { //u8
                write!(f, "de::Ipv4Error: The 'ihl' (Internet Header length) field in the IPv4 header has a value of '{}' which is smaller then minimum size of an IPv4 header (5).", ihl)
            },
            TotalLengthSmallerThanIhl(err) => {
                write!(f, "de::Ipv4Error: The IPv4 'total_length' of {} octets is smaller then the length of {} octets the header itself (based on ihl).", err.total_length, err.header_length)
            },
        }
    }
}

impl Error for Ipv4Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Error when the total length field is smaller then the 'ihl' (internet header length).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv4TotalLengthSmallerThanIhlError {
    /// Length of the IPv4 header in octets/bytes calculated from the ihl field in the IPv4 header.
    pub header_length: u16,
    /// Total length of the IPv4 header including the payload length.
    pub total_length: u16
}

/// Errors that can be found while decoding ipv6 packets.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv6Error {
    /// Error when the ip header version field is not equal 6. The value is the version that was received.
    UnexpectedIpVersion(u8),
}

impl Display for Ipv6Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Ipv6Error::*;
        match self {
            UnexpectedIpVersion(version_number) => { //u8
                write!(f, "de::Ipv6Error: Unexpected IP version number. Expected an IPv6 Header but the header contained the version number {}.", version_number)
            },
        }
    }
}

impl Error for Ipv6Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Errors that can be found while decoding an packet from the ip layer downwards.
///
/// This error is only used when parsing starts at the ip layer without prior
/// knowledge which ip header should be present. If it is known which ip header should
/// be present [`Ipv4Error`] or [`Ipv6Error`] are triggered instead.
///
/// The following functions return [`IpError`] errors:
///
/// * [`crate::IpHeader::from_slice`]
/// * [`crate::IpHeader::read`]
/// * [`crate::SlicedPacket::from_ip`] (as part of [`IpPacketError`])
/// * [`crate::PacketHeaders::from_ip_slice`] (as part of [`IpPacketError`])
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IpError {
    /// Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    UnsupportedIpVersion(u8),
    /// Error when the ihl (Internet Header Length) header length is smaller then the ipv4 header itself (5).
    Ipv4IhlTooSmall(u8),
    /// Error when the total length field is smaller then the 'ihl' (internet header length).
    Ipv4TotalLengthSmallerThanIhl(Ipv4TotalLengthSmallerThanIhlError),
}

impl Display for IpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use IpError::*;

        match self {
            UnsupportedIpVersion(version_number) => { //u8
                write!(f, "de::IpError: Unsupported IP version number {} found in IP header (only 4 & 6 are supported).", version_number)
            },
            Ipv4IhlTooSmall(ihl) => { //u8
                write!(f, "de::IpError: The 'ihl' (Internet Header length) field in the IPv4 header has a value of '{}' which is smaller then minimum size of an IPv4 header (5).", ihl)
            },
            Ipv4TotalLengthSmallerThanIhl(err) => {
                write!(f, "de::IpError: The IPv4 'total_length' of {} octets is smaller then the length of {} octets the header itself (based on ihl).", err.total_length, err.header_length)
            },
        }
    }
}

impl Error for IpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
