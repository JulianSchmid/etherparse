//! The `de` module contains **decoding errors** that can be caused when slicing or
//! decoding headers and packets via `read` and `from_slice` methods.
//!
//! Enums returned as errors by functions decoding & slicing headers 
//! should contain only values that can actually be triggered by the called
//! function (e.g. an UDP parse function should not return an enum with an 
//! TCP parse error that can never be triggered).
//!
//! In case you want to use one error type instead you can convert all error
//! types to an [`de::Error`] using the [`de::Error::from`].
//!
//! # Error Types & Design
//!
//! The errors are split into two categories:
//!
//! * Errors that are caused when getting data (e.g. "slice is too short" or an io error)
//! * Errors that are caused because of the read content (e.g. a length field is shorter then the minimum size)
//!
//! Functions that can not trigger a content errors will directly return
//!
//! * [`UnexpectedEndOfSliceError`] (for functions that read data from slices)
//! * [`std::io::Error`] (for `read` functions where data is read from an io::Read source)
//!
//! as errors.
//!
//! In case content errors can also be triggered one of the following two wrapper
//! types is returned based on the data source:
//!
//! * [`FromSliceError`] is used when decoding from a slice.
//! * [`ReadError`] is used when data is read from an io::Read source.
//!
//! These take a content error type as an argument. For example:
//!
//! ```
//! # use std::error::Error;
//! # use std::fmt::{Display, Formatter};
//! # use etherparse::de::UnexpectedEndOfSliceError;
//! pub enum FromSliceError<T : Error + Display> {
//!     UnexpectedEndOfSlice(UnexpectedEndOfSliceError),
//!     Content(T)
//! }
//! ```
//!
//! This allows return both types of errors and at the same time
//! keep the list of returned errors constrained to the possible errors.
//!
//! Secondly there are error types that indicate issues in
//! the read data:
//!
//! * [`Ipv4Error`]
//! * [`Ipv6Error`]
//! * [`IpError`]
//! * [`Ipv4ExtsError`]
//! * [`Ipv6ExtsError`]
//! * [`IpAuthError`]

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
    /// Errors in the IPv4 extension headers.
    Ipv4Exts(Ipv4ExtsError),
    /// Errors in the IPv6 extension headers.
    Ipv6Exts(Ipv6ExtsError),
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
            Ipv4Exts(err) => err.fmt(f),
            Ipv6Exts(err) => err.fmt(f),
        }
    }
}

impl Error for IpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use IpError::*;
        match self {
            UnsupportedIpVersion(_) => None,
            Ipv4IhlTooSmall(_) => None,
            Ipv4TotalLengthSmallerThanIhl(_) => None,
            Ipv4Exts(ref err) => Some(err),
            Ipv6Exts(ref err) => Some(err),
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

/// Errors that can be encountered when parsing an [`crate::Ipv4Extensions`] or [`crate::Ipv4ExtensionsSlice`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv4ExtsError {
    /// Error during the parsing of an ip authentification header.
    Auth(IpAuthError)
}

impl Display for Ipv4ExtsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Ipv4ExtsError::*;
        match self {
            Auth(err) => err.fmt(f),
        }
    }
}

impl Error for Ipv4ExtsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use Ipv4ExtsError::*;
        match self {
            Auth(ref err) => Some(err),
        }
    }
}

/// Errors that can be encountered when parsing an [`crate::Ipv6Extensions`] or [`crate::Ipv6ExtensionsSlice`].
///
/// The following functions return [`Ipv6ExtsError`] errors:
///
/// * [`crate::Ipv6Extensions::from_slice`]
/// * [`crate::Ipv6Extensions::read`]
/// * [`crate::Ipv6ExtensionsSlice::from_slice`]
/// * [`crate::IpHeader::from_slice`] (as part of [`IpError`])
/// * [`crate::IpHeader::read`] (as part of [`IpError`])
/// * [`crate::SlicedPacket::from_ethernet`] (as part of [`PacketError`])
/// * [`crate::SlicedPacket::from_ether_type`] (as part of [`PacketError`])
/// * [`crate::SlicedPacket::from_ip`] (as part of [`IpPacketError`])
/// * [`crate::PacketHeaders::from_ethernet_slice`] (as part of [`PacketError`])
/// * [`crate::PacketHeaders::from_ether_type`] (as part of [`PacketError`])
/// * [`crate::PacketHeaders::from_ip_slice`] (as part of [`IpPacketError`])
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv6ExtsError {
    /// Error if the ipv6 hop by hop header does not occur directly after the ipv6 header (see rfc8200 chapter 4.1.)
    HopByHopHeaderNotAtStart,
    /// Error during the parsing of an ip authentification header.
    Auth(IpAuthError)
}

impl Display for Ipv6ExtsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Ipv6ExtsError::*;
        match self {
            HopByHopHeaderNotAtStart => {
                write!(f, "de::Ipv6ExtsError: Encountered an IPv6 hop-by-hop header somwhere else then directly after the IPv6 header. This is not allowed according to RFC 8200.")
            },
            Auth(err) => err.fmt(f),
        }
    }
}

impl Error for Ipv6ExtsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use Ipv6ExtsError::*;
        match self {
            HopByHopHeaderNotAtStart => None,
            Auth(ref err) => Some(err),
        }
    }
}

/// Errors that can be encountered when parsing an [`crate::IpAuthenticationHeader`] or [`crate::IpAuthenticationHeaderSlice`].
///
/// The following functions return [`IpAuthError`] errors:
///
/// * [`crate::IpAuthenticationHeader::from_slice`]
/// * [`crate::IpAuthenticationHeader::read`]
/// * [`crate::IpAuthenticationHeaderSlice::from_slice`]
/// * [`crate::Ipv4Extensions::from_slice`] (as part of [`Ipv4ExtsError`])
/// * [`crate::Ipv4Extensions::read`] (as part of [`Ipv4ExtsError`])
/// * [`crate::Ipv4ExtensionsSlice::from_slice`] (as part of [`Ipv4ExtsError`])
/// * [`crate::Ipv6Extensions::from_slice`] (as part of [`Ipv6ExtsError`])
/// * [`crate::Ipv6Extensions::read`] (as part of [`Ipv6ExtsError`])
/// * [`crate::Ipv6ExtensionsSlice::from_slice`] (as part of [`Ipv6ExtsError`])
/// * [`crate::IpHeader::from_slice`] (as part of [`IpError`])
/// * [`crate::IpHeader::read`] (as part of [`IpError`])
/// * [`crate::SlicedPacket::from_ethernet`] (as part of [`PacketError`])
/// * [`crate::SlicedPacket::from_ether_type`] (as part of [`PacketError`])
/// * [`crate::SlicedPacket::from_ip`] (as part of [`IpPacketError`])
/// * [`crate::PacketHeaders::from_ethernet_slice`] (as part of [`PacketError`])
/// * [`crate::PacketHeaders::from_ether_type`] (as part of [`PacketError`])
/// * [`crate::PacketHeaders::from_ip_slice`] (as part of [`IpPacketError`])
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IpAuthError {
    /// Error if the header length in the ip authentication header is zero (the minimum allowed size is 1).
    HeaderLengthZero
}

impl Display for IpAuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use IpAuthError::*;
        match self {
            HeaderLengthZero => {
                write!(f, "de::IpAuthError: Authentication header payload size is 0 which is smaller then the minimum size of the header (1 is the minimum allowed value).")
            },
        }
    }
}

impl Error for IpAuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
