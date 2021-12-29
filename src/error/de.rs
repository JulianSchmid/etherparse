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
    DecodeError(T)
}

impl<T : Error + Display> Display for FromSliceError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use FromSliceError::*;

        match self {
            UnexpectedEndOfSlice(ref err) => err.fmt(f),
            DecodeError(ref err) => Display::fmt(&err, f),
        }
    }
}

impl<T : 'static + Error + Display> Error for FromSliceError<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use FromSliceError::*;

        match self {
            UnexpectedEndOfSlice(ref err) => Some(err),
            DecodeError(ref err) => Some(err),
        }
    }
}

/// Errors that can be found while decoding ipv4 packets.
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
