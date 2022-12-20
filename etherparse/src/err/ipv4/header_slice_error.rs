use crate::err::UnexpectedEndOfSliceError;
use super::HeaderError;

/// Error when decoding the IPv4 part of a message.
#[derive(Debug, Eq, PartialEq)]
pub enum HeaderSliceError {
    /// Error when an unexpected end of a slice is reached even though more data was expected to be present.
    UnexpectedEndOfSlice(UnexpectedEndOfSliceError),

    /// Error caused by the contents of the header.
    Content(HeaderError),
}

impl core::fmt::Display for HeaderSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderSliceError::*;
        match self {
            UnexpectedEndOfSlice(err) => write!(f, "IPv4 Header: Length of the slice ({} bytes/octets) is too small to contain an IPv4 header. The slice must at least contain {} bytes/octets.", err.actual, err.expected_min),
            Content(value) => value.fmt(f),
        }
    }
}

impl std::error::Error for HeaderSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HeaderSliceError::UnexpectedEndOfSlice(_) => None,
            HeaderSliceError::Content(err) => Some(err),
        }
    }
}
