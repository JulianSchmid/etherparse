use crate::err::UnexpectedEndOfSliceError;

use super::HeaderSliceError;

/// Errors that can occur when slicing the IPv4 part of a packet.
#[derive(Debug)]
pub enum SliceError {
    /// Error while slicing the header.
    Header(HeaderSliceError),

    /// Error while slicing the payload of the packet.
    Payload(UnexpectedEndOfSliceError),
}
