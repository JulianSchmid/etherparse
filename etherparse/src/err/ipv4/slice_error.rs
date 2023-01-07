use crate::err::LenError;

use super::HeaderSliceError;

/// Errors that can occur when slicing the IPv4 part of a packet.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SliceError {
    /// Error while slicing the header.
    Header(HeaderSliceError),

    /// Error while slicing the payload of the packet.
    Payload(LenError),
}
