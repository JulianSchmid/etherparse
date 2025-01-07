use std::vec::Vec;

use crate::{IpNumber, IpPayloadSlice, LenSource};

/// Payload of an IP packet. Owned version of [`IpPayloadSlice`].
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpPayload {
    /// Identifying content of the payload.
    pub ip_number: IpNumber,

    /// True if the payload is not complete and has been fragmented.
    ///
    /// This can occur if the IPv4 incdicates that the payload
    /// has been fragmented or if there is an IPv6 fragmentation
    /// header indicating that the payload has been fragmented.
    pub fragmented: bool,

    /// Length field that was used to determine the length
    /// of the payload (e.g. IPv6 "payload_length" field).
    pub len_source: LenSource,

    /// Payload
    pub payload: Vec<u8>,
}

impl<'a> From<IpPayloadSlice<'a>> for IpPayload {
    fn from(slice: IpPayloadSlice<'a>) -> Self {
        Self {
            ip_number: slice.ip_number,
            fragmented: slice.fragmented,
            len_source: slice.len_source,
            payload: slice.payload.to_vec(),
        }
    }
}
