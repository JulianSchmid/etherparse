use std::vec::Vec;

use crate::{EtherPayloadSlice, EtherType};

/// Payload of an IP packet. Owned version of [`EtherPayloadSlice`].
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EtherPayload {
    /// Identifying content of the payload.
    pub ether_type: EtherType,
    /// Payload
    pub payload: Vec<u8>,
}

impl<'a> From<EtherPayloadSlice<'a>> for EtherPayload {
    fn from(slice: EtherPayloadSlice<'a>) -> Self {
        Self {
            ether_type: slice.ether_type,
            payload: slice.payload.to_vec(),
        }
    }
}
