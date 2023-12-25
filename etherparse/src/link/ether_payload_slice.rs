use crate::*;

/// Payload of an IP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EtherPayloadSlice<'a> {
    /// Identifying content of the payload.
    pub ether_type: EtherType,

    /// Payload
    pub payload: &'a [u8],
}
