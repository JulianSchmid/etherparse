use crate::{IpNumber, err::LenSource};

/// Payload of an IP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPayload<'a> {
    /// Identifying content of the payload.
    pub ip_number: IpNumber,

    /// True if the payload is not complete and has been fragmented.
    /// 
    /// This can occur if the IPv4 incdicates that the payload
    /// has been fragmented or if there is an IPv6 fragmentation
    /// header indicating that the payload has been fragmented.
    pub fragmented: bool,
    
    /// Length field that was used to determine the lenght
    /// of the payload (e.g. IPv6 "payload_length" field).
    pub len_source: LenSource,

    /// Payload
    pub payload: &'a [u8],
}
