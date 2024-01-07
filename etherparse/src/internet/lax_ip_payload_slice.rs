use crate::{err::LenSource, *};

/// Laxly identified payload of an IP packet (potentially incomplete).
///
/// To check if the payload is complete check the `incomplete` field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxIpPayloadSlice<'a> {
    /// True if the length field in the IP header indicates more data
    /// should be present but it was not (aka the packet data is cut off).
    ///
    /// Note that this different from fragmentation. If a packet is
    /// fragmented the length field in the individual IP headers is
    /// still correctly set.
    pub incomplete: bool,

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
    pub payload: &'a [u8],
}
