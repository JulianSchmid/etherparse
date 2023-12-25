use crate::{*, link::ether_payload_slice::EtherPayloadSlice};

/// Payload together with an identifier the type of content.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PayloadSlice<'a> {
    /// Payload with it's type identified by an ether type number 
    /// (e.g. after an ethernet II or vlan header).
    Ether(EtherPayloadSlice<'a>),
    /// Payload with is's type identified by an ip number (e.g.
    /// after an IP header or after an)
    Ip(IpPayloadSlice<'a>),
    /// UDP payload.
    Udp(&'a [u8]),
    /// TCP payload.
    Tcp(&'a [u8]),
    /// Payload part of an ICMP V4 message. Check [`crate::Icmpv4Type`]
    /// for a description what will be part of the payload.
    Icmpv4(&'a [u8]),
    /// Payload part of an ICMP V4 message. Check [`crate::Icmpv6Type`]
    /// for a description what will be part of the payload.
    Icmpv6(&'a [u8]),
}

impl<'a>  PayloadSlice<'a> {
    pub fn slice(&self) -> &'a [u8] {
        match self {
            PayloadSlice::Ether(s) => s.payload,
            PayloadSlice::Ip(s) => s.payload,
            PayloadSlice::Udp(s) => s,
            PayloadSlice::Tcp(s) => s,
            PayloadSlice::Icmpv4(s) => s,
            PayloadSlice::Icmpv6(s) => s,
        }
    }
}
