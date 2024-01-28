use crate::*;

/// Laxly parsed payload together with an identifier the type of content & the
/// information if the payload is incomplete.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LaxPayloadSlice<'a> {
    /// Payload with it's type identified by an ether type number
    /// (e.g. after an ethernet II or vlan header).
    Ether(EtherPayloadSlice<'a>),
    /// Payload with is's type identified by an ip number (e.g.
    /// after an IP header or after an)
    Ip(LaxIpPayloadSlice<'a>),
    /// UDP payload.
    Udp { payload: &'a [u8], incomplete: bool },
    /// TCP payload.
    Tcp {
        payload: &'a [u8],
        /// True if the payload has been cut off.
        incomplete: bool,
    },
    /// Payload part of an ICMP V4 message. Check [`crate::Icmpv4Type`]
    /// for a description what will be part of the payload.
    Icmpv4 {
        payload: &'a [u8],
        /// True if the payload has been cut off.
        incomplete: bool,
    },
    /// Payload part of an ICMP V4 message. Check [`crate::Icmpv6Type`]
    /// for a description what will be part of the payload.
    Icmpv6 {
        payload: &'a [u8],
        /// True if the payload has been cut off.
        incomplete: bool,
    },
}

impl<'a> LaxPayloadSlice<'a> {
    pub fn slice(&self) -> &'a [u8] {
        match self {
            LaxPayloadSlice::Ether(e) => e.payload,
            LaxPayloadSlice::Ip(i) => i.payload,
            LaxPayloadSlice::Udp {
                payload,
                incomplete: _,
            } => payload,
            LaxPayloadSlice::Tcp {
                payload,
                incomplete: _,
            } => payload,
            LaxPayloadSlice::Icmpv4 {
                payload,
                incomplete: _,
            } => payload,
            LaxPayloadSlice::Icmpv6 {
                payload,
                incomplete: _,
            } => payload,
        }
    }
}
