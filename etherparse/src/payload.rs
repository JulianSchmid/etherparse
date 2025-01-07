use std::vec::Vec;

use crate::{link::ether_payload::EtherPayload, IpPayload, PayloadSlice};

/// Payload together with an identifier the type of content. Owned version of [`PayloadSlice`].
#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Payload {
    /// Payload with it's type identified by an ether type number
    /// (e.g. after an ethernet II or vlan header).
    Ether(EtherPayload),
    /// Payload with is's type identified by an ip number (e.g.
    /// after an IP header or after an)
    Ip(IpPayload),
    /// UDP payload.
    Udp(Vec<u8>),
    /// TCP payload.
    Tcp(Vec<u8>),
    /// Payload part of an ICMP V4 message. Check [`crate::Icmpv4Type`]
    /// for a description what will be part of the payload.
    Icmpv4(Vec<u8>),
    /// Payload part of an ICMP V4 message. Check [`crate::Icmpv6Type`]
    /// for a description what will be part of the payload.
    Icmpv6(Vec<u8>),
}

impl<'a> From<PayloadSlice<'a>> for Payload {
    fn from(slice: PayloadSlice<'a>) -> Self {
        match slice {
            PayloadSlice::Ether(s) => Self::Ether(s.into()),
            PayloadSlice::Ip(s) => Self::Ip(s.into()),
            PayloadSlice::Udp(s) => Self::Udp(s.to_vec()),
            PayloadSlice::Tcp(s) => Self::Tcp(s.to_vec()),
            PayloadSlice::Icmpv4(s) => Self::Icmpv4(s.to_vec()),
            PayloadSlice::Icmpv6(s) => Self::Icmpv6(s.to_vec()),
        }
    }
}
