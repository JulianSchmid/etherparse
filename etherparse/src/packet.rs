use crate::{LinkHeader, NetHeaders, PacketHeaders, Payload, TransportHeader, VlanHeader};

/// Owned version of [`crate::SlicedPacket`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Packet {
    /// Ethernet II header if present.
    pub link: Option<LinkHeader>,
    /// Single or double vlan headers if present.
    pub vlan: Option<VlanHeader>,
    /// IPv4 or IPv6 header and IP extension headers if present.
    pub net: Option<NetHeaders>,
    /// TCP or UDP header if present.
    pub transport: Option<TransportHeader>,
    /// Payload of the last parsed layer.
    pub payload: Payload,
}

impl From<PacketHeaders<'_>> for Packet {
    fn from(headers: PacketHeaders) -> Self {
        Self {
            link: headers.link,
            vlan: headers.vlan,
            net: headers.net,
            transport: headers.transport,
            payload: headers.payload.into(),
        }
    }
}
