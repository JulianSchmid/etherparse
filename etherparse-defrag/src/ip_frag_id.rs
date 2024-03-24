use etherparse::*;

/// Values identifying a fragmented packet.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct IpFragId<CustomChannelId = ()>
where
    CustomChannelId: core::hash::Hash + Eq + PartialEq + Clone + Sized,
{
    /// First VLAN id of the fragmented packets.
    pub outer_vlan_id: Option<VlanId>,

    /// Second VLAN id of the fragmented packets.
    pub inner_vlan_id: Option<VlanId>,

    /// IP source & destination address.
    pub ip_src_dst: IpSrcDst,

    /// Identifier in the IP header for the fragmented packet.
    pub identifier: u32,

    /// Custom user defined channel identifier (can be used to differentiate packet
    /// sources if the normal ethernet packets identifier are not enough).
    pub channel_id: CustomChannelId,
}

/// Source & destionation IP address.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum IpSrcDst {
    /// IPv4 source & destination pair.
    Ipv4([u8; 4], [u8; 4]),
    /// IPv6 source & destination pair.
    Ipv6([u8; 16], [u8; 16]),
}
