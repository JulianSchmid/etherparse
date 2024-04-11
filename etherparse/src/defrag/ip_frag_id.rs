use crate::{*, defrag::*};

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

    /// IP source & destination address & identifaction field.
    pub ip: IpFragVersionSpecId,

    /// IP number of the payload.
    pub payload_ip_number: IpNumber,

    /// Custom user defined channel identifier (can be used to differentiate packet
    /// sources if the normal ethernet packets identifier are not enough).
    pub channel_id: CustomChannelId,
}
