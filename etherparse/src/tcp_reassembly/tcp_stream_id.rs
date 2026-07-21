use crate::{tcp_reassembly::*, *};
use arrayvec::ArrayVec;

/// Values identifying a single **direction** of a TCP stream.
///
/// A full TCP connection consists of two [`TcpStreamId`]s (one for each
/// direction) as the source & destination addresses and ports are swapped
/// between the two directions.
///
/// The identifier can be extended with a custom "channel id" to further
/// differentiate streams if the addresses & ports alone are not enough
/// (e.g. when capturing from multiple interfaces).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct TcpStreamId<CustomChannelId = ()>
where
    CustomChannelId: core::hash::Hash + Eq + PartialEq + Clone + Sized,
{
    /// VLAN id's of the original packets.
    pub vlan_ids: ArrayVec<VlanId, 3>,

    /// IP source & destination address.
    pub ip: TcpStreamIpId,

    /// TCP source port.
    pub source_port: u16,

    /// TCP destination port.
    pub destination_port: u16,

    /// Custom user defined channel identifier (can be used to differentiate
    /// packet sources if the normal ethernet packet identifiers are not
    /// enough).
    pub channel_id: CustomChannelId,
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    fn example() -> TcpStreamId<u16> {
        TcpStreamId {
            vlan_ids: Default::default(),
            ip: TcpStreamIpId::Ipv4 {
                source: [1, 2, 3, 4],
                destination: [5, 6, 7, 8],
            },
            source_port: 1234,
            destination_port: 80,
            channel_id: 7,
        }
    }

    #[test]
    fn debug_clone_eq_hash() {
        let value = example();
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_ne!(value, {
            let mut other = example();
            other.source_port = 4321;
            other
        });

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            value.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            value.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }
}
