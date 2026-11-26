use crate::*;
use arrayvec::ArrayVec;
use core::net::SocketAddr;

/// Values identifying a TCP connection, the same for both directions.
///
/// The key consists of the VLAN IDs, both endpoints and a user-defined
/// channel id, which can separate packets the protocol headers alone cannot
/// tell apart (e.g. the capture interface or a tunnel). The endpoints are
/// sorted, so both directions of a connection get the same key:
///
/// ```
/// use etherparse::tcp_reassembly::TcpConnectionKey;
/// use std::net::SocketAddr;
///
/// let initiator: SocketAddr = "192.168.1.2:50000".parse().unwrap();
/// let responder: SocketAddr = "10.0.0.1:443".parse().unwrap();
///
/// let key = TcpConnectionKey::new(Default::default(), initiator, responder, ());
/// assert_eq!(
///     key,
///     TcpConnectionKey::new(Default::default(), responder, initiator, ())
/// );
/// assert_eq!(key.endpoints(), [responder, initiator]);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TcpConnectionKey<CustomChannelId = ()> {
    vlan_ids: ArrayVec<VlanId, 3>,
    endpoints: [SocketAddr; 2],
    channel_id: CustomChannelId,
}

impl<CustomChannelId> TcpConnectionKey<CustomChannelId> {
    /// Creates a key from the VLAN IDs, the two endpoints (in any order) and
    /// the channel id.
    pub fn new(
        vlan_ids: ArrayVec<VlanId, 3>,
        a: SocketAddr,
        b: SocketAddr,
        channel_id: CustomChannelId,
    ) -> TcpConnectionKey<CustomChannelId> {
        TcpConnectionKey {
            vlan_ids,
            endpoints: if a <= b { [a, b] } else { [b, a] },
            channel_id,
        }
    }

    /// VLAN IDs of the connection's packets.
    pub fn vlan_ids(&self) -> &[VlanId] {
        &self.vlan_ids
    }

    /// Both endpoints of the connection, the lower one first.
    pub fn endpoints(&self) -> [SocketAddr; 2] {
        self.endpoints
    }

    /// User-defined channel id of the connection.
    pub fn channel_id(&self) -> &CustomChannelId {
        &self.channel_id
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::{collections::hash_map::DefaultHasher, format};

    fn hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    proptest! {
        #[test]
        fn derived_traits(key in tcp_connection_key_any()) {
            // clone & eq
            assert_eq!(key.clone(), key);

            // debug
            assert_eq!(
                format!(
                    "TcpConnectionKey {{ vlan_ids: {:?}, endpoints: {:?}, channel_id: {:?} }}",
                    key.vlan_ids(),
                    key.endpoints(),
                    key.channel_id()
                ),
                format!("{:?}", key)
            );

            // ord & partial ord (vlan ids are compared first)
            {
                use core::cmp::Ordering;
                assert_eq!(Ordering::Equal, key.cmp(&key.clone()));
                assert_eq!(Some(Ordering::Equal), key.partial_cmp(&key.clone()));

                if key.vlan_ids().len() < 3 {
                    let mut more_vlan_ids: ArrayVec<VlanId, 3> =
                        key.vlan_ids().iter().copied().collect();
                    more_vlan_ids.push(VlanId::ZERO);
                    let [a, b] = key.endpoints();
                    let bigger = TcpConnectionKey::new(more_vlan_ids, a, b, *key.channel_id());
                    assert_eq!(Ordering::Less, key.cmp(&bigger));
                }
            }

            // hash
            assert_eq!(hash(&key), hash(&key.clone()));
        }
    }

    proptest! {
        #[test]
        fn new(
            vlan_ids in vlan_ids_any(),
            a in socket_addr_any(),
            b in socket_addr_any(),
            channel_id in any::<u32>(),
        ) {
            let ab = TcpConnectionKey::new(vlan_ids.clone(), a, b, channel_id);
            let ba = TcpConnectionKey::new(vlan_ids.clone(), b, a, channel_id);

            // both orders give the same key
            assert_eq!(ab, ba);
            assert_eq!(hash(&ab), hash(&ba));

            // the endpoints are sorted, the lower one first
            assert_eq!(ab.endpoints(), [a.min(b), a.max(b)]);
            assert_eq!(ab.vlan_ids(), &vlan_ids[..]);
            assert_eq!(ab.channel_id(), &channel_id);
        }
    }

    proptest! {
        #[test]
        fn vlan_ids(
            vlan_ids in vlan_ids_any(),
            a in socket_addr_any(),
            b in socket_addr_any(),
        ) {
            let key = TcpConnectionKey::new(vlan_ids.clone(), a, b, ());
            assert_eq!(key.vlan_ids(), &vlan_ids[..]);
        }
    }

    proptest! {
        #[test]
        fn endpoints(
            a in socket_addr_any(),
            b in socket_addr_any(),
        ) {
            let key = TcpConnectionKey::new(Default::default(), a, b, ());
            if a <= b {
                assert_eq!(key.endpoints(), [a, b]);
            } else {
                assert_eq!(key.endpoints(), [b, a]);
            }
        }
    }

    proptest! {
        #[test]
        fn channel_id(
            a in socket_addr_any(),
            b in socket_addr_any(),
            channel_id in any::<u32>(),
        ) {
            let key = TcpConnectionKey::new(Default::default(), a, b, channel_id);
            assert_eq!(key.channel_id(), &channel_id);
        }
    }
}
