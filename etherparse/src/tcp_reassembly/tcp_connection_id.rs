use crate::{tcp_reassembly::*, *};
use arrayvec::ArrayVec;

/// Values identifying a TCP connection (both directions).
///
/// The two endpoints are stored in a canonical order so that both directions
/// of a connection map to the same identifier (see
/// [`TcpConnectionId::new`], which also reports the
/// [`TcpDirection`] a segment was travelling in).
///
/// # VLAN ids & the custom channel id
///
/// By default the VLAN ids of the packets are part of the identity. Note that
/// this requires both directions of a connection to carry the *same* VLAN
/// ids, which is not the case for every capture setup (e.g. asymmetric
/// routing or a capture point that sees both sides of a router). If the two
/// directions are tagged differently they end up as two separate connections,
/// each containing only one direction, which under
/// [`TcpAckPolicy::Required`] means no data is handed out at all (see
/// [`TcpConnection::is_bidirectional`]).
///
/// To handle this, build the id from a [`TcpSegmentInfo`] with the VLAN ids
/// cleared and move whatever should differentiate the connections into the
/// `channel_id` instead:
///
/// ```no_run
/// # use etherparse::{tcp_reassembly::*, *};
/// # let slice: SlicedPacket = unimplemented!();
/// # let mut pool = TcpStreamReassemblyPool::<(), ()>::new();
/// if let Some(mut info) = TcpSegmentInfo::from_sliced_packet(&slice, ()) {
///     info.vlan_ids.clear();
///     pool.process_tcp(info, ()).unwrap();
/// }
/// ```
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct TcpConnectionId<CustomChannelId = ()> {
    /// VLAN ids of the original packets.
    vlan_ids: ArrayVec<VlanId, 3>,

    /// Endpoint that sorts first (kept in a canonical order so that both
    /// directions produce the same id).
    first: TcpEndpoint,

    /// Endpoint that sorts second.
    second: TcpEndpoint,

    /// Custom user defined channel identifier (can be used to differentiate
    /// packet sources if the normal ethernet packet identifiers are not
    /// enough).
    channel_id: CustomChannelId,
}

impl<CustomChannelId> TcpConnectionId<CustomChannelId> {
    /// Creates an identifier from the source & destination of a segment and
    /// returns the [`TcpDirection`] `source -> destination` corresponds to.
    ///
    /// The endpoints are re-ordered into a canonical order, so both
    /// directions of a connection result in the same identifier.
    pub fn new(
        source: TcpEndpoint,
        destination: TcpEndpoint,
        vlan_ids: ArrayVec<VlanId, 3>,
        channel_id: CustomChannelId,
    ) -> (TcpConnectionId<CustomChannelId>, TcpDirection) {
        if source <= destination {
            (
                TcpConnectionId {
                    vlan_ids,
                    first: source,
                    second: destination,
                    channel_id,
                },
                TcpDirection::FirstToSecond,
            )
        } else {
            (
                TcpConnectionId {
                    vlan_ids,
                    first: destination,
                    second: source,
                    channel_id,
                },
                TcpDirection::SecondToFirst,
            )
        }
    }

    /// VLAN ids of the original packets.
    #[inline]
    pub fn vlan_ids(&self) -> &ArrayVec<VlanId, 3> {
        &self.vlan_ids
    }

    /// Endpoint that sorts first.
    #[inline]
    pub fn first(&self) -> &TcpEndpoint {
        &self.first
    }

    /// Endpoint that sorts second.
    #[inline]
    pub fn second(&self) -> &TcpEndpoint {
        &self.second
    }

    /// Custom user defined channel identifier.
    #[inline]
    pub fn channel_id(&self) -> &CustomChannelId {
        &self.channel_id
    }

    /// Source endpoint of segments travelling in the given direction.
    #[inline]
    pub fn source(&self, direction: TcpDirection) -> &TcpEndpoint {
        match direction {
            TcpDirection::FirstToSecond => &self.first,
            TcpDirection::SecondToFirst => &self.second,
        }
    }

    /// Destination endpoint of segments travelling in the given direction.
    #[inline]
    pub fn destination(&self, direction: TcpDirection) -> &TcpEndpoint {
        match direction {
            TcpDirection::FirstToSecond => &self.second,
            TcpDirection::SecondToFirst => &self.first,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    fn endpoints() -> (TcpEndpoint, TcpEndpoint) {
        (
            TcpEndpoint::from_ipv4([1, 2, 3, 4], 1234),
            TcpEndpoint::from_ipv4([5, 6, 7, 8], 80),
        )
    }

    #[test]
    fn debug_clone_eq_hash() {
        let (a, b) = endpoints();
        let (value, _) = TcpConnectionId::new(a, b, Default::default(), 7u16);
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_ne!(
            value,
            TcpConnectionId::new(a, b, Default::default(), 8u16).0
        );

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

    #[test]
    fn both_directions_share_the_id() {
        let (a, b) = endpoints();
        let (id_ab, dir_ab) = TcpConnectionId::new(a, b, Default::default(), ());
        let (id_ba, dir_ba) = TcpConnectionId::new(b, a, Default::default(), ());

        // same connection, opposite directions
        assert_eq!(id_ab, id_ba);
        assert_eq!(dir_ab.reverse(), dir_ba);

        // the canonical order puts the smaller endpoint first
        assert_eq!(*id_ab.first(), a);
        assert_eq!(*id_ab.second(), b);
        assert_eq!(dir_ab, TcpDirection::FirstToSecond);
        assert_eq!(dir_ba, TcpDirection::SecondToFirst);
    }

    #[test]
    fn source_and_destination() {
        let (a, b) = endpoints();
        let (id, dir) = TcpConnectionId::new(a, b, Default::default(), ());
        assert_eq!(*id.source(dir), a);
        assert_eq!(*id.destination(dir), b);
        assert_eq!(*id.source(dir.reverse()), b);
        assert_eq!(*id.destination(dir.reverse()), a);
    }

    #[test]
    fn accessors() {
        let (a, b) = endpoints();
        let mut vlan_ids = ArrayVec::<VlanId, 3>::new_const();
        vlan_ids.push(VlanId::try_new(12).unwrap());
        let (id, _) = TcpConnectionId::new(a, b, vlan_ids.clone(), 42u16);
        assert_eq!(*id.vlan_ids(), vlan_ids);
        assert_eq!(*id.channel_id(), 42);

        // differing vlan ids result in different connections
        let (other, _) = TcpConnectionId::new(a, b, Default::default(), 42u16);
        assert_ne!(id, other);
    }
}
