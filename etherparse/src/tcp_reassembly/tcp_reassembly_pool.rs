use crate::tcp_reassembly::*;
use core::net::SocketAddr;
use std::collections::{hash_map::Entry, HashMap};

/// Reassembles the byte streams of TCP connections from captured segments.
///
/// Pass every TCP segment to the pool. It groups the segments into
/// connections and puts the bytes of each stream back in order, so they can
/// be read as one contiguous slice:
///
/// ```
/// use etherparse::{tcp_reassembly::*, TcpHeader, TcpSlice};
/// use std::net::IpAddr;
///
/// /// Passes a segment sent by `source` to the pool.
/// fn feed<'p>(
///     pool: &'p mut TcpReassemblyPool,
///     source: [u8; 4],
///     destination: [u8; 4],
///     header: &TcpHeader,
///     payload: &[u8],
/// ) -> TcpProcessed<'p, (), ()> {
///     let bytes = [&header.to_bytes()[..], payload].concat();
///     let segment = TcpSegment {
///         vlan_ids: Default::default(),
///         source: IpAddr::from(source),
///         destination: IpAddr::from(destination),
///         channel_id: (),
///         tcp: TcpSlice::from_slice(&bytes).unwrap(),
///     };
///     pool.process_segment(segment, ())
/// }
///
/// let initiator = [10, 0, 0, 1];
/// let responder = [10, 0, 0, 2];
/// let mut pool = TcpReassemblyPool::default();
///
/// // handshake
/// let mut syn = TcpHeader::new(50000, 80, 1000, 1024);
/// syn.syn = true;
/// feed(&mut pool, initiator, responder, &syn, &[]);
///
/// let mut syn_ack = TcpHeader::new(80, 50000, 5000, 1024);
/// syn_ack.syn = true;
/// syn_ack.ack = true;
/// syn_ack.acknowledgment_number = 1001;
/// feed(&mut pool, responder, initiator, &syn_ack, &[]);
///
/// // request of the initiator
/// let mut request = TcpHeader::new(50000, 80, 1001, 1024);
/// request.ack = true;
/// request.acknowledgment_number = 5001;
/// let processed = feed(&mut pool, initiator, responder, &request, b"GET / HTTP/1.1\r\n");
///
/// // read the bytes of the initiator's stream
/// let (connection, sender) = processed.active.unwrap();
/// assert_eq!(TcpRole::Initiator, sender);
/// let stream = connection.stream_mut(sender);
/// if let TcpRead::Data(data) = stream.read_received() {
///     assert_eq!(b"GET / HTTP/1.1\r\n", data);
///     // mark the bytes as processed
///     let len = data.len();
///     stream.consume(len);
/// }
/// assert_eq!(TcpRead::Pending, stream.read_received());
/// ```
#[derive(Clone, Debug)]
pub struct TcpReassemblyPool<Timestamp = (), CustomChannelId = ()> {
    config: TcpReassemblyConfig,
    /// Open connections, plus the tombstones of ended connections (without
    /// buffers) that absorb their late segments.
    connections:
        HashMap<TcpConnectionKey<CustomChannelId>, TcpConnection<Timestamp, CustomChannelId>>,
    /// Id of the next connection.
    next_id: TcpConnectionId,
}

impl<Timestamp, CustomChannelId> TcpReassemblyPool<Timestamp, CustomChannelId>
where
    Timestamp: Clone,
    CustomChannelId: core::hash::Hash + Eq + Clone,
{
    /// Creates a pool with the given configuration.
    pub fn new(config: TcpReassemblyConfig) -> TcpReassemblyPool<Timestamp, CustomChannelId> {
        TcpReassemblyPool {
            config,
            connections: HashMap::new(),
            next_id: TcpConnectionId(0),
        }
    }

    /// Configuration of the pool.
    pub fn config(&self) -> &TcpReassemblyConfig {
        &self.config
    }

    /// Applies a TCP segment to its connection.
    ///
    /// A SYN of an unknown connection starts a new one. Other segments of
    /// unknown connections are ignored with
    /// [`TcpIgnoreReason::NoConnection`].
    ///
    /// A connection that ends is handed over in [`TcpProcessed::ended`].
    /// Its late segments are then ignored with
    /// [`TcpIgnoreReason::AfterEnd`].
    pub fn process_segment(
        &mut self,
        segment: TcpSegment<'_, CustomChannelId>,
        timestamp: Timestamp,
    ) -> TcpProcessed<'_, Timestamp, CustomChannelId> {
        let tcp = segment.tcp;
        let source = SocketAddr::new(segment.source, tcp.source_port());
        let destination = SocketAddr::new(segment.destination, tcp.destination_port());
        let key = TcpConnectionKey::new(segment.vlan_ids, source, destination, segment.channel_id);

        let connection = match self.connections.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // only a SYN starts a connection
                if false == tcp.syn() || tcp.ack() {
                    return TcpProcessed {
                        active: None,
                        ended: None,
                        ignored: Some(TcpIgnoreReason::NoConnection),
                    };
                }
                let id = self.next_id;
                self.next_id = TcpConnectionId(id.0.wrapping_add(1));
                let key = entry.key().clone();
                entry.insert(TcpConnection::new(id, key, source, timestamp.clone()))
            }
        };
        if connection.end().is_some() {
            // the tombstone of an ended connection absorbs its late segments
            return TcpProcessed {
                active: None,
                ended: None,
                ignored: Some(TcpIgnoreReason::AfterEnd),
            };
        }
        let sender = connection.add_segment(source, &tcp, timestamp);
        if connection.end().is_some() {
            return TcpProcessed {
                active: None,
                ended: Some(connection.hand_over()),
                ignored: None,
            };
        }
        TcpProcessed {
            active: Some((connection, sender)),
            ended: None,
            ignored: None,
        }
    }
}

impl<Timestamp, CustomChannelId> Default for TcpReassemblyPool<Timestamp, CustomChannelId>
where
    Timestamp: Clone,
    CustomChannelId: core::hash::Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new(TcpReassemblyConfig::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{tcp_reassembly::TcpRole::*, test_gens::*, VlanId};
    use proptest::prelude::*;
    use std::{format, vec::Vec};

    #[test]
    fn derived_traits() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script
            .handshake()
            .send(Initiator, b"abc")
            .send(Initiator, b"def");
        script.feed(&mut pool, ..4);

        // clone (the clone continues independently)
        {
            let mut clone = pool.clone();
            let (connection, _) = script.feed(&mut clone, 4..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdef"),
                connection.stream_mut(Initiator).read_received()
            );
            let (connection, _) = script.feed(&mut pool, 2..3).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abc"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // debug
        assert!(format!("{:?}", pool).starts_with("TcpReassemblyPool { config: "));
    }

    proptest! {
        #[test]
        fn new(config in tcp_reassembly_config_any()) {
            let pool = TcpReassemblyPool::<(), ()>::new(config.clone());
            assert_eq!(&config, pool.config());
        }
    }

    #[test]
    fn default() {
        let pool: TcpReassemblyPool<u32, u8> = Default::default();
        assert_eq!(&TcpReassemblyConfig::default(), pool.config());
    }

    proptest! {
        #[test]
        fn config(config in tcp_reassembly_config_any()) {
            assert_eq!(
                &config,
                TcpReassemblyPool::<(), ()>::new(config.clone()).config()
            );
        }
    }

    #[test]
    fn process_segment() {
        // segments of an unknown connection that are not a SYN
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script =
                ConnectionScript::new(addr("10.0.0.1:50000"), addr("10.0.0.2:80"), 1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            for segment in &script.segments[1..] {
                let processed = segment.feed(&mut pool, 0);
                assert!(processed.active.is_none());
                assert_eq!(Some(TcpIgnoreReason::NoConnection), processed.ignored);
            }
        }

        // a SYN starts a connection
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script =
                ConnectionScript::new(addr("10.0.0.1:50000"), addr("10.0.0.2:80"), 1000, 2000);
            script.syn();
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(None, processed.ignored);
            let (connection, sender) = processed.active.unwrap();
            assert_eq!(Initiator, sender);
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                &TcpConnectionKey::new(
                    Default::default(),
                    addr("10.0.0.1:50000"),
                    addr("10.0.0.2:80"),
                    ()
                ),
                connection.key()
            );
            assert_eq!(addr("10.0.0.1:50000"), connection.endpoint(Initiator));
            assert_eq!(addr("10.0.0.2:80"), connection.endpoint(Responder));
            assert_eq!(&7, connection.first_seen());
            assert_eq!(&7, connection.last_seen());
        }

        // handshake and data in both directions
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"GET /")
                .send(Responder, b"HTTP/1.1");
            for segment in &script.segments {
                let processed = segment.feed(&mut pool, ());
                assert_eq!(None, processed.ignored);
                let (connection, sender) = processed.active.unwrap();
                assert_eq!(segment.sender, sender);
                assert_eq!(TcpConnectionId(0), connection.id());
            }
            let (connection, _) = script.segments[2].feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"GET /"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"HTTP/1.1"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a connection whose FINs were both ACKed is handed over
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"GET /")
                .send(Responder, b"HTTP/1.1")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let (last, rest) = script.segments.split_last().unwrap();
            for (i, segment) in rest.iter().enumerate() {
                let processed = segment.feed(&mut pool, i as u32);
                assert!(processed.active.is_some());
                assert!(processed.ended.is_none());
            }
            let processed = last.feed(&mut pool, 100);
            assert!(processed.active.is_none());
            assert_eq!(None, processed.ignored);
            let mut connection = processed.ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(&0, connection.first_seen());
            assert_eq!(&100, connection.last_seen());
            for (role, data) in [(Initiator, &b"GET /"[..]), (Responder, &b"HTTP/1.1"[..])] {
                let stream = connection.stream_mut(role);
                assert!(stream.is_complete());
                assert_eq!(TcpRead::Data(data), stream.read_received());
                stream.consume(data.len());
                assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            }
        }

        // late segments of an ended connection are ignored and start no
        // new connection
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator)
                // new bytes after the end
                .send(Responder, b"def");
            script.feed(&mut pool, ..7).ended.unwrap();
            // retransmissions of every segment after the SYN
            for segment in &script.segments[1..] {
                let processed = segment.feed(&mut pool, ());
                assert!(processed.active.is_none());
                assert!(processed.ended.is_none());
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
        }

        // segments with a different key belong to a different connection
        {
            let mut scripts = Vec::new();
            // base
            scripts.push(ConnectionScript::with_isns(1000, 2000).with_channel_id(0u8));
            // other port
            scripts.push(
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 1000, 2000)
                    .with_channel_id(0u8),
            );
            // other ip address
            scripts.push(
                ConnectionScript::new(addr("10.0.0.1:50000"), addr("10.0.0.3:80"), 1000, 2000)
                    .with_channel_id(0u8),
            );
            // ipv6
            scripts.push(
                ConnectionScript::new(addr("[::1]:50000"), addr("[::2]:80"), 1000, 2000)
                    .with_channel_id(0u8),
            );
            // other vlan ids
            scripts.push({
                let mut script = ConnectionScript::with_isns(1000, 2000).with_channel_id(0u8);
                script.vlan_ids.push(VlanId::try_new(1).unwrap());
                script
            });
            // other channel id
            scripts.push(ConnectionScript::with_isns(1000, 2000).with_channel_id(1u8));

            for (i, script) in scripts.iter_mut().enumerate() {
                script.handshake().send(Initiator, &[i as u8]);
            }

            // feed the connections interleaved
            let mut pool = TcpReassemblyPool::<(), u8>::default();
            for step in 0..4 {
                for (i, script) in scripts.iter().enumerate() {
                    let (connection, _) = script.segments[step].feed(&mut pool, ()).active.unwrap();
                    assert_eq!(TcpConnectionId(i as u64), connection.id());
                    if 3 == step {
                        assert_eq!(
                            TcpRead::Data(&[i as u8]),
                            connection.stream_mut(Initiator).read_received()
                        );
                    }
                }
            }
        }
    }
}
