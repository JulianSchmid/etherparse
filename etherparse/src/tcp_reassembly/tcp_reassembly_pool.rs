use crate::{tcp_reassembly::*, *};
use core::net::SocketAddr;
use std::{
    collections::{hash_map::Entry, HashMap},
    vec::Vec,
};

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
    /// Emptied buffers of recycled connections, re-used by new connections.
    free_buffers: Vec<Vec<u8>>,
    /// Id of the next connection.
    next_id: TcpConnectionId,
    /// Bytes buffered by the streams of the connections, as last accounted
    /// for.
    buffered: usize,
    /// Key of the connection handed out by the last call, whose streams
    /// can have been read since (only kept with a `max_total_buffered`).
    handed_out: Option<TcpConnectionKey<CustomChannelId>>,
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
            free_buffers: Vec::new(),
            next_id: TcpConnectionId(0),
            buffered: 0,
            handed_out: None,
        }
    }

    /// Configuration of the pool.
    pub fn config(&self) -> &TcpReassemblyConfig {
        &self.config
    }

    /// Applies a TCP segment to its connection.
    ///
    /// A SYN, a SYN-ACK or a segment with bytes of an unknown connection
    /// starts a new one. Without a SYN or SYN-ACK, the roles of the
    /// endpoints are guessed (see [`TcpConnection::roles_guessed`]). Other
    /// segments of unknown connections (pure ACKs, FINs without bytes and
    /// RSTs) are ignored with [`TcpIgnoreReason::NoConnection`].
    ///
    /// A connection that ends, e.g. by an RST (see
    /// [`TcpConnectionEnd::Reset`]), is handed over in
    /// [`TcpProcessed::ended`]. Its late segments are then ignored with
    /// [`TcpIgnoreReason::AfterEnd`], also retransmissions of its SYN and
    /// SYN-ACK. A SYN or SYN-ACK with a new ISN starts a new connection with
    /// a new id (a reconnect).
    ///
    /// A SYN with a new ISN on an open connection is kept until a SYN-ACK of
    /// the other endpoint with a new ISN, or one that ACKs the SYN, confirms
    /// the reconnect. That SYN-ACK hands the connection over in
    /// [`TcpProcessed::ended`] (see [`TcpConnectionEnd::Reconnect`]), and
    /// the reconnect, which starts with the SYN if the SYN-ACK ACKs it, is
    /// [`TcpProcessed::active`]. Without such a SYN-ACK, the SYN changes
    /// nothing, so a spoofed SYN can't end a connection.
    pub fn process_segment(
        &mut self,
        segment: TcpSegment<'_, CustomChannelId>,
        timestamp: Timestamp,
    ) -> TcpProcessed<'_, Timestamp, CustomChannelId> {
        // reading the connection handed out last made room
        if let Some(key) = self.handed_out.take() {
            if let Some(connection) = self.connections.get_mut(&key) {
                connection.account_buffered(&mut self.buffered);
            }
        }

        let tcp = segment.tcp;
        let source = SocketAddr::new(segment.source, tcp.source_port());
        let destination = SocketAddr::new(segment.destination, tcp.destination_port());
        let key = TcpConnectionKey::new(segment.vlan_ids, source, destination, segment.channel_id);

        let mut replaced = None;
        let mut replayed_syn = None;
        let connection = match self.connections.entry(key) {
            Entry::Occupied(entry) => {
                let connection = entry.into_mut();
                let reconnect = if connection.end().is_some() {
                    // the tombstone of an ended connection absorbs its late
                    // segments (also of its handshake), but a SYN or SYN-ACK
                    // with a new ISN starts a reconnect
                    tcp.syn()
                        && false == tcp.rst()
                        && false == connection.is_own_handshake(source, &tcp)
                } else {
                    connection.confirms_reconnect(source, &tcp, &self.config)
                };
                if reconnect {
                    // the reconnect starts with the kept SYN if the SYN-ACK
                    // ACKs it, otherwise with the segment
                    let kept = connection.take_reconnect_syn();
                    let kept_syn_acked = kept
                        .as_ref()
                        .is_some_and(|syn| syn.is_acked_by(source, &tcp));
                    let first_seen = match &kept {
                        Some(syn) if kept_syn_acked => syn.timestamp().clone(),
                        _ => timestamp.clone(),
                    };
                    let reconnect = new_connection(
                        &mut self.next_id,
                        &mut self.free_buffers,
                        connection.key().clone(),
                        handshake_initiator(&tcp, source, destination),
                        false,
                        first_seen,
                    );
                    match kept {
                        Some(syn) if kept_syn_acked => replayed_syn = Some(syn),
                        Some(syn) => self.free_buffers.push(syn.into_buffer()),
                        None => {}
                    }
                    let mut ended = core::mem::replace(connection, reconnect);
                    ended.release_buffered(&mut self.buffered);
                    if ended.end().is_none() {
                        ended.end_replaced();
                        replaced = Some(ended);
                    }
                } else if connection.end().is_some() {
                    return TcpProcessed {
                        active: None,
                        ended: None,
                        ignored: Some(TcpIgnoreReason::AfterEnd),
                    };
                }
                connection
            }
            Entry::Vacant(entry) => {
                let Some((initiator, roles_guessed)) =
                    new_connection_initiator(&tcp, source, destination)
                else {
                    return TcpProcessed {
                        active: None,
                        ended: None,
                        ignored: Some(TcpIgnoreReason::NoConnection),
                    };
                };
                let key = entry.key().clone();
                entry.insert(new_connection(
                    &mut self.next_id,
                    &mut self.free_buffers,
                    key,
                    initiator,
                    roles_guessed,
                    timestamp.clone(),
                ))
            }
        };
        // the bytes that would make the pool buffer more than its limit are
        // rejected
        let mut available = self
            .config
            .max_total_buffered
            .map_or(usize::MAX, |max| max.saturating_sub(self.buffered));
        if let Some(syn) = replayed_syn {
            connection.add_reconnect_syn(&syn, &self.config, &mut available);
            self.free_buffers.push(syn.into_buffer());
        }
        let sender = connection.add_segment(source, &tcp, timestamp, &self.config, &mut available);
        // the SYN or SYN-ACK that starts a reconnect doesn't end it: it has
        // no RST, and nothing ACKed a FIN of its sender yet
        if connection.end().is_some() {
            let mut ended = connection.hand_over();
            ended.release_buffered(&mut self.buffered);
            return TcpProcessed {
                active: None,
                ended: Some(ended),
                ignored: None,
            };
        }
        // the next call accounts for the bytes the connection buffers now,
        // and for the ones the user reads until then
        if self.config.max_total_buffered.is_some() {
            self.handed_out = Some(connection.key().clone());
        }
        TcpProcessed {
            active: Some((connection, sender)),
            ended: replaced,
            ignored: None,
        }
    }

    /// Takes back an ended connection, so that its buffers are re-used by
    /// new connections.
    pub fn recycle(&mut self, connection: TcpConnection<Timestamp, CustomChannelId>) {
        self.free_buffers.extend(connection.into_buffers());
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

/// Initiator of the connection that the segment `tcp` from `source` to
/// `destination` starts, and whether it is guessed from the ports. `None`
/// if the segment starts no connection.
fn new_connection_initiator(
    tcp: &TcpSlice<'_>,
    source: SocketAddr,
    destination: SocketAddr,
) -> Option<(SocketAddr, bool)> {
    // a SYN or SYN-ACK starts a connection with known roles, and bytes one
    // with roles guessed from the ports (pure ACKs, FINs without bytes and
    // RSTs don't start one)
    if tcp.rst() {
        None
    } else if tcp.syn() {
        Some((handshake_initiator(tcp, source, destination), false))
    } else if false == tcp.payload().is_empty() {
        // the lower port is the responder's, with equal ports the sender is
        // the initiator
        let initiator = if source.port() < destination.port() {
            destination
        } else {
            source
        };
        Some((initiator, true))
    } else {
        None
    }
}

/// Initiator of the connection whose SYN or SYN-ACK `tcp` was sent from
/// `source` to `destination`.
fn handshake_initiator(
    tcp: &TcpSlice<'_>,
    source: SocketAddr,
    destination: SocketAddr,
) -> SocketAddr {
    // the SYN-ACK is sent by the responder
    if tcp.ack() {
        destination
    } else {
        source
    }
}

/// Creates a connection with the id `next_id` (and moves `next_id` on),
/// whose streams store their bytes in buffers taken from `free_buffers`.
fn new_connection<Timestamp: Clone, CustomChannelId>(
    next_id: &mut TcpConnectionId,
    free_buffers: &mut Vec<Vec<u8>>,
    key: TcpConnectionKey<CustomChannelId>,
    initiator: SocketAddr,
    roles_guessed: bool,
    timestamp: Timestamp,
) -> TcpConnection<Timestamp, CustomChannelId> {
    let id = *next_id;
    *next_id = TcpConnectionId(id.0.wrapping_add(1));
    let buffers = [
        free_buffers.pop().unwrap_or_default(),
        free_buffers.pop().unwrap_or_default(),
    ];
    TcpConnection::new(id, key, initiator, roles_guessed, timestamp, buffers)
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
        // pure ACKs, FINs without bytes and RSTs (also with bytes or a SYN)
        // of an unknown connection start no connection (regression test:
        // the old tcp-reassembly branch created entries for pure ACKs)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin(Initiator).fin(Responder);
            let mut rsts = Vec::new();
            for (syn, payload) in [(false, &b""[..]), (false, b"x"), (true, b"")] {
                let mut rst = script.injected(|s| {
                    s.send(Initiator, payload);
                });
                rst.header.rst = true;
                rst.header.syn = syn;
                rsts.push(rst);
            }
            for segment in script.segments[2..].iter().chain(&rsts) {
                let processed = segment.feed(&mut pool, 0);
                assert!(processed.active.is_none());
                assert!(processed.ended.is_none());
                assert_eq!(Some(TcpIgnoreReason::NoConnection), processed.ignored);
            }
        }

        // bytes start a connection, with roles guessed from the ports
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Responder, b"abc");
            let processed = script.segments[3].feed(&mut pool, 7);
            assert_eq!(None, processed.ignored);
            let (connection, sender) = processed.active.unwrap();
            assert_eq!(Responder, sender);
            assert_eq!(TcpConnectionId(0), connection.id());
            assert!(connection.roles_guessed());
            assert_eq!(addr("10.0.0.1:50000"), connection.endpoint(Initiator));
            assert_eq!(&7, connection.first_seen());
            assert_eq!(
                TcpRead::Data(b"abc"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a SYN-ACK starts a connection, its sender is the responder
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script =
                ConnectionScript::new(addr("10.0.0.1:50000"), addr("10.0.0.2:80"), 1000, 2000);
            script.syn().syn_ack();
            let processed = script.segments[1].feed(&mut pool, 7);
            assert_eq!(None, processed.ignored);
            let (connection, sender) = processed.active.unwrap();
            assert_eq!(Responder, sender);
            assert_eq!(TcpConnectionId(0), connection.id());
            assert!(false == connection.roles_guessed());
            assert_eq!(addr("10.0.0.1:50000"), connection.endpoint(Initiator));
            assert_eq!(addr("10.0.0.2:80"), connection.endpoint(Responder));
            assert_eq!(&7, connection.first_seen());
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
            assert!(false == connection.roles_guessed());
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
        // new connection, also late retransmissions of its SYN and SYN-ACK
        // and an RST with a SYN
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
            let mut rst = script.segments[0].clone();
            rst.header.rst = true;
            rst.header.sequence_number = 5000;
            script.segments.push(rst);
            script.feed(&mut pool, ..7).ended.unwrap();
            for segment in &script.segments {
                let processed = segment.feed(&mut pool, ());
                assert!(processed.active.is_none());
                assert!(processed.ended.is_none());
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
        }

        // a SYN or SYN-ACK with a new ISN on the tombstone of an ended
        // connection starts a new connection with a new id, sent by either
        // endpoint (the SYN-ACK starts it if the SYN was not captured)
        for (initiator, responder) in [
            ("10.0.0.1:50000", "10.0.0.2:80"),
            ("10.0.0.2:80", "10.0.0.1:50000"),
        ] {
            for first in [0, 1] {
                let mut pool = TcpReassemblyPool::<u32, ()>::default();
                let mut ended = ConnectionScript::with_isns(1000, 2000);
                ended.handshake().send(Initiator, b"abc").rst(Responder);
                ended.feed_all(&mut pool).ended.unwrap();
                let mut script =
                    ConnectionScript::new(addr(initiator), addr(responder), 5000, 6000);
                script.handshake().send(Initiator, b"def");
                // without the ACK flag, a SYN doesn't ACK the SYN of the
                // ended connection
                script.segments[0].header.acknowledgment_number = if "10.0.0.1:50000" == initiator {
                    2001
                } else {
                    1001
                };
                let processed = script.segments[first].feed(&mut pool, 7);
                assert!(processed.ended.is_none());
                assert_eq!(None, processed.ignored);
                let (connection, sender) = processed.active.unwrap();
                assert_eq!(script.segments[first].sender, sender);
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(None, connection.end());
                assert!(false == connection.roles_guessed());
                assert_eq!(addr(initiator), connection.endpoint(Initiator));
                assert_eq!(&7, connection.first_seen());
                let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(
                    TcpRead::Data(b"def"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
        }

        // a late SYN-ACK that ACKs the SYN of the ended connection is
        // ignored, also if its sender's stream had no start
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            let syn_ack = script.segments.pop().unwrap();
            script.rst(Initiator);
            script.feed_all(&mut pool).ended.unwrap();
            let processed = syn_ack.feed(&mut pool, ());
            assert!(processed.active.is_none());
            assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
        }

        // a late retransmission of a SYN-ACK whose ISN the responder's
        // stream took is ignored, also if the initiator's stream couldn't
        // take its ACK (a pickup the reader had consumed from)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let syn_ack = script.segments[1].clone();
            script.segments.drain(..3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(1);
            }
            {
                let (connection, _) = syn_ack.feed(&mut pool, ()).active.unwrap();
                let starts =
                    [Initiator, Responder].map(|role| connection.stream(role).status().start);
                assert_eq!(
                    [TcpStreamStart::MidStreamPickup, TcpStreamStart::Observed],
                    starts
                );
            }
            script.rst(Initiator).feed(&mut pool, 1..).ended.unwrap();
            let processed = syn_ack.feed(&mut pool, ());
            assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
        }

        // the tombstone of a pickup knows no ISN, so any SYN starts a new
        // connection there, also a late SYN of the ended connection
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc").rst(Responder);
            let syn = script.segments[0].clone();
            script.segments.drain(..3);
            script.feed_all(&mut pool).ended.unwrap();
            let (connection, _) = syn.feed(&mut pool, ()).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(None, connection.end());
        }

        // a SYN with a new ISN on an open connection is kept until the
        // SYN-ACK of the other endpoint ACKs it: the SYN-ACK hands the
        // connection over as `Reconnect`, and the reconnect, which starts
        // with the SYN, is active with a new id, also if the old responder
        // sends the SYN (regression test: the old tcp-reassembly branch
        // handed the old connection over only if bytes were left, so a
        // caller that read everything didn't see the reconnect)
        for (initiator, responder) in [
            ("10.0.0.1:50000", "10.0.0.2:80"),
            ("10.0.0.2:80", "10.0.0.1:50000"),
        ] {
            for drained in [false, true] {
                let mut pool = TcpReassemblyPool::<u32, ()>::default();
                let mut old = ConnectionScript::with_isns(1000, 2000);
                old.handshake()
                    .send(Initiator, b"abc")
                    .send(Responder, b"def");
                {
                    let (connection, _) = old.feed_all(&mut pool).active.unwrap();
                    if drained {
                        for role in [Initiator, Responder] {
                            let stream = connection.stream_mut(role);
                            stream.read_received();
                            stream.consume(3);
                        }
                    }
                }
                let mut script =
                    ConnectionScript::new(addr(initiator), addr(responder), 5000, 6000);
                script.handshake().send(Initiator, b"ghi");
                {
                    let processed = script.segments[0].feed(&mut pool, 7);
                    assert!(processed.ended.is_none());
                    assert_eq!(None, processed.ignored);
                    let (connection, _) = processed.active.unwrap();
                    assert_eq!(TcpConnectionId(0), connection.id());
                    assert_eq!(None, connection.end());
                }
                let processed = script.segments[1].feed(&mut pool, 8);
                assert_eq!(None, processed.ignored);
                let mut ended = processed.ended.unwrap();
                assert_eq!(TcpConnectionId(0), ended.id());
                assert_eq!(Some(TcpConnectionEnd::Reconnect), ended.end());
                assert_eq!(&7, ended.last_seen());
                let expected = if drained {
                    TcpRead::End(TcpStreamEnd::Reconnect)
                } else {
                    TcpRead::Data(b"abc")
                };
                assert_eq!(expected, ended.stream_mut(Initiator).read_received());
                let (connection, sender) = processed.active.unwrap();
                assert_eq!(Responder, sender);
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(None, connection.end());
                assert!(false == connection.roles_guessed());
                assert_eq!(addr(initiator), connection.endpoint(Initiator));
                assert_eq!(&7, connection.first_seen());
                assert_eq!(&8, connection.last_seen());
                for role in [Initiator, Responder] {
                    let start = connection.stream(role).status().start;
                    assert_eq!(TcpStreamStart::Observed, start);
                }
                let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(
                    TcpRead::Data(b"ghi"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
        }

        // without its SYN-ACK, a SYN with a new ISN has no effect, so a
        // spoofed SYN can't split a live connection (its bytes would lie at
        // offset 3 of the initiator's stream)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number = script.seq(Initiator, 2);
            syn.payload = b"xyz".to_vec();
            script.segments.push(syn);
            script
                .send(Initiator, b"def")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let before = {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                connection.stream(Initiator).status().clone()
            };
            {
                let (connection, sender) = script.feed(&mut pool, 4..5).active.unwrap();
                assert_eq!(Initiator, sender);
                let stream = connection.stream(Initiator);
                assert_eq!(3, stream.highest_offset());
                assert_eq!(&before, stream.status());
            }
            let mut connection = script.feed(&mut pool, 5..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert!(stream.is_complete());
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
        }

        // a kept SYN waits for a SYN-ACK that confirms it: SYN-ACKs from the
        // endpoint that sent it, with the ISN of their sender's stream (a
        // retransmission, also if it ACKs the kept SYN), or with an RST
        // don't, and the kept SYN stays
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn_with_data(b"GET").syn_ack();
            let syn_ack = &script.segments[1];
            let mut others = Vec::new();
            // from the endpoint that sent the SYN
            let mut reversed =
                ConnectionScript::new(addr("10.0.0.2:80"), addr("10.0.0.1:50000"), 5000, 6000);
            reversed.syn().syn_ack();
            others.push(reversed.segments[1].clone());
            // ISN of the responder's stream (retransmissions of the old
            // SYN-ACK and with the ACK of the kept SYN)
            others.push(old.segments[1].clone());
            let mut retransmission = syn_ack.clone();
            retransmission.header.sequence_number = 2000;
            others.push(retransmission);
            // RST (outside of the window, so it doesn't reset the connection)
            let mut rst = syn_ack.clone();
            rst.header.rst = true;
            rst.header.sequence_number = 6000 + (1 << 30);
            others.push(rst);
            old.feed_all(&mut pool);
            script.segments[0].feed(&mut pool, ());
            for other in &others {
                let (connection, _) = other.feed(&mut pool, ()).active.unwrap();
                assert_eq!(TcpConnectionId(0), connection.id());
                assert_eq!(None, connection.end());
            }
            let processed = syn_ack.feed(&mut pool, ());
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"GET"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a SYN-ACK of the other endpoint with a new ISN confirms the
        // reconnect also if it doesn't ACK the kept SYN (e.g. after another
        // SYN replaced the real one): the reconnect then starts at the
        // SYN-ACK, without the bytes of the SYN
        for (ack, spoofed) in [(5000, false), (5005, false), (5004, true)] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn_with_data(b"GET").syn_ack();
            script.segments[1].header.acknowledgment_number = ack;
            script.segments[0].feed(&mut pool, 7);
            if spoofed {
                let mut spoofed = ConnectionScript::with_isns(7777, 0);
                spoofed.syn();
                spoofed.segments[0].feed(&mut pool, 8);
            }
            let processed = script.segments[1].feed(&mut pool, 9);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, sender) = processed.active.unwrap();
            assert_eq!(Responder, sender);
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(&9, connection.first_seen());
            assert_eq!(addr("10.0.0.1:50000"), connection.endpoint(Initiator));
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // a SYN-ACK with a new ISN that confirms no reconnect changes
        // nothing: neither its bytes (they would lie at offset 1 of the
        // responder's stream), nor its ACK or window
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let mut syn_ack = script.segments[1].clone();
            syn_ack.header.sequence_number = 2001;
            syn_ack.header.acknowledgment_number = 1 << 30;
            syn_ack.header.window_size = 0;
            syn_ack.payload = b"x".to_vec();
            let before = {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                [Initiator, Responder].map(|role| {
                    let stream = connection.stream(role);
                    (
                        stream.status().clone(),
                        stream.highest_offset(),
                        stream.acked_offset(),
                    )
                })
            };
            let (connection, sender) = syn_ack.feed(&mut pool, ()).active.unwrap();
            assert_eq!(Responder, sender);
            let after = [Initiator, Responder].map(|role| {
                let stream = connection.stream(role);
                (
                    stream.status().clone(),
                    stream.highest_offset(),
                    stream.acked_offset(),
                )
            });
            assert_eq!(before, after);
            // the window of 0 doesn't count
            let (connection, _) = script
                .send_at(Initiator, 10, b"def")
                .feed(&mut pool, 4..)
                .active
                .unwrap();
            assert_eq!(13, connection.stream(Initiator).highest_offset());
        }

        // ... also on a pickup whose client only sent ACKs: its ACK gives
        // the client's stream no start
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Responder, b"abc");
            let mut syn_ack = script.segments[1].clone();
            syn_ack.header.sequence_number = 900_000;
            syn_ack.header.acknowledgment_number = 777_001;
            script.segments.drain(..3);
            script.segments.push(syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            for role in [Initiator, Responder] {
                let start = connection.stream(role).status().start;
                assert_eq!(TcpStreamStart::MidStreamPickup, start);
            }
            assert_eq!(0, connection.stream(Initiator).highest_offset());
        }

        // a SYN without the ACK flag doesn't confirm a kept SYN, even if its
        // ACK number does: it replaces the kept SYN, as a SYN of the other
        // endpoint
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn();
            let mut reversed =
                ConnectionScript::new(addr("10.0.0.2:80"), addr("10.0.0.1:50000"), 6000, 5000);
            reversed.syn().syn_ack();
            reversed.segments[0].header.acknowledgment_number = 5001;
            old.feed_all(&mut pool);
            script.segments[0].feed(&mut pool, ());
            let processed = reversed.segments[0].feed(&mut pool, ());
            assert!(processed.ended.is_none());
            assert_eq!(TcpConnectionId(0), processed.active.unwrap().0.id());
            let processed = reversed.segments[1].feed(&mut pool, ());
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = processed.active.unwrap();
            assert_eq!(addr("10.0.0.2:80"), connection.endpoint(Initiator));
        }

        // the reconnect gets the bytes of its SYN (TCP Fast Open), whether
        // the SYN-ACK ACKs them or only the SYN, and the buffer that kept
        // the SYN is re-used without its bytes
        for ack in [5001, 5004] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn_with_data(b"GET").syn_ack();
            script.segments[1].header.acknowledgment_number = ack;
            old.feed_all(&mut pool);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"GET"),
                connection.stream_mut(Initiator).read_received()
            );
            let mut next =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 1000, 2000);
            next.handshake().send(Initiator, b"x");
            let (connection, _) = next.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.read_offset());
            assert_eq!(TcpRead::Data(b"x"), stream.read_received());
        }

        // a retransmission of the kept SYN changes nothing, and a SYN with
        // another new ISN replaces it (a SYN-ACK of the replaced SYN starts
        // the reconnect at the SYN-ACK)
        for (isns, confirmed, first_seen) in [
            ([5000, 5000], 5000, 7),
            ([5000, 9000], 9000, 8),
            ([5000, 9000], 5000, 9),
        ] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            old.feed_all(&mut pool);
            for (isn, timestamp) in isns.into_iter().zip([7, 8]) {
                let mut script = ConnectionScript::with_isns(isn, 6000);
                script.syn();
                script.segments[0].feed(&mut pool, timestamp);
            }
            let mut script = ConnectionScript::with_isns(confirmed, 6000);
            script.syn().syn_ack();
            let processed = script.segments[1].feed(&mut pool, 9);
            assert!(processed.ended.is_some());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(&first_seen, connection.first_seen());
        }

        // a SYN on a mid-stream pickup is its own late SYN if it lies at
        // most k windows before the stream's first byte: it gives the stream
        // an observed start, or counts as out-of-window once the read
        // position moved. Other SYNs start a reconnect that the SYN-ACK
        // confirms (k windows are 2 * 100 bytes, the capture starts at the
        // initiator's byte 300)
        for (position, consumed, expected) in [
            (0, false, Some(TcpStreamStart::Observed)),
            (-200, false, Some(TcpStreamStart::Observed)),
            (0, true, Some(TcpStreamStart::MidStreamPickup)),
            (-200, true, Some(TcpStreamStart::MidStreamPickup)),
            (-201, false, None),
            (-201, true, None),
            (1, false, None),
            (1, true, None),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 300)
                .send(Initiator, b"abc");
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number = script.seq(Initiator, (300 + position) as u64) - 1;
            let mut syn_ack = script.segments[1].clone();
            syn_ack.header.sequence_number = 7000;
            syn_ack.header.acknowledgment_number = syn.header.sequence_number + 1;
            script.segments.drain(..3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                if consumed {
                    let stream = connection.stream_mut(Initiator);
                    stream.read_received();
                    stream.consume(1);
                }
            }
            {
                let (connection, _) = syn.feed(&mut pool, ()).active.unwrap();
                let status = connection.stream(Initiator).status();
                if let Some(start) = expected {
                    assert_eq!(start, status.start);
                    let counted = TcpStreamStart::MidStreamPickup == start;
                    assert_eq!(u64::from(counted), status.out_of_window_segments);
                } else {
                    assert_eq!(TcpStreamStart::MidStreamPickup, status.start);
                    assert_eq!(0, status.out_of_window_segments);
                }
            }
            let processed = syn_ack.feed(&mut pool, ());
            assert_eq!(expected.is_none(), processed.ended.is_some());
        }

        // a SYN on a stream without a start is its own late SYN if it lies
        // at most k windows before the other side's last ACK of the stream,
        // or if there is no such ACK. Other SYNs start a reconnect that the
        // SYN-ACK confirms (k windows are 2 * 100 bytes, the responder ACKs
        // the initiator's byte 300)
        for (offset, acked, own) in [
            (300, true, true),
            (100, true, true),
            (99, true, false),
            (301, true, false),
            (301, false, true),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 300)
                .send(Responder, b"abc");
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number = script.seq(Initiator, offset) - 1;
            let mut syn_ack = script.segments[1].clone();
            syn_ack.header.sequence_number = 7000;
            syn_ack.header.acknowledgment_number = syn.header.sequence_number + 1;
            script.segments.drain(..3);
            script.segments[0].header.ack = acked;
            script.feed_all(&mut pool);
            {
                let (connection, _) = syn.feed(&mut pool, ()).active.unwrap();
                let status = connection.stream(Initiator).status();
                let start = if own {
                    TcpStreamStart::Observed
                } else {
                    TcpStreamStart::MidStreamPickup
                };
                assert_eq!(start, status.start);
            }
            let processed = syn_ack.feed(&mut pool, ());
            assert_eq!(own, processed.ended.is_none());
        }

        // a connection that ends while a SYN is kept leaves it in its
        // tombstone: a SYN-ACK that ACKs it starts the reconnect with the SYN
        // (its bytes and timestamp), and a retransmission of the SYN starts
        // it right away
        for retransmitted in [false, true] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake().send(Initiator, b"abc");
            let rst = old.injected(|s| {
                s.rst(Initiator);
            });
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn_with_data(b"GET").syn_ack();
            old.feed_all(&mut pool);
            script.segments[0].feed(&mut pool, 7);
            rst.feed(&mut pool, 8).ended.unwrap();
            if retransmitted {
                let (connection, _) = script.segments[0].feed(&mut pool, 9).active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
            }
            let processed = script.segments[1].feed(&mut pool, 10);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(&if retransmitted { 9 } else { 7 }, connection.first_seen());
            assert_eq!(
                TcpRead::Data(b"GET"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // on a tombstone, a SYN-ACK from the endpoint that sent the kept SYN,
        // or a SYN without the ACK flag, doesn't ACK the kept SYN: the
        // reconnect starts at it
        for syn_ack in [true, false] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            let rst = old.injected(|s| {
                s.rst(Initiator);
            });
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn();
            let mut other =
                ConnectionScript::new(addr("10.0.0.2:80"), addr("10.0.0.1:50000"), 6000, 7000);
            other.syn().syn_ack();
            let mut segment = other.segments[usize::from(syn_ack)].clone();
            segment.header.acknowledgment_number = 5001;
            old.feed_all(&mut pool);
            script.segments[0].feed(&mut pool, 7);
            rst.feed(&mut pool, 8).ended.unwrap();
            let (connection, _) = segment.feed(&mut pool, 9).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(&9, connection.first_seen());
        }

        // ... also if the kept SYN is the packet that finishes the
        // connection, as it makes the last hole overdue (the ACK of the
        // responder covered it one packet before)
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .fin(Responder);
            old.segments[3..].rotate_left(1);
            old.segments.pop();
            old.segments
                .last_mut()
                .unwrap()
                .header
                .acknowledgment_number = old.seq(Initiator, 0);
            old.ack(Initiator).ack(Responder);
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn_with_data(b"GET").syn_ack();
            {
                let (connection, _) = old.feed_all(&mut pool).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let processed = script.segments[0].feed(&mut pool, ());
            assert!(processed.active.is_none());
            let ended = processed.ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), ended.end());
            let processed = script.segments[1].feed(&mut pool, ());
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"GET"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a connection reset by an RST that the receiver can accept is
        // handed over with its bytes, and its late segments are ignored
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .rst(Responder)
                // new bytes after the end
                .send(Initiator, b"def");
            let processed = script.feed(&mut pool, ..5);
            assert!(processed.active.is_none());
            assert_eq!(None, processed.ignored);
            let mut connection = processed.ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                connection.end()
            );
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                TcpRead::Data(b"abc"),
                connection.stream_mut(Initiator).read_received()
            );
            for segment in &script.segments[1..] {
                let processed = segment.feed(&mut pool, 0);
                assert!(processed.active.is_none());
                assert!(processed.ended.is_none());
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
        }

        // an RST outside of the receiver's window is applied to the
        // connection without ending it
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().rst_at(Responder, 1 << 30);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            assert_eq!(None, processed.ignored);
            let (connection, sender) = processed.active.unwrap();
            assert_eq!(Responder, sender);
            assert_eq!(None, connection.end());
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

        // all streams of the pool together buffer at most
        // max_total_buffered bytes, counted as for max_stream_buffer: bytes
        // beyond it are rejected, and reading the connection that was
        // handed out makes room at once
        {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(10),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut first = ConnectionScript::with_isns(1000, 2000);
            first.handshake().send(Initiator, b"abcdefgh");
            let mut second =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000);
            second
                .handshake()
                .send(Initiator, b"12345678")
                .send(Responder, b"xyz");
            {
                let (connection, _) = first.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abcdefgh"), stream.read_received());
                stream.consume(4);
            }
            let (connection, _) = second.feed_all(&mut pool).active.unwrap();
            // 6 bytes fit after the 4 unread bytes of the first connection
            let stream = connection.stream_mut(Initiator);
            assert_eq!(2, stream.status().rejected_bytes);
            assert_eq!(TcpRead::Data(b"123456"), stream.read_received());
            assert_eq!(3, connection.stream(Responder).status().rejected_bytes);
        }

        // connections handed over as ended don't count, also with unread
        // bytes: ones that ended (e.g. by an RST) and ones a reconnect
        // replaced
        for reconnect in [false, true] {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(10),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut first = ConnectionScript::with_isns(1000, 2000);
            first.handshake().send(Initiator, b"abcdefgh");
            if false == reconnect {
                first.rst(Responder);
            }
            let mut second = if reconnect {
                ConnectionScript::with_isns(5000, 6000)
            } else {
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000)
            };
            second.handshake().send(Initiator, b"12345678");
            first.feed_all(&mut pool);
            let (connection, _) = second.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).status().rejected_bytes);
        }

        // a mid-stream pickup none of whose bytes fit doesn't start: the next
        // bytes that fit start it, and the rejected bytes can still be put in
        // front
        {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(8),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut first = ConnectionScript::with_isns(1000, 2000);
            first
                .handshake()
                .send(Initiator, b"abcdefgh")
                .ack(Responder);
            let mut second =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000);
            second
                .handshake()
                .send(Initiator, b"xyz")
                .send(Initiator, b"uvw");
            second.segments.drain(..3);
            first.feed(&mut pool, ..4);
            {
                let (connection, _) = second.segments[0].feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(3, stream.status().rejected_bytes);
                assert_eq!(0, stream.highest_offset());
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            {
                let (connection, _) = first.feed(&mut pool, 4..).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(8);
            }
            second.feed(&mut pool, 1..);
            let (connection, _) = second.segments[0].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(3, stream.status().rejected_bytes);
            assert_eq!(TcpRead::Data(b"xyzuvw"), stream.read_received());
        }

        // putting bytes in front of a mid-stream pickup, or the start of its
        // late SYN or the ACK of its late SYN-ACK, needs room in the pool for
        // the bytes in front (the pickup starts with 2 bytes at 4, another
        // connection buffers 6 bytes)
        for (max_total_buffered, late, start, rejected) in [
            (12, 0, TcpStreamStart::Observed, 0),
            (11, 0, TcpStreamStart::MidStreamPickup, 0),
            (12, 1, TcpStreamStart::Observed, 0),
            (11, 1, TcpStreamStart::MidStreamPickup, 0),
            (12, 3, TcpStreamStart::MidStreamPickup, 0),
            (11, 3, TcpStreamStart::MidStreamPickup, 2),
        ] {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(max_total_buffered),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut first =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000);
            first.handshake().send(Initiator, b"123456");
            let mut second = ConnectionScript::with_isns(1000, 2000);
            second
                .handshake()
                .send(Initiator, b"ab")
                .send_at(Initiator, 4, b"ef");
            let late = second.segments[late].clone();
            second.segments.drain(..4);
            second.feed_all(&mut pool);
            first.feed_all(&mut pool);
            let (connection, _) = late.feed(&mut pool, ()).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!(start, status.start);
            assert_eq!(rejected, status.rejected_bytes);
        }

        // the bytes of a kept SYN that a reconnect replays need room in the
        // pool too, and the bytes of the SYN-ACK get the room that is left
        // (another connection buffers 3 bytes)
        {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(7),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut first =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000);
            first.handshake().send(Initiator, b"123");
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            let mut new = ConnectionScript::with_isns(5000, 6000);
            new.syn_with_data(b"abc").syn_ack();
            new.segments[1].payload = b"xyz".to_vec();
            first.feed_all(&mut pool);
            old.feed_all(&mut pool);
            let (connection, _) = new.feed_all(&mut pool).active.unwrap();
            let [initiator, responder] =
                [Initiator, Responder].map(|role| connection.stream(role).status().rejected_bytes);
            assert_eq!((0, 2), (initiator, responder));
            assert_eq!(
                TcpRead::Data(b"abc"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // the bytes in front of a mid-stream pickup take room from the pool,
        // so less is left for the bytes of the same segment after the
        // pickup's bytes (the pickup starts with 2 bytes at 4)
        {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(8),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 4, b"ef")
                .send_at(Initiator, 0, b"abcdefghij");
            script.segments.drain(..3);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(2, stream.status().rejected_bytes);
            assert_eq!(TcpRead::Data(b"abcdefgh"), stream.read_received());
        }
    }

    #[test]
    fn recycle() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script
            .handshake()
            .send(Initiator, b"abc")
            .send(Responder, b"defgh")
            .fin(Initiator)
            .fin(Responder)
            .ack(Initiator);
        let mut ended = script.feed_all(&mut pool).ended.unwrap();
        // partly read
        ended.stream_mut(Initiator).read_received();
        ended.stream_mut(Initiator).consume(1);
        pool.recycle(ended);

        // a new connection re-uses the buffers without their old bytes
        let mut next =
            ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000);
        next.handshake().send(Initiator, b"x").send(Responder, b"y");
        let (connection, _) = next.feed_all(&mut pool).active.unwrap();
        assert_eq!(TcpConnectionId(1), connection.id());
        for (role, data) in [(Initiator, b"x"), (Responder, b"y")] {
            let stream = connection.stream_mut(role);
            assert_eq!(0, stream.read_offset());
            assert_eq!(TcpRead::Data(data), stream.read_received());
        }
    }
}
