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
    /// Open connections.
    connections:
        HashMap<TcpConnectionKey<CustomChannelId>, TcpConnection<Timestamp, CustomChannelId>>,
    /// What is left of ended connections, which absorbs their late segments
    /// (see [`TcpIgnoreReason::AfterEnd`]). A key is in at most one of the
    /// two maps.
    tombstones: HashMap<TcpConnectionKey<CustomChannelId>, Tombstone<Timestamp>>,
    /// Buffers of recycled connections, re-used by new connections.
    free: FreeBuffers,
    /// Id of the next connection.
    next_id: TcpConnectionId,
    /// Bytes buffered by the streams of the connections, as last accounted
    /// for.
    buffered: usize,
    /// Connections handed out by the last call, whose streams can have
    /// been read since (only kept with a `max_total_buffered`).
    handed_out: Option<HandedOut<CustomChannelId>>,
    /// Ids and keys of the connections an eviction ends, empty between
    /// evictions (kept to re-use its memory).
    evicted_keys: Vec<(TcpConnectionId, TcpConnectionKey<CustomChannelId>)>,
    /// Number of packets ignored as they would have started a connection in
    /// a full pool.
    rejected_connections: u64,
    /// Number of packets applied to no connection.
    ignored_packets: u64,
}

impl<Timestamp, CustomChannelId> TcpReassemblyPool<Timestamp, CustomChannelId>
where
    Timestamp: Clone,
    CustomChannelId: core::hash::Hash + Eq + Clone,
{
    /// Creates a pool with the given configuration.
    pub fn new(config: TcpReassemblyConfig) -> TcpReassemblyPool<Timestamp, CustomChannelId> {
        TcpReassemblyPool {
            free: FreeBuffers::new(&config),
            config,
            connections: HashMap::new(),
            tombstones: HashMap::new(),
            next_id: TcpConnectionId(0),
            buffered: 0,
            handed_out: None,
            evicted_keys: Vec::new(),
            rejected_connections: 0,
            ignored_packets: 0,
        }
    }

    /// Configuration of the pool.
    pub fn config(&self) -> &TcpReassemblyConfig {
        &self.config
    }

    /// Applies a TCP segment to its connection.
    ///
    /// A SYN, a SYN-ACK or a segment with bytes and the ACK flag of an
    /// unknown connection starts a new one. Without a SYN or SYN-ACK, the
    /// roles of the endpoints are guessed (see
    /// [`TcpConnection::roles_guessed`]). Other segments of unknown
    /// connections (pure ACKs, FINs without bytes, RSTs and segments without
    /// the ACK flag) are ignored with [`TcpIgnoreReason::NoConnection`]. A segment
    /// that would start a connection while the pool has
    /// [`TcpReassemblyConfig::max_connections`] connections is ignored with
    /// [`TcpIgnoreReason::TooManyConnections`].
    ///
    /// A connection that ends, e.g. by an RST (see
    /// [`TcpConnectionEnd::Reset`]), is handed over in
    /// [`TcpProcessed::ended`]. Its late segments are then ignored with
    /// [`TcpIgnoreReason::AfterEnd`], also retransmissions of its SYN and
    /// SYN-ACK.
    ///
    /// A SYN or SYN-ACK with a new ISN from an endpoint of an ended or open
    /// connection is a reconnect, in either order of the handshake's
    /// capture: it starts a new connection with a new id, which is
    /// [`TcpProcessed::active`], and hands an open connection over in
    /// [`TcpProcessed::ended`] (see [`TcpConnectionEnd::Reconnect`]). A
    /// retransmission of the connection's own SYN or SYN-ACK repeats its
    /// ISN and starts none, and a late segment of the replaced connection
    /// that arrives before its sender's first segment of the reconnect is
    /// ignored with [`TcpIgnoreReason::AfterEnd`] too, if its sequence
    /// numbers show it is the replaced connection's.
    pub fn process_segment(
        &mut self,
        segment: TcpSegment<'_, CustomChannelId>,
        timestamp: Timestamp,
    ) -> TcpProcessed<'_, Timestamp, CustomChannelId> {
        self.account_handed_out();

        let tcp = segment.tcp;
        let source = SocketAddr::new(segment.source, tcp.source_port());
        let destination = SocketAddr::new(segment.destination, tcp.destination_port());
        let key = TcpConnectionKey::new(segment.vlan_ids, source, destination, segment.channel_id);
        let full = self
            .config
            .max_connections
            .is_some_and(|max| self.connections.len() + self.tombstones.len() >= max);

        let available = available_bytes(&self.config, self.buffered);
        // the connection replaced by a reconnect
        let mut replaced = None;
        let mut entry = match self.connections.entry(key) {
            Entry::Occupied(mut entry) => {
                let connection = entry.get_mut();
                // a late segment of the connection this one replaced is
                // absorbed like on a tombstone (C1)
                if connection.absorbs_late_segment(source, &tcp, &self.config) {
                    return ignore(TcpIgnoreReason::AfterEnd, &mut self.ignored_packets);
                }
                if connection.starts_reconnect(source, &tcp, &self.config, available) {
                    let reconnect = new_connection(
                        &mut self.next_id,
                        &mut self.free,
                        &self.config,
                        entry.key().clone(),
                        handshake_initiator(&tcp, source, destination),
                        false,
                        timestamp.clone(),
                    );
                    let mut ended = core::mem::replace(entry.get_mut(), reconnect);
                    ended.release_buffered(&mut self.buffered);
                    ended.end_unless_finished(TcpConnectionEnd::Reconnect);
                    entry.get_mut().remember_replaced(ended.seq_numbers());
                    replaced = Some(ended);
                }
                entry
            }
            Entry::Vacant(entry) => {
                let connection = if let Some(tombstone) = self.tombstones.get_mut(entry.key()) {
                    // the tombstone of an ended connection absorbs its late
                    // segments (also of its handshake), but a SYN or SYN-ACK
                    // with a new ISN starts a reconnect
                    if false == tcp.syn() || tcp.rst() || tombstone.is_own_handshake(source, &tcp) {
                        tombstone.last_seen = timestamp;
                        return ignore(TcpIgnoreReason::AfterEnd, &mut self.ignored_packets);
                    }
                    let mut connection = new_connection(
                        &mut self.next_id,
                        &mut self.free,
                        &self.config,
                        entry.key().clone(),
                        handshake_initiator(&tcp, source, destination),
                        false,
                        timestamp.clone(),
                    );
                    if let Some(tombstone) = self.tombstones.remove(entry.key()) {
                        connection.remember_replaced(tombstone.into_seqs());
                    }
                    connection
                } else {
                    let Some((initiator, roles_guessed)) =
                        new_connection_initiator(&tcp, source, destination)
                    else {
                        return ignore(TcpIgnoreReason::NoConnection, &mut self.ignored_packets);
                    };
                    if full {
                        self.rejected_connections += 1;
                        return ignore(
                            TcpIgnoreReason::TooManyConnections,
                            &mut self.ignored_packets,
                        );
                    }
                    new_connection(
                        &mut self.next_id,
                        &mut self.free,
                        &self.config,
                        entry.key().clone(),
                        initiator,
                        roles_guessed,
                        timestamp.clone(),
                    )
                };
                entry.insert_entry(connection)
            }
        };

        // the reconnect's SYN released the replaced connection's bytes
        let mut available = available_bytes(&self.config, self.buffered);
        let connection = entry.get_mut();
        let sender = connection.add_segment(
            source,
            &tcp,
            timestamp,
            &self.config,
            &mut available,
            &mut self.free,
        );
        if connection.end().is_some() {
            // the SYN or SYN-ACK that starts a reconnect doesn't end it: it
            // has no RST, and nothing ACKed a FIN of its sender yet
            let (key, mut ended) = entry.remove_entry();
            ended.release_buffered(&mut self.buffered);
            self.tombstones.insert(key, ended.tombstone());
            return TcpProcessed {
                active: None,
                ended: Some(ended),
                ignored: None,
            };
        }
        // the next call accounts for the bytes the connection buffers now,
        // and for the ones the user reads until then
        if self.config.max_total_buffered.is_some() {
            self.handed_out = Some(HandedOut::Connection(entry.key().clone()));
        }
        TcpProcessed {
            active: Some((entry.into_mut(), sender)),
            ended: replaced,
            ignored: None,
        }
    }

    /// Open connection with the key `key`, if any.
    pub fn get_mut(
        &mut self,
        key: &TcpConnectionKey<CustomChannelId>,
    ) -> Option<&mut TcpConnection<Timestamp, CustomChannelId>> {
        self.account_handed_out();
        let connection = self.connections.get_mut(key)?;
        // the next call accounts for the bytes the user reads until then
        if self.config.max_total_buffered.is_some() {
            self.handed_out = Some(HandedOut::Connection(key.clone()));
        }
        Some(connection)
    }

    /// All open connections, in no particular order (sort them by
    /// [`TcpConnection::id`] if needed).
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut TcpConnection<Timestamp, CustomChannelId>> + '_ {
        // the next call accounts for the bytes the user reads until then
        if self.config.max_total_buffered.is_some() {
            self.handed_out = Some(HandedOut::All);
        }
        self.connections.values_mut()
    }

    /// Ends the connections whose last packet is older than `cutoff` and
    /// passes each of them to `callback`, before their buffers are re-used.
    /// Returns the number of connections ended.
    ///
    /// ```
    /// use etherparse::{tcp_reassembly::*, TcpHeader, TcpSlice};
    /// use std::net::IpAddr;
    ///
    /// // timestamps in seconds
    /// let mut pool = TcpReassemblyPool::<u64>::default();
    ///
    /// // a SYN at second 5 starts a connection
    /// let mut syn = TcpHeader::new(50000, 80, 1000, 1024);
    /// syn.syn = true;
    /// let bytes = syn.to_bytes();
    /// let segment = TcpSegment {
    ///     vlan_ids: Default::default(),
    ///     source: IpAddr::from([10, 0, 0, 1]),
    ///     destination: IpAddr::from([10, 0, 0, 2]),
    ///     channel_id: (),
    ///     tcp: TcpSlice::from_slice(&bytes).unwrap(),
    /// };
    /// pool.process_segment(segment, 5);
    ///
    /// // at second 70, end the connections idle for a minute
    /// let evicted = pool.evict_older_than(70 - 60, |connection| {
    ///     assert_eq!(Some(TcpConnectionEnd::Evicted), connection.end());
    ///     // read the bytes left in the streams here
    /// });
    /// assert_eq!(1, evicted);
    /// ```
    ///
    /// A connection ends as [`TcpConnectionEnd::Evicted`], or as
    /// [`TcpConnectionEnd::Finished`] if both its FINs were ACKed. Its holes
    /// become gaps, so all its bytes can be read. The callback gets the
    /// connections in the order of their ids.
    ///
    /// The pool also forgets the connections that ended before (see
    /// [`TcpIgnoreReason::AfterEnd`]) and whose last packet, also a late one
    /// after their end, is older than `cutoff`, without counting them, so
    /// their later packets can start new connections.
    pub fn evict_older_than<F>(&mut self, cutoff: Timestamp, callback: F) -> usize
    where
        Timestamp: PartialOrd,
        F: FnMut(&mut TcpConnection<Timestamp, CustomChannelId>),
    {
        self.evict(|last_seen| last_seen < &cutoff, callback)
    }

    /// Ends all connections and passes each of them to `callback`, before
    /// their buffers are re-used, e.g. at the end of a capture. Returns the
    /// number of connections ended.
    ///
    /// It works like [`TcpReassemblyPool::evict_older_than`] with a cutoff
    /// after every packet, so the pool also forgets all connections that
    /// ended before.
    pub fn evict_all<F>(&mut self, callback: F) -> usize
    where
        F: FnMut(&mut TcpConnection<Timestamp, CustomChannelId>),
    {
        self.evict(|_| true, callback)
    }

    /// Takes back an ended connection, so that its buffers are re-used by
    /// new connections.
    pub fn recycle(&mut self, connection: TcpConnection<Timestamp, CustomChannelId>) {
        connection.recycle(&mut self.free);
    }

    /// Statistics of the pool.
    ///
    /// It walks all open connections to sum up their buffered bytes, so it
    /// takes time proportional to their number.
    pub fn stats(&self) -> TcpPoolStats {
        TcpPoolStats {
            connections: self.connections.len(),
            tombstones: self.tombstones.len(),
            buffered_bytes: self.connections.values().map(TcpConnection::buffered).sum(),
            rejected_connections: self.rejected_connections,
            ignored_packets: self.ignored_packets,
        }
    }

    /// Accounts for the bytes buffered by the connections handed out by the
    /// last call, as reading them made room.
    fn account_handed_out(&mut self) {
        match self.handed_out.take() {
            Some(HandedOut::Connection(key)) => {
                if let Some(connection) = self.connections.get_mut(&key) {
                    connection.account_buffered(&mut self.buffered);
                }
            }
            Some(HandedOut::All) => {
                for connection in self.connections.values_mut() {
                    connection.account_buffered(&mut self.buffered);
                }
            }
            None => {}
        }
    }

    /// Ends the open connections whose last packet `is_old` and passes them
    /// to `callback` in the order of their ids, then re-uses their buffers.
    /// Forgets the tombstones whose last packet `is_old`. Returns the number
    /// of open connections ended.
    fn evict(
        &mut self,
        is_old: impl Fn(&Timestamp) -> bool,
        mut callback: impl FnMut(&mut TcpConnection<Timestamp, CustomChannelId>),
    ) -> usize {
        self.tombstones
            .retain(|_, tombstone| false == is_old(&tombstone.last_seen));

        // collect the keys of the old connections, so they can be ended in
        // the order of their ids
        let mut keys = core::mem::take(&mut self.evicted_keys);
        keys.extend(
            self.connections
                .iter()
                .filter(|(_, connection)| is_old(connection.last_seen()))
                .map(|(key, connection)| (connection.id(), key.clone())),
        );
        keys.sort_unstable_by_key(|(id, _)| *id);

        let count = keys.len();
        let connections = &mut self.connections;
        for mut connection in keys
            .drain(..)
            .filter_map(|(_, key)| connections.remove(&key))
        {
            connection.release_buffered(&mut self.buffered);
            connection.end_unless_finished(TcpConnectionEnd::Evicted);
            callback(&mut connection);
            connection.recycle(&mut self.free);
        }
        self.evicted_keys = keys;
        count
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

/// Connections a pool handed out, whose streams can have been read since.
#[derive(Clone, Debug)]
enum HandedOut<CustomChannelId> {
    /// The connection with the key.
    Connection(TcpConnectionKey<CustomChannelId>),
    /// All connections.
    All,
}

/// Bytes a pool with `buffered` bytes can still buffer before it reaches
/// its limit: the bytes beyond are rejected.
fn available_bytes(config: &TcpReassemblyConfig, buffered: usize) -> usize {
    config
        .max_total_buffered
        .map_or(usize::MAX, |max| max.saturating_sub(buffered))
}

/// Result for a packet that was applied to no connection for `reason`,
/// counted in `ignored_packets`.
fn ignore<'a, Timestamp, CustomChannelId>(
    reason: TcpIgnoreReason,
    ignored_packets: &mut u64,
) -> TcpProcessed<'a, Timestamp, CustomChannelId> {
    *ignored_packets += 1;
    TcpProcessed {
        active: None,
        ended: None,
        ignored: Some(reason),
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
    // with roles guessed from the ports (pure ACKs, FINs without bytes, RSTs
    // and segments without ACK, which every receiver drops (S6), don't
    // start one)
    if tcp.rst() {
        None
    } else if tcp.syn() {
        Some((handshake_initiator(tcp, source, destination), false))
    } else if false == tcp.payload().is_empty() && tcp.ack() {
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
/// whose streams take their buffers from `free` and their limits from
/// `config`.
fn new_connection<Timestamp: Clone, CustomChannelId>(
    next_id: &mut TcpConnectionId,
    free: &mut FreeBuffers,
    config: &TcpReassemblyConfig,
    key: TcpConnectionKey<CustomChannelId>,
    initiator: SocketAddr,
    roles_guessed: bool,
    timestamp: Timestamp,
) -> TcpConnection<Timestamp, CustomChannelId> {
    let id = *next_id;
    *next_id = TcpConnectionId(id.0.wrapping_add(1));
    TcpConnection::new(id, key, initiator, roles_guessed, timestamp, config, free)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{tcp_reassembly::TcpRole::*, test_gens::*, VlanId};
    use proptest::prelude::*;
    use std::{format, vec, vec::Vec};

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

        // the tombstone of a pickup knows no ISN, so a SYN starts a new
        // connection there, unless it lies right before the stream's first
        // byte, where only the ended connection's own late SYN lies (C1):
        // here the capture lost the first bytes too, so the late SYN starts a
        // new connection (a known limit)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .rst(Responder);
            let syn = script.segments[0].clone();
            script.segments.drain(..4);
            script.feed_all(&mut pool).ended.unwrap();
            let (connection, _) = syn.feed(&mut pool, ()).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(None, connection.end());
        }

        // a SYN with a new ISN on an open connection is a reconnect: it hands
        // the connection over as `Reconnect`, and the reconnect, which starts
        // at the SYN, is active with a new id, also if the old responder
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
                let processed = script.segments[0].feed(&mut pool, 7);
                assert_eq!(None, processed.ignored);
                let mut ended = processed.ended.unwrap();
                assert_eq!(TcpConnectionId(0), ended.id());
                assert_eq!(Some(TcpConnectionEnd::Reconnect), ended.end());
                assert_eq!(&0, ended.last_seen());
                let expected = if drained {
                    TcpRead::End(TcpStreamEnd::Reconnect)
                } else {
                    TcpRead::Data(b"abc")
                };
                assert_eq!(expected, ended.stream_mut(Initiator).read_received());
                let (connection, sender) = processed.active.unwrap();
                assert_eq!(Initiator, sender);
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(None, connection.end());
                assert!(false == connection.roles_guessed());
                assert_eq!(addr(initiator), connection.endpoint(Initiator));
                assert_eq!(&7, connection.first_seen());
                let (connection, _) = script.segments[1].feed(&mut pool, 8).active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
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

        // a connection that lost a segment shortly before its close still
        // ends as finished at the ACK of the last FIN: the FIN was captured
        // after the bytes of its direction, so the hole is capture loss and
        // becomes a gap (F3), without waiting for `ack_reorder_tolerance`
        // packets that never come
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, &[b'r'; 100]);
            for _ in 0..50 {
                script.send(Responder, &[b'x'; 1000]);
            }
            script.fin(Initiator).fin(Responder).ack(Initiator);
            script.segments.remove(7);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(&[b'x'; 3000]), stream.read_received());
            stream.consume(3000);
            assert_eq!(TcpRead::Gap { len: Some(1000) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(&[b'x'; 46000]), stream.read_received());
        }

        // a reconnect whose SYN-ACK is captured before its SYN (two taps
        // merged, the old connection's close not captured) starts at the
        // SYN-ACK: the old connection is handed over there, and the SYN that
        // follows is the reconnect's own; the SYN's TCP Fast Open bytes lie
        // before the start that the SYN-ACK's ACK number gave (A2), as in
        // any capture that shows the SYN-ACK first
        for (syn_data, isn) in [(&b""[..], 2000), (b"GET", 2003)] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.handshake().send(Initiator, b"old");
            let (connection, _) = old.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"old"),
                connection.stream_mut(Initiator).read_received()
            );
            let mut script = ConnectionScript::with_isns(2000, 6000);
            script
                .syn_with_data(syn_data)
                .syn_ack()
                .send(Initiator, b"new");
            let processed = script.segments[1].feed(&mut pool, 7);
            let ended = processed.ended.unwrap();
            assert_eq!(TcpConnectionId(0), ended.id());
            assert_eq!(Some(TcpConnectionEnd::Reconnect), ended.end());
            let (connection, sender) = processed.active.unwrap();
            assert_eq!(Responder, sender);
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(&7, connection.first_seen());
            let processed = script.segments[0].feed(&mut pool, 8);
            assert!(processed.ended.is_none());
            assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
            let processed = script.segments[2].feed(&mut pool, 9);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            for (role, isn) in [(Initiator, isn), (Responder, 6000)] {
                let stream = connection.stream(role);
                assert_eq!(Some(isn), stream.isn());
                assert_eq!(TcpStreamStart::Observed, stream.status().start);
            }
            assert_eq!(
                TcpRead::Data(b"new"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // ... the responder's first bytes, captured between the SYN-ACK and
        // the SYN (the initiator's direction lags), are the reconnect's,
        // whether the rest follows the SYN or is captured before it too
        for order in [[1, 2, 0, 3, 4], [1, 2, 4, 0, 3]] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.handshake();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(2_000_000_000, 3_000_000_000);
            script
                .syn()
                .syn_ack()
                .send(Responder, b"banner")
                .ack_to(Initiator, 0)
                .send(Responder, b"next");
            for (timestamp, index) in order.iter().enumerate() {
                let processed = script.segments[*index].feed(&mut pool, timestamp as u32);
                assert_eq!(1 == *index, processed.ended.is_some());
                assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
            }
            let probe = script.injected(|s| {
                s.ack(Initiator);
            });
            let (connection, _) = probe.feed(&mut pool, 5).active.unwrap();
            assert_eq!(&0, connection.first_seen());
            assert_eq!(Some(2_000_000_000), connection.stream(Initiator).isn());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(3_000_000_000), stream.isn());
            assert_eq!(TcpRead::Data(b"bannernext"), stream.read_received());
        }

        // ... in the other order, the SYN starts the reconnect, and the
        // initiator's ACK and request captured before the late SYN-ACK are
        // the reconnect's, also with ISNs near the old ones (a quick reuse
        // of the four-tuple, RFC 6528), where the request would otherwise
        // land in the old stream behind a fake hole
        for initiator_isn in [70_000, 2_000_000_000] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.handshake().send(Initiator, b"old");
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(initiator_isn, 9000);
            script
                .syn()
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"req")
                .ack(Responder);
            let processed = script.segments[0].feed(&mut pool, 7);
            let ended = processed.ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Reconnect), ended.end());
            assert_eq!(3, ended.stream(Initiator).highest_offset());
            assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
            for index in [2, 3, 1] {
                let processed = script.segments[index].feed(&mut pool, 8);
                assert!(processed.ended.is_none());
                assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
            }
            let (connection, _) = script.segments[4].feed(&mut pool, 9).active.unwrap();
            assert_eq!(&7, connection.first_seen());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"req"), stream.read_received());
            assert_eq!(3, stream.acked_offset());
        }

        // ... and the reconnect's segments before the late SYN-ACK count in
        // it like any other: a lost segment between `abc` and `ghi` is a
        // hole; the request's window (65535, the SYN said 1024) lets the
        // response jump ahead by more than two SYN windows; a FIN with the
        // request ends the reconnect once both FINs are ACKed
        for scenario in ["hole", "window", "fin"] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.handshake().send(Initiator, b"old");
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(70_000, 9000);
            script.syn().syn_ack();
            match scenario {
                "hole" => {
                    script
                        .send(Initiator, b"abc")
                        .send(Initiator, b"def")
                        .send(Initiator, b"ghi");
                }
                "window" => {
                    script.segments[0].header.window_size = 1024;
                    script.send(Initiator, b"req");
                    script.segments[2].header.window_size = 65535;
                }
                _ => {
                    script.fin_with_data(Initiator, b"req");
                }
            }
            let early: &[usize] = if "hole" == scenario {
                &[0, 2, 4]
            } else {
                &[0, 2]
            };
            for index in early {
                let processed = script.segments[*index].feed(&mut pool, 7);
                assert_eq!(0 == *index, processed.ended.is_some());
                assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
            }
            let processed = script.segments[1].feed(&mut pool, 8);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            match scenario {
                "hole" => {
                    let stream = connection.stream_mut(Initiator);
                    assert_eq!(9, stream.highest_offset());
                    assert_eq!(vec![3..6], stream.holes().collect::<Vec<_>>());
                    assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                }
                "window" => {
                    let late = script.injected(|s| {
                        s.send_at(Responder, 3000, &[b'x'; 1000]);
                    });
                    let (connection, _) = late.feed(&mut pool, 9).active.unwrap();
                    let stream = connection.stream(Responder);
                    assert_eq!(4000, stream.highest_offset());
                    assert_eq!(0, stream.status().out_of_window_segments);
                }
                _ => {
                    assert_eq!(Some(3), connection.stream(Initiator).fin_offset());
                    script.fin_with_data(Responder, b"ok").ack(Initiator);
                    script.segments[3].feed(&mut pool, 9);
                    let mut connection = script.segments[4].feed(&mut pool, 10).ended.unwrap();
                    assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
                    let stream = connection.stream_mut(Initiator);
                    assert_eq!(TcpRead::Data(b"req"), stream.read_received());
                    stream.consume(3);
                    assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
                }
            }
        }

        // ... also in a one-direction capture, where the reconnect's SYN-ACK
        // never comes: the SYN starts the reconnect, and its bytes are read
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.syn().send(Initiator, b"old");
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(2_000_000_000, 9000);
            script.syn();
            for _ in 0..4 {
                script.send(Initiator, &[b'x'; 1000]);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(&[b'x'; 4000]), stream.read_received());
        }

        // a late SYN that its mid-stream pickup can't take anymore (it was
        // read from) is ignored and counted (C4); a SYN with a new ISN after
        // it starts a reconnect
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.send(Initiator, b"old");
            let (connection, _) = old.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(3);
            let mut late = old.segments[0].clone();
            late.header.syn = true;
            late.header.ack = false;
            late.header.sequence_number = 1000;
            late.payload.clear();
            let processed = late.feed(&mut pool, 7);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                1,
                connection.stream(Initiator).status().out_of_window_segments
            );
            let mut script = ConnectionScript::with_isns(2_000_000_000, 3_000_000_000);
            script.syn();
            let processed = script.segments[0].feed(&mut pool, 8);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
        }

        // a late SYN-ACK that its mid-stream pickup can't take anymore (it
        // was read from) changes nothing, its ACK number included (C4): a
        // reconnect with near ISNs (RFC 6528) captured SYN-ACK first lands
        // its SYN-ACK in the A5 range of the old responder pickup, and the
        // old initiator stream gets no fake gap from its ACK number; the
        // SYN then starts the reconnect
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5_000_000);
            old.send(Initiator, b"old").send(Responder, b"resp");
            let (connection, _) = old.feed_all(&mut pool).active.unwrap();
            for role in [Initiator, Responder] {
                let stream = connection.stream_mut(role);
                stream.read_received();
                stream.consume(stream.highest_offset() as usize);
            }
            let mut script = ConnectionScript::with_isns(1_001_000, 4_000_000);
            script.syn().syn_ack().send(Initiator, b"new");
            let processed = script.segments[1].feed(&mut pool, 7);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let status = connection.stream(Responder).status();
            assert_eq!(1, status.out_of_window_segments);
            let stream = connection.stream(Initiator);
            assert_eq!(0, stream.status().gaps);
            assert_eq!(3, stream.acked_offset());
            assert_eq!(3, stream.highest_offset());
            let processed = script.segments[0].feed(&mut pool, 8);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = script.segments[2].feed(&mut pool, 9).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"new"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a retransmission of the SYN-ACK that started a reconnect is the
        // reconnect's own, so `first_seen` stays the first one's timestamp
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.handshake();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(2000, 6000);
            script.syn().syn_ack();
            let processed = script.segments[1].feed(&mut pool, 20);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            assert_eq!(&20, processed.active.unwrap().0.first_seen());
            for (index, timestamp) in [(1, 21), (0, 22)] {
                let processed = script.segments[index].feed(&mut pool, timestamp);
                assert!(processed.ended.is_none());
                let (connection, _) = processed.active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(&20, connection.first_seen());
            }
        }

        // the reconnect gets the bytes of its SYN (TCP Fast Open), whether
        // the SYN-ACK ACKs them or only the SYN
        for ack in [5001, 5004] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script.syn_with_data(b"GET").syn_ack();
            script.segments[1].header.acknowledgment_number = ack;
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = script.segments[1].feed(&mut pool, 8).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(&7, connection.first_seen());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"GET"), stream.read_received());
            assert_eq!((ack - 5001) as u64, stream.acked_offset());
        }

        // a reconnect's SYN that lies in the A5 range of a mid-stream pickup
        // that can't take bytes in front anymore (it was read from) is taken
        // for the pickup's own late SYN and counted (C4, a known limit): the
        // reconnect then starts at its SYN-ACK, whose ISN the pickup's kept
        // ACK doesn't allow, while a late duplicate of the pickup's own
        // handshake starts none
        for reconnect in [false, true] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.send(Initiator, b"old");
            let (connection, _) = old.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"old"), stream.read_received());
            stream.consume(3);
            let (initiator_isn, responder_isn) = if reconnect { (900, 6000) } else { (1000, 2000) };
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.syn().syn_ack().send(Initiator, b"new");
            let processed = script.segments[0].feed(&mut pool, 7);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                1,
                connection.stream(Initiator).status().out_of_window_segments
            );
            let processed = script.segments[1].feed(&mut pool, 8);
            if reconnect {
                assert_eq!(
                    Some(TcpConnectionEnd::Reconnect),
                    processed.ended.unwrap().end()
                );
                let (connection, _) = processed.active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(&8, connection.first_seen());
                let (connection, _) = script.segments[2].feed(&mut pool, 9).active.unwrap();
                assert_eq!(
                    TcpRead::Data(b"new"),
                    connection.stream_mut(Initiator).read_received()
                );
            } else {
                assert!(processed.ended.is_none());
                assert_eq!(TcpConnectionId(0), processed.active.unwrap().0.id());
                old.send(Initiator, b"2");
                let (connection, _) = old.segments[1].feed(&mut pool, 9).active.unwrap();
                assert_eq!(TcpConnectionId(0), connection.id());
                assert_eq!(
                    TcpRead::Data(b"2"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
        }

        // in a capture merged from two taps, the responder's segments that
        // ACK the request arrive up to `ack_reorder_tolerance` packets before
        // it, and the request is still delivered; one packet more and the
        // hole it fills was given up as a gap (K4(b))
        for late_by in [256, 257] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, &[b'r'; 300]);
            for _ in 0..late_by {
                script.send(Responder, &[b'x'; 1448]);
            }
            let request = script.segments.remove(3);
            script.feed_all(&mut pool);
            let (connection, _) = request.feed(&mut pool, ()).active.unwrap();
            let read = connection.stream_mut(Initiator).read_received();
            if 256 == late_by {
                assert_eq!(TcpRead::Data(&[b'r'; 300]), read);
            } else {
                assert!(matches!(read, TcpRead::Gap { .. }), "{read:?}");
            }
        }

        // a late duplicate of the replaced connection's handshake, captured
        // after the reconnect started, is absorbed like on a tombstone (C1)
        // and starts no further reconnect; the reconnect goes on
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(1_000_000_000, 2_000_000_000);
            script.syn().syn_ack().send(Initiator, b"req");
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            for index in [0, 1] {
                let processed = old.segments[index].feed(&mut pool, 8);
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"req"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                0,
                connection.stream(Initiator).status().out_of_window_segments
            );
        }

        // a server in TIME-WAIT answers a new SYN whose ISN lies below the
        // old stream's end with an ACK of the old FIN, and the client resets
        // that ACK and retransmits its SYN (RFC 9293 3.10.7.3): both are
        // late segments of the replaced connection (C1), so they neither
        // fake a hole in the reconnect nor reset it, and the reconnect goes
        // on with the retransmitted SYN; also when the capture missed the
        // client's FIN and the last ACK (the TIME-WAIT ACK then tells where
        // the client's stream ended), and across a sequence number wrap
        for (lost_close, client_isn, rst_first) in [
            (false, 10_000_000, false),
            (true, 10_000_000, false),
            (true, u32::MAX - 2, false),
            (false, 10_000_000, true),
            (true, 10_000_000, true),
        ] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(client_isn, 20_000_000);
            old.handshake()
                .send(Initiator, b"req")
                .fin(Responder)
                .fin(Initiator)
                .ack(Responder);
            let mut late = old.clone();
            if lost_close {
                old.segments.truncate(old.segments.len() - 2);
            }
            let processed = old.feed_all(&mut pool);
            let old_end = processed.ended.map(|connection| connection.end());
            assert_eq!(lost_close, old_end.is_none());
            // the old client sent up to its ISN + 5: new ISN 2 MB below it
            let mut script =
                ConnectionScript::with_isns(client_isn.wrapping_sub(2_000_000), 30_000_000);
            script.syn();
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(lost_close, processed.ended.is_some());
            assert_eq!(TcpConnectionId(1), processed.active.unwrap().0.id());
            // the TIME-WAIT ACK and the client's RST (<SEQ=SEG.ACK><CTL=RST>,
            // without ACK flag, RFC 9293 3.10.7.3), in either capture order
            late.ack(Responder).rst(Initiator);
            let rst = late.segments.last_mut().unwrap();
            rst.header.ack = false;
            rst.ack = None;
            let mut order = [late.segments.len() - 2, late.segments.len() - 1];
            if rst_first {
                order.reverse();
            }
            for index in order {
                let processed = late.segments[index].feed(&mut pool, 8);
                assert_eq!(
                    Some(TcpIgnoreReason::AfterEnd),
                    processed.ignored,
                    "lost_close={lost_close} rst_first={rst_first}"
                );
            }
            script
                .syn()
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"new");
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"new"), stream.read_received());
            assert_eq!(0, stream.status().gaps);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(3, stream.highest_offset());
        }

        // a stream that sent more than a whole cycle of sequence numbers
        // covers every number: a late segment of the replaced connection
        // that lies before the old stream's first byte by its 32 bits, but
        // within what that stream sent, is the old connection's (C1), while
        // its sender sent nothing of the reconnect (regression test: the
        // span kept only 32 bits, and the old bytes went to the reconnect)
        {
            const SEGMENT_LEN: usize = 1 << 20;
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, &[b'c'; 1024])
                .send(Responder, &[b'x'; SEGMENT_LEN]);
            old.feed(&mut pool, ..4);
            // the server's bytes: one cycle and one more segment, read as
            // they come, from the bytes of one segment with the sequence
            // number changed
            let data = &old.segments[4];
            let mut bytes = data.header.to_bytes().to_vec();
            bytes.extend_from_slice(&data.payload);
            for i in 0..=(1u64 << 32) / SEGMENT_LEN as u64 {
                let offset = i * SEGMENT_LEN as u64;
                bytes[4..8].copy_from_slice(&old.seq(Responder, offset).to_be_bytes());
                let segment = TcpSegment {
                    vlan_ids: Default::default(),
                    source: data.source.ip(),
                    destination: data.destination.ip(),
                    channel_id: (),
                    tcp: TcpSlice::from_slice(&bytes).unwrap(),
                };
                let (connection, _) = pool.process_segment(segment, ()).active.unwrap();
                let stream = connection.stream_mut(Responder);
                assert_eq!(TcpRead::Data(&data.payload[..]), stream.read_received());
                stream.consume(SEGMENT_LEN);
            }
            // the client resets (its ACK of the server's bytes is right in
            // 32 bits: the server sent a cycle and one segment)
            old.rst(Initiator);
            let processed = old.segments.last().unwrap().feed(&mut pool, ());
            let end = processed.ended.map(|connection| connection.end());
            assert_eq!(Some(Some(TcpConnectionEnd::Reset { by: Initiator })), end);
            // a reconnect with the client's ISN inside its old span
            let mut script = ConnectionScript::with_isns(1525, 0x5000_0000);
            script.syn();
            let (connection, _) = script.segments[0].feed(&mut pool, ()).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            // a late segment of the server's old stream, 100 bytes before
            // the cycle's end
            old.send_at(Responder, (1 << 32) - 100, b"late bytes");
            let processed = old.segments.last().unwrap().feed(&mut pool, ());
            assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
        }

        // in a capture merged from two taps, the old close's last ACK can
        // arrive after the reconnect's SYN with a near ISN: it is a late
        // segment of the replaced connection (C1) and fakes no hole; once
        // its sender's stream started in the reconnect (its SYN-ACK came),
        // it is the reconnect's, which doesn't accept it far before its
        // bytes
        for complete in [false, true] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(10_000_000, 20_000_000);
            old.handshake()
                .send(Initiator, b"req")
                .fin(Responder)
                .fin(Initiator)
                .ack(Responder);
            let last_ack = old.segments.pop().unwrap();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(8_000_005, 30_000_000);
            script.handshake().send(Initiator, b"new");
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let fed = if complete { 3 } else { 1 };
            if complete {
                script.feed(&mut pool, 1..fed);
            }
            let processed = last_ack.feed(&mut pool, 8);
            if complete {
                assert_eq!(None, processed.ignored);
                let (connection, _) = processed.active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!((0, 0), (stream.highest_offset(), stream.acked_offset()));
            } else {
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
            let (connection, _) = script.feed(&mut pool, fed..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"new"), stream.read_received());
            assert_eq!(0, stream.status().gaps);
            assert_eq!(3, stream.highest_offset());
        }

        // other late segments of the replaced connection that S5 would take
        // as the answer to a near-ISN reconnect's SYN are the replaced
        // connection's by their sequence numbers (C1): an older ACK from a
        // merged tap (which would fake a hole), bytes still in flight after
        // the client aborted (which would start a ghost responder stream), a
        // LAST-ACK FIN retransmission
        for late in ["older ack", "in flight", "fin"] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(10_000_000, 20_000_000);
            old.handshake().send(Initiator, &[b'q'; 1000]);
            let late_segment = match late {
                "older ack" => {
                    old.ack(Responder);
                    let older_ack = old.segments.pop().unwrap();
                    old.send(Responder, b"resp")
                        .fin(Responder)
                        .fin(Initiator)
                        .ack(Responder);
                    older_ack
                }
                "in flight" => {
                    old.send(Responder, b"in flight");
                    let in_flight = old.segments.pop().unwrap();
                    old.rst(Initiator);
                    in_flight
                }
                _ => {
                    old.send(Responder, b"resp").fin(Responder);
                    let fin = old.segments.last().unwrap().clone();
                    old.fin(Initiator);
                    fin
                }
            };
            // the old connection finished or was reset (a tombstone), or is
            // still open and gets replaced
            let old_ended = old.feed_all(&mut pool).ended.is_some();
            // 500 below the old client's end
            let mut script = ConnectionScript::with_isns(10_000_502, 30_000_000);
            script.handshake().send(Initiator, b"new-req");
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(old_ended, processed.ended.is_none(), "{late}");
            let processed = late_segment.feed(&mut pool, 8);
            assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored, "{late}");
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id(), "{late}");
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"new-req"), stream.read_received());
            assert_eq!((0, 7), (stream.status().gaps, stream.highest_offset()));
            let responder = connection.stream(Responder);
            assert_eq!(TcpStreamStart::Observed, responder.status().start);
            assert_eq!(0, responder.status().out_of_window_segments);
        }

        // once the sender sent bytes in the reconnect, its segments are the
        // reconnect's: in a one-direction capture, the new client's bare FIN
        // that lands right at the old client's end still finishes its stream
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.send(Initiator, &[b'o'; 1000]).fin(Initiator);
            old.feed_all(&mut pool);
            // the old client's end is 2002: the new FIN lands there
            let mut script = ConnectionScript::with_isns(1500, 3000);
            script.syn().send(Initiator, &[b'n'; 501]).fin(Initiator);
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let processed = script.feed(&mut pool, 1..);
            assert_eq!(None, processed.ignored);
            let (connection, _) = processed.active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(&[b'n'; 501]), stream.read_received());
            assert!(stream.is_finished());
        }

        // a reuse after a reset has no TIME-WAIT to keep the ISNs apart: the
        // new ISNs can fall into the old streams' spans, and the reconnect's
        // own segments at the positions its streams expect are its own, not
        // late segments of the replaced connection (C1), with or without
        // the SYN-ACK captured
        for lost in ["nothing", "syn-ack", "first request"] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, &[b'o'; 10_000])
                .send(Responder, &[b'p'; 10_000])
                .rst(Initiator);
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(5000, 6000);
            script
                .handshake()
                .send(Initiator, b"new-")
                .send(Initiator, b"request")
                .send(Responder, b"new-response");
            match lost {
                "syn-ack" => {
                    script.segments.remove(1);
                }
                "first request" => {
                    script.segments.remove(3);
                }
                _ => {}
            }
            let processed = script.feed_all(&mut pool);
            assert_eq!(None, processed.ignored, "{lost}");
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            let stream = connection.stream_mut(Initiator);
            if "first request" == lost {
                // the lost bytes are a hole, the rest arrived
                assert_eq!(11, stream.highest_offset());
                assert_eq!(TcpRead::Pending, stream.read_received());
                assert_eq!(1, stream.holes().count());
            } else {
                assert_eq!(TcpRead::Data(b"new-request"), stream.read_received());
            }
            assert_eq!(
                TcpRead::Data(b"new-response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a merged capture can show the SYN-ACK of a connection whose SYN
        // it lost after the client's request and FIN: it lies right where
        // the responder stream starts (the client's ACKs put the server
        // there), so it is the pickup's own late SYN-ACK, no reconnect (C4)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"GET")
                .fin(Initiator)
                .send(Responder, b"resp");
            let syn_ack = script.segments.remove(1);
            script.segments.drain(..2);
            script.segments.insert(2, syn_ack);
            let processed = script.feed_all(&mut pool);
            assert_eq!(None, processed.ignored);
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(None, connection.end());
            let responder = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, responder.status().start);
            assert_eq!(TcpRead::Data(b"resp"), responder.read_received());
            let initiator = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"GET"), initiator.read_received());
            assert!(initiator.is_finished());
            assert_eq!((0, 1), (pool.stats().tombstones, pool.stats().connections));
        }

        // a capture merged from two taps can show a handshake half after the
        // other side's FIN when it lost the other half: the client tap behind
        // and the SYN-ACK lost, or the server tap behind and the SYN lost
        // after the client half-closed; the stream of the half has no start
        // yet, so the half is its own late SYN or SYN-ACK, no reconnect (C4)
        for (closes_first, order) in [
            (Responder, [4, 5, 0, 2, 3, 6, 7]),
            (Initiator, [2, 3, 4, 1, 5, 6, 7]),
        ] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            if Initiator == closes_first {
                script
                    .fin(Initiator)
                    .send(Responder, b"response")
                    .fin(Responder)
                    .ack(Initiator);
            } else {
                script
                    .send(Responder, b"response")
                    .fin(Responder)
                    .fin(Initiator)
                    .ack(Responder);
            }
            let mut ended = None;
            for (i, index) in order.into_iter().enumerate() {
                let segment = &script.segments[index];
                // a bare ACK starts no connection
                let ignored =
                    (0 == i && segment.payload.is_empty()).then_some(TcpIgnoreReason::NoConnection);
                let processed = segment.feed(&mut pool, i as u32);
                assert_eq!(
                    ignored, processed.ignored,
                    "{closes_first:?}, segment {index}"
                );
                if let Some(connection) = processed.ended {
                    assert!(ended.is_none(), "{closes_first:?}, segment {index}");
                    ended = Some(connection);
                }
            }
            let mut connection = ended.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            assert_eq!(
                TcpRead::Data(b"request"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a capture merged from two taps can show the last ACK of a close
        // before the FIN it ACKs: the ACK marks the FIN's number as a
        // missing byte, which the FIN then takes back, so an eager reader
        // that waited at that hole gets the end, not a gap
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"req")
                .send(Responder, b"resp")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let server_fin = script.segments.remove(6);
            script.segments.push(server_fin);
            let mut got = Vec::new();
            for (i, segment) in script.segments.iter().enumerate() {
                let processed = segment.feed(&mut pool, i as u32);
                let mut connection = processed.ended;
                let stream = match (connection.as_mut(), processed.active) {
                    (Some(ended), _) => ended.stream_mut(Responder),
                    (None, Some((active, _))) => active.stream_mut(Responder),
                    _ => continue,
                };
                loop {
                    match stream.read_received() {
                        TcpRead::Data(data) => {
                            got.extend_from_slice(data);
                            let len = data.len();
                            stream.consume(len);
                        }
                        TcpRead::Gap { len } => {
                            panic!("gap of {len:?} after {} bytes at segment {i}", got.len());
                        }
                        _ => break,
                    }
                }
            }
            assert_eq!(b"resp".to_vec(), got);
            assert_eq!(0, pool.stats().connections);
        }

        // a client that aborts with an RST reconnects at once from the same
        // port, its new ISN 5000 below its old end, and a capture whose
        // client tap lags shows the new SYN-ACK, the old RST, then the new
        // SYN: the SYN-ACK starts the client's stream too (A2), but the
        // client sent nothing in the reconnect yet, so the old RST is the
        // replaced connection's (C1) and resets nothing, with or without ACK
        for rst_ack in [true, false] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, &[b'o'; 10_000])
                .rst(Initiator);
            let mut old_rst = old.segments.pop().unwrap();
            if false == rst_ack {
                old_rst.header.ack = false;
                old_rst.ack = None;
            }
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(6001, 900_000);
            script
                .handshake()
                .send(Initiator, b"new-request")
                .send(Responder, b"new-response");
            let processed = script.segments[1].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let processed = old_rst.feed(&mut pool, 8);
            assert_eq!(
                Some(TcpIgnoreReason::AfterEnd),
                processed.ignored,
                "{rst_ack}"
            );
            script.segments[0].feed(&mut pool, 9);
            let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(None, connection.end());
            assert_eq!(
                TcpRead::Data(b"new-request"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"new-response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a reuse 1 ms after a close (an ISN clock 15625 ahead) whose SYN-ACK
        // the capture lost, with the client's tap lagging: the server's
        // response ACKs the request before the capture shows it, and both its
        // numbers lie past the old streams' FINs, after which their senders
        // sent nothing, so it is the reconnect's (C1), not a late old segment
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, b"req")
                .send(Responder, b"resp")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(1000 + 15_625, 2000 + 15_625);
            script
                .handshake()
                .send(Initiator, b"request")
                .send(Responder, b"response");
            // SYN, response, ACK, request (the SYN-ACK lost)
            for (i, index) in [0, 4, 2, 3].into_iter().enumerate() {
                let processed = script.segments[index].feed(&mut pool, i as u32);
                assert_eq!(None, processed.ignored, "segment {index}");
            }
            let connection = pool.iter_mut().next().unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"request"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a client that aborts after bytes the capture lost reconnects at
        // once with an ISN within them (after an RST, no TIME-WAIT keeps the
        // numbers apart): its old stream has no FIN, so its span reaches k
        // windows past the bytes the capture showed, and the server's segment
        // still in flight, which ACKs the lost bytes past where the new
        // client's stream begins, is a late one of the replaced connection
        // (C1), so the new SYN-ACK starts no further reconnect
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, &[b'o'; 181])
                .send_uncaptured(Initiator, 181)
                .rst(Initiator)
                .send(Responder, b"x");
            let in_flight = old.segments.pop().unwrap();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(1000 + 182, 900_000);
            script
                .handshake()
                .send(Initiator, b"new-request")
                .send(Responder, b"new-response");
            assert_eq!(None, script.segments[0].feed(&mut pool, 7).ignored);
            assert_eq!(
                Some(TcpIgnoreReason::AfterEnd),
                in_flight.feed(&mut pool, 8).ignored
            );
            for segment in &script.segments[1..] {
                let processed = segment.feed(&mut pool, 9);
                assert_eq!(None, processed.ignored);
                assert!(processed.ended.is_none());
            }
            let connection = pool.iter_mut().next().unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"new-request"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"new-response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a client that crashed answers the server's next segment from CLOSED
        // with an RST without ACK at the segment's ACK number (RFC 9293
        // 3.10.7.1): it ACKed the server's SYN-ACK and sent bytes, so it is
        // past SYN-SENT, and the RST resets the new connection, also when the
        // capture lost the SYN-ACK (C1)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake().send(Initiator, b"old").rst(Initiator);
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(900_000, 800_000);
            script
                .handshake()
                .send(Initiator, b"request")
                .ack(Responder)
                .rst(Initiator);
            let rst = script.segments.last_mut().unwrap();
            rst.header.ack = false;
            rst.ack = None;
            // the SYN-ACK lost
            script.segments.remove(1);
            let processed = script.feed(&mut pool, ..);
            assert_eq!(None, processed.ignored);
            let connection = processed.ended.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Initiator }),
                connection.end()
            );
        }

        // a capture that lost the SYN sees a mid-stream pickup; once that
        // ended with an RST, a lagging server tap shows the SYN-ACK, which
        // ACKs the client stream's first byte, and then the late SYN right
        // before it: both are the ended pickup's own late handshake (C1, as
        // C4 on a live pickup), so neither starts a ghost connection
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"request")
                .rst(Initiator);
            // the handshake ACK, the request, the RST
            let processed = script.feed(&mut pool, 2..);
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Initiator }),
                processed.ended.unwrap().end()
            );
            for index in [1, 0] {
                let processed = script.segments[index].feed(&mut pool, 9);
                assert_eq!(
                    Some(TcpIgnoreReason::AfterEnd),
                    processed.ignored,
                    "segment {index}"
                );
            }
            assert_eq!((1, 0), (pool.stats().tombstones, pool.stats().connections));
        }

        // a pickup's first captured byte is only where the capture started,
        // so a reconnect's ISN + 1 can lie right there: the old client's
        // observed SYN decides for the new SYN-ACK first, which ACKs another
        // SYN, so it starts the reconnect on the tombstone, and the response
        // the capture shows before the request is the reconnect's (C1)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Responder, b"banner")
                .send(Responder, b"more")
                .send(Initiator, b"request")
                .rst(Responder);
            // the capture lost the SYN-ACK and the banner: the server's
            // stream is a pickup that starts at 2007
            for index in [0, 2, 4, 5] {
                old.segments[index].feed(&mut pool, 1);
            }
            let processed = old.segments[6].feed(&mut pool, 1);
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                processed.ended.unwrap().end()
            );
            let mut script = ConnectionScript::with_isns(1005, 2006);
            script
                .handshake()
                .send(Initiator, b"new-request")
                .send(Responder, b"new-response");
            // SYN-ACK, SYN, ACK, response, request
            for index in [1, 0, 2, 4, 3] {
                let processed = script.segments[index].feed(&mut pool, 2);
                assert_eq!(None, processed.ignored, "segment {index}");
            }
            let connection = pool.iter_mut().next().unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"new-request"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"new-response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a SYN-ACK that ACKs the client's observed SYN is the server's own
        // whatever the heuristics of its pickup say: one reordered behind the
        // server's later bytes and the client's FIN is the pickup's own late
        // SYN-ACK (C4), which A5 takes while the pickup wasn't read from and
        // ignores once it was, and no reconnect
        for eager in [false, true] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Responder, b"abc")
                .send(Initiator, b"request")
                .send(Responder, b"response")
                .fin(Initiator);
            // the capture lost "abc" and shows the SYN-ACK last
            for index in [0, 2, 4, 5, 6, 1] {
                let processed = script.segments[index].feed(&mut pool, 3);
                assert!(processed.ended.is_none(), "{eager}, segment {index}");
                let (connection, _) = processed.active.unwrap();
                assert_eq!(TcpConnectionId(0), connection.id());
                while let (true, TcpRead::Data(data)) =
                    (eager, connection.stream_mut(Responder).read_received())
                {
                    let len = data.len();
                    connection.stream_mut(Responder).consume(len);
                }
            }
            let connection = pool.iter_mut().next().unwrap();
            let isn = connection.stream(Responder).isn();
            assert_eq!((false == eager).then_some(2000), isn, "{eager}");
            assert_eq!(1, pool.stats().connections);
        }

        // a capture merged from two taps whose server tap lags far behind
        // shows the client's ACKs more than a window ahead of the bytes they
        // ACK: each counts once the bytes reach within a window of it (K1),
        // so the ACK of the server's FIN finishes the connection, and a
        // reader of the ACKed bytes gets all of them
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            let mut sent = Vec::new();
            for i in 0..400u32 {
                let data = [(i % 251) as u8; 1460];
                sent.extend_from_slice(&data);
                script.send(Responder, &data);
                if 1 == i % 2 {
                    script.ack(Initiator);
                }
            }
            script
                .fin(Responder)
                .ack(Initiator)
                .fin(Initiator)
                .ack(Responder);
            // the server's segments arrive 75 positions (50 of its segments,
            // 73 KB) late
            let mut order: Vec<(usize, usize)> = script
                .segments
                .iter()
                .enumerate()
                .map(|(i, segment)| (i + usize::from(Responder == segment.sender) * 75, i))
                .collect();
            order.sort();
            let mut ended = None;
            for (_, index) in order {
                if let Some(connection) = script.segments[index].feed(&mut pool, 1).ended {
                    ended = Some(connection);
                }
            }
            let mut connection = ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Responder);
            let mut got = Vec::new();
            while let TcpRead::Data(data) = stream.read_acked() {
                got.extend_from_slice(data);
                let len = data.len();
                stream.consume(len);
            }
            assert_eq!(sent.len(), got.len());
            assert!(sent == got);
        }

        // the same with a burst of loss on the lagging tap: the client's ACKs
        // lead the bytes by more than a window all the time, so none counts
        // before the close, but the stream moved forward after them, so the
        // window the client accepts reaches past them (S4), and the bytes
        // after the burst land behind a hole of its length, which K2 gives
        // up in time; an eager reader gets every captured byte and one gap.
        // Mirrored, the client's tap lags past k windows: its ACKs trail the
        // bytes, so after the burst every segment lies after the window
        // until an ACK moves the stream forward towards them, then the
        // window reaches past them too (the leading data, S4), and the bytes
        // after them land behind one hole: the burst and the two segments
        // before the ACK (regression test: the rest of the stream was lost)
        for (lagging, lag, first_after_gap) in [(Responder, 75, 300), (Initiator, 150, 302)] {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            let mut captured = Vec::new();
            let mut lost = Vec::new();
            for i in 0..600u32 {
                let data = [(i % 251) as u8; 1460];
                let lost_by_capture = (200..300).contains(&i);
                if false == (200..first_after_gap).contains(&i) {
                    captured.extend_from_slice(&data);
                }
                script.send(Responder, &data);
                lost.push(lost_by_capture);
                if 1 == i % 2 {
                    script.ack(Initiator);
                    lost.push(false);
                }
            }
            script
                .fin(Responder)
                .ack(Initiator)
                .fin(Initiator)
                .ack(Responder);
            // the server's tap lags from its SYN-ACK on, the client's after
            // its request
            let mut order: Vec<(usize, usize)> = script
                .segments
                .iter()
                .enumerate()
                .filter(|(i, _)| *i < 4 || false == lost.get(i - 4).copied().unwrap_or(false))
                .map(|(i, segment)| {
                    let lags = lagging == segment.sender && (Responder == lagging || 4 <= i);
                    (i + usize::from(lags) * lag, i)
                })
                .collect();
            order.sort();
            let (mut got, mut gaps) = (Vec::new(), Vec::new());
            let mut ended = None;
            for (_, index) in order {
                let processed = script.segments[index].feed(&mut pool, 1);
                let mut connection = processed.ended;
                let stream = match (connection.as_mut(), processed.active) {
                    (Some(ended), _) => ended.stream_mut(Responder),
                    (None, Some((active, _))) => active.stream_mut(Responder),
                    _ => continue,
                };
                loop {
                    match stream.read_received() {
                        TcpRead::Data(data) => {
                            got.extend_from_slice(data);
                            let len = data.len();
                            stream.consume(len);
                        }
                        TcpRead::Gap { len } => {
                            gaps.push(len);
                            stream.consume_gap();
                        }
                        _ => break,
                    }
                }
                if connection.is_some() {
                    ended = connection;
                }
            }
            let gap = (first_after_gap - 200) as u64 * 1460;
            assert_eq!(Some(TcpConnectionEnd::Finished), ended.unwrap().end());
            assert_eq!(vec![Some(gap)], gaps);
            assert_eq!(captured.len(), got.len());
            assert!(captured == got);
        }

        // a segment the network lost before the tap: the receiver's
        // duplicate ACKs stay at the hole, and the sender sends up to a
        // window past it before it retransmits, so a hole the ACKs don't
        // cover waits up to the receiver's window, short of 64 KiB of the
        // buffer, also where that is more than half the buffer (K4(d);
        // regression test: half the buffer gave the hole up as a gap before
        // the retransmission came); a mid-stream pickup shows no window
        // scale, so there the fallback window, sized to the window, stands
        // in for it once the receiver's ACKs counted (regression test: the
        // pickup gave the hole up at half the buffer)
        for (max_stream_buffer, scale, field, len, ahead) in [
            // a window of 640,000 bytes in a buffer of 1 MiB
            (1 << 20, 4u8, 40000u16, 1460, 600_000),
            // a window of 5 MiB in the default buffer of 8 MiB
            (8 << 20, 7, 40960, 16384, 4_700_000),
        ] {
            for (acked, pickup) in [(false, false), (true, false), (false, true), (true, true)] {
                let config = TcpReassemblyConfig {
                    max_stream_buffer,
                    fallback_window: u32::from(field) << scale,
                    ..Default::default()
                };
                let mut pool = TcpReassemblyPool::<(), ()>::new(config);
                let mut script = ConnectionScript::with_isns(1000, 2000);
                script.window_scales = [Some(scale); 2];
                script.window_size = field;
                script.handshake();
                let data_of =
                    |i: usize| -> Vec<u8> { (0..len).map(|j| ((i * 7 + j) % 251) as u8).collect() };
                let mut sent = Vec::new();
                for i in 0..20 {
                    script.send(Responder, &data_of(i));
                    sent.extend_from_slice(&data_of(i));
                    script.ack(Initiator);
                }
                // the lost segment, then the ones after it with duplicate ACKs
                let hole = script.next_offset(Responder);
                script.send(Responder, &data_of(20));
                script.segments.pop();
                sent.extend_from_slice(&data_of(20));
                let mut i = 21;
                while (i - 20) * len <= ahead {
                    script.send(Responder, &data_of(i));
                    sent.extend_from_slice(&data_of(i));
                    script.ack_to(Initiator, hole);
                    i += 1;
                }
                // the retransmission
                script.send_at(Responder, hole, &data_of(20));
                script.ack(Initiator);
                if pickup {
                    script.segments.drain(..3);
                }
                let (mut got, mut gaps) = (Vec::new(), Vec::new());
                let mut rejected = 0;
                // the server's stream, as the pool names its role
                let mut server = None;
                for segment in &script.segments {
                    let Some((connection, role)) = segment.feed(&mut pool, ()).active else {
                        continue;
                    };
                    if Responder == segment.sender {
                        server = Some(role);
                    }
                    let Some(server) = server else {
                        continue;
                    };
                    let stream = connection.stream_mut(server);
                    loop {
                        let read = if acked {
                            stream.read_acked()
                        } else {
                            stream.read_received()
                        };
                        match read {
                            TcpRead::Data(data) => {
                                got.extend_from_slice(data);
                                let len = data.len();
                                stream.consume(len);
                            }
                            TcpRead::Gap { len } => {
                                gaps.push(len);
                                stream.consume_gap();
                            }
                            _ => break,
                        }
                    }
                    rejected = stream.status().rejected_bytes;
                }
                assert_eq!(
                    (0, Vec::<Option<u64>>::new()),
                    (rejected, gaps),
                    "{acked} {pickup}"
                );
                assert!(sent == got, "{acked} {pickup}");
            }
        }

        // the implied ACK lies at least the receiver's window behind the
        // bytes (K2), also on a mid-stream pickup, where the fallback window,
        // sized to the window, stands in for it once the receiver's ACKs
        // counted: with the ACKs a window behind the bytes, a reader of the
        // ACKed bytes reads up to the receiver's ACK (regression test: the
        // pickup implied an ACK 1 MiB ahead of the receiver's)
        for pickup in [false, true] {
            let config = TcpReassemblyConfig {
                fallback_window: 5 << 20,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            // a window of 5 MiB
            script.window_scales = [Some(7); 2];
            script.window_size = 40960;
            script.handshake();
            let window = 5 << 20;
            for i in 1..=640u64 {
                script.send(Responder, &[(i % 251) as u8; 16384]);
                if i * 16384 > window {
                    script.ack_to(Initiator, i * 16384 - window);
                }
            }
            if pickup {
                script.segments.drain(..3);
            }
            // the last segment is the client's ACK
            let (connection, client) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(client.other());
            assert_eq!(640 * 16384 - window, stream.acked_offset(), "{pickup}");
        }

        // the hole at the read position is overdue once half the buffer is
        // filled from it, also when the read position reaches it (K4(d)): a
        // reader that reads the received bytes only later, or only the ACKed
        // ones as they come, gets a gap and the bytes after it (regression
        // test: the check ran after packets only, and such a reader stalled)
        for eager_acked in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            // a window of 6 MiB, so the implied ACK lies far back
            script.window_scales = [Some(7); 2];
            script.window_size = 49152;
            script
                .handshake()
                .send(Responder, b"a")
                .send_uncaptured(Responder, 1000);
            for _ in 0..71 {
                script.send(Responder, &[b'x'; 60_000]);
            }
            script.ack(Initiator);
            let (mut got, mut gaps) = (0, Vec::new());
            let mut read = |stream: &mut TcpStream| loop {
                let read = if eager_acked {
                    stream.read_acked()
                } else {
                    stream.read_received()
                };
                match read {
                    TcpRead::Data(data) => {
                        let len = data.len();
                        got += len;
                        stream.consume(len);
                    }
                    TcpRead::Gap { len } => {
                        gaps.push((got, len));
                        stream.consume_gap();
                    }
                    _ => break,
                }
            };
            // the late reader reads once, after the last packet, from the
            // open connection
            let last = script.segments.len() - 1;
            for (i, segment) in script.segments.iter().enumerate() {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                if eager_acked || last == i {
                    read(connection.stream_mut(Responder));
                }
            }
            let expected = (71 * 60_000 + 1, vec![(1, Some(1000))]);
            assert_eq!(expected, (got, gaps), "{eager_acked}");
        }

        // a reader stalled at a hole from capture loss gets past it before
        // the stream's buffer is full: K2's implied ACK lies at most half
        // the buffer behind the bytes, also with large segments (as captured
        // on a host with GRO/TSO), in a capture of one direction and of both
        // (regression test: with the implied ACK waiting
        // `ack_reorder_tolerance` packets, the buffer overflowed, and bytes
        // the capture showed were rejected as a second gap); where a known
        // window keeps the implied ACK further back, a hole the seen ACK
        // covers is overdue once the bytes from it fill half the buffer
        // (K4(d); regression test: jumbo frames overflowed a 1 MiB buffer
        // within `ack_reorder_tolerance` packets)
        for (both, max_stream_buffer, len, segments) in [
            (false, 256 * 1024, 1460, 600),
            (true, 8 * 1024 * 1024, 60_000, 400),
            (true, 1024 * 1024, 9000, 600),
        ] {
            let config = TcpReassemblyConfig {
                max_stream_buffer,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<u32, ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            // a window of 3 MiB after the SYNs
            script.window_scales = [Some(6); 2];
            script.window_size = 49152;
            script.handshake();
            let mut captured = Vec::new();
            for i in 0..segments {
                let data: Vec<u8> = (0..len).map(|j| ((i * 7 + j) % 251) as u8).collect();
                script.send(Responder, &data);
                if 100 == i {
                    script.segments.pop();
                } else {
                    captured.extend_from_slice(&data);
                }
                if 1 == i % 2 {
                    script.ack(Initiator);
                }
            }
            script.fin(Responder);
            let (mut got, mut gaps) = (Vec::new(), Vec::new());
            let mut rejected = 0;
            let shown = script
                .segments
                .iter()
                .filter(|segment| both || Responder == segment.sender);
            for segment in shown {
                let Some((connection, _)) = segment.feed(&mut pool, 1).active else {
                    continue;
                };
                let stream = connection.stream_mut(Responder);
                loop {
                    match stream.read_received() {
                        TcpRead::Data(data) => {
                            got.extend_from_slice(data);
                            let len = data.len();
                            stream.consume(len);
                        }
                        TcpRead::Gap { len } => {
                            gaps.push(len);
                            stream.consume_gap();
                        }
                        _ => break,
                    }
                }
                rejected = stream.status().rejected_bytes;
            }
            assert_eq!(0, rejected, "{both}");
            assert_eq!(vec![Some(len as u64)], gaps, "{both}");
            assert_eq!(captured.len(), got.len(), "{both}");
            assert!(captured == got, "{both}");
        }

        // a capture that lost a burst of more than k windows and an ACK in
        // it shows the next ACK two windows after the last one: it counts
        // (K1), so the burst is one gap of its length (regression test:
        // with one window, the ACK was evidence of a jump, which the bytes
        // after the burst confirmed, and the gap's length was unknown)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 4096;
            script.handshake().send(Initiator, b"request");
            let mut lost = vec![false; 4];
            for i in 0..30u32 {
                script.send(Responder, &[i as u8; 1460]);
                lost.push((10..18).contains(&i));
                if 1 == i % 2 {
                    script.ack(Initiator);
                    // the ACK of the first 12 segments
                    lost.push(11 == i);
                }
            }
            script
                .fin(Responder)
                .ack(Initiator)
                .fin(Initiator)
                .ack(Responder);
            lost.resize(script.segments.len(), false);
            let (mut got, mut gaps) = (0, Vec::new());
            let mut ended = None;
            for (segment, _) in script.segments.iter().zip(lost).filter(|(_, lost)| !lost) {
                let processed = segment.feed(&mut pool, 1);
                let mut connection = processed.ended;
                let stream = match (connection.as_mut(), processed.active) {
                    (Some(ended), _) => ended.stream_mut(Responder),
                    (None, Some((active, _))) => active.stream_mut(Responder),
                    _ => continue,
                };
                loop {
                    match stream.read_received() {
                        TcpRead::Data(data) => {
                            let len = data.len();
                            got += len;
                            stream.consume(len);
                        }
                        TcpRead::Gap { len } => {
                            gaps.push(len);
                            stream.consume_gap();
                        }
                        _ => break,
                    }
                }
                if connection.is_some() {
                    ended = connection;
                }
            }
            assert_eq!(Some(TcpConnectionEnd::Finished), ended.unwrap().end());
            assert_eq!(vec![Some(8 * 1460)], gaps);
            assert_eq!(22 * 1460, got);
        }

        // a capture that lost the SYN-ACK, with the client's tap lagging,
        // shows the server's RST before the client's ACK and request: the
        // RST ACKs the request, so the client got past SYN-SENT, and the RST
        // ends the connection like the bytes the server would have sent
        // (S5)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, &[b'r'; 947])
                .rst(Responder);
            // SYN, RST, ACK, request
            assert_eq!(None, script.segments[0].feed(&mut pool, 1).ignored);
            let processed = script.segments[4].feed(&mut pool, 2);
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                processed.ended.unwrap().end()
            );
            for index in [2, 3] {
                let processed = script.segments[index].feed(&mut pool, 3);
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
        }

        // the tombstone of a reconnect absorbs late duplicates of the replaced
        // connection's handshake as well (C1): one that arrives after the
        // reconnect finished is ignored, while a SYN with a third ISN starts
        // a new connection
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(1_000_000_000, 2_000_000_000);
            script
                .handshake()
                .send(Initiator, b"req")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let processed = script.feed(&mut pool, 1..);
            assert_eq!(
                Some(TcpConnectionEnd::Finished),
                processed.ended.unwrap().end()
            );
            assert_eq!((0, 1), (pool.stats().connections, pool.stats().tombstones));
            for index in [0, 1] {
                let processed = old.segments[index].feed(&mut pool, 8);
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
            assert_eq!((0, 1), (pool.stats().connections, pool.stats().tombstones));
            let mut third = ConnectionScript::with_isns(3_000_000_000, 4_000_000_000);
            third.syn();
            let processed = third.segments[0].feed(&mut pool, 9);
            assert!(processed.ended.is_none());
            assert_eq!(TcpConnectionId(2), processed.active.unwrap().0.id());
        }

        // the bytes a late SYN-ACK puts in front of its own mid-stream pickup
        // were checked against the pool's budget (C4), so its ACK number
        // can't spend them on the other pickup's start first (A2, D4): the
        // sender's stream gets the observed start, the other one stays a
        // pickup
        {
            let config = TcpReassemblyConfig {
                max_total_buffered: Some(17),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<u32, ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 5000);
            script
                .handshake()
                .send(Initiator, b"req")
                .send(Responder, b"resp");
            // the capture starts after the handshake, whose SYN-ACK comes
            // late with a shifted ISN pair: both pickups would put 10 bytes
            // in front, the budget has 10 left
            let mut late = script.segments[1].clone();
            late.header.sequence_number = 4990;
            late.header.acknowledgment_number = 991;
            script.segments.push(late);
            let (connection, _) = script.feed(&mut pool, 3..).active.unwrap();
            let responder = connection.stream(Responder);
            assert_eq!(TcpStreamStart::Observed, responder.status().start);
            assert_eq!(0, responder.status().out_of_window_segments);
            assert_eq!(14, responder.highest_offset());
            let initiator = connection.stream(Initiator);
            assert_eq!(TcpStreamStart::MidStreamPickup, initiator.status().start);
            assert_eq!(3, initiator.highest_offset());
        }

        // a SYN-ACK that answers another SYN than the unanswered one of the
        // connection starts a reconnect, also while that SYN waits (S5): a
        // failed attempt whose answer was never captured doesn't block the
        // next attempt, whose SYN the capture missed
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.syn();
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(1_000_000_000, 2_000_000_000);
            script
                .syn()
                .syn_ack()
                .ack(Initiator)
                .send(Responder, b"banner");
            let processed = script.segments[1].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(b"banner"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // a reconnect whose SYN-ACK was not captured still delivers both
        // directions: the responder's bytes ACK the request within k windows
        // of the SYN, so they answer it (S5) and start the responder's
        // stream as a mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 5000);
            old.handshake().send(Initiator, b"old");
            old.feed_all(&mut pool);
            let mut script = ConnectionScript::with_isns(2_000_000_000, 3_000_000_000);
            script.syn().syn_ack().send(Initiator, &[b'q'; 100]);
            for _ in 0..200 {
                script.send(Responder, &[b'r'; 1000]);
            }
            script.segments.remove(1);
            let processed = script.segments[0].feed(&mut pool, 7);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(
                TcpRead::Data(&[b'q'; 100]),
                connection.stream_mut(Initiator).read_received()
            );
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(&[b'r'; 200_000]), stream.read_received());
        }

        // a retransmission of the reconnect's SYN is the reconnect's own and
        // starts no further one, a SYN with another new ISN does
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake();
            old.feed_all(&mut pool);
            for (isn, timestamp, id) in [(5000, 7, 1), (5000, 8, 1), (9000, 9, 2)] {
                let mut script = ConnectionScript::with_isns(isn, 6000);
                script.syn();
                let processed = script.segments[0].feed(&mut pool, timestamp);
                assert_eq!(8 != timestamp, processed.ended.is_some());
                let (connection, _) = processed.active.unwrap();
                assert_eq!(TcpConnectionId(id), connection.id());
                assert_eq!(
                    &timestamp.min(7 + (id - 1) as u32 * 2),
                    connection.first_seen()
                );
            }
        }

        // a late SYN-ACK of an ended connection that ACKs the TCP Fast Open
        // bytes of the SYN belongs to its handshake, also if the responder's
        // ISN was never seen (the initiator resets the connection right
        // after its SYN), and also if a retransmission of the SYN carried
        // the bytes, before or after the reset
        for (before_reset, after_reset) in [
            (&[&b"GET"[..]][..], &[][..]),
            (&[&b"G"[..], &b"GET"[..]][..], &[][..]),
            (&[&b"G"[..]][..], &[&b"GET"[..]][..]),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn_with_data(before_reset[0]);
            let retransmission = |script: &ConnectionScript, payload: &[u8]| {
                let mut syn = script.segments[0].clone();
                syn.payload = payload.to_vec();
                syn
            };
            for payload in &before_reset[1..] {
                let syn = retransmission(&script, payload);
                script.segments.push(syn);
            }
            script.rst_at(Initiator, 3);
            for payload in after_reset {
                let syn = retransmission(&script, payload);
                script.segments.push(syn);
            }
            script.syn_ack();
            let reset = before_reset.len();
            assert!(script.feed(&mut pool, ..reset + 1).ended.is_some());
            for segment in &script.segments[reset + 1..] {
                let processed = segment.feed(&mut pool, ());
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            }
            assert_eq!((0, 1), (pool.stats().connections, pool.stats().tombstones));
        }

        // a SYN on a mid-stream pickup is its own late SYN if it lies at
        // most k windows before the stream's first byte: it gives the stream
        // an observed start, or counts as out-of-window once the read
        // position moved (C4). Other SYNs start a reconnect right away (C2;
        // k windows are 2 * 100 bytes, the capture starts at the initiator's
        // byte 300)
        for (position, consumed) in [
            (0, false),
            (-200, false),
            (0, true),
            (-200, true),
            (-201, false),
            (-201, true),
            (1, false),
            (1, true),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let in_range = (-200..=0).contains(&position);
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 300)
                .send(Initiator, b"abc");
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number = script.seq(Initiator, (300 + position) as u64) - 1;
            script.segments.drain(..3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                if consumed {
                    let stream = connection.stream_mut(Initiator);
                    stream.read_received();
                    stream.consume(1);
                }
            }
            let processed = syn.feed(&mut pool, ());
            assert_eq!(false == in_range, processed.ended.is_some());
            let (connection, _) = processed.active.unwrap();
            if in_range {
                assert_eq!(TcpConnectionId(0), connection.id());
                let status = connection.stream(Initiator).status();
                let start = if consumed {
                    TcpStreamStart::MidStreamPickup
                } else {
                    TcpStreamStart::Observed
                };
                assert_eq!(start, status.start);
                assert_eq!(u64::from(consumed), status.out_of_window_segments);
            } else {
                assert_eq!(TcpConnectionId(1), connection.id());
            }
        }

        // a SYN on a stream without a start is its own late SYN if it lies
        // at most k windows before the other side's last ACK of the stream,
        // or if there is no such ACK: it gives the stream an observed start.
        // Other SYNs start a reconnect right away (k windows are 2 * 100
        // bytes, the responder ACKs the initiator's byte 300)
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
            script.segments.drain(..3);
            script.segments[0].header.ack = acked;
            script.feed_all(&mut pool);
            let processed = syn.feed(&mut pool, ());
            assert_eq!(false == own, processed.ended.is_some());
            let (connection, _) = processed.active.unwrap();
            if own {
                assert_eq!(TcpConnectionId(0), connection.id());
                let status = connection.stream(Initiator).status();
                assert_eq!(TcpStreamStart::Observed, status.start);
            } else {
                assert_eq!(TcpConnectionId(1), connection.id());
            }
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

        // a pool with max_connections connections, tombstones included,
        // ignores segments that would start another one, while segments of
        // its connections and reconnects on their keys are applied (segments
        // that would start no connection stay NoConnection)
        {
            let config = TcpReassemblyConfig {
                max_connections: Some(2),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut open = ConnectionScript::with_isns(1000, 2000);
            open.handshake().send(Initiator, b"abc");
            let mut ended =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 3000, 4000);
            ended.handshake().rst(Initiator);
            let mut other =
                ConnectionScript::new(addr("10.0.0.1:50002"), addr("10.0.0.2:80"), 5000, 6000);
            other.handshake().send(Initiator, b"x");
            open.feed(&mut pool, ..3);
            ended.feed_all(&mut pool).ended.unwrap();
            for (segment, expected) in [
                (0, TcpIgnoreReason::TooManyConnections),
                (2, TcpIgnoreReason::NoConnection),
                (3, TcpIgnoreReason::TooManyConnections),
            ] {
                let processed = other.segments[segment].feed(&mut pool, ());
                assert!(processed.active.is_none());
                assert!(processed.ended.is_none());
                assert_eq!(Some(expected), processed.ignored);
            }
            {
                let (connection, _) = open.segments[3].feed(&mut pool, ()).active.unwrap();
                assert_eq!(
                    TcpRead::Data(b"abc"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let mut reconnect =
                ConnectionScript::new(addr("10.0.0.1:50001"), addr("10.0.0.2:80"), 7000, 8000);
            reconnect.syn();
            let (connection, _) = reconnect.feed_all(&mut pool).active.unwrap();
            assert_eq!(TcpConnectionId(2), connection.id());
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
    fn get_mut() {
        // the open connection with the key, None for unknown keys and ended
        // connections
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut open = ConnectionScript::with_isns(1000, 2000);
            open.handshake().send(Initiator, b"abc");
            open.feed_all(&mut pool);
            let mut ended = ConnectionScript::with_port(50001, 3000, 4000);
            ended.handshake().rst(Initiator);
            ended.feed_all(&mut pool);
            let connection = pool.get_mut(&key_of(&open)).unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                TcpRead::Data(b"abc"),
                connection.stream_mut(Initiator).read_received()
            );
            assert!(pool.get_mut(&key_of(&ended)).is_none());
            let unknown = ConnectionScript::with_port(50002, 0, 0);
            assert!(pool.get_mut(&key_of(&unknown)).is_none());
        }

        // reading the connection makes room in the pool's budget at once,
        // also reading the connection handed out before it
        for read_before in [false, true] {
            let (mut pool, first, second) = budget_scripts();
            second.feed(&mut pool, ..3);
            {
                let (connection, _) = first.feed_all(&mut pool).active.unwrap();
                if read_before {
                    let stream = connection.stream_mut(Initiator);
                    stream.read_received();
                    stream.consume(8);
                }
            }
            let read = if read_before { &second } else { &first };
            let stream = pool.get_mut(&key_of(read)).unwrap().stream_mut(Initiator);
            if false == read_before {
                stream.read_received();
                stream.consume(8);
            }
            let (connection, _) = second.feed(&mut pool, 3..).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).status().rejected_bytes);
        }
    }

    #[test]
    fn iter_mut() {
        // all open connections, each once
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            for i in 0..10 {
                let mut script = ConnectionScript::with_port(50000 + i, 1000, 2000);
                script.handshake().send(Initiator, b"ab");
                if 0 == i % 4 {
                    script.rst(Initiator);
                }
                script.feed_all(&mut pool);
            }
            let mut ids: Vec<_> = pool
                .iter_mut()
                .map(|connection| {
                    assert_eq!(
                        TcpRead::Data(b"ab"),
                        connection.stream_mut(Initiator).read_received()
                    );
                    connection.id().0
                })
                .collect();
            ids.sort_unstable();
            assert_eq!(vec![1, 2, 3, 5, 6, 7, 9], ids);
        }

        // reading the connections makes room in the pool's budget at once
        {
            let (mut pool, first, second) = budget_scripts();
            first.feed_all(&mut pool);
            second.feed(&mut pool, ..3);
            for connection in pool.iter_mut() {
                let stream = connection.stream_mut(Initiator);
                if let TcpRead::Data(data) = stream.read_received() {
                    let len = data.len();
                    stream.consume(len);
                }
            }
            let (connection, _) = second.feed(&mut pool, 3..).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).status().rejected_bytes);
        }
    }

    #[test]
    fn evict_older_than() {
        // connections whose last packet is older than the cutoff end as
        // evicted: the callback gets them in the order of their ids, their
        // holes are gaps (here the initiator's byte 2), and reads end with
        // End(Evicted). Connections seen at the cutoff or later stay, and a
        // later segment of an evicted connection starts a new one
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let scripts: Vec<_> = (0..10)
                .map(|i| {
                    let mut script = ConnectionScript::with_port(50000 + i, 1000, 2000);
                    script
                        .handshake()
                        .send(Initiator, b"ab")
                        .send_at(Initiator, 3, b"d")
                        .ack(Responder)
                        .send(Initiator, b"e");
                    script
                })
                .collect();
            // connection i is seen last at i % 3
            for (i, script) in scripts.iter().enumerate() {
                for segment in &script.segments[..6] {
                    segment.feed(&mut pool, (i % 3) as u32);
                }
            }
            let mut evicted = Vec::new();
            let count = pool.evict_older_than(2, |connection| {
                evicted.push(connection.id().0);
                assert_eq!(Some(TcpConnectionEnd::Evicted), connection.end());
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"ab"), stream.read_received());
                stream.consume(2);
                assert_eq!(TcpRead::Gap { len: Some(1) }, stream.read_received());
                stream.consume_gap();
                assert_eq!(TcpRead::Data(b"d"), stream.read_received());
                stream.consume(1);
                assert_eq!(TcpRead::End(TcpStreamEnd::Evicted), stream.read_received());
                assert_eq!(
                    TcpRead::End(TcpStreamEnd::Evicted),
                    connection.stream_mut(Responder).read_received()
                );
            });
            assert_eq!(7, count);
            assert_eq!(vec![0, 1, 3, 4, 6, 7, 9], evicted);
            {
                let (connection, _) = scripts[2].segments[6].feed(&mut pool, 3).active.unwrap();
                assert_eq!(TcpConnectionId(2), connection.id());
                assert_eq!(
                    TcpRead::Data(b"ab"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = scripts[0].segments[6].feed(&mut pool, 3).active.unwrap();
            assert_eq!(TcpConnectionId(10), connection.id());
            assert_eq!(
                TcpRead::Data(b"e"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a connection whose FINs were both ACKed is finished at the last
        // ACK (F3), whatever hole the ACKs cover, so eviction finds nothing
        // of it; its hole is a gap and reads end with End(Fin)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .send_at(Initiator, 3, b"d")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert_eq!((1, 1), (stream.status().gaps, stream.status().gap_bytes));
            assert_eq!(TcpRead::Data(b"ab"), stream.read_received());
            stream.consume(2);
            assert_eq!(TcpRead::Gap { len: Some(1) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"d"), stream.read_received());
            stream.consume(1);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            assert!(stream.is_finished());
            assert!(false == stream.is_complete());
            assert_eq!(
                TcpRead::End(TcpStreamEnd::Fin),
                connection.stream_mut(Responder).read_received()
            );
            assert_eq!(0, pool.evict_older_than(1, |_| {}));
        }

        // a connection whose FINs were not both ACKed ends as evicted, also
        // without holes (reads at its FINs still end with End(Fin))
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .fin(Initiator)
                .fin(Responder);
            script.feed_all(&mut pool);
            let count = pool.evict_older_than(1, |connection| {
                assert_eq!(Some(TcpConnectionEnd::Evicted), connection.end());
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(2);
                assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            });
            assert_eq!(1, count);
        }

        // ended connections older than the cutoff are forgotten without
        // being counted, so a later segment with bytes starts a new
        // connection, while younger ones still absorb their late segments
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let scripts = [(50000, 1), (50001, 2)].map(|(port, timestamp)| {
                let mut script = ConnectionScript::with_port(port, 1000, 2000);
                script.handshake().send(Initiator, b"ab").rst(Initiator);
                for segment in &script.segments {
                    segment.feed(&mut pool, timestamp);
                }
                script.send(Initiator, b"c");
                script
            });
            assert_eq!(0, pool.evict_older_than(2, |_| panic!()));
            let processed = scripts[1].segments[5].feed(&mut pool, 3);
            assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
            let (connection, _) = scripts[0].segments[5].feed(&mut pool, 3).active.unwrap();
            assert_eq!(TcpConnectionId(2), connection.id());
        }

        // a late segment that an ended connection absorbs keeps it from
        // being forgotten
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"ab").rst(Initiator);
            for segment in &script.segments {
                segment.feed(&mut pool, 1);
            }
            script.send(Initiator, b"c");
            for timestamp in [3, 4] {
                let processed = script.segments[5].feed(&mut pool, timestamp);
                assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
                assert_eq!(0, pool.evict_older_than(2, |_| panic!()));
            }
        }

        // evicted connections leave the pool's budget (the ACK makes the
        // pool account for the bytes of the first connection)
        {
            let (mut pool, first, second) = budget_scripts();
            first.feed_all(&mut pool);
            assert_eq!(1, pool.evict_older_than(1, |_| {}));
            let (connection, _) = second.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).status().rejected_bytes);
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

        // recycled buffers are shrunk to max_pooled_buffer_capacity bytes:
        // 32 bytes, or 2 holes of 16 bytes
        {
            let config = TcpReassemblyConfig {
                max_pooled_buffer_capacity: 32,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut first = ConnectionScript::with_isns(1000, 2000);
            first
                .handshake()
                .send(Initiator, &[1; 100])
                .send(Responder, &[2; 100]);
            // 8 holes in the responder's stream
            for i in 0..8 {
                first.send_at(Responder, 101 + 2 * i, &[3]);
            }
            first.rst(Responder);
            let ended = first.feed_all(&mut pool).ended.unwrap();
            pool.recycle(ended);

            // 32 bytes fit into the initiator's buffer of the next
            // connection, and 2 holes into the responder's buffer for holes,
            // one more byte or hole makes them grow
            let mut next = ConnectionScript::with_isns(3000, 4000);
            next.handshake()
                .send(Initiator, &[4; 32])
                .send(Initiator, &[5])
                .send_at(Responder, 0, &[6])
                .send_at(Responder, 2, &[6])
                .send_at(Responder, 4, &[6])
                .send_at(Responder, 6, &[6]);
            let bytes: Vec<_> = next.segments.iter().map(TestSegment::to_bytes).collect();
            let mut feed = |range: core::ops::Range<usize>| {
                count_allocations(|| {
                    for i in range {
                        next.segments[i].feed_bytes(&bytes[i], &mut pool, ());
                    }
                })
                .0
            };
            assert_eq!(0, feed(0..4));
            assert_eq!(1, feed(4..5));
            assert_eq!(0, feed(5..8));
            assert_eq!(1, feed(8..9));
        }

        // the pool keeps at most max_pooled_buffers buffers per kind, and
        // only buffers with capacity: buffers without one would take the
        // place of buffers with one
        {
            let config = TcpReassemblyConfig {
                max_pooled_buffers: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let first = late_bytes(50000, 10_000);
            let mut other = ConnectionScript::with_port(50001, 3000, 4000);
            other
                .handshake()
                .send(Initiator, &[5; 48])
                .send(Responder, &[6; 48])
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            // the other connection, whose buffers for holes, gaps and ACKs
            // have no capacity, is recycled first
            first.feed(&mut pool, ..7);
            let ended = other.feed_all(&mut pool).ended.unwrap();
            pool.recycle(ended);
            let ended = first.feed(&mut pool, 7..).ended.unwrap();
            pool.recycle(ended);

            // the next connection on the key gets the initiator's buffers for
            // bytes and holes of the other connection, and the buffer for
            // ACKs of the first one, so only the responder's buffers for
            // bytes and holes are new (storing bytes uses the one for holes)
            let next = late_bytes(50000, 20_000);
            let bytes: Vec<_> = next.segments.iter().map(TestSegment::to_bytes).collect();
            let (allocations, ()) = count_allocations(|| {
                for (segment, bytes) in next.segments.iter().zip(&bytes).take(7) {
                    segment.feed_bytes(bytes, &mut pool, ());
                }
            });
            assert_eq!(2, allocations);
        }

        // after the first rounds, new connections re-use the buffers of
        // recycled ones: for their bytes, holes, gaps and the ACKs they keep,
        // and for kept SYNs, so processing allocates nothing (in the second
        // round, the table of the tombstones grows once more, as entries
        // move between it and the table of the connections)
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let rounds: Vec<_> = (0..8).map(steady_state_round).collect();
            for (round, segments) in rounds.iter().enumerate() {
                let (allocations, ends) =
                    count_allocations(|| feed_and_recycle(&mut pool, segments, round as u32));
                assert_eq!(
                    [
                        Some(TcpConnectionEnd::Finished),
                        Some(TcpConnectionEnd::Reset { by: Responder }),
                        Some(TcpConnectionEnd::Reconnect),
                        Some(TcpConnectionEnd::Finished),
                        Some(TcpConnectionEnd::Reconnect),
                        Some(TcpConnectionEnd::Finished),
                        Some(TcpConnectionEnd::Finished),
                    ],
                    ends
                );
                if 1 < round {
                    assert_eq!(0, allocations, "round {}", round);
                }
            }
        }
    }

    #[test]
    fn stats() {
        // an empty pool
        assert_eq!(
            TcpPoolStats::default(),
            TcpReassemblyPool::<(), ()>::default().stats()
        );

        // open connections and tombstones are counted apart, the bytes the
        // streams buffer as for max_total_buffered (also right after
        // reading them), and ignored packets whatever the reason, the ones
        // that would start a connection in a full pool also as rejected
        // connections
        {
            let config = TcpReassemblyConfig {
                max_connections: Some(3),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<u32, ()>::new(config);
            let script = |port| ConnectionScript::with_port(port, 1000, 2000);
            // 6 bytes (with 2 placeholders) and 2 bytes
            let mut open = script(50000);
            open.handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 5, b"f")
                .send(Responder, b"xy");
            open.feed_all(&mut pool);
            let mut other = script(50001);
            other.handshake().send(Initiator, b"0123");
            other.feed_all(&mut pool);
            let mut ended = script(50002);
            ended.handshake().send(Initiator, b"x").rst(Initiator);
            ended.feed_all(&mut pool);
            // NoConnection, AfterEnd and TooManyConnections twice
            let mut ignored = script(50003);
            ignored.handshake();
            ignored.segments[2].feed(&mut pool, 0);
            ended.segments[3].feed(&mut pool, 0);
            ignored.segments[0].feed(&mut pool, 0);
            ignored.segments[1].feed(&mut pool, 0);
            assert_eq!(
                TcpPoolStats {
                    connections: 2,
                    tombstones: 1,
                    buffered_bytes: 12,
                    rejected_connections: 2,
                    ignored_packets: 4,
                },
                pool.stats()
            );
            {
                let (connection, _) = open.segments[4].feed(&mut pool, 0).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(2);
            }
            assert_eq!(10, pool.stats().buffered_bytes);

            // eviction leaves only the counters
            pool.evict_all(|_| {});
            assert_eq!(
                TcpPoolStats {
                    connections: 0,
                    tombstones: 0,
                    buffered_bytes: 0,
                    rejected_connections: 2,
                    ignored_packets: 4,
                },
                pool.stats()
            );
        }
    }

    /// Key of the connection that `script` writes.
    fn key_of(script: &ConnectionScript) -> TcpConnectionKey {
        TcpConnectionKey::new(
            Default::default(),
            script.endpoint(Initiator),
            script.endpoint(Responder),
            (),
        )
    }

    /// Pool whose streams buffer at most 10 bytes together, a connection
    /// whose initiator sends 8 bytes, followed by an ACK (so the pool
    /// accounts for the bytes), and a second connection whose initiator
    /// sends 10 bytes after the handshake.
    fn budget_scripts() -> (
        TcpReassemblyPool<u32, ()>,
        ConnectionScript,
        ConnectionScript,
    ) {
        let config = TcpReassemblyConfig {
            max_total_buffered: Some(10),
            ..Default::default()
        };
        let mut first = ConnectionScript::with_isns(1000, 2000);
        first
            .handshake()
            .send(Initiator, b"abcdefgh")
            .ack(Responder);
        let mut second = ConnectionScript::with_port(50001, 3000, 4000);
        second.handshake().send(Initiator, b"0123456789");
        (TcpReassemblyPool::new(config), first, second)
    }

    /// Connection on `port` that finishes after the initiator's bytes 16..32
    /// arrived after the responder ACKed them, so that it uses buffers for
    /// bytes, holes and kept ACKs (each stream sends 48 bytes).
    fn late_bytes(port: u16, isn: u32) -> ConnectionScript {
        let mut script = ConnectionScript::with_port(port, isn, isn + 1000);
        script
            .handshake()
            .send(Initiator, &[1; 16])
            .send(Initiator, &[2; 16])
            .send(Initiator, &[3; 16])
            .send(Responder, &[4; 48])
            .fin(Initiator)
            .fin(Responder)
            .ack(Initiator);
        let late = script.segments.remove(4);
        script.segments.insert(6, late);
        script
    }

    /// Serialized segments of connections that use every kind of buffer and
    /// end in every way that hands them over: one that finishes after a
    /// hole was filled, one reset with a gap, and two replaced by reconnects
    /// that finish, after a SYN was kept: one starts with the SYN, the other
    /// one at a SYN-ACK that doesn't ACK it, and one whose holes are split
    /// and filled. The ISNs depend on `round`, so the SYNs of a round start
    /// new connections on the tombstones of the round before.
    fn steady_state_round(round: u32) -> Vec<(TestSegment, Vec<u8>)> {
        let isn = round.wrapping_mul(1_000_000);
        let finished = late_bytes(50000, isn);

        // the initiator's bytes 16..32 are lost
        let mut reset = ConnectionScript::with_port(50001, isn + 2000, isn + 3000);
        reset
            .handshake()
            .send(Initiator, &[1; 16])
            .send(Initiator, &[2; 16])
            .send(Initiator, &[3; 16])
            .send(Responder, &[4; 48])
            .rst(Responder);
        reset.segments.remove(4);

        let reconnects = [50002, 50003].map(|port| {
            let mut replaced = ConnectionScript::with_port(port, isn + 4000, isn + 5000);
            replaced
                .handshake()
                .send(Initiator, &[1; 48])
                .send(Responder, &[2; 48]);
            let mut reconnect = ConnectionScript::with_port(port, isn + 6000, isn + 7000);
            reconnect
                .handshake()
                .send(Initiator, &[3; 48])
                .send(Responder, &[4; 48])
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            replaced.segments.append(&mut reconnect.segments);
            replaced
        });

        // a segment splits the hole 16..48 into two while a later hole
        // exists, and all of them are filled later
        let mut split = ConnectionScript::with_port(50004, isn + 9000, isn + 10000);
        split
            .handshake()
            .send_at(Initiator, 0, &[1; 16])
            .send_at(Initiator, 48, &[4; 16])
            .send_at(Initiator, 80, &[6; 16])
            .send_at(Initiator, 24, &[2; 8])
            .send_at(Initiator, 16, &[2; 8])
            .send_at(Initiator, 32, &[3; 16])
            .send_at(Initiator, 64, &[5; 16])
            .send(Responder, &[7; 96])
            .fin(Initiator)
            .fin(Responder)
            .ack(Initiator);

        [finished, reset]
            .iter()
            .chain(&reconnects)
            .chain([&split])
            .flat_map(|script| &script.segments)
            .map(|segment| (segment.clone(), segment.to_bytes()))
            .collect()
    }

    /// Feeds the serialized `segments` to `pool`, reads every connection
    /// handed over to its end and recycles it, and returns their ends.
    fn feed_and_recycle(
        pool: &mut TcpReassemblyPool<u32, ()>,
        segments: &[(TestSegment, Vec<u8>)],
        timestamp: u32,
    ) -> [Option<TcpConnectionEnd>; 7] {
        let mut ends = [None; 7];
        let mut count = 0;
        for (segment, bytes) in segments {
            let processed = segment.feed_bytes(bytes, pool, timestamp);
            if let Some(mut connection) = processed.ended {
                for role in [Initiator, Responder] {
                    read_to_end(connection.stream_mut(role));
                }
                ends[count] = connection.end();
                count += 1;
                pool.recycle(connection);
            }
        }
        ends
    }

    /// Reads all bytes of `stream`, stepping over gaps.
    fn read_to_end(stream: &mut TcpStream) {
        loop {
            match stream.read_received() {
                TcpRead::Data(data) => {
                    let len = data.len();
                    stream.consume(len);
                }
                TcpRead::Gap { .. } => stream.consume_gap(),
                _ => break,
            }
        }
    }
}
