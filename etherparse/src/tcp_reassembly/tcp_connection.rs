use crate::{tcp_reassembly::*, *};
use core::net::SocketAddr;
use std::vec::Vec;

/// Both streams of a TCP connection, as reassembled by a
/// [`TcpReassemblyPool`].
#[derive(Clone, Debug)]
pub struct TcpConnection<Timestamp = (), CustomChannelId = ()> {
    id: TcpConnectionId,
    key: TcpConnectionKey<CustomChannelId>,
    initiator: SocketAddr,
    roles_guessed: bool,
    initiator_stream: TcpStream,
    responder_stream: TcpStream,
    first_seen: Timestamp,
    last_seen: Timestamp,
    end: Option<TcpConnectionEnd>,
    /// Number of packets applied to the connection.
    packets: u64,
}

impl<Timestamp, CustomChannelId> TcpConnection<Timestamp, CustomChannelId> {
    /// Creates a connection whose initiator is the endpoint `initiator`
    /// (guessed from the ports if `roles_guessed`) and whose first packet
    /// was seen at `timestamp`. Its streams store their bytes in the empty
    /// `buffers`.
    pub(crate) fn new(
        id: TcpConnectionId,
        key: TcpConnectionKey<CustomChannelId>,
        initiator: SocketAddr,
        roles_guessed: bool,
        timestamp: Timestamp,
        buffers: [Vec<u8>; 2],
    ) -> TcpConnection<Timestamp, CustomChannelId>
    where
        Timestamp: Clone,
    {
        let [initiator_buffer, responder_buffer] = buffers;
        TcpConnection {
            id,
            key,
            initiator,
            roles_guessed,
            initiator_stream: TcpStream::new(initiator_buffer),
            responder_stream: TcpStream::new(responder_buffer),
            first_seen: timestamp.clone(),
            last_seen: timestamp,
            end: None,
            packets: 0,
        }
    }

    /// Id the pool assigned to the connection.
    pub fn id(&self) -> TcpConnectionId {
        self.id
    }

    /// Key identifying the connection.
    pub fn key(&self) -> &TcpConnectionKey<CustomChannelId> {
        &self.key
    }

    /// Address and port of the endpoint with the given role.
    pub fn endpoint(&self, role: TcpRole) -> SocketAddr {
        match role {
            TcpRole::Initiator => self.initiator,
            TcpRole::Responder => {
                let [a, b] = self.key.endpoints();
                if a == self.initiator {
                    b
                } else {
                    a
                }
            }
        }
    }

    /// Returns true if the roles of the endpoints were guessed from their
    /// ports, as the connection started without a SYN or SYN-ACK.
    ///
    /// The endpoint with the lower port is then the responder. With equal
    /// ports, the sender of the connection's first packet is the initiator.
    /// A late SYN or SYN-ACK that gives a stream an observed start confirms
    /// the roles if it agrees with them; the roles never change.
    pub fn roles_guessed(&self) -> bool {
        self.roles_guessed
    }

    /// Stream sent by the endpoint with the given role.
    pub fn stream(&self, role: TcpRole) -> &TcpStream {
        match role {
            TcpRole::Initiator => &self.initiator_stream,
            TcpRole::Responder => &self.responder_stream,
        }
    }

    /// Stream sent by the endpoint with the given role, for reading.
    pub fn stream_mut(&mut self, role: TcpRole) -> &mut TcpStream {
        match role {
            TcpRole::Initiator => &mut self.initiator_stream,
            TcpRole::Responder => &mut self.responder_stream,
        }
    }

    /// Timestamp of the connection's first packet.
    pub fn first_seen(&self) -> &Timestamp {
        &self.first_seen
    }

    /// Timestamp of the connection's last packet.
    pub fn last_seen(&self) -> &Timestamp {
        &self.last_seen
    }

    /// Reason why the connection ended, `None` while it is open.
    pub fn end(&self) -> Option<TcpConnectionEnd> {
        self.end
    }

    /// Applies a segment sent by `source` and returns the role of the sender.
    pub(crate) fn add_segment(
        &mut self,
        source: SocketAddr,
        tcp: &TcpSlice<'_>,
        timestamp: Timestamp,
        config: &TcpReassemblyConfig,
    ) -> TcpRole {
        self.last_seen = timestamp;
        self.packets = self.packets.saturating_add(1);
        let sender = if source == self.initiator {
            TcpRole::Initiator
        } else {
            TcpRole::Responder
        };
        if tcp.rst() {
            self.add_reset(sender, tcp, config);
        } else {
            self.add_data_segment(sender, tcp, config);
        }
        for role in [TcpRole::Initiator, TcpRole::Responder] {
            let window = self
                .stream(role.other())
                .advertised_window(self.stream(role));
            let packet = self.packets;
            self.stream_mut(role).after_packet(window, packet, config);
        }

        // finished once both FINs were ACKed and the holes left are overdue
        if self.end.is_none()
            && [&self.initiator_stream, &self.responder_stream]
                .iter()
                .all(|stream| stream.can_finish())
        {
            self.end = Some(TcpConnectionEnd::Finished);
        }
        if let Some(end) = self.end {
            let stream_end = match end {
                TcpConnectionEnd::Finished => TcpStreamEnd::Fin,
                TcpConnectionEnd::Reset { .. } => TcpStreamEnd::Reset,
            };
            self.initiator_stream.connection_ended(stream_end);
            self.responder_stream.connection_ended(stream_end);
        }
        sender
    }

    /// Applies a segment without RST sent by `sender`.
    fn add_data_segment(
        &mut self,
        sender: TcpRole,
        tcp: &TcpSlice<'_>,
        config: &TcpReassemblyConfig,
    ) {
        let starts = self.starts();
        // the SYN-ACK ACKs the other side's SYN, so the other stream starts
        // there, even if its SYN was not seen
        if tcp.syn() && tcp.ack() {
            let window = self.window(sender.other(), config);
            self.stream_mut(sender.other()).observe_start(
                tcp.acknowledgment_number(),
                window,
                config,
            );
        }
        // the window the sender advertised before this segment limits what
        // the other side could send, so the ACK is applied first
        self.add_ack(sender, tcp, config);
        let window = self.window(sender, config);
        let packet = self.packets;
        self.stream_mut(sender)
            .add_segment(tcp, window, packet, config);

        // a late SYN or SYN-ACK that gave a stream an observed start
        // confirms guessed roles if its sender has the role the guess gave it
        if self.roles_guessed && tcp.syn() {
            let syn_sender = if tcp.ack() {
                TcpRole::Responder
            } else {
                TcpRole::Initiator
            };
            if syn_sender == sender && starts != self.starts() {
                self.roles_guessed = false;
            }
        }
    }

    /// Applies an RST sent by `sender`: one that the receiver can accept
    /// ends the connection, and its ACK counts. Others are ignored with
    /// their ACK and window, as they don't belong to the connection (e.g.
    /// injected ones). RSTs carry no bytes of the stream, and their SYN and
    /// FIN flags are ignored.
    fn add_reset(&mut self, sender: TcpRole, tcp: &TcpSlice<'_>, config: &TcpReassemblyConfig) {
        let window = self.window(sender, config);
        let seq = tcp.sequence_number();
        if self.stream_mut(sender).add_reset(seq, window) {
            self.add_ack(sender, tcp, config);
            self.end = Some(TcpConnectionEnd::Reset { by: sender });
        }
    }

    /// Applies the ACK number of a segment sent by `sender` (if it has one)
    /// to the other stream.
    fn add_ack(&mut self, sender: TcpRole, tcp: &TcpSlice<'_>, config: &TcpReassemblyConfig) {
        if tcp.ack() {
            let window = self.window(sender.other(), config);
            let packet = self.packets;
            self.stream_mut(sender.other())
                .add_ack(tcp.acknowledgment_number(), window, packet);
        }
    }

    /// How the streams of the initiator and the responder started.
    fn starts(&self) -> [TcpStreamStart; 2] {
        [&self.initiator_stream, &self.responder_stream].map(|stream| stream.status().start)
    }

    /// Receive window of the stream sent by `role`, as advertised by its
    /// receiver, or the fallback window while that is unknown.
    fn window(&self, role: TcpRole, config: &TcpReassemblyConfig) -> u64 {
        self.stream(role.other())
            .advertised_window(self.stream(role))
            .unwrap_or(u64::from(config.fallback_window))
    }

    /// Returns the connection with its streams and leaves a tombstone
    /// without buffers in its place, which keeps the key, id and timestamps.
    pub(crate) fn hand_over(&mut self) -> TcpConnection<Timestamp, CustomChannelId>
    where
        Timestamp: Clone,
        CustomChannelId: Clone,
    {
        let tombstone = TcpConnection {
            id: self.id,
            key: self.key.clone(),
            initiator: self.initiator,
            roles_guessed: self.roles_guessed,
            initiator_stream: TcpStream::new(Vec::new()),
            responder_stream: TcpStream::new(Vec::new()),
            first_seen: self.first_seen.clone(),
            last_seen: self.last_seen.clone(),
            end: self.end,
            packets: self.packets,
        };
        core::mem::replace(self, tombstone)
    }

    /// Returns the buffers of both streams, emptied for re-use.
    pub(crate) fn into_buffers(self) -> [Vec<u8>; 2] {
        [
            self.initiator_stream.into_buffer(),
            self.responder_stream.into_buffer(),
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tcp_reassembly::TcpRole::*;
    use std::format;

    #[test]
    fn derived_traits() {
        let mut pool = TcpReassemblyPool::<u32, ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();

        // clone
        {
            let mut clone = connection.clone();
            assert_eq!(connection.id(), clone.id());
            assert_eq!(connection.key(), clone.key());
            assert_eq!(connection.endpoint(Initiator), clone.endpoint(Initiator));
            assert_eq!(connection.first_seen(), clone.first_seen());
            assert_eq!(connection.last_seen(), clone.last_seen());
            assert_eq!(
                TcpRead::Data(b"abc"),
                clone.stream_mut(Initiator).read_received()
            );
        }

        // debug
        assert!(format!("{:?}", connection).starts_with(&format!(
            "TcpConnection {{ id: TcpConnectionId(0), key: {:?}, ",
            connection.key()
        )));
    }

    #[test]
    fn id() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        for (i, port) in [50000, 50001, 50002].into_iter().enumerate() {
            let mut script = ConnectionScript::new(
                addr(&format!("10.0.0.1:{}", port)),
                addr("10.0.0.2:80"),
                1000,
                2000,
            );
            script.handshake();
            for segment in &script.segments {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(TcpConnectionId(i as u64), connection.id());
            }
        }
    }

    #[test]
    fn key() {
        let mut pool = TcpReassemblyPool::<(), u8>::default();
        let mut script = ConnectionScript::new(addr("[::2]:443"), addr("[::1]:50000"), 1000, 2000)
            .with_channel_id(7u8);
        script.vlan_ids.push(VlanId::try_new(3).unwrap());
        script.handshake();
        let expected = TcpConnectionKey::new(
            script.vlan_ids.clone(),
            addr("[::1]:50000"),
            addr("[::2]:443"),
            7u8,
        );
        for segment in &script.segments {
            let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
            assert_eq!(&expected, connection.key());
        }
    }

    #[test]
    fn endpoint() {
        let cases = [
            // initiator is the lower endpoint
            (addr("10.0.0.1:50000"), addr("10.0.0.2:80")),
            // initiator is the higher endpoint
            (addr("10.0.0.3:50000"), addr("10.0.0.2:80")),
            // connection to itself
            (addr("10.0.0.1:50000"), addr("10.0.0.1:50000")),
        ];
        for (initiator, responder) in cases {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::new(initiator, responder, 1000, 2000);
            script.handshake();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(initiator, connection.endpoint(Initiator));
            assert_eq!(responder, connection.endpoint(Responder));
        }
    }

    #[test]
    fn roles_guessed() {
        // a SYN or SYN-ACK starts the connection: the roles are known
        for first in [0, 1] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let (connection, _) = script.feed(&mut pool, first..).active.unwrap();
            assert!(false == connection.roles_guessed());
        }

        // bytes start the connection: the endpoint with the lower port is
        // the responder, with equal ports the sender is the initiator
        for (initiator, responder, first_sender, guessed_initiator) in [
            // first bytes from the initiator, with the higher port
            ("10.0.0.1:50000", "10.0.0.2:80", Initiator, "10.0.0.1:50000"),
            // first bytes from the responder, with the lower port
            ("10.0.0.1:50000", "10.0.0.2:80", Responder, "10.0.0.1:50000"),
            // the initiator has the lower port, so the guess is wrong
            ("10.0.0.1:80", "10.0.0.2:50000", Initiator, "10.0.0.2:50000"),
            // equal ports
            ("10.0.0.1:80", "10.0.0.2:80", Initiator, "10.0.0.1:80"),
            ("10.0.0.1:80", "10.0.0.2:80", Responder, "10.0.0.2:80"),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::new(addr(initiator), addr(responder), 1000, 2000);
            script
                .handshake()
                .send(first_sender, b"abc")
                .send(first_sender.other(), b"def");
            let (connection, _) = script.feed(&mut pool, 3..).active.unwrap();
            assert!(connection.roles_guessed());
            assert_eq!(addr(guessed_initiator), connection.endpoint(Initiator));
            // the streams belong to the guessed roles
            for (sender, data) in [(first_sender, b"abc"), (first_sender.other(), b"def")] {
                let role = if script.endpoint(sender) == addr(guessed_initiator) {
                    Initiator
                } else {
                    Responder
                };
                assert_eq!(
                    TcpRead::Data(data),
                    connection.stream_mut(role).read_received()
                );
            }
        }

        // a late SYN or SYN-ACK that gives a stream an observed start
        // confirms guessed roles if it agrees with them
        for (late, initiator, responder, guessed) in [
            // SYN of the guessed initiator
            (0, "10.0.0.1:50000", "10.0.0.2:80", false),
            // SYN-ACK of the guessed responder
            (1, "10.0.0.1:50000", "10.0.0.2:80", false),
            // SYN of the guessed responder
            (0, "10.0.0.1:80", "10.0.0.2:50000", true),
            // SYN-ACK of the guessed initiator
            (1, "10.0.0.1:80", "10.0.0.2:50000", true),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::new(addr(initiator), addr(responder), 1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            let late = script.segments[late].clone();
            script.segments.drain(..3);
            script.segments.push(late);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(guessed, connection.roles_guessed());
        }

        // ... but not if it gives no stream an observed start, as the
        // streams were read from
        for late in [0, 1] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            let late = script.segments[late].clone();
            script.segments.drain(..3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                for role in [Initiator, Responder] {
                    let stream = connection.stream_mut(role);
                    stream.read_received();
                    stream.consume(1);
                }
            }
            let (connection, _) = late.feed(&mut pool, ()).active.unwrap();
            assert!(connection.roles_guessed());
        }
    }

    #[test]
    fn stream() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script
            .handshake()
            .send(Initiator, b"abc")
            .send(Responder, b"defgh");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        connection.stream_mut(Initiator).read_received();
        connection.stream_mut(Initiator).consume(3);
        connection.stream_mut(Responder).read_received();
        connection.stream_mut(Responder).consume(5);
        assert_eq!(3, connection.stream(Initiator).read_offset());
        assert_eq!(5, connection.stream(Responder).read_offset());
    }

    #[test]
    fn stream_mut() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script
            .handshake()
            .send(Initiator, b"abc")
            .send(Responder, b"def");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        assert_eq!(
            TcpRead::Data(b"abc"),
            connection.stream_mut(Initiator).read_received()
        );
        assert_eq!(
            TcpRead::Data(b"def"),
            connection.stream_mut(Responder).read_received()
        );
    }

    #[test]
    fn first_seen() {
        let mut pool = TcpReassemblyPool::<u32, ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        for (i, segment) in script.segments.iter().enumerate() {
            let (connection, _) = segment.feed(&mut pool, 10 + i as u32).active.unwrap();
            assert_eq!(&10, connection.first_seen());
        }
    }

    #[test]
    fn last_seen() {
        let mut pool = TcpReassemblyPool::<u32, ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        // a retransmission updates it too, and so does an RST outside of the
        // receiver's window
        let retransmission = script.segments[3].clone();
        script.segments.push(retransmission);
        script.rst_at(Responder, 1 << 30);
        for (i, segment) in script.segments.iter().enumerate() {
            let (connection, _) = segment.feed(&mut pool, 10 + i as u32).active.unwrap();
            assert_eq!(&(10 + i as u32), connection.last_seen());
        }
    }

    #[test]
    fn end() {
        // open connection
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
        }

        // every order of the FINs finishes the connection with the last ACK
        let closes: [fn(&mut ConnectionScript); 4] = [
            // initiator first
            |script| {
                script.fin(Initiator).fin(Responder).ack(Initiator);
            },
            // initiator first, ACKed before the responder's FIN
            |script| {
                script
                    .fin(Initiator)
                    .ack(Responder)
                    .fin(Responder)
                    .ack(Initiator);
            },
            // responder first
            |script| {
                script.fin(Responder).fin(Initiator).ack(Responder);
            },
            // simultaneous
            |script| {
                script.simultaneous_fins().ack(Initiator).ack(Responder);
            },
        ];
        for close in closes {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            close(&mut script);
            let (last, rest) = script.segments.split_last().unwrap();
            for segment in rest {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let connection = last.feed(&mut pool, ()).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // without the last ACK the connection stays open, although both
        // streams are finished
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            assert!(connection.stream(Initiator).is_finished());
            assert!(connection.stream(Responder).is_finished());
        }

        // an ACK of the bytes before the FIN doesn't ACK the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Responder, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let ack_number = script.seq(Responder, 3);
            script
                .segments
                .last_mut()
                .unwrap()
                .header
                .acknowledgment_number = ack_number;
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
        }

        // an ACK more than one window after the FIN doesn't ACK it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            script.segments[5].header.acknowledgment_number = script.seq(Initiator, 105);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(None, connection.end());
            }
            script.ack_to(Responder, 104);
            let connection = script.feed(&mut pool, 7..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // both FINs are ACKed, but bytes before a FIN were not captured: the
        // next segment after the hole was given up finishes the connection
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator)
                .ack(Initiator);
            script.segments.remove(3);
            {
                let (connection, _) = script.feed(&mut pool, ..6).active.unwrap();
                assert!(connection.stream_mut(Initiator).give_up_hole());
                assert_eq!(None, connection.end());
            }
            let connection = script.feed(&mut pool, 6..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // the ACK of a FIN arrives before the FIN, and its position was
        // given up before the FIN arrived
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Responder, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let fin = script.segments.remove(5);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Responder);
                stream.read_received();
                stream.consume(3);
                assert!(stream.give_up_hole());
                stream.consume_gap();
            }
            let connection = fin.feed(&mut pool, ()).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // the ACK of a FIN arrives before the FIN (reordered capture)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Responder, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            let ack = script.segments.pop().unwrap();
            script.segments.insert(5, ack);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // an injected FIN after the receiver's window doesn't keep the real
        // FIN from finishing the connection (regression test, the old
        // tcp-reassembly branch accepted it)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let injected = script.injected(|s| {
                s.fin_at(Initiator, 1 << 20, &[]);
            });
            script.segments.push(injected);
            script.fin(Initiator).fin(Responder).ack(Initiator);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(3), stream.fin_offset());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // both FINs are ACKed, but bytes before a FIN are missing (with and
        // without bytes in the FIN)
        for fin_data in [&b""[..], b"gh"] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin_with_data(Initiator, fin_data)
                .fin(Responder)
                .ack(Initiator);
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let mut connection = missing.feed(&mut pool, ()).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            assert_eq!(
                TcpRead::Data(&[&b"abcdef"[..], fin_data].concat()[..]),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // both FINs are ACKed and the hole left before a FIN is overdue (the
        // ACK of the FIN covered it for the ACK reorder tolerance): the
        // connection finishes and hands the hole over as a counted gap
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator)
                .ack(Initiator);
            script.segments.remove(4);
            {
                let (connection, _) = script.feed(&mut pool, ..7).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let mut connection = script.feed(&mut pool, 7..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert!(stream.is_finished());
            assert_eq!(0, stream.holes().count());
            assert_eq!((1, 3), (stream.status().gaps, stream.status().gap_bytes));
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // a hole is overdue once the ACK of N packets ago reaches its end,
        // in the streams of both roles
        for (sender, receiver) in [(Initiator, Responder), (Responder, Initiator)] {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(sender, b"abc")
                .send(sender, b"def")
                .send(sender, b"ghi")
                .send(sender, b"jkl")
                .fin_with_data(sender, b"mno")
                .ack_to(receiver, 12)
                .fin(receiver)
                .ack(sender);
            script.segments.remove(6);
            script.segments.remove(4);
            {
                let (connection, _) = script.feed(&mut pool, ..8).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let connection = script.feed(&mut pool, 8..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let status = connection.stream(sender).status();
            assert_eq!((2, 6), (status.gaps, status.gap_bytes));
        }

        // a connection picked up in the middle finishes too, also if one
        // side sent nothing but its FIN
        for initiator_data in [&b"abc"[..], b""] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"lost")
                .send(Responder, b"def")
                .send(Initiator, initiator_data)
                .fin(Responder)
                .fin(Initiator)
                .ack(Responder);
            script.segments.drain(..4);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(initiator_data.len() as u64), stream.fin_offset());
            assert!(stream.is_finished());
        }

        // ... and also if the ACK of the FIN of the side that sent nothing
        // else arrives before that FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"lost")
                .send(Responder, b"def")
                .fin(Responder)
                .fin(Initiator)
                .ack(Responder);
            script.segments.drain(..4);
            script.segments.swap(2, 3);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // a connection finishes after a jump right before a FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_at(Initiator, 1000, b"xyz")
                .fin(Responder)
                .ack(Initiator);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            assert_eq!(1, connection.stream(Initiator).status().resyncs);
        }

        // all holes left have to be overdue, not only the first one
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .send(Initiator, b"jkl")
                .fin_with_data(Initiator, b"mno")
                // the first hole is overdue two packets later
                .ack_to(Responder, 6)
                .ack(Initiator)
                .ack(Initiator)
                // the second hole is overdue two packets later
                .fin(Responder)
                .ack(Initiator)
                .ack(Initiator);
            script.segments.remove(6);
            script.segments.remove(4);
            {
                let (connection, _) = script.feed(&mut pool, ..11).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let connection = script.feed(&mut pool, 11..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // an RST at the sender's next byte resets the connection, sent by
        // either side
        for sender in [Initiator, Responder] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def")
                .rst(sender);
            {
                let (connection, _) = script.feed(&mut pool, ..5).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let connection = script.feed(&mut pool, 5..).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: sender }),
                connection.end()
            );
        }

        // an injected RST after the receiver's window is counted, but
        // doesn't end the connection (regression test, the old
        // tcp-reassembly branch accepted it)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            let injected = script.injected(|s| {
                s.rst_at(Initiator, 1 << 20);
            });
            script.segments.push(injected);
            {
                let (connection, sender) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(Initiator, sender);
                assert_eq!(None, connection.end());
                let status = connection.stream(Initiator).status();
                assert_eq!(1, status.out_of_window_segments);
            }
            script.fin(Initiator).fin(Responder).ack(Initiator);
            let connection = script.feed(&mut pool, 5..).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
        }

        // the receiver accepts an RST from its ACK up to one window after
        // the bytes sent (and the FIN), also with a window of 0
        for (window, fin, offset, reset) in [
            // before the ACK
            (100, false, 3, false),
            // at the ACK
            (100, false, 4, true),
            // up to one window after the bytes sent
            (100, false, 110, true),
            (100, false, 111, false),
            // ... and after the FIN
            (100, true, 111, true),
            (100, true, 112, false),
            // window of 0
            (0, false, 3, false),
            (0, false, 4, true),
            (0, false, 10, true),
            (0, false, 11, false),
            (0, true, 11, true),
            (0, true, 12, false),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"0123456789");
            if fin {
                script.fin(Initiator);
            }
            script.window_size = window;
            script.ack_to(Responder, 4);
            let rst = script.injected(|s| {
                s.rst_at(Initiator, offset);
            });
            script.segments.push(rst);
            let processed = script.feed_all(&mut pool);
            if reset {
                let connection = processed.ended.unwrap();
                assert_eq!(
                    Some(TcpConnectionEnd::Reset { by: Initiator }),
                    connection.end()
                );
            } else {
                let (connection, _) = processed.active.unwrap();
                assert_eq!(None, connection.end());
                let status = connection.stream(Initiator).status();
                assert_eq!(1, status.out_of_window_segments);
            }
        }

        // an RST 2^31 away from the bytes sent, or before the stream's first
        // byte, is not accepted
        for seq in [1001u32.wrapping_add(1 << 31), 1000] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let mut rst = script.injected(|s| {
                s.rst(Initiator);
            });
            rst.header.sequence_number = seq;
            script.segments.push(rst);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            let status = connection.stream(Initiator).status();
            assert_eq!(1, status.out_of_window_segments);
        }

        // an RST of a stream without a start is accepted from the other
        // side's ACK of the stream up to one window after it (the
        // initiator's stream was not captured, the responder ACKs 10 bytes
        // of it)
        for (offset, reset) in [(9, false), (10, true), (110, true), (111, false)] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"0123456789")
                .send(Responder, b"abc")
                .ack(Initiator)
                .rst_at(Initiator, offset);
            script.segments.drain(..4);
            let processed = script.feed_all(&mut pool);
            if reset {
                let connection = processed.ended.unwrap();
                assert_eq!(
                    Some(TcpConnectionEnd::Reset { by: Initiator }),
                    connection.end()
                );
            } else {
                let (connection, _) = processed.active.unwrap();
                assert_eq!(None, connection.end());
                let status = connection.stream(Initiator).status();
                assert_eq!(1, status.out_of_window_segments);
            }
        }

        // ... and at any sequence number without such an ACK
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"0123456789")
                .send(Responder, b"abc")
                .rst_at(Initiator, 1 << 30);
            script.segments.drain(..4);
            script.segments[0].header.ack = false;
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Initiator }),
                connection.end()
            );
        }

        // an RST with bytes, a SYN or a FIN resets the connection too,
        // without storing its bytes or its FIN
        for (payload, syn, fin) in [
            (&b"xyz"[..], false, false),
            (b"", true, false),
            (b"", false, true),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let mut rst = script.injected(|s| {
                s.send(Initiator, payload);
            });
            rst.header.rst = true;
            rst.header.syn = syn;
            rst.header.fin = fin;
            script.segments.push(rst);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Initiator }),
                connection.end()
            );
            let stream = connection.stream_mut(Initiator);
            assert_eq!(None, stream.fin_offset());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Reset), stream.read_received());
        }

        // an RST whose ACK ACKs the last FIN resets the connection, it
        // doesn't finish it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder)
                .rst(Initiator);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Initiator }),
                connection.end()
            );
        }

        // an ACK doesn't keep an RST at or after the received bytes from
        // resetting the connection, as a forged ACK could (also once a FIN
        // cut the hole that ACK left, with a window of 0), but RSTs before
        // the received bytes stay ignored
        for (fin, window, offset, reset) in [
            (false, 100, 3, true),
            (false, 100, 2, false),
            (true, 0, 4, true),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            let mut forged = script.injected(|s| {
                s.ack_to(Responder, 10);
            });
            forged.header.window_size = window;
            script.segments.push(forged);
            if fin {
                script.fin(Initiator);
            }
            let rst = script.injected(|s| {
                s.rst_at(Initiator, offset);
            });
            script.segments.push(rst);
            let processed = script.feed_all(&mut pool);
            assert_eq!(reset, processed.ended.is_some());
        }

        // a pickup accepts an RST at the receiver's ACK before its first
        // byte, which is kept until bytes can't be prepended anymore (the
        // capture starts at the initiator's byte 5, the responder ACKs 3)
        for (offset, reset) in [(3, true), (2, false)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"01234")
                .send(Initiator, b"56789")
                .ack_to(Responder, 3)
                .rst_at(Initiator, offset);
            script.segments.drain(..4);
            let processed = script.feed_all(&mut pool);
            assert_eq!(reset, processed.ended.is_some());
        }

        // RSTs before the point a stream resynced at are ignored, also
        // without an ACK of the jump
        for (offset, reset) in [(998, false), (1000, true)] {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(1),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .rst_at(Initiator, offset);
            let processed = script.feed_all(&mut pool);
            assert_eq!(reset, processed.ended.is_some());
        }

        // an RST from a direction never seen resets the connection, e.g.
        // the answer to a SYN on a closed port
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().rst(Responder);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                connection.end()
            );
        }
    }
}
