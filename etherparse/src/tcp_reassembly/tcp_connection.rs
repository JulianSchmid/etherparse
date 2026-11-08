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
    /// SYN that is not its stream's own (a new ISN, or one that may be
    /// blind, S5), kept until a SYN-ACK of the other endpoint confirms the
    /// reconnect it starts or the simultaneous open it is part of (`None`
    /// without one). A tombstone keeps the one its connection kept.
    reconnect_syn: Option<ReconnectSyn<Timestamp>>,
    /// Bytes the streams buffered when the pool last accounted for them.
    accounted: usize,
}

impl<Timestamp, CustomChannelId> TcpConnection<Timestamp, CustomChannelId> {
    /// Creates a connection whose initiator is the endpoint `initiator`
    /// (guessed from the ports if `roles_guessed`) and whose first packet
    /// was seen at `timestamp`. Its streams take their buffers from `free`.
    pub(crate) fn new(
        id: TcpConnectionId,
        key: TcpConnectionKey<CustomChannelId>,
        initiator: SocketAddr,
        roles_guessed: bool,
        timestamp: Timestamp,
        free: &mut FreeBuffers,
    ) -> TcpConnection<Timestamp, CustomChannelId>
    where
        Timestamp: Clone,
    {
        TcpConnection {
            id,
            key,
            initiator,
            roles_guessed,
            initiator_stream: TcpStream::new(free),
            responder_stream: TcpStream::new(free),
            first_seen: timestamp.clone(),
            last_seen: timestamp,
            end: None,
            packets: 0,
            reconnect_syn: None,
            accounted: 0,
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

    /// Applies a segment sent by `source`, storing at most `available` more
    /// bytes (the pool's budget, reduced by the bytes stored), and returns
    /// the role of the sender. A SYN that is kept takes its buffer from
    /// `free`.
    pub(crate) fn add_segment(
        &mut self,
        source: SocketAddr,
        tcp: &TcpSlice<'_>,
        timestamp: Timestamp,
        config: &TcpReassemblyConfig,
        available: &mut usize,
        free: &mut FreeBuffers,
    ) -> TcpRole
    where
        Timestamp: Clone,
    {
        self.last_seen = timestamp;
        self.packets = self.packets.saturating_add(1);
        let sender = self.role(source);
        let verdict = self.verdict(sender, tcp, config);
        // a SYN-ACK or RST that ACKs the receiver's SYN knows its ISN, which
        // outweighs an ACK kept for the sender's stream without a start
        if Verdict::Dropped != verdict
            && (tcp.syn() || tcp.rst())
            && self.answers_observed_syn(sender, tcp)
            && (tcp.rst() || false == self.kept_ack_allows(sender, tcp, config))
        {
            self.stream_mut(sender).drop_kept_ack();
        }
        let window = self.window(sender.other(), config);
        match verdict {
            Verdict::Dropped => {
                self.stream_mut(sender).count_out_of_window();
                // the dropped segments agree within the window of their own
                // stream (R3), and may end the wait for the ACK of the SYN
                if tcp.ack() || tcp.syn() || tcp.rst() {
                    let window = self.window(sender, config);
                    self.stream_mut(sender.other())
                        .record_dropped(tcp, window, config);
                }
            }
            Verdict::Reset => self.add_reset(sender, tcp, config),
            Verdict::KeepSyn { maybe_blind } => {
                self.keep_reconnect_syn(source, tcp, maybe_blind, free);
            }
            Verdict::ForeignSynAck => {
                // the SYN it answers may follow in a capture merged from two
                // taps: it is kept for that SYN (C2), unless a SYN is kept
                if self
                    .reconnect_syn
                    .as_ref()
                    .is_none_or(|kept| kept.ack.is_some())
                {
                    self.keep_reconnect_syn(source, tcp, false, free);
                }
                self.stream_mut(sender.other())
                    .answer_syn(tcp, window, config);
            }
            // the pool replaced the connection on `ConfirmsReconnect` before
            Verdict::ConfirmsReconnect => {
                self.stream_mut(sender.other())
                    .answer_syn(tcp, window, config);
            }
            Verdict::Applied => {
                self.stream_mut(sender.other())
                    .answer_syn(tcp, window, config);
                if tcp.syn() {
                    self.confirm_kept_syn(sender, source, tcp, window, config, available, free);
                }
                self.add_data_segment(sender, tcp, config, available);
            }
        }
        // a SYN kept as possibly blind whose stream has a start now is kept
        // no longer: it is that stream's late SYN (A5), or it is dropped if
        // the stream started at another SYN or the SYN lies too far before
        // its first bytes
        let started = self
            .reconnect_syn
            .as_ref()
            .is_some_and(|syn| syn.maybe_blind && self.stream(self.role(syn.source)).has_start());
        if let Some(syn) = self.reconnect_syn.take_if(|_| started) {
            self.apply_kept_syn(syn, config, available, free);
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
            self.end_with(end);
        }
        sender
    }

    /// Ends the connection, of which no more packets come (e.g. as a
    /// reconnect replaces it): as finished if both FINs were ACKed, as every
    /// hole the ACKs cover counts as overdue, and with `end` otherwise.
    pub(crate) fn end_unless_finished(&mut self, end: TcpConnectionEnd) {
        let finished = [&self.initiator_stream, &self.responder_stream]
            .iter()
            .all(|stream| stream.is_fin_acked());
        self.end_with(if finished {
            TcpConnectionEnd::Finished
        } else {
            end
        });
    }

    /// Ends the connection with `end`: the holes of both streams become
    /// gaps, as late segments can't fill them anymore, and reads return the
    /// end once nothing more is readable.
    pub(crate) fn end_with(&mut self, end: TcpConnectionEnd) {
        self.end = Some(end);
        let stream_end = match end {
            TcpConnectionEnd::Finished => TcpStreamEnd::Fin,
            TcpConnectionEnd::Reset { .. } => TcpStreamEnd::Reset,
            TcpConnectionEnd::Evicted => TcpStreamEnd::Evicted,
            TcpConnectionEnd::Reconnect => TcpStreamEnd::Reconnect,
        };
        self.initiator_stream.connection_ended(stream_end);
        self.responder_stream.connection_ended(stream_end);
    }

    /// Decides what the connection does with the segment `tcp` sent by
    /// `sender`, by the state of its handshake (S5, S6) and the SYN it
    /// keeps (C2, C3); see [`Verdict`]. The decision changes nothing.
    fn verdict(
        &self,
        sender: TcpRole,
        tcp: &TcpSlice<'_>,
        config: &TcpReassemblyConfig,
    ) -> Verdict {
        // every receiver drops a segment without ACK that is no SYN or RST
        // (RFC 9293 3.10.7.4, S6), and while the receiver's SYN is
        // unanswered, it drops every segment that doesn't ACK that SYN (S5)
        let window = self.window(sender.other(), config);
        if false == (tcp.ack() || tcp.syn() || tcp.rst())
            || self.drops_before_syn_acked(sender, tcp, window, config)
        {
            return Verdict::Dropped;
        }
        if tcp.rst() {
            return Verdict::Reset;
        }
        if false == tcp.syn() {
            return Verdict::Applied;
        }
        // a SYN of a side without a start while the other side's SYN is
        // unanswered may be blind, unless it is the SYN-ACK that answers it:
        // a simultaneous open's SYN-ACK repeats its ISN and anchors the
        // stream, so the SYN is only kept
        let stream = self.stream(sender);
        let other = self.stream(sender.other());
        let maybe_blind = false == stream.has_start()
            && other.awaits_syn_ack()
            && false == other.acks_unacked_syn(tcp, window, config);
        // a SYN-ACK that ACKs the other stream's SYN is the own one too,
        // whatever ACK a blind segment left kept for its stream (S5)
        let answers = self.answers_observed_syn(sender, tcp);
        let own = answers || stream.is_own_syn(tcp, self.window(sender, config), config);
        // a mid-stream pickup that can't put bytes in front anymore takes no
        // late SYN (A5): one in its range is kept, as a reconnect's SYN can
        // lie there by chance (C4), but confirms no reconnect either
        let takes = answers || stream.can_take_syn(tcp, self.window(sender, config), config);
        if false == tcp.ack() {
            // a SYN-ACK of the other endpoint captured before the SYN it
            // ACKs was kept for it: the SYN confirms the reconnect (C2)
            let answered = self
                .reconnect_syn
                .as_ref()
                .is_some_and(|kept| kept.acks(self.endpoint(sender), tcp));
            return if answered && false == (own || tcp.fin()) {
                Verdict::ConfirmsReconnect
            } else if maybe_blind || false == takes {
                Verdict::KeepSyn { maybe_blind }
            } else {
                Verdict::Applied
            };
        }
        // a SYN-ACK confirms a reconnect if a SYN of the other endpoint is
        // kept and it ACKs that SYN without having the ISN of its sender's
        // stream, or has a new ISN itself while its sender's SYN is answered
        // (a side whose own SYN is unanswered confirms one only by ACKing
        // the kept SYN, S5); a kept SYN-ACK of the other endpoint confirms
        // one only by being ACKed, like a kept SYN
        let kept = self
            .reconnect_syn
            .as_ref()
            .filter(|syn| syn.source != self.endpoint(sender));
        let confirms = match kept {
            None => false,
            Some(_) if tcp.fin() => false,
            // the sender's own SYN-ACK (a retransmission, or a late one of
            // a mid-stream pickup) confirms nothing
            Some(syn) if syn.is_acked_by(self.endpoint(sender), tcp) => false == own,
            // a SYN kept as possibly blind confirms a reconnect only by being
            // ACKed, as a blind SYN-ACK could have any ISN
            Some(syn) => false == (syn.maybe_blind || stream.awaits_syn_ack() || own),
        };
        if confirms {
            Verdict::ConfirmsReconnect
        } else if maybe_blind || false == takes {
            // a SYN-ACK with a new ISN that confirms no reconnect changes
            // nothing (C3)
            Verdict::ForeignSynAck
        } else {
            Verdict::Applied
        }
    }

    /// Applies the kept SYN of a simultaneous open (one kept as possibly
    /// blind, S5) if the SYN-ACK `tcp` sent by `sender` from `source`
    /// confirms it as its stream's own SYN, so that the stream starts at
    /// the SYN with its bytes, window scale and window, not at the ACK
    /// number (A2): the other side's SYN-ACK confirms it by ACKing it (C2
    /// found no reconnect), the sender's own SYN-ACK by repeating its ISN.
    /// The confirmation outweighs an ACK kept for the stream (S5), the
    /// applied SYN counts as no further packet (it counted when it was
    /// kept), and the SYN-ACK answers it. A SYN kept as a reconnect's stays
    /// kept.
    #[allow(clippy::too_many_arguments)]
    fn confirm_kept_syn(
        &mut self,
        sender: TcpRole,
        source: SocketAddr,
        tcp: &TcpSlice<'_>,
        window: u64,
        config: &TcpReassemblyConfig,
        available: &mut usize,
        free: &mut FreeBuffers,
    ) {
        // a SYN kept as a reconnect's is replayed by the pool instead; a
        // stream that got a pickup start from bytes before the SYN-ACK takes
        // the SYN as a late one (A5)
        let Some(syn) = self.reconnect_syn.take_if(|syn| {
            syn.maybe_blind
                && (syn.is_acked_by(source, tcp)
                    || (syn.source == source && syn.isn == tcp.sequence_number()))
        }) else {
            return;
        };
        self.apply_kept_syn(syn, config, available, free);
        self.stream_mut(sender.other())
            .answer_syn(tcp, window, config);
    }

    /// Applies the kept SYN `syn` to its stream as the stream's own SYN (or
    /// as a late one, A5, if the stream started from bytes meanwhile) and
    /// recycles it; a stream that started at another SYN drops it as
    /// out-of-window. An ACK kept for the stream that doesn't allow the SYN
    /// is dropped first, as the SYN is confirmed. The SYN's conflicting
    /// retransmissions count only if the SYN was taken.
    fn apply_kept_syn(
        &mut self,
        syn: ReconnectSyn<Timestamp>,
        config: &TcpReassemblyConfig,
        available: &mut usize,
        free: &mut FreeBuffers,
    ) {
        if let Some(syn_tcp) = syn.tcp() {
            let syn_sender = self.role(syn.source);
            let stream = self.stream(syn_sender);
            // a stream that started at another SYN can't take the kept one
            // (C3): it is a blind one
            if stream.isn().is_some_and(|isn| isn != syn.isn) {
                self.stream_mut(syn_sender).count_out_of_window();
                syn.recycle(free);
                return;
            }
            if false == stream.has_start()
                && false == self.kept_ack_allows(syn_sender, &syn_tcp, config)
            {
                self.stream_mut(syn_sender).drop_kept_ack();
            }
            self.add_data_segment(syn_sender, &syn_tcp, config, available);
            if Some(syn.isn) == self.stream(syn_sender).isn() {
                self.stream_mut(syn_sender)
                    .count_conflicting_retransmissions(syn.conflicting);
                // an ACK kept for the stream counts now that it has a start,
                // before the bytes of the confirming segment are compared
                // (retransmissions of ACKed bytes don't conflict, D2)
                let window = self
                    .stream(syn_sender.other())
                    .advertised_window(self.stream(syn_sender));
                self.stream_mut(syn_sender).apply_kept_ack(window, config);
            }
        }
        syn.recycle(free);
    }

    /// Returns true if the ACK kept for the stream of `sender`, if any,
    /// allows the SYN or SYN-ACK `tcp` to start the stream (C4).
    fn kept_ack_allows(
        &self,
        sender: TcpRole,
        tcp: &TcpSlice<'_>,
        config: &TcpReassemblyConfig,
    ) -> bool {
        let window = self.window(sender, config);
        self.stream(sender).kept_ack_allows_syn(
            tcp.sequence_number().wrapping_add(1),
            window,
            config,
        )
    }

    /// Returns true if the segment `tcp` sent by `sender`, whose stream has
    /// no start, ACKs the observed SYN of the other stream: its sender
    /// knows that ISN (S5).
    fn answers_observed_syn(&self, sender: TcpRole, tcp: &TcpSlice<'_>) -> bool {
        tcp.ack()
            && false == self.stream(sender).has_start()
            && self
                .stream(sender.other())
                .syn()
                .is_some_and(|syn| syn.is_acked_by(tcp.acknowledgment_number()))
    }

    /// Returns true if the receiver of the segment `tcp` sent by `sender`
    /// drops it, as its own SYN is unanswered and the segment doesn't ACK
    /// it (S5, see [`TcpStream::drops_before_syn_acked`]); an RST or FIN of
    /// a side with neither a start nor a kept ACK has to ACK the SYN also
    /// after the wait. A receiver in SYN-RECEIVED, whose other side has a
    /// start, checks an RST by its sequence number instead (RFC 9293
    /// 3.10.7.4, F4), and a SYN-ACK without RST and FIN that ACKs the kept
    /// SYN (of a reconnect or a simultaneous open) answers that SYN and is
    /// applied. `window` is the receive window of the receiver's stream.
    fn drops_before_syn_acked(
        &self,
        sender: TcpRole,
        tcp: &TcpSlice<'_>,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> bool {
        if tcp.rst() && self.stream(sender).has_start() {
            return false;
        }
        if tcp.syn()
            && false == (tcp.rst() || tcp.fin())
            && self
                .reconnect_syn
                .as_ref()
                .is_some_and(|syn| syn.is_acked_by(self.endpoint(sender), tcp))
        {
            return false;
        }
        let bare =
            false == self.stream(sender).has_start() && false == self.stream(sender).has_kept_ack();
        self.stream(sender.other())
            .drops_before_syn_acked(tcp, window, config, bare)
    }

    /// Applies a segment without RST sent by `sender`, storing at most
    /// `available` more bytes.
    fn add_data_segment(
        &mut self,
        sender: TcpRole,
        tcp: &TcpSlice<'_>,
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) {
        let starts = self.starts();
        // the SYN-ACK ACKs the other side's SYN, so the other stream starts
        // there, even if its SYN was not seen; the ACK number of one that
        // the other stream's kept ACK refuses as its start is not kept
        // either, as it would replace that ACK (A4)
        let mut ack_counts = true;
        if tcp.syn() && tcp.ack() {
            let window = self.window(sender.other(), config);
            let other = self.stream_mut(sender.other());
            let had_start = other.has_start();
            let observed = other.observe_start(
                tcp.acknowledgment_number(),
                // the SYN-ACK carries none of the SYN's bytes
                0,
                window,
                config,
                available,
            );
            ack_counts = observed || had_start;
        }
        // the window the sender advertised before this segment limits what
        // the other side could send, so the ACK is applied first
        if ack_counts {
            self.add_ack(sender, tcp, config);
        }
        let window = self.window(sender, config);
        let packet = self.packets;
        self.stream_mut(sender)
            .add_segment(tcp, window, packet, config, available);

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

    /// Keeps the SYN `tcp` of `source`, which is not its stream's own, in a buffer
    /// from `free` until the other endpoint's SYN-ACK confirms the
    /// reconnect it starts. A retransmission of the kept SYN only adds the
    /// TCP Fast Open bytes it carries beyond the kept ones (the bytes
    /// received first win, and differing bytes count as a conflict once the
    /// SYN is replayed); a SYN with another ISN or from the other endpoint
    /// replaces it.
    fn keep_reconnect_syn(
        &mut self,
        source: SocketAddr,
        tcp: &TcpSlice<'_>,
        maybe_blind: bool,
        free: &mut FreeBuffers,
    ) where
        Timestamp: Clone,
    {
        if let Some(syn) = self
            .reconnect_syn
            .as_mut()
            .filter(|syn| syn.is_retransmitted_by(source, tcp))
        {
            syn.add_retransmission(tcp.payload());
            return;
        }
        // re-use the buffer of a replaced SYN
        let mut segment = self
            .reconnect_syn
            .take()
            .map_or_else(|| free.bytes.take(), |syn| syn.segment);
        segment.clear();
        segment.extend_from_slice(tcp.slice());
        self.reconnect_syn = Some(ReconnectSyn {
            source,
            timestamp: self.last_seen.clone(),
            isn: tcp.sequence_number(),
            ack: tcp.ack().then(|| tcp.acknowledgment_number()),
            payload_len: tcp.payload().len(),
            conflicting: 0,
            maybe_blind,
            segment,
        });
    }

    /// Returns true if `tcp`, sent by `source`, is a SYN-ACK or SYN that
    /// confirms a reconnect (see [`Verdict::ConfirmsReconnect`]): the pool
    /// replaces the connection then.
    pub(crate) fn confirms_reconnect(
        &self,
        source: SocketAddr,
        tcp: &TcpSlice<'_>,
        config: &TcpReassemblyConfig,
    ) -> bool {
        // only a SYN or SYN-ACK can, so the verdict is left to `add_segment`
        // for every other segment
        tcp.syn() && Verdict::ConfirmsReconnect == self.verdict(self.role(source), tcp, config)
    }

    /// Takes the kept SYN of a reconnect, if there is one.
    pub(crate) fn take_reconnect_syn(&mut self) -> Option<ReconnectSyn<Timestamp>> {
        self.reconnect_syn.take()
    }

    /// Applies the kept SYN or SYN-ACK `syn` of a reconnect as the
    /// connection's first packet, storing at most `available` more bytes.
    pub(crate) fn add_reconnect_syn(
        &mut self,
        syn: &ReconnectSyn<Timestamp>,
        config: &TcpReassemblyConfig,
        available: &mut usize,
        free: &mut FreeBuffers,
    ) where
        Timestamp: Clone,
    {
        if let Some(tcp) = syn.tcp() {
            let timestamp = syn.timestamp.clone();
            let sender = self.add_segment(syn.source, &tcp, timestamp, config, available, free);
            // retransmissions of the SYN carried differing bytes
            self.stream_mut(sender)
                .count_conflicting_retransmissions(syn.conflicting);
        }
    }

    /// Applies the ACK number of a segment sent by `sender` (if it has one)
    /// to the other stream.
    fn add_ack(&mut self, sender: TcpRole, tcp: &TcpSlice<'_>, config: &TcpReassemblyConfig) {
        if tcp.ack() {
            let window = self.window(sender.other(), config);
            let packet = self.packets;
            self.stream_mut(sender.other()).add_ack(
                tcp.acknowledgment_number(),
                window,
                packet,
                config,
            );
        }
    }

    /// Role of the endpoint `source`.
    fn role(&self, source: SocketAddr) -> TcpRole {
        if source == self.initiator {
            TcpRole::Initiator
        } else {
            TcpRole::Responder
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

    /// What the pool keeps of the connection once it ended, taking the kept
    /// SYN of a reconnect along.
    pub(crate) fn tombstone(&mut self) -> Tombstone<Timestamp>
    where
        Timestamp: Clone,
    {
        Tombstone {
            initiator: self.initiator,
            syns: [self.initiator_stream.syn(), self.responder_stream.syn()],
            last_seen: self.last_seen.clone(),
            reconnect_syn: self.reconnect_syn.take(),
        }
    }

    /// Number of bytes both streams buffer, each from its read position to
    /// its furthest stored byte, with the placeholders of holes.
    pub(crate) fn buffered(&self) -> usize {
        self.initiator_stream.buffered() + self.responder_stream.buffered()
    }

    /// Updates `total`, the bytes buffered by the pool's connections, with
    /// the bytes the streams buffer now (reading them makes room).
    pub(crate) fn account_buffered(&mut self, total: &mut usize) {
        let buffered = self.buffered();
        *total = total
            .saturating_sub(self.accounted)
            .saturating_add(buffered);
        self.accounted = buffered;
    }

    /// Takes the bytes the streams buffered out of `total`, the bytes
    /// buffered by the pool's connections, as the connection leaves the
    /// pool.
    pub(crate) fn release_buffered(&mut self, total: &mut usize) {
        *total = total.saturating_sub(self.accounted);
        self.accounted = 0;
    }

    /// Puts the buffers of both streams and of the kept SYN into `free` for
    /// re-use.
    pub(crate) fn recycle(self, free: &mut FreeBuffers) {
        self.initiator_stream.recycle(free);
        self.responder_stream.recycle(free);
        if let Some(syn) = self.reconnect_syn {
            syn.recycle(free);
        }
    }
}

/// What the pool keeps of an ended connection: enough to absorb its late
/// segments, to tell a late retransmission of its handshake from a
/// reconnect, and to evict it once no late segment came for long enough.
#[derive(Clone, Debug)]
pub(crate) struct Tombstone<Timestamp> {
    /// Endpoint that initiated the connection.
    initiator: SocketAddr,
    /// SYNs of the initiator's and the responder's stream, if observed.
    syns: [Option<ObservedSyn>; 2],
    /// Timestamp of the connection's last packet, also a late one.
    pub last_seen: Timestamp,
    /// SYN or SYN-ACK that the connection kept (see
    /// [`TcpConnection::confirms_reconnect`]).
    pub reconnect_syn: Option<ReconnectSyn<Timestamp>>,
}

impl<Timestamp> Tombstone<Timestamp> {
    /// Returns true if the SYN or SYN-ACK `tcp`, sent by `source`, belongs
    /// to the handshake of the ended connection: it has the ISN of its
    /// sender's stream, or it is a SYN-ACK that ACKs the SYN of the other
    /// stream (up to the end of the SYN's TCP Fast Open bytes). A
    /// retransmitted SYN can carry more TCP Fast Open bytes, which a late
    /// SYN-ACK can ACK.
    pub fn is_own_handshake(&mut self, source: SocketAddr, tcp: &TcpSlice<'_>) -> bool {
        let [own, other] = if source == self.initiator {
            [0, 1]
        } else {
            [1, 0]
        };
        if let Some(syn) = self.syns[own]
            .as_mut()
            .filter(|syn| syn.isn == tcp.sequence_number())
        {
            syn.len = syn.len.max(tcp.payload().len() as u32);
            return true;
        }
        tcp.ack()
            && self.syns[other].is_some_and(|syn| syn.is_acked_by(tcp.acknowledgment_number()))
    }
}

/// What a connection does with a segment, decided by the state of its
/// handshake and the SYN it keeps before anything else looks at the
/// segment (S5, S6, C2, C3; the decision table in the spec's S5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The receiver drops the segment: it has no ACK flag and is no SYN or
    /// RST (S6), or the receiver's SYN is unanswered and the segment doesn't
    /// ACK it (S5). It counts as out-of-window and changes nothing else,
    /// apart from ending the wait after enough agreeing dropped segments.
    Dropped,
    /// An RST, which F4 checks by its sequence number (the ACK of an ignored
    /// one is dropped with it).
    Reset,
    /// A SYN without ACK that is not its stream's own, or that may be blind
    /// (`maybe_blind`): kept until a SYN-ACK confirms the reconnect it
    /// starts or the simultaneous open it is part of (C2).
    KeepSyn { maybe_blind: bool },
    /// A SYN-ACK with a new ISN that confirms no reconnect: it changes
    /// nothing but what its ACK answers (C3), and is kept for the SYN it
    /// answers if no SYN is kept (C2).
    ForeignSynAck,
    /// A SYN-ACK that confirms a reconnect, or a SYN that a kept SYN-ACK
    /// answers (C2): the pool replaces the connection with one that starts
    /// at the kept SYN or SYN-ACK.
    ConfirmsReconnect,
    /// A segment of the sender's stream, the stream's own SYN or SYN-ACK
    /// included: applied, after the kept SYN of a simultaneous open that
    /// the SYN-ACK confirms.
    Applied,
}

/// SYN that is not its stream's own, kept until a SYN-ACK of the other
/// endpoint confirms the reconnect it starts or the simultaneous open it is
/// part of; or such a SYN-ACK captured before its SYN, kept until that SYN
/// arrives (C2).
#[derive(Clone, Debug)]
pub(crate) struct ReconnectSyn<Timestamp> {
    /// Endpoint that sent the SYN.
    source: SocketAddr,
    /// Timestamp of the SYN.
    timestamp: Timestamp,
    /// ISN of the SYN.
    isn: u32,
    /// ACK number, if the kept segment is a SYN-ACK.
    ack: Option<u32>,
    /// Number of bytes the SYN carries (TCP Fast Open), with the ones its
    /// retransmissions added.
    payload_len: usize,
    /// Number of retransmissions of the SYN that carried bytes differing
    /// from the ones received first.
    conflicting: u64,
    /// Whether the SYN was kept as a possibly blind one, from a side without
    /// a start while the other side's SYN was unanswered (S5), rather than
    /// as a reconnect's: a SYN-ACK that confirms it applies it to its stream.
    maybe_blind: bool,
    /// TCP header and payload of the SYN, replayed if it starts a reconnect.
    segment: Vec<u8>,
}

impl<Timestamp> ReconnectSyn<Timestamp> {
    /// Timestamp of the SYN.
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns true if the SYN-ACK `tcp`, sent by `source`, ACKs the SYN: it
    /// comes from the other endpoint and ACKs from the SYN's ISN + 1 up to
    /// the end of its bytes (a server ACKs TCP Fast Open bytes it accepts).
    pub fn is_acked_by(&self, source: SocketAddr, tcp: &TcpSlice<'_>) -> bool {
        let acked = tcp
            .acknowledgment_number()
            .wrapping_sub(self.isn.wrapping_add(1));
        source != self.source && tcp.ack() && (acked as usize) <= self.payload_len
    }

    /// Returns true if the kept segment is a SYN-ACK of another endpoint
    /// that ACKs the SYN `tcp` sent by `source`: it ACKs from the ISN of the
    /// SYN plus one up to the end of its bytes (a server ACKs TCP Fast Open
    /// bytes it accepts).
    pub fn acks(&self, source: SocketAddr, tcp: &TcpSlice<'_>) -> bool {
        self.ack.is_some_and(|ack| {
            let acked = ack.wrapping_sub(tcp.sequence_number().wrapping_add(1));
            source != self.source
                && tcp.syn()
                && false == tcp.ack()
                && (acked as usize) <= tcp.payload().len()
        })
    }

    /// Returns true if the SYN `tcp`, sent by `source`, is a retransmission
    /// of the kept SYN: it comes from the same endpoint with the same ISN.
    pub fn is_retransmitted_by(&self, source: SocketAddr, tcp: &TcpSlice<'_>) -> bool {
        source == self.source
            && tcp.syn()
            && false == tcp.ack()
            && tcp.sequence_number() == self.isn
    }

    /// Takes the TCP Fast Open bytes that the `payload` of a retransmission
    /// of the SYN adds beyond the kept ones. The bytes received first stay,
    /// and differing bytes count as a conflicting retransmission.
    fn add_retransmission(&mut self, payload: &[u8]) {
        let kept = &self.segment[self.segment.len() - self.payload_len..];
        let overlap = kept.len().min(payload.len());
        if kept[..overlap] != payload[..overlap] {
            self.conflicting += 1;
        }
        if let Some(added) = payload.get(overlap..) {
            self.segment.extend_from_slice(added);
            self.payload_len += added.len();
        }
    }

    /// Puts the buffer that kept the SYN into `free` for re-use.
    pub fn recycle(self, free: &mut FreeBuffers) {
        free.bytes.put(self.segment);
    }

    /// The SYN (`None` can't happen, as its bytes come from a TCP slice).
    fn tcp(&self) -> Option<TcpSlice<'_>> {
        TcpSlice::from_slice(&self.segment).ok()
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
        // a retransmission updates it too, and so do an RST outside of the
        // receiver's window, the SYN of a reconnect and a SYN-ACK with
        // another ISN
        let retransmission = script.segments[3].clone();
        script.segments.push(retransmission);
        script.rst_at(Responder, 1 << 30);
        let mut syn = script.segments[0].clone();
        syn.header.sequence_number = 5000;
        script.segments.push(syn);
        let mut syn_ack = script.segments[1].clone();
        syn_ack.header.sequence_number = 6000;
        script.segments.push(syn_ack);
        for (i, segment) in script.segments.iter().enumerate() {
            let (connection, _) = segment.feed(&mut pool, 10 + i as u32).active.unwrap();
            assert_eq!(&(10 + i as u32), connection.last_seen());
        }
    }

    #[test]
    fn syn_unanswered() {
        // while the initiator's SYN is unanswered, it drops every segment
        // that doesn't ACK the SYN (S5): a blind RST without ACK or with one
        // before the SYN, blind data and a blind FIN change nothing but the
        // count, with any sequence number
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            for (rst, fin, data, ack) in [
                (true, false, &b""[..], None),
                (true, false, &b""[..], Some(1001 - 50)),
                (false, false, b"zz", None),
                (false, true, b"", None),
                (false, true, b"x", None),
            ] {
                let mut blind = script.injected(|s| {
                    s.fin_at(Responder, 1 << 30, data);
                });
                blind.header.ack = ack.is_some();
                blind.header.acknowledgment_number = ack.unwrap_or(0);
                blind.header.rst = rst;
                blind.header.fin = fin;
                blind.ack = None;
                script.segments.push(blind);
            }
            script
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            assert_eq!(
                0,
                connection.stream(Initiator).status().out_of_window_segments
            );
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert!(false == stream.is_finished());
            assert_eq!(5, stream.status().out_of_window_segments);
        }

        // a SYN with an RST and no ACK is no simultaneous open and dropped
        // too, with any sequence number
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind = script.injected(|s| {
                s.rst_at(Responder, 1 << 30);
            });
            blind.header.syn = true;
            blind.header.ack = false;
            blind.ack = None;
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // a pickup keeps a SYN of the responder with a new ISN, then the
        // responder's own SYN starts its stream, which the kept ACK of the
        // initiator's bytes answers already, so a blind SYN-ACK of the
        // initiator with a new ISN confirms the reconnect the kept SYN
        // started (C2's two-segment limit, the kept SYN being blind too)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"data");
            let own_syn = script.segments.remove(1);
            script.segments.drain(..2);
            let mut reconnect_syn = own_syn.clone();
            reconnect_syn.header.sequence_number = 10000;
            reconnect_syn.header.ack = false;
            reconnect_syn.ack = None;
            script.segments.push(reconnect_syn);
            let mut own_syn = own_syn;
            own_syn.header.ack = false;
            own_syn.ack = None;
            script.segments.push(own_syn);
            let mut forged = script.injected(|s| {
                s.send(Initiator, b"");
            });
            forged.header.syn = true;
            forged.header.sequence_number = 30000;
            forged.header.acknowledgment_number = 50000;
            script.segments.push(forged);
            let processed = script.feed_all(&mut pool);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
        }

        // an RST that ACKs the SYN resets the connection, e.g. from a closed
        // port, with any sequence number
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().rst_at(Responder, 1 << 30);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                connection.end()
            );
        }

        // a SYN-ACK that doesn't ACK the SYN is dropped too, with its ACK
        // number and window, and so is a FIN after its ISN: the real SYN-ACK
        // anchors the responder stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut forged = script.injected(|s| {
                s.syn_ack();
            });
            forged.header.sequence_number = 7000;
            forged.header.acknowledgment_number = 1001 + (1 << 30);
            forged.header.window_size = 0;
            script.segments.push(forged);
            let mut fin = script.injected(|s| {
                s.fin_at(Responder, 0, b"");
            });
            fin.header.sequence_number = 7001;
            fin.header.ack = false;
            fin.ack = None;
            script.segments.push(fin);
            script
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"request"), stream.read_received());
            assert_eq!(0, stream.status().out_of_window_segments);
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert!(false == stream.is_finished());
            assert_eq!(2, stream.status().out_of_window_segments);
        }

        // a SYN without ACK of the responder may be a simultaneous open and
        // is kept, and a FIN after it still has to ACK the initiator's SYN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut syn = script.injected(|s| {
                s.syn_ack();
            });
            syn.header.ack = false;
            syn.ack = None;
            script.segments.push(syn);
            let mut fin = script.injected(|s| {
                s.fin_at(Responder, 0, b"");
            });
            fin.header.ack = false;
            fin.ack = None;
            script.segments.push(fin);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(None, stream.fin_offset());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // the responder's SYN-ACK awaits its ACK too: the initiator's
        // segments have to ACK it until one does
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            let mut blind = script.injected(|s| {
                s.send_at(Initiator, 1 << 30, b"zz");
            });
            blind.header.acknowledgment_number = 7000;
            script.segments.push(blind);
            script.ack(Initiator).send(Initiator, b"request");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"request"), stream.read_received());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // ... and a lost SYN-ACK is answered by the ACK of the bytes after
        // the SYN, within k windows of it (the response ACKs the request),
        // so the response starts the responder stream at the kept ACK
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"request")
                .send(Responder, b"response");
            script.segments.remove(1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert_eq!(0, stream.status().out_of_window_segments);
        }

        // the SYN's own sender answers it too with anything but a
        // retransmission of the SYN: with the SYN-ACK and the responder's
        // early ACKs not captured, the initiator's ACK answers its SYN, so
        // the response that ACKs 300 bytes (more than k fallback windows
        // after the SYN) isn't dropped
        {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, &[1; 100])
                .send(Initiator, &[2; 100])
                .send(Initiator, &[3; 100])
                .send(Responder, b"response");
            script.segments.remove(1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert_eq!(0, stream.status().out_of_window_segments);
        }

        // ... but a segment of the SYN's sender that its own stream ignores
        // doesn't answer the SYN, e.g. an RST outside of its window spoofed
        // with its address: the blind RST without ACK after it is still
        // dropped
        {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let spoofed = script.injected(|s| {
                s.rst_at(Initiator, 1000);
            });
            script.segments.push(spoofed);
            let mut blind = script.injected(|s| {
                s.rst_at(Responder, 1 << 30);
            });
            blind.header.ack = false;
            blind.ack = None;
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            assert_eq!(
                1,
                connection.stream(Initiator).status().out_of_window_segments
            );
            let stream = connection.stream_mut(Responder);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // ... and a side that gives up its SYN-ACK with a new SYN of its own
        // (a reconnect from the former responder) lets the other side's
        // SYN-ACK through, which confirms the reconnect
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.syn().syn_ack();
            old.feed_all(&mut pool);
            let mut new =
                ConnectionScript::new(addr("10.0.0.2:80"), addr("10.0.0.1:50000"), 7000, 9000);
            new.syn()
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request");
            let processed = new.feed(&mut pool, ..2);
            assert_eq!(
                Some(TcpConnectionEnd::Reconnect),
                processed.ended.unwrap().end()
            );
            let (connection, _) = new.feed(&mut pool, 2..).active.unwrap();
            assert_eq!(TcpConnectionId(1), connection.id());
            assert_eq!(addr("10.0.0.2:80"), connection.endpoint(Initiator));
            assert_eq!(
                TcpRead::Data(b"request"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // ... but a SYN-ACK that confirms no reconnect, as a SYN of its own
        // sender replaced the kept one, ACKs neither the kept SYN nor the
        // receiver's unanswered SYN-ACK: it is dropped and counted (a SYN
        // with a new ISN ends no wait, as a blind one could)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.syn().syn_ack();
            old.feed_all(&mut pool);
            let mut from_responder =
                ConnectionScript::new(addr("10.0.0.2:80"), addr("10.0.0.1:50000"), 1 << 30, 9000);
            from_responder.syn().syn_ack();
            let mut from_initiator = ConnectionScript::with_isns(7500, 9500);
            from_initiator.syn();
            from_responder.segments[0].feed(&mut pool, ());
            from_initiator.segments[0].feed(&mut pool, ());
            let (connection, _) = from_responder.segments[1]
                .feed(&mut pool, ())
                .active
                .unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                1,
                connection.stream(Initiator).status().out_of_window_segments
            );
        }

        // late segments of a connection that a reconnect replaced don't ACK
        // the new SYN: a late RST doesn't reset the new connection, and late
        // bytes don't start its responder stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut old = ConnectionScript::with_isns(1000, 2000);
            old.handshake()
                .send(Initiator, b"req")
                .send(Responder, b"old-reply")
                .rst(Responder);
            assert!(old.feed_all(&mut pool).ended.is_some());
            let mut new = ConnectionScript::with_isns(5000, 6000);
            new.syn();
            new.feed_all(&mut pool);
            for late in [
                old.injected(|s| {
                    s.rst_at(Responder, 9);
                }),
                old.injected(|s| {
                    s.send_at(Responder, 0, b"old-reply");
                }),
            ] {
                let processed = late.feed(&mut pool, ());
                assert_eq!(None, processed.ignored);
                let (connection, _) = processed.active.unwrap();
                assert_eq!(TcpConnectionId(1), connection.id());
                assert_eq!(None, connection.end());
            }
            new.syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let (connection, _) = new.feed(&mut pool, 1..).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert_eq!(2, stream.status().out_of_window_segments);
        }

        // a late SYN-ACK whose ACK number a mid-stream pickup can't take as
        // its start still ACKs the pickup's bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let mut syn_ack = script.segments.remove(1);
            syn_ack.header.acknowledgment_number = 1001 + 3;
            script.segments.drain(..2);
            script.segments.push(syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            assert_eq!(3, stream.acked_offset());
        }
    }

    #[test]
    fn syn_answered() {
        // the wait for the ACK of a SYN ends with an ACK of the bytes the
        // stream jumped to (R2): with the handshake ACK and 300 bytes of the
        // response lost, the rest of the response lies after the window and
        // the initiator's ACK confirms the jump, so it answers the SYN-ACK
        // and resyncs the stream instead of being dropped
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send_uncaptured(Responder, 300)
                .send(Responder, b"response")
                .ack(Initiator)
                .send(Responder, b"more");
            script.segments.remove(2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                0,
                connection.stream(Initiator).status().out_of_window_segments
            );
            let stream = connection.stream_mut(Responder);
            assert_eq!(1, stream.status().resyncs);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"more"), stream.read_received());
        }

        // with resync_after_segments, that many consecutive dropped segments
        // of the other side, each within one window of the one before, end
        // the wait too (the capture misses the responder's direction after
        // the SYN-ACK, so the initiator's ACKs lie beyond k windows)
        for (after, expected) in [(Some(3), 3), (None, 4)] {
            let config = TcpReassemblyConfig {
                resync_after_segments: after,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send_uncaptured(Responder, 500)
                .ack(Initiator)
                .ack(Initiator)
                .ack(Initiator)
                .send(Initiator, b"request");
            script.segments.remove(2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(expected, stream.status().out_of_window_segments);
            let read = stream.read_received();
            assert_eq!(after.is_some(), TcpRead::Data(b"request") == read);
        }

        // a side in SYN-RECEIVED checks an RST by its sequence number, not
        // by its ACK: the RST that answers a SYN-ACK carries none
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            let mut rst = script.injected(|s| {
                s.rst(Initiator);
            });
            rst.header.ack = false;
            rst.ack = None;
            script.segments.push(rst);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Initiator }),
                connection.end()
            );
        }

        // a blind ACK from the initiator's address before the SYN-ACK is
        // kept for the responder stream, but the SYN-ACK that ACKs the
        // initiator's SYN outweighs it and starts the responder stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind = script.injected(|s| {
                s.ack(Initiator);
            });
            blind.header.ack = true;
            blind.header.acknowledgment_number = 1001 + (1 << 30);
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // an RST that F4 ignores is dropped with its ACK (also for the SYN
        // it would answer): with the handshake ACK not captured, a blind
        // RST/ACK from the initiator's address outside of its window doesn't
        // answer the SYN-ACK, so a blind FIN without ACK after it is still
        // dropped (without the RST it is dropped too)
        for with_rst in [true, false] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            if with_rst {
                let rst = script.injected(|s| {
                    s.rst_at(Initiator, 1 << 30);
                });
                script.segments.push(rst);
            }
            let mut fin = script.injected(|s| {
                s.fin(Initiator);
            });
            fin.header.ack = false;
            fin.ack = None;
            script.segments.push(fin);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(None, stream.fin_offset());
            assert_eq!(TcpRead::Pending, stream.read_received());
            assert_eq!(
                1 + u64::from(with_rst),
                stream.status().out_of_window_segments
            );
        }

        // a SYN-ACK has to ACK the SYN itself: one that ACKs 50 bytes after
        // it is dropped, although other segments may ACK that far
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut forged = script.injected(|s| {
                s.syn_ack();
            });
            forged.header.sequence_number = 7000;
            forged.header.acknowledgment_number = 1001 + 50;
            script.segments.push(forged);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // the wait that dropped segments ended leaves the other side with
        // neither a start nor a kept ACK, and an RST or FIN of that side
        // still has to ACK the SYN: with resync_after_segments = Some(1), a
        // blind data segment ends the wait, and a blind RST or FIN after it
        // is dropped, so the real handshake and response arrive
        for (rst, fin) in [(true, false), (false, true)] {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(1),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind_data = script.injected(|s| {
                s.send_at(Responder, 0, b"zz");
            });
            blind_data.header.sequence_number = 0x3000_0000;
            blind_data.header.acknowledgment_number = 0x6000_0000;
            script.segments.push(blind_data);
            let mut blind = script.injected(|s| {
                s.fin_at(Responder, 0, b"");
            });
            blind.header.rst = rst;
            blind.header.fin = fin;
            blind.header.sequence_number = 0x4000_0000;
            blind.header.acknowledgment_number = 0x6000_0000;
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(None, stream.fin_offset());
            assert_eq!(2, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // ... also when the kept SYN's own sender confirms it first with a
        // SYN-ACK that repeats its ISN: the kept SYN is applied before it,
        // so its bytes win and differing bytes of the SYN-ACK count (D1,
        // D2), and the other side's SYN-ACK finds the stream started
        for (payload, conflicts) in [(&b""[..], 0), (b"xyz", 1)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            let mut responder_syn_ack = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn_ack.payload = payload.to_vec();
            script.segments.push(responder_syn_ack);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            let mut next = script.injected(|s| {
                s.send_at(Responder, 3, b"next");
            });
            next.header.acknowledgment_number = 1001;
            script.segments.push(next);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(conflicts, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abcnext"), stream.read_received());
        }

        // ... also when the stream got a pickup start from the responder's
        // bytes before either SYN-ACK: the kept SYN was kept as a possibly
        // blind one, not as a reconnect's, so it is applied as a late SYN
        // (A5) whichever SYN-ACK comes first, its bytes are read, and no SYN
        // stays kept that a later blind SYN-ACK could turn into a reconnect
        for responder_first in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            let mut next = script.injected(|s| {
                s.send_at(Responder, 3, b"next");
            });
            next.header.acknowledgment_number = 1001;
            script.segments.push(next);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2004;
            let responder_syn_ack = script.injected(|s| {
                s.syn_ack();
            });
            if responder_first {
                script.segments.push(responder_syn_ack);
                script.segments.push(initiator_syn_ack);
            } else {
                script.segments.push(initiator_syn_ack);
                script.segments.push(responder_syn_ack);
            }
            let mut blind = script.injected(|s| {
                s.send(Initiator, b"");
            });
            blind.header.syn = true;
            blind.header.sequence_number = 9000;
            blind.header.acknowledgment_number = 2001;
            script.segments.push(blind);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"abcnext"), stream.read_received());
            assert_eq!(0, stream.status().out_of_window_segments);
        }

        // a SYN with a FIN or RST that ACKs the SYN exactly knows the ISN
        // and is applied: a SYN-ACK with a FIN anchors the responder stream
        // and ends it there, a SYN-ACK with an RST resets the connection
        for rst in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut syn_ack = script.injected(|s| {
                s.syn_ack();
            });
            syn_ack.header.sequence_number = 7000;
            syn_ack.header.rst = rst;
            syn_ack.header.fin = false == rst;
            script.segments.push(syn_ack);
            let processed = script.feed_all(&mut pool);
            if rst {
                assert_eq!(
                    Some(TcpConnectionEnd::Reset { by: Responder }),
                    processed.ended.unwrap().end()
                );
            } else {
                let (connection, _) = processed.active.unwrap();
                let stream = connection.stream(Responder);
                assert_eq!(Some(7000), stream.isn());
                assert_eq!(Some(0), stream.fin_offset());
            }
        }

        // ... and a retransmission of the kept SYN with differing bytes
        // counts as a conflicting retransmission once the SYN is applied
        // (D2), the bytes received first winning (D1)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            for payload in [&b"abc"[..], b"xbcd"] {
                let mut responder_syn = script.injected(|s| {
                    s.syn_ack();
                });
                responder_syn.header.ack = false;
                responder_syn.ack = None;
                responder_syn.payload = payload.to_vec();
                script.segments.push(responder_syn);
            }
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(1, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abcd"), stream.read_received());
        }

        // ... and the confirmation outweighs an ACK a blind segment with the
        // initiator's address left kept for the responder stream, so the
        // kept SYN still starts it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            let mut blind = script.injected(|s| {
                s.ack(Initiator);
            });
            blind.header.acknowledgment_number = 0x4000_0000;
            script.segments.push(blind);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2004;
            script.segments.push(initiator_syn_ack);
            let mut next = script.injected(|s| {
                s.send_at(Responder, 3, b"next");
            });
            next.header.acknowledgment_number = 1001;
            script.segments.push(next);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"abcnext"), stream.read_received());
        }

        // an RST or FIN of a side with neither a start nor a kept ACK that
        // ACKs the SYN is applied after the wait like before it: after the
        // responder's pure ACK answered the SYN (its SYN-ACK not captured),
        // its FIN that ACKs the SYN starts and ends its stream (A4), and its
        // RST that ACKs the SYN resets the connection (F4)
        for rst in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut pure_ack = script.injected(|s| {
                s.ack(Responder);
            });
            pure_ack.header.acknowledgment_number = 1001;
            script.segments.push(pure_ack);
            let mut end = script.injected(|s| {
                s.fin_at(Responder, 0, b"");
            });
            end.header.rst = rst;
            end.header.fin = false == rst;
            end.header.acknowledgment_number = 1001;
            script.segments.push(end);
            let processed = script.feed_all(&mut pool);
            if rst {
                assert_eq!(
                    Some(TcpConnectionEnd::Reset { by: Responder }),
                    processed.ended.unwrap().end()
                );
            } else {
                let (connection, _) = processed.active.unwrap();
                let stream = connection.stream(Responder);
                assert_eq!(Some(0), stream.fin_offset());
                assert_eq!(0, stream.status().out_of_window_segments);
            }
        }
    }

    #[test]
    fn syn_answered_before() {
        // an ACK of the SYN that arrived before the SYN in a reordered
        // capture answers it already: the responder's bytes ACK the
        // initiator's SYN, the SYN arrives after them, and the responder's
        // next segment with an ACK far beyond k windows is stored
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Responder, b"response");
            let syn = script.segments.remove(0);
            script.segments.drain(..2);
            script.segments.push(syn);
            let mut far = script.injected(|s| {
                s.send(Responder, b"more");
            });
            far.header.acknowledgment_number = 1001 + (1 << 30);
            script.segments.push(far);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(1000), connection.stream(Initiator).isn());
            let stream = connection.stream_mut(Responder);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"responsemore"), stream.read_received());
        }

        // a SYN-ACK that answers the SYN drops an ACK kept for its stream
        // only if that ACK doesn't allow the SYN-ACK: in a capture merged
        // from two taps, the initiator's ACK and request arrive before the
        // SYN-ACK, and their ACK of the responder's bytes is kept
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"req")
                .send(Responder, b"resp");
            let syn_ack = script.segments.remove(1);
            script.segments[2].header.acknowledgment_number = 2005;
            script.segments.insert(3, syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(4, stream.acked_offset());
            assert_eq!(TcpRead::Data(b"resp"), stream.read_acked());
        }
    }

    #[test]
    fn syn_not_answered() {
        // (see also syn_answered_before and syn_kept_and_answered)
        // an ACK of the bytes the stream jumped to answers the SYN unless it
        // comes with an RST or FIN: a blind byte spoofed with the initiator's
        // address makes a resync candidate, and a blind RST/ACK or FIN/ACK
        // of it from the responder's address is still dropped
        for (rst, fin) in [(true, false), (false, true)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let blind_byte = script.injected(|s| {
                s.send_at(Initiator, 1 << 30, b"x");
            });
            script.segments.push(blind_byte);
            let mut blind = script.injected(|s| {
                s.fin_at(Responder, 1 << 30, b"");
            });
            blind.header.rst = rst;
            blind.header.fin = fin;
            blind.header.ack = true;
            blind.header.acknowledgment_number = 1001 + (1 << 30) + 1;
            script.segments.push(blind);
            script
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(None, stream.fin_offset());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"request"), stream.read_received());
        }

        // a SYN with a new ISN spoofed with the initiator's address doesn't
        // end the wait for the ACK of the initiator's SYN, so a blind RST
        // without ACK from the responder's address after it is still
        // dropped, and the real SYN-ACK anchors
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut spoofed = script.injected(|s| {
                s.syn();
            });
            spoofed.header.sequence_number = 0x7000_0000;
            script.segments.push(spoofed);
            let mut blind = script.injected(|s| {
                s.rst_at(Responder, 1 << 30);
            });
            blind.header.ack = false;
            blind.ack = None;
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // ... and neither does a SYN with an RST that ACKs the spoofed SYN
        // (only the SYN-ACK that confirms the reconnect passes), with or
        // without a FIN
        for fin in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut spoofed = script.injected(|s| {
                s.syn();
            });
            spoofed.header.sequence_number = 0x7000_0000;
            script.segments.push(spoofed);
            let mut blind = script.injected(|s| {
                s.rst_at(Responder, 0);
            });
            blind.header.syn = true;
            blind.header.fin = fin;
            blind.header.sequence_number = 0x4000_0000;
            blind.header.ack = true;
            blind.header.acknowledgment_number = 0x7000_0001;
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // an RST/ACK that ACKs the SYN outweighs a kept ACK like a SYN-ACK
        // does: after a blind ACK from the initiator's address, the RST/ACK
        // of a closed port still resets the connection
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind = script.injected(|s| {
                s.ack(Initiator);
            });
            blind.header.ack = true;
            blind.header.acknowledgment_number = 1001 + (1 << 30);
            script.segments.push(blind);
            let mut rst = script.injected(|s| {
                s.rst_at(Responder, 0);
            });
            rst.header.sequence_number = 0;
            script.segments.push(rst);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                connection.end()
            );
        }

        // dropped segments agree within the receive window of their own
        // stream (the one the responder advertised for the initiator's
        // segments), not within the window of the other direction
        for (syn_window, syn_ack_window, agree) in [(100, 60000, true), (60000, 100, false)] {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(3),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            script.segments[0].header.window_size = syn_window;
            script.segments[1].header.window_size = syn_ack_window;
            for i in 1..=3 {
                let mut ack = script.injected(|s| {
                    s.send_at(Initiator, 5000 * i, b"");
                });
                ack.header.acknowledgment_number = 2001 + (1 << 20);
                script.segments.push(ack);
            }
            let mut request = script.injected(|s| {
                s.send(Initiator, b"request");
            });
            request.header.acknowledgment_number = 2001 + (1 << 20);
            script.segments.push(request);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(
                3 + u64::from(false == agree),
                stream.status().out_of_window_segments
            );
            assert_eq!(agree, TcpRead::Data(b"request") == stream.read_received());
        }
    }

    #[test]
    fn syn_kept_and_answered() {
        // a SYN without ACK of the responder while the initiator's SYN is
        // unanswered may be blind, so it is kept instead of anchoring the
        // responder stream (a simultaneous open's SYN-ACK repeats its ISN):
        // the real SYN-ACK anchors, and both streams are read in full
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind = script.injected(|s| {
                s.syn_ack();
            });
            blind.header.ack = false;
            blind.ack = None;
            blind.header.sequence_number = 0x4000_0000;
            script.segments.push(blind);
            script
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request")
                .send(Responder, b"response")
                .send(Initiator, b"more")
                .send(Responder, b"more");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"responsemore"), stream.read_received());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"requestmore"), stream.read_received());
        }

        // ... and a simultaneous open still anchors both streams: the
        // responder's SYN is kept, the initiator's SYN-ACK ACKs it and gives
        // the responder stream its start, and the responder's SYN-ACK is
        // its own
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            script.segments.push(responder_syn);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.ack = true;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            script
                .syn_ack()
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(Some(2000), connection.stream(Responder).isn());
            assert_eq!(Some(1000), connection.stream(Initiator).isn());
            assert_eq!(
                TcpRead::Data(b"response"),
                connection.stream_mut(Responder).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"request"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // ... also when the responder's SYN-ACK is not captured: the
        // initiator's SYN-ACK confirms the kept SYN as the responder's own,
        // so its window counts (an RST 10000 bytes after the response lies
        // outside of the 100-byte window)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            script.segments.push(responder_syn);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.ack = true;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            script
                .syn_ack()
                .send(Responder, b"response")
                .send(Initiator, b"request")
                .rst_at(Responder, 10000);
            script.segments.remove(3);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert_eq!(
                TcpRead::Data(b"request"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // ... and the kept SYN is applied before the SYN-ACK that confirms
        // it, so the stream starts at the SYN with its TCP Fast Open bytes,
        // whether the SYN-ACK ACKs none, some or all of them (A2 would put
        // the start at the ACK number), and the SYN counted as a packet
        // once: with an ACK reorder tolerance of 2, the hole an ACK covers
        // is still filled by the second packet after it, the SYN-ACK being
        // the first
        for acked in [0, 2, 3] {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            // the initiator's byte after a hole, and the responder's ACK of
            // it, before the initiator's SYN-ACK
            let mut late = script.injected(|s| {
                s.send_at(Initiator, 5, b"z");
            });
            late.header.acknowledgment_number = 2001;
            script.segments.push(late);
            let mut covering_ack = script.injected(|s| {
                s.ack(Responder);
            });
            covering_ack.header.sequence_number = 2004;
            covering_ack.header.acknowledgment_number = 1007;
            script.segments.push(covering_ack);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001 + acked;
            script.segments.push(initiator_syn_ack);
            let mut filling = script.injected(|s| {
                s.send(Initiator, b"12345");
            });
            filling.header.acknowledgment_number = 2001;
            script.segments.push(filling);
            let mut next = script.injected(|s| {
                s.send_at(Responder, 3, b"next");
            });
            next.header.acknowledgment_number = 1007;
            script.segments.push(next);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"abcnext"), stream.read_received());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().gaps);
            assert_eq!(TcpRead::Data(b"12345z"), stream.read_received());
        }

        // ... the SYN-ACK answers the SYN it applied, so the responder waits
        // for nothing and the initiator's bytes with an ACK beyond k windows
        // of the responder's SYN are stored (window 100)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            script.segments.push(responder_syn);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            let mut data = script.injected(|s| {
                s.send(Initiator, b"request");
            });
            data.header.acknowledgment_number = 2001 + 1000;
            script.segments.push(data);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"request"), stream.read_received());
        }

        // ... and the applied SYN counts as no packet: the connection's
        // last packet stays the SYN-ACK and its first the SYN
        {
            let mut pool = TcpReassemblyPool::<u32, ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            script.segments.push(responder_syn);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            for (i, segment) in script.segments.iter().enumerate() {
                let (connection, _) = segment.feed(&mut pool, 1 + i as u32).active.unwrap();
                assert_eq!(&(1 + i as u32), connection.last_seen());
                assert_eq!(&1, connection.first_seen());
            }
        }

        // ... and the confirmation keeps an ACK kept for the stream that
        // allows the SYN: the initiator's ACK of the SYN's bytes arrives
        // before the initiator's SYN-ACK, and they are read as ACKed
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            let mut ack = script.injected(|s| {
                s.ack(Initiator);
            });
            ack.header.acknowledgment_number = 2004;
            script.segments.push(ack);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_acked());
        }

        // a SYN kept as possibly blind whose stream starts from bytes before
        // any SYN-ACK is captured is applied as a late SYN of that stream
        // then, so its bytes are read and no SYN stays kept: a blind
        // SYN-ACK of the initiator with a new ISN confirms no reconnect
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"tfo".to_vec();
            script.segments.push(responder_syn);
            let mut hello = script.injected(|s| {
                s.send(Initiator, b"hello");
            });
            hello.header.acknowledgment_number = 2004;
            script.segments.push(hello);
            let mut world = script.injected(|s| {
                s.send_at(Responder, 3, b"world");
            });
            world.header.acknowledgment_number = 1006;
            script.segments.push(world);
            let mut blind = script.injected(|s| {
                s.send(Initiator, b"");
            });
            blind.header.syn = true;
            blind.header.sequence_number = 0x5555_0000;
            blind.header.acknowledgment_number = 0x1234_5678;
            script.segments.push(blind);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"tfoworld"), stream.read_received());
        }

        // ... as a late SYN, the kept SYN's bytes join the bytes that
        // started the stream, which were stored first and win where they
        // differ (D1): data at the SYN's first byte with a differing byte
        // conflicts and stays, data after it is prepended to
        for (offset, data, expected, conflicts) in
            [(0, &b"abd"[..], &b"abd"[..], 1), (2, b"cd", b"abcd", 0)]
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            let mut later = script.injected(|s| {
                s.send_at(Responder, offset, data);
            });
            later.header.acknowledgment_number = 1001;
            script.segments.push(later);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(conflicts, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(expected), stream.read_received());
        }

        // ... and an ACK kept for the stream counts as soon as the kept SYN
        // starts it, before the confirming segment's bytes are compared: a
        // SYN-ACK that retransmits the SYN's bytes differently after the
        // other side ACKed them conflicts with nothing (D2)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"abc".to_vec();
            script.segments.push(responder_syn);
            let mut ack = script.injected(|s| {
                s.ack(Initiator);
            });
            ack.header.acknowledgment_number = 2004;
            script.segments.push(ack);
            let mut responder_syn_ack = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn_ack.payload = b"abd".to_vec();
            script.segments.push(responder_syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(3, stream.acked_offset());
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // a kept SYN is never applied to a stream that started at another
        // SYN: a stray SYN without ACK from the responder's address with an
        // ISN near the real one is dropped once the real SYN-ACK anchors the
        // stream, its bytes land nowhere, and so is one whose stream gets
        // its start from the initiator's SYN-ACK (A2) while no SYN-ACK of
        // its own was captured yet
        for a2_first in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 4990);
            script.syn();
            let mut stray = script.injected(|s| {
                s.syn_ack();
            });
            stray.header.ack = false;
            stray.ack = None;
            stray.header.sequence_number = 5000;
            stray.payload = b"EVIL".to_vec();
            script.segments.push(stray);
            if a2_first {
                let mut initiator_syn_ack = script.injected(|s| {
                    s.send(Initiator, b"");
                });
                initiator_syn_ack.header.syn = true;
                initiator_syn_ack.header.sequence_number = 1000;
                initiator_syn_ack.header.acknowledgment_number = 4991;
                script.segments.push(initiator_syn_ack);
            }
            script
                .syn_ack()
                .ack(Initiator)
                .send(Responder, b"0123456789abcdefghij");
            let mut later = script.injected(|s| {
                s.send(Initiator, b"");
            });
            later.header.syn = true;
            later.header.sequence_number = 0x6000_0000;
            later.header.acknowledgment_number = 5001;
            script.segments.push(later);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(4990), stream.isn());
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(
                TcpRead::Data(b"0123456789abcdefghij"),
                stream.read_received()
            );
        }

        // ... and nothing before a start applies a kept SYN: a pure ACK or
        // the filler byte of a keep-alive from the responder's address near a
        // stray SYN starts no stream (A4) and leaves it kept, and the real
        // handshake drops it
        for keep_alive in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 4990);
            script.syn();
            let mut stray = script.injected(|s| {
                s.syn_ack();
            });
            stray.header.ack = false;
            stray.ack = None;
            stray.header.sequence_number = 5000;
            stray.payload = b"EVIL".to_vec();
            script.segments.push(stray);
            // the initiator's bytes arrive before the SYN-ACK, and keep an
            // ACK for the responder
            let mut early = script.injected(|s| {
                s.send(Initiator, b"q");
            });
            early.header.acknowledgment_number = if keep_alive { 5002 } else { 4991 };
            script.segments.push(early);
            let mut probe = script.injected(|s| {
                s.ack(Responder);
            });
            probe.header.sequence_number = 5001;
            probe.header.acknowledgment_number = 1002;
            if keep_alive {
                probe.payload = b"E".to_vec();
            }
            script.segments.push(probe);
            script
                .syn_ack()
                .ack(Initiator)
                .send(Responder, b"0123456789abcdefghij");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(
                TcpRead::Data(b"q"),
                connection.stream_mut(Initiator).read_received()
            );
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(4990), stream.isn());
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(
                TcpRead::Data(b"0123456789abcdefghij"),
                stream.read_received()
            );
        }

        // ... and a kept SYN that lies after the bytes that started its
        // stream is dropped, also if k windows cover more than half of the
        // sequence space: a stray SYN 0x6000_0000 after the real ISN with
        // the real SYN-ACK not captured
        {
            let config = TcpReassemblyConfig {
                fallback_window: 1 << 30,
                hole_give_up_window_factor: Some(3),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut stray = script.injected(|s| {
                s.syn_ack();
            });
            stray.header.ack = false;
            stray.ack = None;
            stray.header.sequence_number = 2000 + 0x6000_0000;
            stray.payload = b"EVIL".to_vec();
            script.segments.push(stray);
            let mut ack = script.injected(|s| {
                s.ack(Initiator);
            });
            ack.header.acknowledgment_number = 2001;
            script.segments.push(ack);
            let mut data = script.injected(|s| {
                s.send(Responder, b"hello");
            });
            data.header.acknowledgment_number = 1001;
            script.segments.push(data);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(None, stream.isn());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"hello"), stream.read_received());
        }

        // ... and while it is kept, it confirms a reconnect only by being
        // ACKed: with the initiator's SYN answered by the responder's pure
        // ACK and the responder stream still without a start, a blind SYN-ACK
        // of the initiator with a new ISN replaces nothing, and the real one
        // then applies the kept SYN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            responder_syn.payload = b"tfo".to_vec();
            script.segments.push(responder_syn);
            let mut pure_ack = script.injected(|s| {
                s.ack(Responder);
            });
            pure_ack.header.sequence_number = 2004;
            pure_ack.header.acknowledgment_number = 1001;
            script.segments.push(pure_ack);
            let mut blind = script.injected(|s| {
                s.send(Initiator, b"");
            });
            blind.header.syn = true;
            blind.header.sequence_number = 0x5555_0000;
            blind.header.acknowledgment_number = 0x1234_5678;
            script.segments.push(blind);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2004;
            script.segments.push(initiator_syn_ack);
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(TcpRead::Data(b"tfo"), stream.read_received());
        }

        // ... with the conflicts of its retransmissions counting only if
        // the stream takes the SYN: one that lies more than k windows before
        // the bytes the stream starts at (A5) is dropped and counted, and
        // the stream stays clean
        for (distance, taken) in [(3, true), (100_000, false)] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            for payload in [&b"abc"[..], b"abd"] {
                let mut responder_syn = script.injected(|s| {
                    s.syn_ack();
                });
                responder_syn.header.ack = false;
                responder_syn.ack = None;
                responder_syn.payload = payload.to_vec();
                script.segments.push(responder_syn);
            }
            let mut next = script.injected(|s| {
                s.send_at(Responder, distance, b"next");
            });
            next.header.acknowledgment_number = 1001;
            script.segments.push(next);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(taken, Some(2000) == stream.isn());
            assert_eq!(taken, 1 == stream.status().conflicting_retransmissions);
            assert_eq!(taken, 0 == stream.status().out_of_window_segments);
            assert_eq!(false == taken, stream.is_clean());
            let expected: &[u8] = if taken { b"abcnext" } else { b"next" };
            assert_eq!(TcpRead::Data(expected), stream.read_received());
        }

        // a resync candidate with a FIN gives no exit either: a blind data
        // segment with a FIN far away from the initiator's address and a
        // blind ACK of it from the responder's address would end the
        // initiator stream for good
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind_fin = script.injected(|s| {
                s.fin_at(Initiator, 1 << 30, b"x");
            });
            blind_fin.header.ack = false;
            blind_fin.ack = None;
            script.segments.push(blind_fin);
            let mut blind_ack = script.injected(|s| {
                s.ack(Responder);
            });
            blind_ack.header.ack = true;
            blind_ack.header.acknowledgment_number = 1001 + (1 << 30) + 2;
            script.segments.push(blind_ack);
            script.syn_ack().ack(Initiator).send(Initiator, b"request");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(None, stream.fin_offset());
            assert_eq!(0, stream.status().resyncs);
            assert_eq!(TcpRead::Data(b"request"), stream.read_received());
            assert_eq!(
                1,
                connection.stream(Responder).status().out_of_window_segments
            );
        }

        // a SYN-ACK with a FIN confirms no reconnect and doesn't pass S5
        // through the kept SYN: a blind SYN from the initiator's address and
        // a blind SYN/ACK/FIN of it from the responder's address change
        // nothing but the counts
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut spoofed = script.injected(|s| {
                s.syn();
            });
            spoofed.header.sequence_number = 0x7000_0000;
            script.segments.push(spoofed);
            let mut blind = script.injected(|s| {
                s.syn_ack();
            });
            blind.header.fin = true;
            blind.header.sequence_number = 0x4000_0000;
            blind.header.acknowledgment_number = 0x7000_0001;
            script.segments.push(blind);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(2000), stream.isn());
            assert_eq!(None, stream.fin_offset());
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // a blind ACK kept for the responder stream doesn't turn the real
        // SYN-ACK into a reconnect either: the SYN-ACK ACKs the initiator's
        // SYN, so it is the responder's own, kept SYN or not
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn_with_data(b"fastopen");
            let mut blind_ack = script.injected(|s| {
                s.ack(Initiator);
            });
            blind_ack.header.ack = true;
            blind_ack.header.acknowledgment_number = 1001 + (1 << 30);
            script.segments.push(blind_ack);
            let mut blind_syn = script.injected(|s| {
                s.syn();
            });
            blind_syn.header.sequence_number = 0x7000_0000;
            script.segments.push(blind_syn);
            script.syn_ack().ack(Initiator).send(Initiator, b"request");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(Some(2000), connection.stream(Responder).isn());
            assert_eq!(
                TcpRead::Data(b"fastopenrequest"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // only an RST with the ACK flag overrules a kept ACK: one without
        // the flag whose ACK field happens to hold the right number is
        // checked against the kept ACK and dropped
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut blind_ack = script.injected(|s| {
                s.ack(Initiator);
            });
            blind_ack.header.ack = true;
            blind_ack.header.acknowledgment_number = 0x5000_0000;
            script.segments.push(blind_ack);
            let mut rst = script.injected(|s| {
                s.rst_at(Responder, 0);
            });
            rst.header.sequence_number = 0x1000_0000;
            rst.header.ack = false;
            rst.header.acknowledgment_number = 1001;
            rst.ack = None;
            script.segments.push(rst);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            assert_eq!(
                1,
                connection.stream(Responder).status().out_of_window_segments
            );
        }

        // the ACK that answers a SYN is checked with the window of the
        // SYN's stream: the initiator's ACK 5000 bytes after the SYN-ACK
        // answers it with a SYN window of 60000, so the initiator's bytes
        // after it are stored although their ACK lies beyond that range
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            script.segments[0].header.window_size = 60000;
            script.segments[1].header.window_size = 100;
            let mut ack = script.injected(|s| {
                s.ack(Initiator);
            });
            ack.header.acknowledgment_number = 2001 + 5000;
            script.segments.push(ack);
            let mut data = script.injected(|s| {
                s.send(Initiator, b"request");
            });
            data.header.acknowledgment_number = 2001 + (1 << 20);
            script.segments.push(data);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"request"), stream.read_received());
        }

        // every receiver drops a segment without ACK that is no SYN or RST
        // (S6): blind data and a blind FIN without ACK change nothing but
        // the count, on a connection in its handshake and on an established
        // one, and such a segment starts no connection
        for handshake in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            if handshake {
                script.handshake().send(Initiator, b"request");
            } else {
                script.syn();
            }
            for (fin, data) in [(false, &b"zz"[..]), (true, b""), (true, b"x")] {
                let mut blind = script.injected(|s| {
                    s.fin_at(Responder, 0, data);
                });
                blind.header.fin = fin;
                blind.header.ack = false;
                blind.ack = None;
                script.segments.push(blind);
            }
            if false == handshake {
                script.syn_ack().ack(Initiator).send(Initiator, b"request");
            }
            script.send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(None, stream.fin_offset());
            assert_eq!(3, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Responder, b"abc");
            script.segments[3].header.ack = false;
            let processed = script.segments[3].feed(&mut pool, ());
            assert_eq!(Some(TcpIgnoreReason::NoConnection), processed.ignored);
        }

        // a side whose own SYN is unanswered confirms a reconnect only by
        // ACKing the kept SYN: with the responder's SYN kept, a blind SYN-ACK
        // from the initiator's address with any ISN and ACK number replaces
        // nothing, and the simultaneous open completes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut responder_syn = script.injected(|s| {
                s.syn_ack();
            });
            responder_syn.header.ack = false;
            responder_syn.ack = None;
            script.segments.push(responder_syn);
            let mut blind = script.injected(|s| {
                s.send(Initiator, b"");
            });
            blind.header.syn = true;
            blind.header.sequence_number = 0x5000_0000;
            blind.header.acknowledgment_number = 0x6000_0000;
            script.segments.push(blind);
            let mut initiator_syn_ack = script.injected(|s| {
                s.send(Initiator, b"");
            });
            initiator_syn_ack.header.syn = true;
            initiator_syn_ack.header.sequence_number = 1000;
            initiator_syn_ack.header.acknowledgment_number = 2001;
            script.segments.push(initiator_syn_ack);
            script
                .syn_ack()
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                TcpRead::Data(b"request"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"response"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // an RST that ACKs the SYN drops a kept ACK even if that ACK allows
        // the RST, as F4 measures the RST from the kept ACK: the closed
        // port's RST/ACK at sequence number 0 resets the connection after a
        // blind ACK from the initiator's address kept 5 for the responder
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 0xffff_ffff);
            script.syn();
            let mut blind = script.injected(|s| {
                s.ack(Initiator);
            });
            blind.header.sequence_number = 0x9000_0000;
            blind.header.acknowledgment_number = 5;
            script.segments.push(blind);
            let mut rst = script.injected(|s| {
                s.rst_at(Responder, 0);
            });
            rst.header.sequence_number = 0;
            rst.header.acknowledgment_number = 1001;
            script.segments.push(rst);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
                connection.end()
            );
        }

        // an RST answers a SYN only if it ACKs the SYN itself, like a
        // SYN-ACK: one that ACKs a byte after it is dropped (a receiver in
        // SYN-SENT accepts only an RST that ACKs its SYN, F4)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut rst = script.injected(|s| {
                s.rst_at(Responder, 0);
            });
            rst.header.sequence_number = 0xdead_beef;
            rst.header.acknowledgment_number = 1002;
            script.segments.push(rst);
            script.syn_ack().ack(Initiator).send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.end());
            let stream = connection.stream_mut(Responder);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
        }

        // a SYN-ACK with a FIN confirms no reconnect on an established
        // connection either
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            let mut kept = script.injected(|s| {
                s.syn();
            });
            kept.header.sequence_number = 0x7000_0000;
            kept.header.ack = false;
            kept.ack = None;
            script.segments.push(kept);
            let mut syn_ack_fin = script.injected(|s| {
                s.syn_ack();
            });
            syn_ack_fin.header.fin = true;
            syn_ack_fin.header.sequence_number = 0x4000_0000;
            syn_ack_fin.header.acknowledgment_number = 0x7000_0001;
            script.segments.push(syn_ack_fin);
            script.send(Responder, b"response");
            let processed = script.feed_all(&mut pool);
            assert!(processed.ended.is_none());
            let (connection, _) = processed.active.unwrap();
            assert_eq!(TcpConnectionId(0), connection.id());
            assert_eq!(
                TcpRead::Data(b"response"),
                connection.stream_mut(Responder).read_received()
            );
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

        // ... and at any sequence number without such an ACK, as the
        // responder's stream has none after the initiator's SYN (the RST
        // has to ACK the SYN then, S5)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().rst_at(Responder, 1 << 30);
            let connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(
                Some(TcpConnectionEnd::Reset { by: Responder }),
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

        // an ACK kept before the first byte of a pickup lies at most as far
        // before it as bytes can be put in front (k windows of 100 bytes):
        // a forged one further before doesn't widen the RST check
        for (ack, reset) in [(-200, true), (-201, false)] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 1000)
                .send(Initiator, b"abc")
                .ack_to(Responder, (1000 + ack) as u64)
                .rst_at(Initiator, (1000 + ack) as u64);
            script.segments.drain(..3);
            let processed = script.feed_all(&mut pool);
            assert_eq!(reset, processed.ended.is_some());
        }

        // the ACK kept before the first byte of a pickup doesn't count
        // anymore once a later ACK counted (the responder ACKs byte 0, then
        // byte 3, so RSTs from byte 3 on are accepted)
        for (position, reset) in [(-1, false), (0, false), (3, true)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 0)
                .ack_to(Responder, 3)
                .rst_at(Initiator, 0);
            script.segments.drain(..3);
            let rst = script.segments.last_mut().unwrap();
            rst.header.sequence_number = rst.header.sequence_number.wrapping_add_signed(position);
            let processed = script.feed_all(&mut pool);
            assert_eq!(reset, processed.ended.is_some());
        }

        // the window of a segment the receiver doesn't accept (e.g. a blind
        // pure ACK with a random sequence number) doesn't count for the RSTs
        // it accepts (the window is 100 bytes, the forged window 1000)
        for (position, reset) in [(1 << 20, false), (0, true)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            let mut ack = script.injected(|s| {
                s.ack(Responder);
            });
            ack.header.sequence_number = ack.header.sequence_number.wrapping_add(position);
            ack.header.window_size = 1000;
            script.segments.push(ack);
            script.rst_at(Initiator, 3 + 500);
            let processed = script.feed_all(&mut pool);
            assert_eq!(reset, processed.ended.is_some());
        }

        // a retransmitted SYN-ACK doesn't bring the window back from the
        // start of the connection (the responder's window shrank to 0, so
        // only an RST at the next byte is accepted)
        for (offset, reset) in [(53, false), (3, true)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            script.window_size = 0;
            script.ack(Responder);
            let syn_ack = script.segments[1].clone();
            script.segments.push(syn_ack);
            script.rst_at(Initiator, offset);
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

        // the SYN-ACK of a reconnect ends the connection as `Reconnect`: its
        // holes become gaps, and its streams end at their FIN, or with
        // `End(Reconnect)`
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .send(Responder, b"jkl")
                .fin(Responder);
            script.segments.remove(4);
            let mut reconnect = ConnectionScript::with_isns(5000, 6000);
            reconnect.syn().syn_ack();
            script.segments.extend(reconnect.segments);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Reconnect), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.holes().count());
            assert_eq!((1, 3), (stream.status().gaps, stream.status().gap_bytes));
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"ghi"), stream.read_received());
            stream.consume(3);
            assert_eq!(
                TcpRead::End(TcpStreamEnd::Reconnect),
                stream.read_received()
            );
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"jkl"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // a reconnect ends a connection whose FINs were both ACKed as
        // `Finished`, also before the hole the ACK of the FIN covered is
        // overdue, as no more packets of it come
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .fin(Responder)
                .ack(Initiator);
            script.segments.remove(3);
            let mut reconnect = ConnectionScript::with_isns(5000, 6000);
            reconnect.syn().syn_ack();
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(None, connection.end());
            }
            let mut connection = reconnect.feed_all(&mut pool).ended.unwrap();
            assert_eq!(Some(TcpConnectionEnd::Finished), connection.end());
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
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
