use crate::tcp_reassembly::*;
use core::ops::Range;
use std::vec::Vec;

/// Simple model of the bytes a [`TcpReassemblyPool`] delivers.
///
/// It works on the true stream offsets that a [`ConnectionScript`] records
/// in its segments, so it is independent of the sequence number handling
/// it checks. Offsets of the pool are relative to the first byte the pool
/// knows of a stream (its base). It expects segments without window scale
/// options, and endpoints whose ports make guessed roles right.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReferenceModel {
    /// Configuration of the pool the model is compared with.
    config: TcpReassemblyConfig,
    /// Whether a segment started the connection.
    created: bool,
    /// Whether the roles are guessed, as a segment without a SYN started
    /// the connection and no late SYN confirmed them.
    roles_guessed: bool,
    /// Streams indexed by role.
    streams: [ModelStream; 2],
    /// "window" field of the last segment of each role.
    windows: [Option<u16>; 2],
    /// Whether the stream of each role took its SYN.
    syns: [bool; 2],
    /// End of the connection.
    end: Option<TcpConnectionEnd>,
    /// Number of packets applied so far.
    packets: u64,
}

/// What a reader does to a stream besides reading and consuming bytes (see
/// [`ReferenceModel::apply_action`]).
#[derive(Copy, Clone, Debug)]
pub(crate) enum ReaderAction {
    /// [`TcpStream::give_up_hole`]
    GiveUpHole,
    /// [`TcpStream::consume_gap`]
    ConsumeGap,
    /// [`TcpStream::discard_until`] with an offset this far after the read
    /// offset
    DiscardAhead(u64),
    /// [`TcpStream::discard_all`]
    DiscardAll,
}

/// Model of one stream.
#[derive(Clone, Debug, Default)]
struct ModelStream {
    /// Offset of the pool's offset 0 (`None` while the stream has no
    /// start).
    base: Option<u64>,
    /// Whether the start is known from the stream's SYN or the ACK of the
    /// SYN-ACK.
    observed: bool,
    /// Whether the stream was picked up at a FIN without bytes.
    started_at_fin: bool,
    /// Whether the read offset moved forward.
    read_moved: bool,
    /// Last ACK of the other side that couldn't be applied yet: before the
    /// stream had a start, or at or before its first byte while bytes can
    /// be prepended.
    pending_ack: Option<u64>,
    /// Received bytes by offset, up to the furthest received byte (bytes
    /// that arrive after they were consumed or given up are ignored).
    bytes: Vec<Option<u8>>,
    /// Bytes from offset 0 on up to the first missing byte that can still
    /// arrive: received bytes, and placeholders for bytes that were given
    /// up (in gaps) or discarded (before the read offset).
    received: Vec<u8>,
    /// Holes that were given up and not stepped over yet, in order (they
    /// lie in `received`).
    gaps: Vec<Range<u64>>,
    /// Every hole that was given up, in the order they were given up.
    given_up: Vec<Range<u64>>,
    /// Number of gaps (holes that were given up).
    gap_count: u64,
    /// Number of bytes in the holes that were given up.
    gap_bytes: u64,
    /// Offset after the furthest byte known to be sent (received, ACKed or
    /// before the FIN).
    highest: u64,
    /// Offset of the FIN.
    fin_offset: Option<u64>,
    /// Number of segments with bytes that differ from the bytes received
    /// first (from the read and ACKed offsets on).
    conflicting_retransmissions: u64,
    /// Number of segments with bytes or a FIN after the window, or with
    /// bytes after the FIN.
    out_of_window_segments: u64,
    /// Highest ACK of the other side that was not ignored.
    ack: u64,
    /// Number of each packet that moved `ack` forward, and `ack` after it.
    ack_history: Vec<(u64, u64)>,
    /// `ack` as it was `ack_reorder_tolerance` packets ago.
    settled_ack: u64,
    /// Highest offset minus k times the largest window of the receiver,
    /// after any packet of the connection so far (0 without a hole give up
    /// window factor k).
    implied_ack: u64,
    /// Largest window the receiver advertised while its window was known.
    largest_window: Option<u64>,
    /// Offset of the next byte to read.
    read_offset: u64,
}

impl ModelStream {
    /// Applies a segment of the stream's sender, whose receiver has the
    /// receive window `window`:
    /// - a SYN gives the stream an observed start at it (see
    ///   [`ModelStream::observe_start`]), a SYN that a mid-stream pickup
    ///   can't take counts as out-of-window and is ignored;
    /// - without a start, the first bytes or a FIN without bytes start a
    ///   mid-stream pickup, but a byte ending at the last ACK of the other
    ///   side (a keep-alive) doesn't;
    /// - bytes up to k windows before the first byte of a mid-stream pickup
    ///   are put in front (see [`ModelStream::can_prepend`]), other bytes
    ///   before it count as out-of-window (once per segment);
    /// - a segment with bytes or a FIN starting more than k windows after
    ///   the highest or the ACKed offset is counted and not stored (k is the
    ///   hole give up window factor, 2 without one);
    /// - a keep-alive (one byte ending at the ACK, without SYN, FIN or RST)
    ///   inside an overdue hole is ignored;
    /// - bytes received for the first time are stored, bytes received before
    ///   keep their first content, and the segment counts as a conflicting
    ///   retransmission if ones that are neither read, ACKed nor in a gap
    ///   differ;
    /// - the first FIN that doesn't lie before received bytes ends the
    ///   stream (cutting the gaps and moving the read offset back to it),
    ///   and bytes after it are counted and not stored;
    /// - bytes before the highest offset that were not received are holes.
    fn add_segment<CustomChannelId>(
        &mut self,
        segment: &TestSegment<CustomChannelId>,
        window: u64,
        config: &TcpReassemblyConfig,
    ) {
        let start = segment.offset;
        let end = start + segment.payload.len() as u64;
        let header = &segment.header;
        // the receiver accepts k windows before and after the stream's bytes
        let factor = config.hole_give_up_window_factor.unwrap_or(2);
        let range = u64::from(factor) * window;
        if header.syn {
            if false == self.observe_start(start, range) {
                self.out_of_window_segments += 1;
                return;
            }
        } else if self.base.is_none() {
            let keep_alive = 1 == segment.payload.len()
                && false == (header.fin || header.rst)
                && Some(end) == self.pending_ack;
            if (segment.payload.is_empty() && false == header.fin) || keep_alive {
                return;
            }
            self.start_at(start);
            self.started_at_fin = segment.payload.is_empty();
        }
        let mut out_of_window = false;
        if let Some(base) = self.base {
            if start < base && false == segment.payload.is_empty() && false == self.observed {
                if self.can_prepend() && base - start <= range {
                    self.start_at(start);
                } else {
                    out_of_window = true;
                }
            }
        }

        let window_end = self.ack.max(self.highest) + range;
        if (false == segment.payload.is_empty() || segment.header.fin) && start > window_end {
            self.out_of_window_segments += 1;
            return;
        }
        if 1 == segment.payload.len()
            && false == (header.syn || header.fin || header.rst)
            && end == self.ack
            && self
                .holes()
                .iter()
                .any(|hole| hole.contains(&start) && self.is_overdue(hole))
        {
            return;
        }
        if segment.header.fin && self.fin_offset.is_none() && end >= self.bytes.len() as u64 {
            self.fin_offset = Some(end);
            // missing bytes after the FIN (from an ACK of it) don't exist,
            // even if they were given up
            self.highest = end;
            self.read_offset = self.read_offset.min(end);
            self.gaps.retain_mut(|gap| {
                gap.end = gap.end.min(end);
                gap.start < gap.end
            });
            self.received.truncate(end as usize);
        }
        let payload = match self.fin_offset {
            Some(fin) if end > fin && false == segment.payload.is_empty() => {
                out_of_window = true;
                &segment.payload[..fin.saturating_sub(start) as usize]
            }
            _ => &segment.payload[..],
        };
        if out_of_window {
            self.out_of_window_segments += 1;
        }

        if false == payload.is_empty() {
            let start = start as usize;
            let end = start + payload.len();
            let compared_start = self.read_offset.max(self.acked_offset());
            let conflicting = (start..end).zip(payload).any(|(offset, byte)| {
                offset as u64 >= compared_start
                    && false == self.in_gap(offset as u64)
                    && self
                        .bytes
                        .get(offset)
                        .is_some_and(|received| received.is_some_and(|b| b != *byte))
            });
            if conflicting {
                self.conflicting_retransmissions += 1;
            }
            // bytes that were consumed or given up are ignored
            let stored_end = (start..end)
                .rev()
                .find(|offset| false == self.ignores(*offset as u64))
                .map_or(0, |offset| offset + 1);
            if self.bytes.len() < stored_end {
                self.bytes.resize(stored_end, None);
            }
            for (offset, byte) in (start..end).zip(payload) {
                if false == self.ignores(offset as u64) {
                    self.bytes[offset].get_or_insert(*byte);
                }
            }
            self.highest = self.highest.max(end as u64);
        }
        self.extend_received();
    }

    /// Gives the stream an observed start at `start`. A mid-stream pickup
    /// takes it if it is at or before its first byte, at most `range` bytes
    /// before it, and bytes can be prepended. Returns true if the stream has
    /// an observed start afterwards.
    fn observe_start(&mut self, start: u64, range: u64) -> bool {
        match self.base {
            Some(_) if self.observed => return true,
            Some(base) if start > base || base - start > range || false == self.can_prepend() => {
                return false
            }
            _ => {}
        }
        self.start_at(start);
        self.observed = true;
        true
    }

    /// Returns true if bytes can be prepended to the stream: it is a
    /// mid-stream pickup whose read offset never moved and that wasn't
    /// picked up at a FIN.
    fn can_prepend(&self) -> bool {
        false == self.observed && false == self.read_moved && false == self.started_at_fin
    }

    /// Moves the first byte the pool knows to `start` (at or before the
    /// previous one).
    fn start_at(&mut self, start: u64) {
        self.base = Some(start);
        self.read_offset = start;
        self.highest = self.highest.max(start);
        self.received.truncate(start as usize);
        self.extend_received();
    }

    /// Appends the received bytes and the placeholders of given up bytes
    /// after the end of `received`.
    fn extend_received(&mut self) {
        loop {
            let offset = self.received.len() as u64;
            let byte = match self.bytes.get(offset as usize) {
                Some(Some(byte)) => *byte,
                _ if offset < self.read_offset || self.in_gap(offset) => 0,
                _ => break,
            };
            self.received.push(byte);
        }
    }

    /// Returns true if the byte at `offset` lies in a gap.
    fn in_gap(&self, offset: u64) -> bool {
        self.gaps.iter().any(|gap| gap.contains(&offset))
    }

    /// Returns true if a byte arriving at `offset` is ignored, as it was
    /// consumed or given up.
    fn ignores(&self, offset: u64) -> bool {
        offset < self.read_offset || self.in_gap(offset)
    }

    /// Applies an ACK of the other side in the packet with the number
    /// `packet`, whose receive window before it was `window`: ACKs more than
    /// one window after the highest offset (plus the FIN) are ignored,
    /// others mark the bytes up to them as sent (but none after the FIN).
    /// ACKs of the stream's first byte or before it don't count. The last
    /// ACK before the stream had a start, or at or before its first byte
    /// while bytes can be prepended, is kept and applied after every packet.
    fn add_ack(&mut self, ack: u64, window: u64, packet: u64) {
        let Some(base) = self.base else {
            self.pending_ack = Some(ack);
            return;
        };
        if ack <= base && self.can_prepend() {
            self.pending_ack = Some(ack);
            return;
        }
        let sent_end = self.highest + u64::from(self.fin_offset.is_some());
        if ack > sent_end + window {
            return;
        }
        if ack > self.ack.max(base) {
            self.ack = ack;
            self.ack_history.push((packet, ack));
        }
        let end = self.fin_offset.map_or(self.ack, |fin| fin.min(self.ack));
        self.highest = self.highest.max(end);
    }

    /// Ranges of missing bytes before the highest offset.
    fn holes(&self) -> Vec<Range<u64>> {
        let mut holes: Vec<Range<u64>> = Vec::new();
        // all bytes before the first missing one were received
        let first_missing = self.received.len();
        for (offset, byte) in self.bytes.iter().enumerate().skip(first_missing) {
            let offset = offset as u64;
            match holes.last_mut() {
                _ if byte.is_some() => {}
                Some(hole) if hole.end == offset => hole.end += 1,
                _ => holes.push(offset..offset + 1),
            }
        }
        // the bytes after the furthest received one are missing too
        let received_end = first_missing.max(self.bytes.len()) as u64;
        if received_end < self.highest {
            holes.push(received_end..self.highest);
        }
        holes
    }

    /// First range of missing bytes before the highest offset, if any.
    fn first_hole(&self) -> Option<Range<u64>> {
        // all bytes before the first missing one were received
        let start = self.received.len() as u64;
        let end = (start..self.highest.min(self.bytes.len() as u64))
            .find(|offset| self.bytes[*offset as usize].is_some())
            .unwrap_or(self.highest);
        (start < end).then_some(start..end)
    }

    /// Returns true if `hole` ends at or before the implied ACK or the ACK
    /// of `ack_reorder_tolerance` packets ago.
    fn is_overdue(&self, hole: &Range<u64>) -> bool {
        hole.end <= self.implied_ack.max(self.settled_ack)
    }

    /// Applies the pending ACK, updates the implied ACK and the ACK of
    /// `ack_reorder_tolerance` packets ago after the packet with the number
    /// `packet`, where `window` is the receive window of the stream's
    /// receiver (`None` while it is unknown), and gives up an overdue hole
    /// at the read offset.
    fn after_packet(&mut self, window: Option<u64>, packet: u64, config: &TcpReassemblyConfig) {
        if let Some(ack) = self.pending_ack.take() {
            let ack_window = window.unwrap_or(u64::from(config.fallback_window));
            self.add_ack(ack, ack_window, packet);
        }
        if let Some(window) = window {
            self.largest_window = Some(self.largest_window.unwrap_or(0).max(window));
        }
        if let Some(factor) = config.hole_give_up_window_factor {
            let window = self
                .largest_window
                .unwrap_or(u64::from(config.fallback_window));
            let implied_ack = self.highest.saturating_sub(u64::from(factor) * window);
            self.implied_ack = self.implied_ack.max(implied_ack);
        }
        let tolerance = u64::from(config.ack_reorder_tolerance);
        self.settled_ack = self
            .ack_history
            .iter()
            .rev()
            .find(|(ack_packet, _)| ack_packet + tolerance <= packet)
            .map_or(0, |(_, ack)| *ack);
        self.give_up_overdue_hole();
    }

    /// Gives up the hole at the read offset if it is overdue.
    fn give_up_overdue_hole(&mut self) {
        if self.first_hole().is_some_and(|hole| self.is_overdue(&hole)) {
            self.give_up_hole();
        }
    }

    /// Gives up the hole at the read offset, returns false if there is
    /// none.
    fn give_up_hole(&mut self) -> bool {
        match self.first_hole() {
            Some(hole) if hole.start == self.read_offset => {
                self.give_up(hole);
                true
            }
            _ => false,
        }
    }

    /// Turns `hole` into a gap.
    fn give_up(&mut self, hole: Range<u64>) {
        self.given_up.push(hole.clone());
        self.gap_count += 1;
        self.gap_bytes += hole.end - hole.start;
        self.gaps.push(hole);
        self.gaps.sort_by_key(|gap| gap.start);
        self.extend_received();
    }

    /// Moves the read offset over the gap at the read offset, if any.
    fn consume_gap(&mut self) {
        if let Some(gap) = self.gap_at_read_offset() {
            self.gaps.remove(0);
            self.read_offset = gap.end;
            self.read_moved = true;
            self.give_up_overdue_hole();
        }
    }

    /// Moves the read offset over `len` bytes.
    fn consume(&mut self, len: u64) {
        self.read_offset += len;
        self.read_moved |= 0 < len;
        self.give_up_overdue_hole();
    }

    /// Gap at the read offset, if any.
    fn gap_at_read_offset(&self) -> Option<Range<u64>> {
        self.gaps
            .first()
            .filter(|gap| gap.start == self.read_offset)
            .cloned()
    }

    /// Moves the read offset to `offset` (at most the highest offset),
    /// discarding the holes and gaps before it (without counting the holes
    /// as gaps).
    fn discard_until(&mut self, offset: u64) {
        let offset = offset.min(self.highest);
        if offset <= self.read_offset {
            return;
        }
        self.gaps.retain_mut(|gap| {
            gap.start = gap.start.max(offset);
            gap.start < gap.end
        });
        self.read_offset = offset;
        self.read_moved = true;
        self.extend_received();
        self.give_up_overdue_hole();
    }

    /// Offset up to which the other side ACKed the bytes, or must have
    /// ACKed them.
    fn acked_offset(&self) -> u64 {
        self.ack.max(self.implied_ack).min(self.highest)
    }

    /// Expected result of reading the contiguous received bytes from the
    /// read offset on, but not after `limit` or a gap.
    fn read(&self, limit: u64) -> TcpRead<'_> {
        if let Some(gap) = self.gap_at_read_offset() {
            return TcpRead::Gap {
                len: Some(gap.end - gap.start),
            };
        }
        let next_gap = self.gaps.first().map_or(u64::MAX, |gap| gap.start);
        let start = self.read_offset as usize;
        let end = (self.received.len() as u64).min(limit).min(next_gap) as usize;
        if start < end {
            TcpRead::Data(&self.received[start..end])
        } else if Some(self.read_offset) == self.fin_offset {
            TcpRead::End(TcpStreamEnd::Fin)
        } else {
            TcpRead::Pending
        }
    }

    /// Returns true if the FIN was seen and all bytes before it were
    /// received or given up.
    fn is_finished(&self) -> bool {
        Some(self.received.len() as u64) == self.fin_offset
    }

    /// Returns true if the FIN was ACKed and all holes are overdue.
    fn can_finish(&self) -> bool {
        self.fin_offset.is_some_and(|fin| fin < self.ack)
            && self.holes().iter().all(|hole| self.is_overdue(hole))
    }

    /// Gives up all holes.
    fn give_up_all_holes(&mut self) {
        for hole in self.holes() {
            self.give_up(hole);
        }
    }
}

impl ReferenceModel {
    /// Model of a connection in a pool with the configuration `config`.
    pub fn new(config: TcpReassemblyConfig) -> ReferenceModel {
        ReferenceModel {
            config,
            ..Default::default()
        }
    }

    /// Applies the ACK of a segment to the other stream and the segment to
    /// the stream of its sender:
    /// - only a SYN or bytes without an RST start the connection, which has
    ///   guessed roles without a SYN;
    /// - the ACK of a SYN-ACK gives the other stream an observed start;
    /// - a SYN or SYN-ACK of the role it belongs to confirms guessed roles
    ///   if it gives a stream an observed start.
    ///
    /// The connection is finished once both FINs are ACKed and all holes
    /// left are overdue, which gives up these holes; later segments change
    /// nothing.
    pub fn apply<CustomChannelId>(&mut self, segment: &TestSegment<CustomChannelId>) {
        let header = &segment.header;
        if self.end.is_some() {
            return;
        }
        if false == self.created {
            if header.rst || (false == header.syn && segment.payload.is_empty()) {
                return;
            }
            self.created = true;
            self.roles_guessed = false == header.syn;
        }
        self.packets += 1;
        let sender = role_index(segment.sender);
        let other = role_index(segment.sender.other());
        let observed = self.streams.each_ref().map(|stream| stream.observed);
        if let (true, Some(ack)) = (header.syn, segment.ack) {
            let factor = self.config.hole_give_up_window_factor.unwrap_or(2);
            let range = u64::from(factor) * self.window(segment.sender.other());
            self.streams[other].observe_start(ack, range);
        }
        if let Some(ack) = segment.ack {
            let window = self.window(segment.sender.other());
            self.streams[other].add_ack(ack, window, self.packets);
        }
        let window = self.window(segment.sender);
        self.streams[sender].add_segment(segment, window, &self.config);
        self.windows[sender] = Some(header.window_size);
        self.syns[sender] |= header.syn && self.streams[sender].observed;
        let syn_role = if header.ack {
            TcpRole::Responder
        } else {
            TcpRole::Initiator
        };
        if header.syn
            && syn_role == segment.sender
            && observed != self.streams.each_ref().map(|stream| stream.observed)
        {
            self.roles_guessed = false;
        }
        for role in [TcpRole::Initiator, TcpRole::Responder] {
            let window = self.known_window(role);
            self.streams[role_index(role)].after_packet(window, self.packets, &self.config);
        }
        if self.streams.iter().all(ModelStream::can_finish) {
            self.end = Some(TcpConnectionEnd::Finished);
            for stream in &mut self.streams {
                stream.give_up_all_holes();
            }
        }
    }

    /// Receive window of the stream of `role`: the last window its receiver
    /// advertised (never scaled, as there are no window scale options), or
    /// the fallback window until both SYNs were seen.
    fn window(&self, role: TcpRole) -> u64 {
        self.known_window(role)
            .unwrap_or(u64::from(self.config.fallback_window))
    }

    /// Last window the receiver of the stream of `role` advertised, `None`
    /// until both SYNs were seen.
    fn known_window(&self, role: TcpRole) -> Option<u64> {
        match self.windows[role_index(role.other())] {
            Some(window) if self.syns == [true, true] => Some(u64::from(window)),
            _ => None,
        }
    }

    /// End of the connection, `None` while it is open.
    pub fn end(&self) -> Option<TcpConnectionEnd> {
        self.end
    }

    /// Returns true once a segment started the connection.
    pub fn created(&self) -> bool {
        self.created
    }

    /// Returns true if the roles are guessed.
    pub fn roles_guessed(&self) -> bool {
        self.roles_guessed
    }

    /// Contiguous received bytes of the stream of `role` from offset 0 on.
    pub fn received(&self, role: TcpRole) -> &[u8] {
        &self.streams[role_index(role)].received
    }

    /// Returns true if the contiguous received bytes of the stream of
    /// `role` cover `data` and match it, apart from bytes that were given
    /// up and bytes before the stream's first byte known to the pool.
    pub fn received_matches(&self, role: TcpRole, data: &[u8]) -> bool {
        let stream = &self.streams[role_index(role)];
        let base = stream.base.unwrap_or(0);
        stream.received.len() >= data.len()
            && data.iter().enumerate().all(|(offset, byte)| {
                stream.received[offset] == *byte
                    || (offset as u64) < base
                    || stream
                        .given_up
                        .iter()
                        .any(|gap| gap.contains(&(offset as u64)))
            })
    }

    /// FIN offset of the stream of `role`.
    pub fn fin_offset(&self, role: TcpRole) -> Option<u64> {
        self.streams[role_index(role)].fin_offset
    }

    /// Applies `action` to `stream` and to the stream of `role`, and checks
    /// that both find the same hole to give up.
    pub fn apply_action(
        &mut self,
        role: TcpRole,
        stream: &mut TcpStream,
        action: ReaderAction,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        use proptest::prelude::*;

        let expected = &mut self.streams[role_index(role)];
        match action {
            ReaderAction::GiveUpHole => {
                prop_assert_eq!(expected.give_up_hole(), stream.give_up_hole());
            }
            ReaderAction::ConsumeGap => {
                expected.consume_gap();
                stream.consume_gap();
            }
            ReaderAction::DiscardAhead(distance) => {
                let offset = expected.read_offset + distance;
                expected.discard_until(offset);
                stream.discard_until(offset - expected.base.unwrap_or(0));
            }
            ReaderAction::DiscardAll => {
                expected.discard_until(expected.highest);
                stream.discard_all();
            }
        }
        Ok(())
    }

    /// Checks that `stream` matches the stream of `role`, then consumes
    /// `consume_len` bytes of both after reading them with `read_acked` (if
    /// `acked`) or `read_received`.
    pub fn check_and_consume(
        &mut self,
        role: TcpRole,
        stream: &mut TcpStream,
        consume_len: usize,
        acked: bool,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        use proptest::prelude::*;

        let expected = &mut self.streams[role_index(role)];
        // offsets of the pool are relative to the stream's first byte
        let base = expected.base.unwrap_or(0);
        prop_assert_eq!(expected.read_offset - base, stream.read_offset());
        prop_assert_eq!(
            expected.acked_offset().saturating_sub(base),
            stream.acked_offset()
        );
        prop_assert_eq!(expected.highest - base, stream.highest_offset());
        prop_assert_eq!(
            expected.fin_offset.map(|fin| fin - base),
            stream.fin_offset()
        );
        let holes: Vec<_> = expected
            .holes()
            .into_iter()
            .map(|hole| hole.start - base..hole.end - base)
            .collect();
        prop_assert_eq!(holes, stream.holes().collect::<Vec<_>>());
        prop_assert_eq!(expected.is_finished(), stream.is_finished());
        let clean = 0 == expected.gap_count && 0 == expected.conflicting_retransmissions;
        prop_assert_eq!(clean, stream.is_clean());
        let observed = expected.observed;
        prop_assert_eq!(
            clean && observed && expected.is_finished(),
            stream.is_complete()
        );
        prop_assert_eq!(
            &TcpStreamStatus {
                start: if observed {
                    TcpStreamStart::Observed
                } else {
                    TcpStreamStart::MidStreamPickup
                },
                gaps: expected.gap_count,
                gap_bytes: expected.gap_bytes,
                resyncs: 0,
                conflicting_retransmissions: expected.conflicting_retransmissions,
                out_of_window_segments: expected.out_of_window_segments,
            },
            stream.status()
        );

        // read both ways, the last read limits the bytes that are consumed
        let mut read_len = 0;
        for read_acked in [false == acked, acked] {
            let read_offset = stream.read_offset();
            let acked_offset = stream.acked_offset();
            let (expected_read, read) = if read_acked {
                (expected.read(expected.acked_offset()), stream.read_acked())
            } else {
                (expected.read(u64::MAX), stream.read_received())
            };
            prop_assert_eq!(expected_read, read);
            read_len = match read {
                TcpRead::Data(data) => data.len(),
                _ => 0,
            };
            // read_acked never returns bytes that were not ACKed
            if read_acked && read_len > 0 {
                prop_assert!(read_offset + read_len as u64 <= acked_offset);
            }
        }
        stream.consume(consume_len);
        expected.consume(consume_len.min(read_len) as u64);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{tcp_reassembly::TcpRole::*, test_gens::*};
    use proptest::{collection::vec, prelude::*, sample::Index};

    /// Order in which the endpoints send their FINs.
    #[derive(Copy, Clone, Debug)]
    enum FinOrder {
        InitiatorFirst,
        ResponderFirst,
        /// Each FIN is sent before the other one arrived.
        Simultaneous,
    }

    /// Sends the bytes `data` of both streams (indexed by role) in segments
    /// cut by `segment_lens` and interleaved by `directions` (true for the
    /// initiator). Each segment starts with up to `resent_lens` bytes that
    /// were already sent.
    fn send_interleaved(
        script: &mut ConnectionScript,
        data: [&[u8]; 2],
        segment_lens: &[usize],
        resent_lens: &[usize],
        directions: &[bool],
    ) {
        let mut sent = [0usize, 0usize];
        let mut step = 0;
        while sent[0] < data[0].len() || sent[1] < data[1].len() {
            let initiator_done = sent[0] == data[0].len();
            let responder_done = sent[1] == data[1].len();
            let role = if responder_done
                || (false == initiator_done && directions[step % directions.len()])
            {
                Initiator
            } else {
                Responder
            };
            let i = role_index(role);
            let start = sent[i] - resent_lens[step % resent_lens.len()].min(sent[i]);
            let len = segment_lens[step % segment_lens.len()].min(data[i].len() - sent[i]);
            script.send_at(role, start as u64, &data[i][start..sent[i] + len]);
            sent[i] += len;
            step += 1;
        }
    }

    /// Feeds `segments` to `pool` and checks both streams against the
    /// reference model after each segment, reading partially from the pool
    /// or from the ended connection it handed over. `acked_reads` decides
    /// whether the bytes are consumed after reading them with `read_acked`
    /// or `read_received`, and `actions` what the reader does before
    /// reading.
    ///
    /// Returns the model and the ended connection, if any.
    fn feed_and_check(
        pool: &mut TcpReassemblyPool<(), ()>,
        segments: &[TestSegment],
        consume_lens: &[usize],
        acked_reads: &[bool],
        actions: &[Option<ReaderAction>],
    ) -> Result<(ReferenceModel, Option<TcpConnection>), TestCaseError> {
        let mut model = ReferenceModel::new(pool.config().clone());
        let mut ended = None;
        for (step, segment) in segments.iter().enumerate() {
            let after_end = model.end().is_some();
            model.apply(segment);
            let processed = segment.feed(pool, ());
            if false == model.created() {
                prop_assert!(processed.active.is_none());
                prop_assert!(processed.ended.is_none());
                prop_assert_eq!(Some(TcpIgnoreReason::NoConnection), processed.ignored);
                continue;
            }
            let connection = if after_end {
                prop_assert!(processed.active.is_none());
                prop_assert!(processed.ended.is_none());
                prop_assert_eq!(Some(TcpIgnoreReason::AfterEnd), processed.ignored);
                ended.as_mut().unwrap()
            } else if model.end().is_some() {
                prop_assert!(processed.active.is_none());
                prop_assert_eq!(None, processed.ignored);
                ended = processed.ended;
                ended.as_mut().unwrap()
            } else {
                prop_assert!(processed.ended.is_none());
                prop_assert_eq!(None, processed.ignored);
                processed.active.unwrap().0
            };
            prop_assert_eq!(model.end(), connection.end());
            prop_assert_eq!(model.roles_guessed(), connection.roles_guessed());
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                if let Some(action) = actions[(step + i) % actions.len()] {
                    model.apply_action(role, connection.stream_mut(role), action)?;
                }
                model.check_and_consume(
                    role,
                    connection.stream_mut(role),
                    consume_lens[(step + i) % consume_lens.len()],
                    acked_reads[(step + i) % acked_reads.len()],
                )?;
            }
        }
        Ok((model, ended))
    }

    proptest! {
        #[test]
        fn in_order_streams(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fin_data_lens in [proptest::option::of(0usize..64), proptest::option::of(0usize..64)],
            fin_order in prop_oneof![
                Just(FinOrder::InitiatorFirst),
                Just(FinOrder::ResponderFirst),
                Just(FinOrder::Simultaneous),
            ],
            final_acks in [any::<bool>(), any::<bool>()],
            late_segments in vec(
                (tcp_role_any(), 0usize..8, vec(any::<u8>(), 0..8), any::<bool>()),
                0..8
            ),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // some of them starting with bytes that were already sent
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data, &responder_data];
            // bytes sent before the FIN segment (which carries the rest)
            let data_lens = [0, 1].map(|i| {
                data[i].len() - fin_data_lens[i].unwrap_or(0).min(data[i].len())
            });
            send_interleaved(
                &mut script,
                [&data[0][..data_lens[0]], &data[1][..data_lens[1]]],
                &segment_lens,
                &resent_lens,
                &directions,
            );

            // FINs carrying the rest of the bytes
            let roles = match fin_order {
                FinOrder::ResponderFirst => [Responder, Initiator],
                _ => [Initiator, Responder],
            };
            let both_fins = fin_data_lens.iter().all(Option::is_some);
            if matches!(fin_order, FinOrder::Simultaneous) && both_fins {
                for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                    script.send(role, &data[i][data_lens[i]..]);
                }
                script.simultaneous_fins();
            } else {
                for role in roles {
                    let i = role_index(role);
                    if fin_data_lens[i].is_some() {
                        script.fin_with_data(role, &data[i][data_lens[i]..]);
                    } else {
                        // without a FIN, the rest is sent as normal bytes
                        script.send(role, &data[i][data_lens[i]..]);
                    }
                }
            }

            // ACKs of the FINs that were not ACKed yet
            for role in roles {
                if final_acks[role_index(role)] {
                    script.ack(role);
                }
            }

            // late segments ending before, at, or after the end of the
            // stream (possibly with another FIN)
            for (role, back, payload, fin) in &late_segments {
                let len = data[role_index(*role)].len();
                let start = (len - (*back).min(len)) as u64;
                if *fin {
                    script.fin_at(*role, start, payload);
                } else {
                    script.send_at(*role, start, payload);
                }
            }

            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let (model, ended) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
            )?;

            // the model received everything that was sent, and the FINs end
            // the streams
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert_eq!(&data[i][..], &model.received(role)[..data[i].len()]);
                if fin_data_lens[i].is_some() {
                    prop_assert_eq!(Some(data[i].len() as u64), model.fin_offset(role));
                }
            }

            // with both FINs and their ACKs the connection is finished
            if both_fins && final_acks.iter().all(|ack| *ack) {
                prop_assert_eq!(Some(TcpConnectionEnd::Finished), model.end());
            }

            // an ended connection is finished and can be read to its end
            // (late segments with differing bytes can make it unclean)
            if let Some(mut connection) = ended {
                for role in [Initiator, Responder] {
                    let stream = connection.stream_mut(role);
                    prop_assert!(stream.is_finished());
                    stream.read_received();
                    stream.consume(usize::MAX);
                    prop_assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
                    prop_assert_eq!(model.fin_offset(role), Some(stream.read_offset()));
                }
                pool.recycle(connection);
            }
        }

        #[test]
        fn reordered_streams(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            retransmissions in vec(
                (
                    tcp_role_any(),
                    any::<Index>(),
                    0usize..3000,
                    proptest::option::of((any::<Index>(), 1u8..=255)),
                ),
                0..16
            ),
            duplicates in vec(any::<Index>(), 0..8),
            positions in vec(any::<Index>(), 1..16),
            delays in vec(0usize..8, 1..64),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data[..], &responder_data[..]];
            send_interleaved(&mut script, data, &segment_lens, &resent_lens, &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // retransmissions cut differently than the original segments
            // (carrying the FIN if they reach it, some with a corrupted byte),
            // and duplicates
            let originals = script.segments.len() - 3;
            let mut corrupted = false;
            for (role, start, len, corruption) in &retransmissions {
                let i = role_index(*role);
                let start = start.index(data[i].len() + 1);
                let end = (start + len).min(data[i].len());
                let mut payload = data[i][start..end].to_vec();
                if let Some((position, xor)) = corruption {
                    if start < end {
                        payload[position.index(end - start)] ^= xor;
                        corrupted = true;
                    }
                }
                if fins[i] && end == data[i].len() {
                    script.fin_at(*role, start as u64, &payload);
                } else {
                    script.send_at(*role, start as u64, &payload);
                }
            }
            if originals > 0 {
                for index in &duplicates {
                    let duplicate = script.segments[3 + index.index(originals)].clone();
                    script.segments.push(duplicate);
                }
            }

            // move the segments after the handshake by a bounded distance,
            // the retransmissions and duplicates start at random positions
            let mut keyed: Vec<_> = script
                .segments
                .drain(3..)
                .enumerate()
                .map(|(i, segment)| {
                    let position = if i < originals {
                        i
                    } else {
                        positions[i % positions.len()].index(originals + 1)
                    };
                    (position + delays[i % delays.len()], segment)
                })
                .collect();
            keyed.sort_by_key(|(key, _)| *key);
            script.segments.extend(keyed.into_iter().map(|(_, segment)| segment));

            // the retransmissions and duplicates can ACK bytes that are sent
            // much later, which would make holes overdue (the windows are too
            // large for the implied ACK to do so)
            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                ack_reorder_tolerance: u32::MAX,
                ..Default::default()
            });
            let (model, ended) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
            )?;

            // every byte arrived, so the streams were delivered byte-exact
            // (unless a corrupted retransmission arrived first)
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                if false == corrupted {
                    prop_assert_eq!(data[i], model.received(role));
                }
                prop_assert_eq!(data[i].len(), model.received(role).len());
                prop_assert_eq!(fins[i].then_some(data[i].len() as u64), model.fin_offset(role));
            }

            // with both FINs the connection is finished
            prop_assert_eq!(fins[0] && fins[1], ended.is_some());
        }

        #[test]
        fn random_acks(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            windows in vec(prop_oneof![0u16..64, any::<u16>()], 1..16),
            acks in vec((tcp_role_any(), any::<Index>(), any::<Index>()), 0..32),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data[..], &responder_data[..]];
            send_interleaved(&mut script, data, &segment_lens, &resent_lens, &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // pure ACKs of random offsets (also after the bytes that were
            // sent) at random positions after the handshake
            for (role, position, offset) in &acks {
                let sent = data[role_index(role.other())].len() + 1;
                script.ack_to(*role, offset.index(2 * sent) as u64);
                let ack = script.segments.pop().unwrap();
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, ack);
            }

            // random receive windows, which make some of the ACKs implausible
            for (segment, window) in script.segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = *window;
            }

            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let (model, _) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
            )?;

            // the ACKs don't change the received bytes, but they can make
            // holes overdue, whose bytes are ignored after they were given up
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received_matches(role, data[i]));
            }
        }

        #[test]
        fn out_of_window_segments(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            windows in vec(prop_oneof![0u16..64, 0u16..2048], 1..16),
            injected in vec(
                (
                    tcp_role_any(),
                    any::<Index>(),
                    0u64..8192,
                    vec(any::<u8>(), 0..8),
                    any::<bool>(),
                ),
                0..16
            ),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data[..], &responder_data[..]];
            send_interleaved(&mut script, data, &segment_lens, &[0], &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // segments the endpoints didn't send, with bytes or a FIN after
            // the end of the stream, at random positions after the handshake
            for (role, position, distance, payload, fin) in &injected {
                let offset = data[role_index(*role)].len() as u64 + distance;
                let segment = script.injected(|script| {
                    if *fin {
                        script.fin_at(*role, offset, payload);
                    } else {
                        script.send_at(*role, offset, payload);
                    }
                });
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, segment);
            }

            // random receive windows
            for (segment, window) in script.segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = *window;
            }

            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let (model, _) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
            )?;

            // the injected bytes don't change the bytes that were sent (the
            // ACKs of injected segments can make holes overdue, whose bytes
            // are ignored after they were given up)
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received_matches(role, data[i]));
            }
        }

        #[test]
        fn conflicting_retransmissions(
            isn in tcp_isn_any(),
            data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            retransmissions in vec(
                (
                    any::<Index>(),
                    1usize..3000,
                    proptest::option::of((any::<Index>(), 1u8..=255)),
                ),
                0..16
            ),
        ) {
            // the stream in order, followed by retransmissions of randomly cut
            // ranges, some of them with a corrupted byte
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script.handshake();
            send_interleaved(&mut script, [&data, &[]], &segment_lens, &[0], &[true]);
            let mut corrupted = 0;
            if false == data.is_empty() {
                for (start, len, corruption) in &retransmissions {
                    let start = start.index(data.len());
                    let end = (start + len).min(data.len());
                    let mut payload = data[start..end].to_vec();
                    if let Some((position, xor)) = corruption {
                        payload[position.index(end - start)] ^= xor;
                        corrupted += 1;
                    }
                    script.send_at(Initiator, start as u64, &payload);
                }
            }

            // the bytes received first are delivered, and each corrupted
            // segment counts once
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            prop_assert_eq!(corrupted, stream.status().conflicting_retransmissions);
            prop_assert_eq!(0 == corrupted, stream.is_clean());
            if data.is_empty() {
                prop_assert_eq!(TcpRead::Pending, stream.read_received());
            } else {
                prop_assert_eq!(TcpRead::Data(&data[..]), stream.read_received());
            }
        }

        #[test]
        fn capture_loss(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            extra_acks in 0usize..32,
            keep_alives in vec((tcp_role_any(), any::<Index>()), 0..4),
            lost in vec((any::<Index>(), proptest::option::of(any::<Index>())), 0..16),
            windows in vec(
                prop_oneof![1 => 1u16..256, 2 => 256u16..8192, 1 => Just(u16::MAX)],
                1..16
            ),
            config in tcp_overdue_config_any(),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // followed by the FINs, their ACKs and more ACKs (so that the ACK
            // reorder tolerance can pass)
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data[..], &responder_data[..]];
            send_interleaved(&mut script, data, &segment_lens, &resent_lens, &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);
            for i in 0..extra_acks {
                script.ack(if 0 == i % 2 { Initiator } else { Responder });
            }

            // keep-alive probes repeating the last byte sent, at random
            // positions after the handshake
            for (role, position) in &keep_alives {
                let data = data[role_index(*role)];
                if let Some(last) = data.last() {
                    let probe = script.injected(|script| {
                        script.send_at(*role, data.len() as u64 - 1, &[*last]);
                    });
                    let position = 3 + position.index(script.segments.len() - 2);
                    script.segments.insert(position, probe);
                }
            }

            // segments lost in the capture, or captured later
            for (index, later) in &lost {
                if script.segments.len() > 3 {
                    let i = 3 + index.index(script.segments.len() - 3);
                    let segment = script.segments.remove(i);
                    if let Some(later) = later {
                        let position = i + later.index(script.segments.len() - i + 1);
                        script.segments.insert(position, segment);
                    }
                }
            }

            // random receive windows, small ones make holes overdue early
            for (segment, window) in script.segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = *window;
            }

            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let (model, ended) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                let len = model.received(role).len().min(data[i].len());
                prop_assert!(model.received_matches(role, &data[i][..len]));
            }

            // a finished connection can be read to its FINs, stepping over
            // the gaps
            if let Some(mut connection) = ended {
                for role in [Initiator, Responder] {
                    let stream = connection.stream_mut(role);
                    prop_assert!(stream.is_finished());
                    for _ in 0..10_000 {
                        match stream.read_received() {
                            TcpRead::Data(data) => {
                                let len = data.len();
                                stream.consume(len);
                            }
                            TcpRead::Gap { .. } => stream.consume_gap(),
                            _ => break,
                        }
                    }
                    prop_assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
                }
            }
        }

        #[test]
        fn mid_stream_pickups(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            pickup in any::<Index>(),
            late in vec((any::<Index>(), 0usize..16), 0..6),
            keep_alives in vec((tcp_role_any(), any::<Index>()), 0..4),
            delays in vec(0usize..4, 1..64),
            windows in vec(
                prop_oneof![1 => 1u16..256, 2 => 256u16..8192, 1 => Just(u16::MAX)],
                1..16
            ),
            fallback_window in prop_oneof![Just(4 * 1024 * 1024), 64u32..8192],
            config in tcp_overdue_config_any(),
            consume_lens in vec(prop_oneof![Just(0usize), 0usize..3000], 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data[..], &responder_data[..]];
            send_interleaved(&mut script, data, &segment_lens, &resent_lens, &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // the capture starts at a random segment, a few of the segments
            // before it are captured later (e.g. the SYN)
            let lost: Vec<_> = script
                .segments
                .drain(..pickup.index(script.segments.len()))
                .collect();
            if false == lost.is_empty() {
                for (index, position) in &late {
                    let segment = lost[index.index(lost.len())].clone();
                    let position = (*position).min(script.segments.len());
                    script.segments.insert(position, segment);
                }
            }

            // keep-alive probes repeating the last byte sent, at random
            // positions (some of them the first segment of their stream)
            for (role, position) in &keep_alives {
                let data = data[role_index(*role)];
                if let Some(last) = data.last() {
                    let probe = script.injected(|script| {
                        script.send_at(*role, data.len() as u64 - 1, &[*last]);
                    });
                    let position = position.index(script.segments.len() + 1);
                    script.segments.insert(position, probe);
                }
            }

            // move the segments by a bounded distance
            let mut keyed: Vec<_> = script
                .segments
                .drain(..)
                .enumerate()
                .map(|(i, segment)| (i + delays[i % delays.len()], segment))
                .collect();
            keyed.sort_by_key(|(key, _)| *key);
            script.segments.extend(keyed.into_iter().map(|(_, segment)| segment));

            // random receive windows (used once both SYNs were seen)
            for (segment, window) in script.segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = *window;
            }

            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                fallback_window,
                ..config
            });
            let (model, _) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up or lie before the first byte captured
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                let len = model.received(role).len().min(data[i].len());
                prop_assert!(model.received_matches(role, &data[i][..len]));
            }
        }

        #[test]
        fn reader_actions(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            lost in vec((any::<Index>(), proptest::option::of(any::<Index>())), 0..8),
            acks in vec((tcp_role_any(), any::<Index>(), any::<Index>()), 0..8),
            actions in vec(
                proptest::option::weighted(0.3, prop_oneof![
                    3 => Just(ReaderAction::GiveUpHole),
                    3 => Just(ReaderAction::ConsumeGap),
                    2 => prop_oneof![0u64..64, 0u64..32 * 1024].prop_map(ReaderAction::DiscardAhead),
                    1 => Just(ReaderAction::DiscardAll),
                ]),
                1..32
            ),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data[..], &responder_data[..]];
            send_interleaved(&mut script, data, &segment_lens, &resent_lens, &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // segments lost in the capture, or captured later
            for (index, later) in &lost {
                if script.segments.len() > 3 {
                    let i = 3 + index.index(script.segments.len() - 3);
                    let segment = script.segments.remove(i);
                    if let Some(later) = later {
                        let position = i + later.index(script.segments.len() - i + 1);
                        script.segments.insert(position, segment);
                    }
                }
            }

            // pure ACKs of random offsets (also after the bytes that were
            // sent) at random positions after the handshake
            for (role, position, offset) in &acks {
                let sent = data[role_index(role.other())].len() + 1;
                script.ack_to(*role, offset.index(2 * sent) as u64);
                let ack = script.segments.pop().unwrap();
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, ack);
            }

            // FINs that were not lost
            let captured_fins = [Initiator, Responder].map(|role| {
                script.segments.iter().any(|segment| segment.sender == role && segment.header.fin)
            });

            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let (_, mut ended) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &actions,
            )?;

            // giving up every hole lets both streams be read to their end, a
            // captured FIN ends them (an ACK of nothing gets an open
            // connection from the pool, and ends it if both streams are
            // finished by now)
            let probe = script.injected(|script| {
                script.ack_to(Responder, 0);
            });
            let processed = probe.feed(&mut pool, ());
            let mut ended_by_probe = processed.ended;
            let connection = match processed.active {
                Some((connection, _)) => connection,
                None => ended_by_probe.as_mut().or(ended.as_mut()).unwrap(),
            };
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                let stream = connection.stream_mut(role);
                // every step reads bytes, steps over a gap or gives up a hole
                let mut drained = false;
                for _ in 0..10_000 {
                    match stream.read_received() {
                        TcpRead::Data(data) => {
                            let len = data.len();
                            stream.consume(len);
                        }
                        TcpRead::Gap { .. } => stream.consume_gap(),
                        TcpRead::Pending => {
                            if false == stream.give_up_hole() {
                                drained = true;
                                break;
                            }
                        }
                        TcpRead::End(_) => {
                            drained = true;
                            break;
                        }
                    }
                }
                prop_assert!(drained);
                prop_assert_eq!(0, stream.holes().count());
                prop_assert_eq!(stream.highest_offset(), stream.read_offset());
                if captured_fins[i] {
                    prop_assert_eq!(Some(data[i].len() as u64), stream.fin_offset());
                    prop_assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
                }
            }
        }
    }
}
