use crate::tcp_reassembly::*;
use core::ops::Range;
use std::vec::Vec;

/// Simple model of the bytes a [`TcpReassemblyPool`] delivers.
///
/// It works on the true stream offsets that a [`ConnectionScript`] records
/// in its segments, so it is independent of the sequence number handling
/// it checks. It expects segments without window scale options.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReferenceModel {
    /// Configuration of the pool the model is compared with.
    config: TcpReassemblyConfig,
    /// Streams indexed by role.
    streams: [ModelStream; 2],
    /// "window" field of the last segment of each role.
    windows: [Option<u16>; 2],
    /// Whether the SYN of each role was seen.
    syns: [bool; 2],
    /// End of the connection.
    end: Option<TcpConnectionEnd>,
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
    /// Highest offset minus k windows of the receiver after any packet of
    /// the connection so far (0 without a hole give up window factor k).
    implied_ack: u64,
    /// Offset of the next byte to read.
    read_offset: u64,
}

impl ModelStream {
    /// Applies a segment of the stream's sender, whose receiver has the
    /// receive window `window`:
    /// - a segment with bytes or a FIN starting more than k windows after
    ///   the highest or the ACKed offset is counted and not stored (k is the
    ///   hole give up window factor, 2 without one);
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
        let factor = config.hole_give_up_window_factor.unwrap_or(2);
        let window_end = self.ack.max(self.highest) + u64::from(factor) * window;
        if (false == segment.payload.is_empty() || segment.header.fin) && start > window_end {
            self.out_of_window_segments += 1;
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
                self.out_of_window_segments += 1;
                &segment.payload[..fin.saturating_sub(start) as usize]
            }
            _ => &segment.payload[..],
        };

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

    /// Applies an ACK of the other side, whose receive window before it was
    /// `window`: ACKs more than one window after the highest offset (plus
    /// the FIN) are ignored, others mark the bytes up to them as sent (but
    /// none after the FIN).
    fn add_ack(&mut self, ack: u64, window: u64) {
        let sent_end = self.highest + u64::from(self.fin_offset.is_some());
        if ack > sent_end + window {
            return;
        }
        self.ack = self.ack.max(ack);
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

    /// Gives up the hole at the read offset, returns false if there is
    /// none.
    fn give_up_hole(&mut self) -> bool {
        match self.holes().first() {
            Some(hole) if hole.start == self.read_offset => {
                self.gap_count += 1;
                self.gap_bytes += hole.end - hole.start;
                self.gaps.insert(0, hole.clone());
                self.extend_received();
                true
            }
            _ => false,
        }
    }

    /// Moves the read offset over the gap at the read offset, if any.
    fn consume_gap(&mut self) {
        if let Some(gap) = self.gap_at_read_offset() {
            self.gaps.remove(0);
            self.read_offset = gap.end;
        }
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
        self.extend_received();
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

    /// Returns true if the stream is finished and its FIN was ACKed.
    fn is_finished_and_acked(&self) -> bool {
        self.is_finished() && self.fin_offset.is_some_and(|fin| fin < self.ack)
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
    /// the stream of its sender. The connection is finished once both
    /// streams are finished and both FINs are ACKed; later segments change
    /// nothing.
    pub fn apply<CustomChannelId>(&mut self, segment: &TestSegment<CustomChannelId>) {
        if self.end.is_some() {
            return;
        }
        let sender = role_index(segment.sender);
        if let Some(ack) = segment.ack {
            let window = self.window(segment.sender.other());
            self.streams[role_index(segment.sender.other())].add_ack(ack, window);
        }
        let window = self.window(segment.sender);
        self.streams[sender].add_segment(segment, window, &self.config);
        self.windows[sender] = Some(segment.header.window_size);
        self.syns[sender] |= segment.header.syn;
        if let Some(factor) = self.config.hole_give_up_window_factor {
            for role in [TcpRole::Initiator, TcpRole::Responder] {
                let window = self.window(role);
                let stream = &mut self.streams[role_index(role)];
                let implied_ack = stream.highest.saturating_sub(u64::from(factor) * window);
                stream.implied_ack = stream.implied_ack.max(implied_ack);
            }
        }
        if self.streams.iter().all(ModelStream::is_finished_and_acked) {
            self.end = Some(TcpConnectionEnd::Finished);
        }
    }

    /// Receive window of the stream of `role`: the last window its receiver
    /// advertised (never scaled, as there are no window scale options), or
    /// the fallback window until both SYNs were seen.
    fn window(&self, role: TcpRole) -> u64 {
        match self.windows[role_index(role.other())] {
            Some(window) if self.syns == [true, true] => u64::from(window),
            _ => u64::from(self.config.fallback_window),
        }
    }

    /// End of the connection, `None` while it is open.
    pub fn end(&self) -> Option<TcpConnectionEnd> {
        self.end
    }

    /// Contiguous received bytes of the stream of `role` from offset 0 on.
    pub fn received(&self, role: TcpRole) -> &[u8] {
        &self.streams[role_index(role)].received
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
                stream.discard_until(offset);
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
        prop_assert_eq!(expected.read_offset, stream.read_offset());
        prop_assert_eq!(expected.acked_offset(), stream.acked_offset());
        prop_assert_eq!(expected.highest, stream.highest_offset());
        prop_assert_eq!(expected.fin_offset, stream.fin_offset());
        prop_assert_eq!(expected.holes(), stream.holes().collect::<Vec<_>>());
        prop_assert_eq!(expected.is_finished(), stream.is_finished());
        let clean = 0 == expected.gap_count && 0 == expected.conflicting_retransmissions;
        prop_assert_eq!(clean, stream.is_clean());
        prop_assert_eq!(clean && expected.is_finished(), stream.is_complete());
        prop_assert_eq!(
            &TcpStreamStatus {
                gaps: expected.gap_count,
                gap_bytes: expected.gap_bytes,
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
        expected.read_offset += consume_len.min(read_len) as u64;
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

            let mut pool = TcpReassemblyPool::<(), ()>::default();
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

            // the ACKs don't change the received bytes
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert_eq!(data[i], model.received(role));
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

            // the injected bytes don't change the bytes that were sent
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received(role).starts_with(data[i]));
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
