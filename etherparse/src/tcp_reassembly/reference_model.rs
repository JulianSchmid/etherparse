use crate::tcp_reassembly::*;
use core::net::SocketAddr;
use core::ops::Range;
use std::vec::Vec;

/// Simple model of the bytes a [`TcpReassemblyPool`] delivers.
///
/// It works on the true stream offsets that a [`ConnectionScript`] records
/// in its segments, so it is independent of the sequence number handling
/// it checks. After a resync, the offsets of a stream leave out the jump
/// (they are the true offsets minus a shift). Offsets of the pool are
/// relative to the first byte the pool knows of a stream (its base). It
/// expects segments without window scale options, and endpoints whose ports
/// make guessed roles right.
///
/// A SYN on the tombstone of an ended connection, or a confirmed reconnect,
/// starts the model again as a new connection, which takes the later
/// segments. Segments of another script than the connection's (see
/// [`ConnectionScript::incarnation`]) are assumed to lie far away from its
/// streams, and the model only predicts what the pool does with some of
/// them (see [`ReferenceModel::predicts`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct ReferenceModel {
    /// Configuration of the pool the model is compared with.
    config: TcpReassemblyConfig,
    /// Id of the connection (the number of connections before it on the
    /// same key).
    id: u64,
    /// Whether a segment started the connection.
    created: bool,
    /// Endpoint of the initiator, once the connection was created (the
    /// roles of a segment follow its endpoints, as in the pool, not the
    /// roles of its script).
    initiator: Option<SocketAddr>,
    /// Incarnation of the script whose segment started the connection.
    incarnation: Option<u32>,
    /// Whether the roles are guessed, as a segment without a SYN started
    /// the connection and no late SYN confirmed them.
    roles_guessed: bool,
    /// Streams indexed by role.
    streams: [ModelStream; 2],
    /// "window" field of the last segment of each role.
    windows: [Option<u16>; 2],
    /// Whether the stream of each role took its SYN (the one before its
    /// first byte, which a resync can move).
    syns: [bool; 2],
    /// End of the connection.
    end: Option<TcpConnectionEnd>,
    /// Number of packets applied so far.
    packets: u64,
    /// SYN of a side without a start that may be blind, kept while the other
    /// side's SYN is unanswered until a SYN-ACK confirms it (S5), with the
    /// bytes its retransmissions added.
    kept_syn: Option<TestSegment>,
    /// Number of retransmissions of the kept SYN that carried differing
    /// bytes.
    kept_syn_conflicting: u64,
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
    /// [`TcpStream::force_resync`]
    ForceResync,
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
    /// Most bytes a SYN of the stream carried (TCP Fast Open).
    syn_len: u64,
    /// Whether the stream was picked up at a FIN without bytes.
    started_at_fin: bool,
    /// Whether a segment far from the kept ACK was refused as the start.
    start_disputed: bool,
    /// Whether the stream's SYN was seen but not ACKed by the other side
    /// yet (S5).
    syn_unacked: bool,
    /// Last segment of the other side dropped while the SYN was unanswered
    /// (true offsets of its bytes) and the number of consecutive ones that
    /// agree (S5).
    dropped: Option<(Range<u64>, u32)>,
    /// Whether the read offset moved forward.
    read_moved: bool,
    /// Last ACK of the other side that couldn't be applied yet: before the
    /// stream had a start, or at or before its first byte while bytes can
    /// be prepended.
    kept_ack: Option<(u64, u64)>,
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
    /// Every range that was discarded, in the order they were discarded.
    discarded: Vec<Range<u64>>,
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
    /// Number of bytes that were not stored as they didn't fit the memory
    /// limits.
    rejected_bytes: u64,
    /// Offset after the furthest byte that didn't fit the memory limits (0
    /// without one).
    rejected_end: u64,
    /// Number of segments with bytes or a FIN after the window, with bytes
    /// after the FIN, or with bytes before the first byte that the stream
    /// doesn't take (except the filler byte of a keep-alive right before an
    /// observed start), plus the refused first segment of a pickup (A4).
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
    /// True offset minus offset of the bytes after the last resync (0
    /// without one).
    shift: i64,
    /// Offset of each resync and the shift of the bytes from there on.
    resyncs: Vec<(u64, i64)>,
    /// Offsets of the gaps of unknown length that resyncs left, which the
    /// reader didn't step over yet.
    resync_gaps: Vec<u64>,
    /// Data segments after the window since the stream moved forward or
    /// received other bytes. The last one is the candidate of a resync.
    candidates: Vec<ModelCandidate>,
    /// True offset of the latest ACK more than one window after the bytes
    /// known to be sent, while the stream didn't move forward.
    resync_ack: Option<u64>,
    /// Whether the next data segment is the stream's new start.
    forced: bool,
    /// What reading returns away from the FIN once nothing more is
    /// readable, as the connection ended.
    end: Option<TcpStreamEnd>,
}

/// Data segment after the window that a stream may have jumped to.
#[derive(Clone, Debug)]
struct ModelCandidate {
    /// True offsets of the bytes.
    bytes: Range<u64>,
    /// Whether a FIN follows the bytes.
    fin: bool,
    /// Whether the bytes lie within one window of the candidate before.
    agrees: bool,
}

impl ModelStream {
    /// Applies a segment of the stream's sender in the packet with the
    /// number `packet`, whose receiver has the receive window `window`:
    /// - a SYN gives the stream an observed start at it (see
    ///   [`ModelStream::observe_start`]), a SYN that a mid-stream pickup
    ///   can't take counts as out-of-window and is ignored;
    /// - without a start, the first bytes or a FIN without bytes start a
    ///   mid-stream pickup, but a byte ending at the last ACK of the other
    ///   side (a keep-alive) doesn't, and neither does the first segment far
    ///   from that ACK (a FIN never): the next bytes do, and drop the ACK;
    /// - bytes up to k windows before the first byte of a mid-stream pickup
    ///   are put in front (see [`ModelStream::can_prepend`]), other bytes
    ///   before it count as out-of-window (once per segment);
    /// - a segment with bytes or a FIN starting more than k windows after
    ///   the highest or the ACKed offset is counted and not stored (k is the
    ///   hole give up window factor, 2 without one). If its bytes lie within
    ///   one window of the last ACK more than one window after the bytes
    ///   sent, or if it is the n-th consecutive such segment that lies within
    ///   one window of the one before (with `resync_after_segments = n`),
    ///   the stream resyncs at them, and that ACK counts after them (and
    ///   ACKs the bytes before them). Otherwise they are the candidate of a
    ///   resync (unless the FIN is known or it is a SYN), and a FIN without
    ///   bytes right after them is the candidate's FIN;
    /// - other bytes show that the stream didn't jump, so there is no
    ///   candidate anymore, and after `force_resync` the next bytes are the
    ///   stream's new start wherever they lie;
    /// - a keep-alive (one byte ending at the ACK, without SYN or FIN)
    ///   inside an overdue hole is ignored;
    /// - bytes received for the first time are stored, bytes received before
    ///   keep their first content, and the segment counts as a conflicting
    ///   retransmission if ones that are neither read, ACKed, in a gap nor
    ///   before a resync differ;
    /// - the first FIN that doesn't lie before received bytes or a resync
    ///   ends the stream (cutting the gaps and moving the read offset back
    ///   to it), and bytes after it are counted and not stored;
    /// - bytes before the highest offset that were not received are holes;
    /// - new bytes are rejected (and counted) from the first one that would
    ///   make the buffer, from the read offset to the furthest stored byte,
    ///   larger than the stream's limit or the pool's budget `available` on,
    ///   and all of them if storing them leaves more holes before the
    ///   furthest stored byte than the hole limit. Without a
    ///   start, bytes none of which fit don't start the stream, and bytes in
    ///   front of a mid-stream pickup are rejected if they don't fit (see
    ///   [`ModelStream::fits_in_front`]). A stream doesn't resync while it
    ///   has more gaps than the hole limit.
    fn add_segment<CustomChannelId>(
        &mut self,
        segment: &TestSegment<CustomChannelId>,
        window: u64,
        packet: u64,
        config: &TcpReassemblyConfig,
        available: &mut u64,
    ) -> bool {
        let payload = &segment.payload[..];
        let header = &segment.header;
        // the receiver accepts k windows before and after the stream's bytes
        let factor = config.hole_give_up_window_factor.unwrap_or(2).max(1);
        let range = u64::from(factor) * window;
        // the sender can have sent into a larger window before it shrank
        let sent_into = window.max(self.largest_window.unwrap_or(0));
        // without a base, the kept ACK tells what the receiver accepts, also
        // for the segment that starts the stream
        let had_base = self.base.is_some();
        let accepted_without_base = self
            .kept_ack
            .is_none_or(|(ack, _)| (segment.offset as i64 - ack as i64).unsigned_abs() <= range);
        if header.syn {
            if false == self.observe_start(segment.offset, payload.len(), range, config, available)
            {
                self.out_of_window_segments += 1;
                return false;
            }
            // the SYN that starts the stream awaits its ACK
            // an ACK of the SYN that arrived before it answers it already
            if false == had_base {
                self.syn_unacked = false
                    == self.kept_ack.is_some_and(|(ack, _)| {
                        (segment.offset..=segment.offset + range).contains(&ack)
                    });
            }
        } else if self.base.is_none() {
            let keep_alive = 1 == payload.len()
                && false == header.fin
                && Some(segment.offset + 1) == self.kept_ack.map(|(ack, _)| ack);
            if (payload.is_empty() && false == header.fin) || keep_alive {
                return accepted_without_base;
            }
            // the first segment far from the kept ACK doesn't start the
            // stream, the next one with bytes does, a FIN never
            if false == accepted_without_base && (header.fin || false == self.start_disputed) {
                self.out_of_window_segments += 1;
                self.start_disputed = true;
                return false;
            }
            if false == payload.is_empty() && 0 == (config.max_stream_buffer as u64).min(*available)
            {
                self.rejected_bytes += payload.len() as u64;
                return accepted_without_base;
            }
            // the start overrules a kept ACK it disagrees with
            if false == accepted_without_base {
                self.kept_ack = None;
            }
            self.start_at(segment.offset);
            self.started_at_fin = payload.is_empty();
        }
        // offsets leave out the jumps of the resyncs so far
        let mut start = segment.offset as i64 - self.shift;

        let window_end = (self.ack.max(self.highest) + u64::from(factor) * sent_into) as i64;
        let mut after_window = start > window_end;
        let mut jump_ack = None;
        if false == payload.is_empty() && false == header.syn && self.fin_offset.is_none() {
            let bytes = segment.offset..segment.offset + payload.len() as u64;
            let confirming_ack = self
                .resync_ack
                .filter(|ack| within_window(&bytes, *ack, window));
            let confirmed = if after_window {
                let agrees = self
                    .candidates
                    .last()
                    .is_some_and(|previous| within_window(&previous.bytes, bytes.start, window));
                self.candidates.push(ModelCandidate {
                    bytes,
                    fin: header.fin,
                    agrees,
                });
                let consecutive = 1 + self
                    .candidates
                    .iter()
                    .rev()
                    .take_while(|candidate| candidate.agrees)
                    .count();
                confirming_ack.is_some()
                    || config
                        .resync_after_segments
                        .is_some_and(|after| consecutive >= after as usize)
            } else {
                self.candidates.clear();
                false
            };
            if (self.forced || confirmed) && self.can_resync(config) {
                jump_ack = confirming_ack;
                self.resync(segment.offset);
                start = segment.offset as i64 - self.shift;
                after_window = false;
            }
        }
        // the receiver drops segments outside of its window, with their
        // window: k windows before the bytes sent to k windows after them
        let plausible = if had_base {
            false == after_window
                && self.highest as i64 - (u64::from(factor) * sent_into) as i64 <= start
        } else {
            accepted_without_base
        };
        if (false == payload.is_empty() || header.fin) && after_window {
            if let Some(candidate) = self.candidates.last_mut() {
                if payload.is_empty() && segment.offset == candidate.bytes.end {
                    candidate.fin = true;
                }
            }
            self.out_of_window_segments += 1;
            return plausible;
        }

        let mut out_of_window = false;
        // bytes before a jump are ignored without counting
        if let Some(base) = self.base.filter(|_| self.resyncs.is_empty()) {
            if start < base as i64 && false == payload.is_empty() && false == self.observed {
                if false == self.can_prepend() || base as i64 - start > range as i64 {
                    out_of_window = true;
                } else if self.fits_in_front(start as u64, payload.len(), config, *available) {
                    *available -= base - start as u64;
                    self.start_at(start as u64);
                } else {
                    self.rejected_bytes += (payload.len() as u64).min(base - start as u64);
                }
            } else if start < base as i64 && false == payload.is_empty() {
                // only the filler byte of a keep-alive before an observed
                // start doesn't count, nor the Fast Open bytes of the own
                // SYN (A2)
                out_of_window = false
                    == (header.syn
                        || (start == base as i64 - 1 && 1 == payload.len() && false == header.fin));
            }
        }
        let end = start + payload.len() as i64;

        if 1 == payload.len()
            && false == (header.syn || header.fin)
            && end == self.ack as i64
            && self
                .holes()
                .iter()
                .any(|hole| hole.contains(&(start as u64)) && self.is_overdue(hole))
        {
            return plausible;
        }
        let received_end = (self.bytes.len() as u64)
            .max(self.resync_offset())
            .max(self.rejected_end);
        if segment.header.fin && self.fin_offset.is_none() && end >= received_end as i64 {
            let end = end as u64;
            self.fin_offset = Some(end);
            // missing bytes after the FIN (from an ACK of it) don't exist,
            // even if they were given up
            self.set_highest(end);
            self.read_offset = self.read_offset.min(end);
            self.gaps.retain_mut(|gap| {
                gap.end = gap.end.min(end);
                gap.start < gap.end
            });
            self.received.truncate(end as usize);
        }
        let payload = match self.fin_offset {
            Some(fin) if end > fin as i64 && false == payload.is_empty() => {
                out_of_window = true;
                &payload[..(fin as i64 - start).max(0) as usize]
            }
            _ => payload,
        };
        if out_of_window {
            self.out_of_window_segments += 1;
        }

        // bytes that were consumed, given up, or sent before a jump are
        // ignored
        let new: Vec<(u64, u8)> = (start..)
            .zip(payload)
            .filter_map(|(offset, byte)| {
                u64::try_from(offset)
                    .ok()
                    .filter(|offset| false == self.ignores(*offset))
                    .map(|offset| (offset, *byte))
            })
            .collect();
        let acked = self.acked_offset();
        let conflicting = new.iter().any(|(offset, byte)| {
            *offset >= acked
                && self
                    .bytes
                    .get(*offset as usize)
                    .is_some_and(|received| received.is_some_and(|b| b != *byte))
        });
        if conflicting {
            self.conflicting_retransmissions += 1;
        }

        // the bytes that don't fit the limits are rejected
        let buffered = self.buffered();
        let new = match (new.first(), new.last()) {
            (Some((first, _)), Some((last, _))) => {
                let (first, end) = (*first, *last + 1);
                let buf_end = (self.bytes.len() as u64).max(self.read_offset);
                let limit = self
                    .read_offset
                    .saturating_add(config.max_stream_buffer as u64)
                    .min(buf_end.saturating_add(*available));
                let mut stored_end = end.min(limit).max(first);
                if first < stored_end
                    && self.holes_after(first..stored_end) > config.max_holes_per_stream
                {
                    stored_end = first;
                }
                let (stored, rejected): (Vec<_>, Vec<_>) = new
                    .into_iter()
                    .partition(|(offset, _)| *offset < stored_end);
                let rejected = rejected
                    .iter()
                    .filter(|(offset, _)| {
                        false
                            == self
                                .bytes
                                .get(*offset as usize)
                                .is_some_and(|byte| byte.is_some())
                    })
                    .count() as u64;
                if 0 < rejected {
                    self.rejected_bytes += rejected;
                    self.rejected_end = self.rejected_end.max(end);
                }
                stored
            }
            _ => new,
        };
        if let Some((last, _)) = new.last() {
            if self.bytes.len() <= *last as usize {
                self.bytes.resize(*last as usize + 1, None);
            }
        }
        for (offset, byte) in new {
            self.bytes[offset as usize].get_or_insert(byte);
        }
        *available = available.saturating_sub(self.buffered().saturating_sub(buffered));
        if false == payload.is_empty() {
            let end = start + payload.len() as i64;
            self.set_highest(self.highest.max(end.max(0) as u64));
        }
        self.extend_received();
        if let Some(ack) = jump_ack {
            self.add_jump_ack(ack, window, packet, config);
        }
        plausible
    }

    /// Number of bytes from the read offset to the furthest stored byte.
    fn buffered(&self) -> u64 {
        (self.bytes.len() as u64).saturating_sub(self.read_offset)
    }

    /// Returns true if bytes from the offset `start` on fit in front of the
    /// first byte of a mid-stream pickup, the first `len` of which are
    /// received, with the pool's budget `available`: the buffer from `start`
    /// to the furthest stored byte fits the stream's limit, the bytes in
    /// front fit the budget, and the hole they leave before the first byte
    /// fits the hole limit (which counts the holes before the furthest
    /// stored byte).
    fn fits_in_front(
        &self,
        start: u64,
        len: usize,
        config: &TcpReassemblyConfig,
        available: u64,
    ) -> bool {
        let front = self.base.unwrap_or(start) - start;
        let holes = self.counted_holes() + usize::from((len as u64) < front);
        self.bytes.len() as u64 - start <= config.max_stream_buffer as u64
            && front <= available
            && holes <= config.max_holes_per_stream
    }

    /// Number of holes before the furthest stored byte after storing the
    /// bytes in `range` (the missing bytes before bytes after the highest
    /// offset are a hole too).
    fn holes_after(&self, range: Range<u64>) -> usize {
        let received_end = (self.bytes.len() as u64).max(range.end);
        let mut holes = self.holes();
        if range.start > self.highest {
            match holes.last_mut() {
                Some(hole) if hole.end == self.highest => hole.end = range.start,
                _ => holes.push(self.highest..range.start),
            }
        }
        holes
            .iter()
            .map(|hole| {
                if hole.end <= range.start || range.end <= hole.start {
                    usize::from(hole.end <= received_end)
                } else {
                    usize::from(hole.start < range.start)
                        + usize::from(range.end < hole.end && hole.end <= received_end)
                }
            })
            .sum()
    }

    /// Number of holes before the furthest stored byte.
    fn counted_holes(&self) -> usize {
        let received_end = self.bytes.len() as u64;
        self.holes()
            .iter()
            .filter(|hole| hole.end <= received_end)
            .count()
    }

    /// Returns true if the stream can resync: it has at most as many gaps
    /// the reader didn't step over as the hole limit.
    fn can_resync(&self, config: &TcpReassemblyConfig) -> bool {
        self.gaps.len() + self.resync_gaps.len() <= config.max_holes_per_stream
    }

    /// Returns true if the stream's sender, whose SYN was seen but not ACKed
    /// yet, drops the `segment` of the other side (S5): it accepts only a
    /// segment that ACKs the SYN (see [`ModelStream::acks_unacked_syn`]) and
    /// a SYN without ACK, FIN and RST.
    fn drops_before_syn_acked(
        &self,
        segment: &TestSegment,
        range: u64,
        window: u64,
        other_bare: bool,
        same_script: bool,
    ) -> bool {
        let header = &segment.header;
        // an RST or FIN towards a side with neither a start nor a kept ACK
        // has to ACK the SYN also after the wait
        let waits = self.syn_unacked || (other_bare && self.observed && (header.rst || header.fin));
        waits
            && false == self.acks_unacked_syn(segment, range, window, same_script)
            && false == (header.syn && false == (header.ack || header.fin || header.rst))
    }

    /// Returns true if the `segment` of the other side ACKs the stream's SYN
    /// that waits for its ACK: a SYN-ACK the SYN itself (with its bytes),
    /// another segment the SYN or bytes up to `range` after it, or the
    /// resync candidate within `window`.
    fn acks_unacked_syn(
        &self,
        segment: &TestSegment,
        range: u64,
        window: u64,
        same_script: bool,
    ) -> bool {
        let (Some(base), Some(ack)) = (self.base, segment.ack) else {
            return false;
        };
        // the offsets of another script's segments mean nothing here
        if false == same_script {
            return false;
        }
        if segment.header.syn || segment.header.rst {
            return (base..=base + self.syn_len).contains(&ack);
        }
        (base..=base + range).contains(&ack)
            || (false == segment.header.fin
                && self.candidates.last().is_some_and(|candidate| {
                    false == candidate.fin && within_window(&candidate.bytes, ack, window)
                }))
    }

    /// Returns true if the ACK at the true offset `ack` ACKs the stream's
    /// observed SYN (or its TCP Fast Open bytes).
    fn acks_syn_of(&self, ack: u64, same_script: bool) -> bool {
        same_script
            && self.observed
            && self
                .base
                .is_some_and(|base| (base..=base + self.syn_len).contains(&ack))
    }

    /// Ends the wait for the ACK of the stream's SYN if the `segment` of the
    /// other side ACKs it (S5).
    fn answer_syn(&mut self, segment: &TestSegment, range: u64, window: u64, same_script: bool) {
        if self.acks_unacked_syn(segment, range, window, same_script) {
            self.syn_unacked = false;
        }
    }

    /// Records a `segment` of the other side dropped while the SYN is
    /// unanswered: `resync_after_segments` consecutive ones, each within
    /// `window` of the one before, end the wait (S5).
    fn record_dropped(&mut self, segment: &TestSegment, window: u64, config: &TcpReassemblyConfig) {
        let bytes = segment.offset..segment.offset + segment.payload.len() as u64;
        let agreeing = match &self.dropped {
            Some((previous, agreeing)) if within_window(previous, bytes.start, window) => {
                agreeing + 1
            }
            _ => 1,
        };
        self.dropped = Some((bytes, agreeing));
        if config
            .resync_after_segments
            .is_some_and(|after| agreeing >= after)
        {
            self.syn_unacked = false;
        }
    }

    /// Gives the stream an observed start at the true offset `start`, where
    /// the SYN carries `len` bytes. A mid-stream pickup takes it if it is at
    /// or before its first byte, at most `range` bytes before it, bytes can
    /// be prepended and they fit (see [`ModelStream::fits_in_front`]).
    /// Returns true if the stream has an observed start afterwards.
    fn observe_start(
        &mut self,
        start: u64,
        len: usize,
        range: u64,
        config: &TcpReassemblyConfig,
        available: &mut u64,
    ) -> bool {
        // a stream that can prepend didn't resync, its offsets are the true
        // ones
        match self.base {
            Some(_) if self.observed => {
                self.syn_len = self.syn_len.max(len as u64);
                return true;
            }
            Some(_) if false == self.can_prepend() => return false,
            Some(base) if start > base || base - start > range => return false,
            Some(_) if false == self.fits_in_front(start, len, config, *available) => return false,
            Some(base) => *available -= base - start,
            // the kept ACK has to allow the start, as for a late SYN: it
            // lies at or after the first byte, at most `range` after it
            None if self.kept_ack.is_some_and(|(ack, _)| {
                false == (0..=range as i64).contains(&(ack as i64 - start as i64))
            }) =>
            {
                return false
            }
            None => {}
        }
        self.start_at(start);
        self.observed = true;
        self.syn_len = len as u64;
        true
    }

    /// Returns true if the SYN `segment` of the stream's sender can be the
    /// stream's own SYN: it has the ISN of the stream's observed start (see
    /// [`ModelStream::has_isn_of`]), or without one, the SYN's first byte
    /// lies at or before the stream's first byte and at most `range` bytes
    /// before it. Without a start, the same holds for the other side's kept
    /// ACK, if there is one.
    fn is_own_syn(&self, segment: &TestSegment, range: u64) -> bool {
        let start = segment.offset as i64;
        let within = |first: i64| (0..=range as i64).contains(&(first - start));
        match self.base {
            _ if self.observed => self.has_isn_of(segment),
            // offsets of the pool leave out the jumps of the resyncs
            Some(base) => within(base as i64 + self.shift),
            None => self.kept_ack.is_none_or(|(ack, _)| within(ack as i64)),
        }
    }

    /// Returns true if the stream has an observed start that has the ISN of
    /// the SYN or SYN-ACK `segment` of the same script: the start is the
    /// first byte of that SYN, or lies within its TCP Fast Open bytes (the
    /// ACK of a SYN-ACK that ACKed them, A2). Resyncs don't change it.
    fn has_isn_of(&self, segment: &TestSegment) -> bool {
        // the start can lie after the SYN's Fast Open bytes (A2)
        let bytes = segment.offset..=segment.offset + segment.payload.len() as u64;
        self.observed && self.base.is_some_and(|base| bytes.contains(&base))
    }

    /// Returns true if bytes can be prepended to the stream: it is a
    /// mid-stream pickup whose read offset never moved, that wasn't picked
    /// up at a FIN, didn't resync and has no resync forced.
    fn can_prepend(&self) -> bool {
        false == self.observed
            && false == self.read_moved
            && false == self.started_at_fin
            && self.resyncs.is_empty()
            && false == self.forced
    }

    /// Makes the next data segment the stream's new start, unless the stream
    /// has no start yet or its FIN is known.
    fn force_resync(&mut self) {
        if self.base.is_some() && self.fin_offset.is_none() {
            self.forced = true;
        }
    }

    /// Moves the first byte the pool knows to `start` (at or before the
    /// previous one).
    fn start_at(&mut self, start: u64) {
        self.base = Some(start);
        self.read_offset = start;
        self.set_highest(self.highest.max(start));
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
    /// consumed or given up, or lies before a resync.
    fn ignores(&self, offset: u64) -> bool {
        offset < self.read_offset || self.in_gap(offset) || offset < self.resync_offset()
    }

    /// Offset of the last resync (0 without one).
    fn resync_offset(&self) -> u64 {
        self.resyncs.last().map_or(0, |(offset, _)| *offset)
    }

    /// Moves the highest offset to `offset`. If that moves the stream
    /// forward, it didn't jump: there is no candidate or ACK of a jump
    /// anymore.
    fn set_highest(&mut self, offset: u64) {
        if offset > self.highest {
            self.candidates.clear();
            self.resync_ack = None;
        }
        self.highest = offset;
    }

    /// Continues the stream with the byte at the true offset `start` at the
    /// highest offset, behind a gap of unknown length: all holes are given
    /// up, and later offsets leave out the jump.
    fn resync(&mut self, start: u64) {
        for hole in self.holes() {
            self.give_up(hole);
        }
        // resyncs without bytes between them leave one gap
        if Some(&self.highest) != self.resync_gaps.last() {
            self.resync_gaps.push(self.highest);
        }
        self.shift = start as i64 - self.highest as i64;
        self.resyncs.push((self.highest, self.shift));
        self.candidates.clear();
        self.resync_ack = None;
        self.forced = false;
    }

    /// Applies the ACK of the other side at the true offset `ack` in the
    /// packet with the number `packet`, whose receive window before it was
    /// `window`: ACKs more than one window after the highest offset (plus
    /// the FIN) resync the stream after the candidate if they lie within one
    /// window of it, and are kept for a resync otherwise. Other ACKs mark
    /// the bytes up to them as sent (but none after the FIN). ACKs of the
    /// stream's first byte or before it, or before a resync, don't count.
    /// The last ACK before the stream had a start, or at or before its first
    /// byte while bytes can be prepended, is kept and applied after every
    /// packet.
    fn add_ack(&mut self, ack: u64, window: u64, packet: u64, config: &TcpReassemblyConfig) {
        let Some(base) = self.base else {
            self.kept_ack = Some((ack, packet));
            return;
        };
        let offset = ack as i64 - self.shift;
        // kept until a later ACK counts, if bytes can be put in front that
        // far
        if offset <= base as i64 && self.can_prepend() && self.ack <= base {
            let factor = config.hole_give_up_window_factor.unwrap_or(2).max(1);
            let range = u64::from(factor) * window;
            if (base as i64 - offset) as u64 <= range {
                self.kept_ack = Some((ack, packet));
            }
            return;
        }
        let sent_end = self.highest + u64::from(self.fin_offset.is_some());
        // the sender can have sent into a larger window before it shrank
        if offset > (sent_end + window.max(self.largest_window.unwrap_or(0))) as i64 {
            match self.candidates.last().cloned() {
                Some(candidate)
                    if self.fin_offset.is_none()
                        && within_window(&candidate.bytes, ack, window)
                        && self.can_resync(config) =>
                {
                    self.resync(candidate.bytes.end);
                    if candidate.fin {
                        self.fin_offset = Some(self.highest);
                    }
                    self.add_jump_ack(ack, window, packet, config);
                }
                _ => self.resync_ack = Some(ack),
            }
            return;
        }
        if offset < self.resync_offset() as i64 {
            return;
        }
        let offset = offset as u64;
        if offset > self.ack.max(base) {
            self.ack = offset;
            self.ack_history.push((packet, offset));
            self.kept_ack = None;
        }
        let end = self.fin_offset.map_or(self.ack, |fin| fin.min(self.ack));
        self.set_highest(self.highest.max(end));
    }

    /// Applies the ACK at the true offset `ack` that confirmed a jump, after
    /// the resync: it ACKs the bytes before the jump too.
    fn add_jump_ack(&mut self, ack: u64, window: u64, packet: u64, config: &TcpReassemblyConfig) {
        self.add_ack(ack, window, packet, config);
        self.ack = self.ack.max(self.resync_offset());
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

    /// Returns true if `hole` ends at or before the implied ACK, the ACK of
    /// `ack_reorder_tolerance` packets ago or the end of the furthest bytes
    /// that didn't fit the memory limits.
    fn is_overdue(&self, hole: &Range<u64>) -> bool {
        hole.end
            <= self
                .implied_ack
                .max(self.settled_ack)
                .max(self.rejected_end)
    }

    /// Applies the kept ACK, which counts once the stream has a start.
    fn apply_kept_ack(&mut self, window: Option<u64>, config: &TcpReassemblyConfig) {
        if let Some((ack, ack_packet)) = self.kept_ack.take() {
            let ack_window = window.unwrap_or(u64::from(config.fallback_window));
            self.add_ack(ack, ack_window, ack_packet, config);
        }
    }

    /// Applies the kept ACK, updates the implied ACK and the ACK of
    /// `ack_reorder_tolerance` packets ago after the packet with the number
    /// `packet`, where `window` is the receive window of the stream's
    /// receiver (`None` while it is unknown), and gives up an overdue hole
    /// at the read offset.
    fn after_packet(&mut self, window: Option<u64>, packet: u64, config: &TcpReassemblyConfig) {
        self.apply_kept_ack(window, config);
        if let Some(window) = window {
            self.largest_window = Some(self.largest_window.unwrap_or(0).max(window));
        }
        if let Some(factor) = config.hole_give_up_window_factor {
            let factor = factor.max(1);
            let window = self
                .largest_window
                .unwrap_or(u64::from(config.fallback_window));
            // at most half of the stream's buffer, but never less than a
            // known window
            let distance = (u64::from(factor) * window)
                .min(config.max_stream_buffer as u64 / 2)
                .max(self.largest_window.unwrap_or(0));
            let implied_ack = self.highest.saturating_sub(distance);
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

    /// Moves the read offset over the gap at the read offset, if any (the
    /// gap of a resync comes first).
    fn consume_gap(&mut self) {
        if Some(&self.read_offset) == self.resync_gaps.first() {
            self.resync_gaps.remove(0);
            self.give_up_overdue_hole();
        } else if let Some(gap) = self.gap_at_read_offset() {
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
    /// as gaps). The gap of a resync at `offset` stays.
    fn discard_until(&mut self, offset: u64) {
        let offset = offset.min(self.highest);
        if offset <= self.read_offset {
            return;
        }
        self.gaps.retain_mut(|gap| {
            gap.start = gap.start.max(offset);
            gap.start < gap.end
        });
        self.resync_gaps.retain(|gap| *gap >= offset);
        self.discarded.push(self.read_offset..offset);
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
        if Some(&self.read_offset) == self.resync_gaps.first() {
            return TcpRead::Gap { len: None };
        }
        if let Some(gap) = self.gap_at_read_offset() {
            return TcpRead::Gap {
                len: Some(gap.end - gap.start),
            };
        }
        let next_gap = self
            .gaps
            .first()
            .map_or(u64::MAX, |gap| gap.start)
            .min(self.resync_gaps.first().copied().unwrap_or(u64::MAX));
        let start = self.read_offset as usize;
        let end = (self.received.len() as u64).min(limit).min(next_gap) as usize;
        if start < end {
            TcpRead::Data(&self.received[start..end])
        } else if Some(self.read_offset) == self.fin_offset {
            TcpRead::End(TcpStreamEnd::Fin)
        } else if let Some(end) = self.end {
            TcpRead::End(end)
        } else {
            TcpRead::Pending
        }
    }

    /// Returns true if the FIN was seen and all bytes before it were
    /// received or given up.
    fn is_finished(&self) -> bool {
        Some(self.received.len() as u64) == self.fin_offset
    }

    /// Returns true if the FIN was ACKed (F3).
    fn can_finish(&self) -> bool {
        self.is_fin_acked()
    }

    /// Returns true if the FIN was ACKed.
    fn is_fin_acked(&self) -> bool {
        self.fin_offset.is_some_and(|fin| fin < self.ack)
    }

    /// Gives up all holes, as the connection ended, and makes reading
    /// return `end` once nothing more is readable away from the FIN.
    fn connection_ended(&mut self, end: TcpStreamEnd) {
        for hole in self.holes() {
            self.give_up(hole);
        }
        self.end = Some(end);
    }

    /// Returns true if the receiver, whose receive window is `window`, can
    /// accept an RST of the stream's sender at the true offset `offset`: it
    /// lies from the receiver's ACK up to one window after the bytes known to
    /// be sent and the FIN. The receiver's ACK is the lower one of the ACK
    /// that counted (at least the stream's first byte) and an ACK kept before
    /// the first byte, but at most the end of the received bytes, and after
    /// a resync at least the resync point. Without a start, the RST lies up
    /// to one window after the receiver's last ACK, or anywhere without such
    /// an ACK.
    fn accepts_reset(&self, offset: u64, window: u64) -> bool {
        match self.base {
            Some(base) => {
                let offset = offset as i64 - self.shift;
                let sent_end = self.highest + u64::from(self.fin_offset.is_some());
                let mut ack = self.ack.max(base) as i64;
                if let Some((kept, _)) = self.kept_ack {
                    ack = ack.min(kept as i64 - self.shift);
                }
                let received_end = (self.bytes.len() as u64).max(base);
                let mut first = ack.min(received_end as i64);
                if false == self.resyncs.is_empty() {
                    first = first.max(self.resync_offset() as i64);
                }
                first <= offset && offset <= (sent_end + window) as i64
            }
            None => self
                .kept_ack
                .is_none_or(|(ack, _)| ack <= offset && offset <= ack + window),
        }
    }
}

/// Returns true if the SYN-ACK `segment` ACKs the SYN `syn` of the same
/// script: it comes from the other endpoint and ACKs from the SYN's first
/// byte up to the end of its bytes.
fn acks_syn(segment: &TestSegment, syn: &TestSegment) -> bool {
    let bytes = syn.offset..=syn.offset + syn.payload.len() as u64;
    syn.incarnation == segment.incarnation
        && syn.source != segment.source
        && segment.ack.is_some_and(|ack| bytes.contains(&ack))
}

/// Returns true if the SYN `segment` retransmits the SYN `syn` of the same
/// script: it comes from the same endpoint, without the ACK flag.

fn retransmits_syn(segment: &TestSegment, syn: &TestSegment) -> bool {
    segment.header.syn
        && segment.header.ack == syn.header.ack
        && syn.incarnation == segment.incarnation
        && syn.sender == segment.sender
}

/// Returns true if the true offset `offset` lies at most `window` bytes
/// before or after the `bytes`.
fn within_window(bytes: &Range<u64>, offset: u64, window: u64) -> bool {
    offset + window >= bytes.start && offset <= bytes.end + window
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
    ///   if it gives a stream an observed start;
    /// - an RST that the receiver can accept (see
    ///   [`ModelStream::accepts_reset`]) resets the connection, and its ACK
    ///   counts. Other RSTs count as out-of-window. Neither stores anything
    ///   else of the RST.
    ///
    /// A SYN or SYN-ACK that is not the own one of its sender's stream (see
    /// [`ReferenceModel::is_own_syn`]) starts a reconnect (see
    /// [`ReferenceModel::starts_reconnect`]): it ends the connection, as
    /// finished if both FINs were ACKed and as a reconnect otherwise, and
    /// the model starts again as a new connection with the segment. The
    /// ended connection is returned. A SYN of a side without a start that
    /// may be blind (S5) is kept instead (a retransmission of it adds the
    /// bytes it carries beyond the kept ones and counts if its bytes differ,
    /// another SYN replaces it) until a SYN-ACK confirms it.
    ///
    /// The connection is finished once both FINs are ACKed, unless it was
    /// reset. Ending it gives up all holes;
    /// later segments change nothing, but a SYN or SYN-ACK that doesn't
    /// belong to its handshake starts a new connection (see
    /// [`ReferenceModel::is_own_handshake`]).
    pub fn apply(&mut self, segment: &TestSegment) -> Option<ReferenceModel> {
        let header = &segment.header;
        let reconnect = if self.end.is_some() {
            if header.rst || false == header.syn || self.is_own_handshake(segment) {
                // a retransmitted SYN can carry more Fast Open bytes
                if header.syn && self.has_isn_of_sender(segment) {
                    let stream = &mut self.streams[role_index(self.sender_role(segment))];
                    stream.syn_len = stream.syn_len.max(segment.payload.len() as u64);
                }
                return None;
            }
            true
        } else {
            // (only a connection that exists can be reconnected)
            self.created && self.starts_reconnect(segment)
        };
        if reconnect {
            // the reconnect starts at the segment
            let next = self.next_connection();
            let mut replaced = core::mem::replace(self, next);
            self.apply(segment);
            if replaced.end.is_some() {
                return None;
            }
            replaced.end_unless_finished(TcpConnectionEnd::Reconnect);
            return Some(replaced);
        }
        if false == self.created {
            if header.rst
                || (false == header.syn && (segment.payload.is_empty() || false == header.ack))
            {
                return None;
            }
            self.created = true;
            self.initiator = Some(if TcpRole::Initiator == segment.sender {
                segment.source
            } else {
                segment.destination
            });
            self.incarnation = Some(segment.incarnation);
            self.roles_guessed = false == header.syn;
        }
        self.packets += 1;
        let sender_role = self.sender_role(segment);
        let sender = role_index(sender_role);
        let other = role_index(sender_role.other());
        // the streams of the connection are the only ones in the pool
        let buffered: u64 = self.streams.iter().map(ModelStream::buffered).sum();
        let mut available = self
            .config
            .max_total_buffered
            .map_or(u64::MAX, |max| (max as u64).saturating_sub(buffered));
        let range = self.range(sender_role.other());
        let other_window = self.window(sender_role.other());
        // a side in SYN-RECEIVED checks an RST by its sequence number (F4),
        // and a SYN-ACK that ACKs the kept SYN confirms the reconnect (C2)
        let acks_kept_syn = header.syn
            && false == (header.rst || header.fin)
            && self
                .kept_syn
                .as_ref()
                .is_some_and(|syn| acks_syn(segment, syn));
        // every receiver drops a segment without ACK that is no SYN or RST
        // (S6)
        let same_script = Some(segment.incarnation) == self.incarnation;
        let without_ack = false == (header.ack || header.syn || header.rst);
        let bare = self.streams[sender].base.is_none() && self.streams[sender].kept_ack.is_none();
        let dropped = without_ack
            || (false == (header.rst && self.streams[sender].base.is_some())
                && false == acks_kept_syn
                && self.streams[other].drops_before_syn_acked(
                    segment,
                    range,
                    other_window,
                    bare,
                    same_script,
                ));
        if false == dropped {
            // a SYN-ACK or RST that ACKs the receiver's SYN outweighs a kept
            // ACK
            if (header.syn || header.rst)
                && self.answers_observed_syn(segment)
                && (header.rst || false == self.is_own_syn(segment))
            {
                self.streams[sender].kept_ack = None;
            }
            // an RST that F4 ignores is dropped with its ACK
            if false == header.rst {
                self.streams[other].answer_syn(segment, range, other_window, same_script);
            }
        }
        if dropped {
            self.streams[sender].out_of_window_segments += 1;
            // the dropped segments agree within the window of their own
            // stream (R3); a segment without ACK changes nothing else (S6)
            if false == without_ack {
                let window = self.window(sender_role);
                self.streams[other].record_dropped(segment, window, &self.config);
            }
        } else if header.rst {
            let window = self.window(sender_role);
            if self.streams[sender].accepts_reset(segment.offset, window) {
                if let Some(ack) = segment.ack {
                    let window = self.window(sender_role.other());
                    self.streams[other].add_ack(ack, window, self.packets, &self.config);
                }
                self.end = Some(TcpConnectionEnd::Reset { by: sender_role });
            } else {
                self.streams[sender].out_of_window_segments += 1;
            }
        } else if header.syn && self.maybe_blind_syn(segment) {
            if header.ack {
                // a SYN-ACK that may be blind is ignored (S5)
                self.streams[sender].out_of_window_segments += 1;
            } else if let Some(syn) = self
                .kept_syn
                .as_mut()
                .filter(|syn| retransmits_syn(segment, syn))
            {
                // the SYNs of a script all have the same ISN; a retransmission
                // of the kept SYN adds the Fast Open bytes beyond the kept
                // ones, the first win
                let overlap = syn.payload.len().min(segment.payload.len());
                if syn.payload[..overlap] != segment.payload[..overlap] {
                    self.kept_syn_conflicting += 1;
                }
                if let Some(added) = segment.payload.get(overlap..) {
                    syn.payload.extend_from_slice(added);
                }
            } else {
                self.kept_syn = Some(segment.clone());
                self.kept_syn_conflicting = 0;
            }
        } else {
            self.apply_own_segment(segment, &mut available);
        }
        // a kept SYN whose stream has a start is kept no longer: a late SYN
        // (A5), or dropped
        let started = self.kept_syn.as_ref().is_some_and(|syn| {
            self.streams[role_index(self.sender_role(syn))]
                .base
                .is_some()
        });
        if let Some(syn) = self.kept_syn.take_if(|_| started) {
            self.apply_kept_syn(syn, &mut available);
        }
        for role in [TcpRole::Initiator, TcpRole::Responder] {
            let window = self.known_window(role);
            self.streams[role_index(role)].after_packet(window, self.packets, &self.config);
        }
        if self.end.is_none() && self.streams.iter().all(ModelStream::can_finish) {
            self.end = Some(TcpConnectionEnd::Finished);
        }
        if let Some(end) = self.end {
            self.end_with(end);
        }
        None
    }

    /// Ends the connection with `end`, giving up all holes.
    fn end_with(&mut self, end: TcpConnectionEnd) {
        self.end = Some(end);
        let stream_end = match end {
            TcpConnectionEnd::Finished => TcpStreamEnd::Fin,
            TcpConnectionEnd::Reset { .. } => TcpStreamEnd::Reset,
            TcpConnectionEnd::Evicted => TcpStreamEnd::Evicted,
            TcpConnectionEnd::Reconnect => TcpStreamEnd::Reconnect,
        };
        for stream in &mut self.streams {
            stream.connection_ended(stream_end);
        }
    }

    /// Ends the connection, of which no more packets come: as finished if
    /// both FINs were ACKed, with `end` otherwise.
    fn end_unless_finished(&mut self, end: TcpConnectionEnd) {
        let finished = self.streams.iter().all(ModelStream::is_fin_acked);
        self.end_with(if finished {
            TcpConnectionEnd::Finished
        } else {
            end
        });
    }

    /// Evicts the connection (see [`TcpReassemblyPool::evict_all`]): an open
    /// one ends as finished if both FINs were ACKed, as evicted otherwise,
    /// and is returned. The model then starts again as the next connection
    /// on the key, which a later segment starts as on an unknown key.
    pub fn evict(&mut self) -> Option<ReferenceModel> {
        if false == self.created {
            return None;
        }
        let next = self.next_connection();
        let mut evicted = core::mem::replace(self, next);
        if evicted.end.is_some() {
            return None;
        }
        evicted.end_unless_finished(TcpConnectionEnd::Evicted);
        Some(evicted)
    }

    /// Applies the kept SYN `syn` to its stream as the stream's own (or late)
    /// SYN: an ACK kept for the stream that doesn't allow the SYN is dropped
    /// first, the SYN's conflicts count only if the SYN was taken, and an
    /// ACK kept for the stream counts right away then.
    fn apply_kept_syn(&mut self, syn: TestSegment, available: &mut u64) {
        let conflicting = core::mem::take(&mut self.kept_syn_conflicting);
        let syn_role = self.sender_role(&syn);
        let syn_sender = role_index(syn_role);
        // a stream that started at another SYN can't take the kept one
        if self.streams[syn_sender].observed && false == self.streams[syn_sender].has_isn_of(&syn) {
            self.streams[syn_sender].out_of_window_segments += 1;
            return;
        }
        if self.streams[syn_sender].base.is_none() && false == self.is_own_syn(&syn) {
            self.streams[syn_sender].kept_ack = None;
        }
        self.apply_own_segment(&syn, available);
        if self.streams[syn_sender].has_isn_of(&syn) {
            self.streams[syn_sender].conflicting_retransmissions += conflicting;
            let window = self.known_window(syn_role);
            self.streams[syn_sender].apply_kept_ack(window, &self.config);
        }
    }

    /// Applies `segment`, which the receiver accepts in its handshake state
    /// (S5, S6) and which is no RST or kept SYN, to the connection's streams,
    /// with the pool's budget `available`.
    fn apply_own_segment(&mut self, segment: &TestSegment, available: &mut u64) {
        let header = &segment.header;
        let sender_role = self.sender_role(segment);
        let sender = role_index(sender_role);
        let other = role_index(sender_role.other());
        // the SYN-ACK of a simultaneous open confirms the kept SYN of the
        // other side as that stream's own: it is applied first, so that the
        // stream starts at the SYN, and counts as no further packet
        if header.syn {
            // the stream's own SYN-ACK, repeating the kept SYN's ISN,
            // confirms it as well
            if let Some(syn) = self.kept_syn.take_if(|syn| {
                acks_syn(segment, syn)
                    || (syn.sender == segment.sender
                        && syn.incarnation == segment.incarnation
                        && syn.offset == segment.offset)
            }) {
                self.apply_kept_syn(syn, available);
                // the SYN-ACK answers the SYN of its receiver, which is the
                // applied SYN if the other side confirmed it
                let receiver = self.sender_role(segment).other();
                let (range, window) = (self.range(receiver), self.window(receiver));
                let same_script = Some(segment.incarnation) == self.incarnation;
                self.streams[role_index(receiver)].answer_syn(segment, range, window, same_script);
            }
        }
        let observed = self.streams.each_ref().map(|stream| stream.observed);
        // the ACK of a SYN-ACK that the other stream's kept ACK refuses
        // as its start is not kept either
        let mut ack_counts = true;
        if let (true, Some(ack)) = (header.syn, segment.ack) {
            let range = self.range(sender_role.other());
            let had_base = self.streams[other].base.is_some();
            let started = self.streams[other].observe_start(ack, 0, range, &self.config, available);
            ack_counts = started || had_base;
        }
        if let (true, Some(ack)) = (ack_counts, segment.ack) {
            let window = self.window(sender_role.other());
            self.streams[other].add_ack(ack, window, self.packets, &self.config);
        }
        let window = self.window(sender_role);
        let plausible = self.streams[sender].add_segment(
            segment,
            window,
            self.packets,
            &self.config,
            available,
        );
        // a retransmitted or late SYN carries the window from the start
        if plausible && false == (header.syn && self.windows[sender].is_some()) {
            self.windows[sender] = Some(header.window_size);
        }
        // the sender moved past its SYN (S5)
        if plausible && false == header.syn {
            self.streams[sender].syn_unacked = false;
        }
        // a SYN after a resync gives no window (A3), also after one that
        // kept the mapping
        self.syns[sender] |= header.syn
            && self.streams[sender].has_isn_of(segment)
            && self.streams[sender].resyncs.is_empty();
        let syn_role = if header.ack {
            TcpRole::Responder
        } else {
            TcpRole::Initiator
        };
        if header.syn
            && syn_role == sender_role
            && observed != self.streams.each_ref().map(|stream| stream.observed)
        {
            self.roles_guessed = false;
        }
    }

    /// Role of the sender of `segment` in this connection: the pool tells
    /// the roles by the endpoints, so a segment of a reconnect script with
    /// swapped roles has the other role in the connection it hits.
    fn sender_role(&self, segment: &TestSegment) -> TcpRole {
        match self.initiator {
            Some(initiator) if initiator != segment.source => TcpRole::Responder,
            Some(_) => TcpRole::Initiator,
            None => segment.sender,
        }
    }

    /// Model of the next connection on the same key.
    fn next_connection(&self) -> ReferenceModel {
        ReferenceModel {
            id: self.id + 1,
            ..ReferenceModel::new(self.config.clone())
        }
    }

    /// Returns true if the SYN or SYN-ACK `segment` starts a reconnect: it
    /// has a new ISN, i.e. it is not the own SYN or SYN-ACK of its sender's
    /// stream (see [`ReferenceModel::is_own_syn`]), may not be blind (S5),
    /// and the receiver doesn't drop it.
    fn starts_reconnect(&self, segment: &TestSegment) -> bool {
        let header = &segment.header;
        if false == header.syn || header.rst || header.fin {
            return false;
        }
        // a SYN-ACK that ACKs the kept SYN is applied (S5)
        let acks_kept_syn = self
            .kept_syn
            .as_ref()
            .is_some_and(|syn| acks_syn(segment, syn));
        if false == acks_kept_syn && self.dropped_before_syn_acked(segment) {
            return false;
        }
        false
            == (self.maybe_blind_syn(segment)
                || self.is_own_syn(segment)
                || self.answers_observed_syn(segment))
    }

    /// Returns true if the receiver drops `segment` while its SYN is
    /// unanswered (S5).
    fn dropped_before_syn_acked(&self, segment: &TestSegment) -> bool {
        let other_role = self.sender_role(segment).other();
        let other = role_index(other_role);
        let (range, window) = (self.range(other_role), self.window(other_role));
        let sender = role_index(self.sender_role(segment));
        let bare = self.streams[sender].base.is_none() && self.streams[sender].kept_ack.is_none();
        let same_script = Some(segment.incarnation) == self.incarnation;
        self.streams[other].drops_before_syn_acked(segment, range, window, bare, same_script)
    }

    /// Returns true if `segment`, whose sender's stream has no start, ACKs
    /// the observed SYN of the other stream (S5).
    fn answers_observed_syn(&self, segment: &TestSegment) -> bool {
        let sender = self.sender_role(segment);
        self.streams[role_index(sender)].base.is_none()
            && segment.ack.is_some_and(|ack| {
                let same_script = Some(segment.incarnation) == self.incarnation;
                self.streams[role_index(sender.other())].acks_syn_of(ack, same_script)
            })
    }

    /// Returns true if the SYN `segment` without ACK comes from a side
    /// without a start while the other side's SYN is unanswered: it may be
    /// blind, so it is only kept (S5).
    fn maybe_blind_syn(&self, segment: &TestSegment) -> bool {
        let sender = self.sender_role(segment);
        self.streams[role_index(sender)].base.is_none()
            && self.streams[role_index(sender.other())].syn_unacked
    }

    /// Range before and after the bytes of the stream of `role` that its
    /// receiver accepts: k windows (k is the hole give up window factor, 2
    /// without one).
    fn range(&self, role: TcpRole) -> u64 {
        let factor = self.config.hole_give_up_window_factor.unwrap_or(2).max(1);
        u64::from(factor) * self.window(role)
    }

    /// Returns true if the SYN or SYN-ACK `segment` belongs to the handshake
    /// of the connection: it comes from the connection's script, and it has
    /// the ISN of its sender's stream, or it is a SYN-ACK that ACKs the
    /// observed start of the other stream.
    fn is_own_handshake(&self, segment: &TestSegment) -> bool {
        let other = &self.streams[role_index(self.sender_role(segment).other())];
        // the SYN-ACK can ACK the SYN's TCP Fast Open bytes too
        let acks_syn = match (other.base, segment.ack) {
            (Some(base), Some(ack)) => (base..=base + other.syn_len).contains(&ack),
            _ => false,
        };
        self.has_isn_of_sender(segment)
            || (Some(segment.incarnation) == self.incarnation && other.observed && acks_syn)
    }

    /// Returns true if the SYN or SYN-ACK `segment` comes from the
    /// connection's script and has the ISN of its sender's stream (see
    /// [`ModelStream::has_isn_of`]).
    fn has_isn_of_sender(&self, segment: &TestSegment) -> bool {
        Some(segment.incarnation) == self.incarnation
            && self.streams[role_index(self.sender_role(segment))].has_isn_of(segment)
    }

    /// Returns true if the SYN `segment` can be the own SYN of its sender's
    /// stream (see [`ModelStream::is_own_syn`]). SYNs of other scripts lie
    /// far away from the streams, so they never are.
    fn is_own_syn(&self, segment: &TestSegment) -> bool {
        Some(segment.incarnation) == self.incarnation
            && self.streams[role_index(self.sender_role(segment))]
                .is_own_syn(segment, self.range(self.sender_role(segment)))
    }

    /// Returns true if the model predicts what the pool does with
    /// `segment`. For segments of another script than the connection's, it
    /// only does on the tombstone of an ended connection, for a SYN-ACK that
    /// ACKs the kept SYN, and for SYNs and SYN-ACKs while every stream has a
    /// start or an ACK of the other side (a stream without either takes any
    /// of them as its own, and its role is unknown here).
    pub fn predicts(&self, segment: &TestSegment) -> bool {
        let header = &segment.header;
        let acks_kept_syn = self
            .kept_syn
            .as_ref()
            .is_some_and(|syn| acks_syn(segment, syn));
        false == self.created
            || self.end.is_some()
            || Some(segment.incarnation) == self.incarnation
            || (header.syn
                && false == header.rst
                && (acks_kept_syn
                    || self
                        .streams
                        .iter()
                        .all(|stream| stream.base.is_some() || stream.kept_ack.is_some())))
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

    /// Id of the connection.
    pub fn id(&self) -> TcpConnectionId {
        TcpConnectionId(self.id)
    }

    /// Incarnation of the script whose segment started the connection.
    pub fn incarnation(&self) -> Option<u32> {
        self.incarnation
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
    /// `role` match the bytes of `data` sent at the same true offsets,
    /// apart from bytes that were given up or discarded and bytes before the
    /// stream's first byte known to the pool.
    pub fn received_matches(&self, role: TcpRole, data: &[u8]) -> bool {
        let stream = &self.streams[role_index(role)];
        let base = stream.base.unwrap_or(0);
        stream.received.iter().enumerate().all(|(offset, byte)| {
            let offset = offset as u64;
            let shift = stream
                .resyncs
                .iter()
                .rev()
                .find(|(resync, _)| *resync <= offset)
                .map_or(0, |(_, shift)| *shift);
            let sent = usize::try_from(offset as i64 + shift)
                .ok()
                .and_then(|offset| data.get(offset));
            offset < base
                || stream.given_up.iter().any(|gap| gap.contains(&offset))
                || stream.discarded.iter().any(|range| range.contains(&offset))
                || sent.is_none_or(|sent| sent == byte)
        })
    }

    /// Number of resyncs of the stream of `role`.
    pub fn resyncs(&self, role: TcpRole) -> u64 {
        self.streams[role_index(role)].resyncs.len() as u64
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
            ReaderAction::ForceResync => {
                expected.force_resync();
                stream.force_resync();
            }
        }
        Ok(())
    }

    /// Checks `stream` against the stream of `role` as
    /// [`ReferenceModel::check_and_consume`] does, reading both to their
    /// end and stepping over gaps.
    pub fn check_to_end(
        &mut self,
        role: TcpRole,
        stream: &mut TcpStream,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        use proptest::prelude::*;

        for _ in 0..10_000 {
            self.check_and_consume(role, stream, usize::MAX, false)?;
            match stream.read_received() {
                TcpRead::Data(_) => {}
                TcpRead::Gap { .. } => self.apply_action(role, stream, ReaderAction::ConsumeGap)?,
                read => {
                    prop_assert!(matches!(read, TcpRead::End(_)));
                    return Ok(());
                }
            }
        }
        prop_assert!(false, "stream not read to its end");
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
        // the memory limits hold (the missing bytes after the furthest
        // stored byte can make one more hole, and resyncs wait while there
        // are more gaps than holes allowed)
        let config = &self.config;
        prop_assert!(stream.holes().count() <= config.max_holes_per_stream.saturating_add(1));
        prop_assert!(expected.counted_holes() <= config.max_holes_per_stream);
        prop_assert!(expected.buffered() <= config.max_stream_buffer as u64);
        if self.end.is_none() {
            let gaps = expected.gaps.len() + expected.resync_gaps.len();
            prop_assert!(gaps <= config.max_holes_per_stream.saturating_mul(2) + 2);
        }
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
        let clean = 0 == expected.gap_count
            && expected.resyncs.is_empty()
            && 0 == expected.conflicting_retransmissions
            && 0 == expected.rejected_bytes;
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
                resyncs: expected.resyncs.len() as u64,
                conflicting_retransmissions: expected.conflicting_retransmissions,
                rejected_bytes: expected.rejected_bytes,
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
            read_len = match read {
                TcpRead::Data(data) => data.len(),
                _ => 0,
            };
            prop_assert_eq!(expected_read, read);
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

    /// Sends the bytes `data` of both streams (indexed by role) after the
    /// bytes each role sent so far, in segments cut by `segment_lens` and
    /// interleaved by `directions` (true for the initiator). Each segment
    /// starts with up to `resent_lens` bytes of `data` that were already
    /// sent.
    fn send_interleaved(
        script: &mut ConnectionScript,
        data: [&[u8]; 2],
        segment_lens: &[usize],
        resent_lens: &[usize],
        directions: &[bool],
    ) {
        let offsets = [Initiator, Responder].map(|role| script.next_offset(role));
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
            script.send_at(
                role,
                offsets[i] + start as u64,
                &data[i][start..sent[i] + len],
            );
            sent[i] += len;
            step += 1;
        }
    }

    /// Feeds `segments` to `pool` and checks both streams against the
    /// reference model after each segment, reading partially from the pool
    /// or from the ended connection it handed over. `acked_reads` decides
    /// whether the bytes are consumed after reading them with `read_acked`
    /// or `read_received`, `actions` what the reader does before reading,
    /// and `evictions` whether all connections are evicted before a segment
    /// (see [`evict_and_check`]). Segments whose effect the model can't
    /// predict are left out (see [`ReferenceModel::predicts`]).
    ///
    /// Returns the model and the ended connection, if any.
    fn feed_and_check(
        pool: &mut TcpReassemblyPool<(), ()>,
        segments: &[TestSegment],
        consume_lens: &[usize],
        acked_reads: &[bool],
        actions: &[Option<ReaderAction>],
        evictions: &[bool],
    ) -> Result<(ReferenceModel, Option<TcpConnection>), TestCaseError> {
        let mut model = ReferenceModel::new(pool.config().clone());
        let mut ended = None;
        for (step, segment) in segments.iter().enumerate() {
            if evictions[step % evictions.len()] {
                evict_and_check(pool, &mut model)?;
            }
            if false == model.predicts(segment) {
                continue;
            }
            // segments on the tombstone are ignored, unless they start a new
            // connection
            let id = model.id();
            let after_end = model.end().is_some();
            let replaced = model.apply(segment);
            let after_end = after_end && id == model.id();
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
                // a confirmed reconnect hands over the connection it replaced
                prop_assert_eq!(None, processed.ignored);
                prop_assert_eq!(replaced.is_some(), processed.ended.is_some());
                if let (Some(mut expected), Some(mut replaced)) = (replaced, processed.ended) {
                    prop_assert_eq!(expected.id(), replaced.id());
                    prop_assert_eq!(expected.end(), replaced.end());
                    for role in [Initiator, Responder] {
                        expected.check_and_consume(role, replaced.stream_mut(role), 0, false)?;
                    }
                }
                processed.active.unwrap().0
            };
            prop_assert_eq!(model.id(), connection.id());
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

    /// Evicts all connections of `pool` and checks that the callback gets
    /// the one the model expects, if any (see [`ReferenceModel::evict`]),
    /// reading it to its end.
    fn evict_and_check(
        pool: &mut TcpReassemblyPool<(), ()>,
        model: &mut ReferenceModel,
    ) -> Result<(), TestCaseError> {
        let mut expected = model.evict();
        let mut checked = Ok(());
        let mut calls = 0;
        let count = pool.evict_all(|connection| {
            calls += 1;
            if let Some(expected) = expected.as_mut() {
                checked = (|| {
                    prop_assert_eq!(expected.id(), connection.id());
                    prop_assert_eq!(expected.end(), connection.end());
                    for role in [Initiator, Responder] {
                        expected.check_to_end(role, connection.stream_mut(role))?;
                    }
                    Ok(())
                })();
            }
        });
        checked?;
        prop_assert_eq!(usize::from(expected.is_some()), count);
        prop_assert_eq!(count, calls);
        Ok(())
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
                &[false],
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
            // the retransmissions and duplicates start at random positions;
            // the FINs and their ACKs (also retransmitted or duplicated ones)
            // stay behind all data, as a capture shows a direction's data
            // before its FIN (and the ACK of the FIN comes an RTT later), and
            // the connection finishes at that ACK whatever holes are left (F3)
            let closing = originals - fins.iter().filter(|fin| **fin).count() - 2;
            let mut keyed: Vec<_> = script
                .segments
                .drain(3..)
                .enumerate()
                .map(|(i, segment)| {
                    let closes = segment.header.fin || segment.payload.is_empty();
                    let position = if i < closing {
                        i
                    } else if i < originals || closes {
                        originals + 8
                    } else {
                        positions[i % positions.len()].index(closing + 1)
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
                &[false],
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
                &[false],
            )?;

            // the ACKs don't change the received bytes, but they can make
            // holes overdue, whose bytes are ignored after they were given up
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received(role).len() >= data[i].len());
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
            // (without an ACK, so that nothing confirms a jump to them)
            for (role, position, distance, payload, fin) in &injected {
                let offset = data[role_index(*role)].len() as u64 + distance;
                let mut segment = script.injected(|script| {
                    if *fin {
                        script.fin_at(*role, offset, payload);
                    } else {
                        script.send_at(*role, offset, payload);
                    }
                });
                segment.header.ack = false;
                segment.ack = None;
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
                &[false],
            )?;

            // the injected segments after the window are only counted: the
            // streams don't resync, and keep the bytes that were sent
            // (injected bytes within the window can make the hole before
            // them overdue, whose bytes are ignored after it was given up)
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert_eq!(0, model.resyncs(role));
                prop_assert!(model.received(role).len() >= data[i].len());
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
                &[false],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received_matches(role, data[i]));
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
                &[false],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up or lie before the first byte captured
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received_matches(role, data[i]));
            }
        }

        #[test]
        fn resyncs(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            before in [stream_data_any(4 * 1024), stream_data_any(4 * 1024)],
            after in [stream_data_any(4 * 1024), stream_data_any(4 * 1024)],
            jumps in [
                proptest::option::of(prop_oneof![0u64..1000, 3000u64..20_000]),
                proptest::option::of(prop_oneof![0u64..1000, 3000u64..20_000]),
            ],
            segment_lens in vec(1usize..200, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            pickup in any::<bool>(),
            one_direction in any::<bool>(),
            lost in vec(any::<Index>(), 0..4),
            injected in vec(
                (tcp_role_any(), any::<Index>(), 0u64..5000, vec(any::<u8>(), 1..8)),
                0..4
            ),
            window in 200u16..1000,
            resync_after_segments in proptest::option::of(0u32..4),
            delays in proptest::option::of(vec(0usize..3, 1..64)),
            actions in vec(proptest::option::weighted(0.05, Just(ReaderAction::ForceResync)), 1..32),
            consume_lens in vec(0usize..3000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // both streams send their bytes, then the streams with a jump
            // continue later (the bytes in between were not captured),
            // followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.window_size = window;
            script.handshake();
            send_interleaved(&mut script, [&before[0], &before[1]], &segment_lens, &[0], &directions);
            for (role, jump) in [Initiator, Responder].into_iter().zip(jumps) {
                if let Some(jump) = jump {
                    script.send_uncaptured(role, jump);
                }
            }
            send_interleaved(&mut script, [&after[0], &after[1]], &segment_lens, &[0], &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // segments lost in the capture
            for index in &lost {
                if script.segments.len() > 3 {
                    script.segments.remove(3 + index.index(script.segments.len() - 3));
                }
            }

            // segments the endpoints didn't send, without an ACK, near or
            // after the end of the stream (data after the window that
            // doesn't agree with the bytes after the jump)
            let sent = [0, 1].map(|i| {
                before[i].len() as u64 + jumps[i].unwrap_or(0) + after[i].len() as u64
            });
            for (role, position, distance, payload) in &injected {
                let mut segment = script.injected(|script| {
                    script.send_at(*role, sent[role_index(*role)] + distance, payload);
                });
                segment.header.ack = false;
                segment.ack = None;
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, segment);
            }

            // a capture of the initiator's direction only (and the SYN-ACK),
            // so no ACKs confirm its jump
            if one_direction {
                let mut i = 0;
                script.segments.retain(|segment| {
                    i += 1;
                    i <= 3 || Initiator == segment.sender
                });
            }

            // the capture starts after the handshake
            let first = if pickup {
                script.segments.drain(..3);
                0
            } else {
                3
            };

            // move the segments after the handshake by a bounded distance
            if let Some(delays) = &delays {
                let mut keyed: Vec<_> = script
                    .segments
                    .drain(first..)
                    .enumerate()
                    .map(|(i, segment)| (i + delays[i % delays.len()], segment))
                    .collect();
                keyed.sort_by_key(|(key, _)| *key);
                script.segments.extend(keyed.into_iter().map(|(_, segment)| segment));
            }

            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                fallback_window: u32::from(window),
                resync_after_segments,
                ..Default::default()
            });
            let (model, _) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &actions,
                &[false],
            )?;

            // the bytes after a resync are the ones sent after the jump (the
            // injected bytes lie after them)
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                let mut sent = before[i].clone();
                sent.resize(before[i].len() + jumps[i].unwrap_or(0) as usize, 0);
                sent.extend_from_slice(&after[i]);
                prop_assert!(model.received_matches(role, &sent));
            }

            // in an undisturbed capture of both directions, the ACKs of the
            // other side make a stream resync after a jump of more than k
            // windows (if earlier bytes arrive after the bytes after the
            // jump, they show that the stream didn't jump, until more bytes
            // after the jump arrive)
            let disturbed = one_direction
                || delays.is_some()
                || false == lost.is_empty()
                || false == injected.is_empty();
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                let jumped = jumps[i].is_some_and(|jump| jump >= 3000)
                    && false == after[i].is_empty()
                    && (false == pickup || false == before[i].is_empty());
                if jumped && false == disturbed {
                    prop_assert!(model.resyncs(role) > 0);
                }
            }
        }

        #[test]
        fn resets(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(4 * 1024),
            responder_data in stream_data_any(4 * 1024),
            segment_lens in vec(1usize..500, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            rst in proptest::option::of((tcp_role_any(), any::<Index>(), any::<bool>())),
            injected in vec(
                (
                    tcp_role_any(),
                    any::<Index>(),
                    any::<bool>(),
                    prop_oneof![0u64..64, 0u64..8192, 0u64..(1 << 30)],
                    any::<bool>(),
                ),
                0..4
            ),
            lost in vec(any::<Index>(), 0..4),
            one_direction in any::<bool>(),
            pickup in any::<bool>(),
            windows in vec(
                prop_oneof![1 => 0u16..64, 1 => 64u16..2048, 1 => Just(u16::MAX)],
                1..16
            ),
            fallback_window in prop_oneof![Just(4 * 1024 * 1024), 64u32..4096],
            config in tcp_overdue_config_any(),
            consume_lens in vec(0usize..1000, 1..32),
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

            // an RST of an endpoint after the SYN (e.g. of a closed port), at
            // the next byte it would send and ACKing what the other side sent
            // so far (or without an ACK), followed by the segments sent after
            // it, whose late arrival is ignored; one without ACK while the
            // receiver is in SYN-SENT is dropped (S5)
            let mut rst_dropped = false;
            if let Some((role, position, with_ack)) = &rst {
                let position = 1 + position.index(script.segments.len());
                rst_dropped = false == *with_ack && 1 == position && Responder == *role;
                let next = |role| {
                    script.segments[..position]
                        .iter()
                        .filter(|segment| role == segment.sender)
                        .map(|segment| {
                            segment.offset
                                + segment.payload.len() as u64
                                + u64::from(segment.header.fin)
                        })
                        .max()
                        .unwrap_or(0)
                };
                let mut segment = script.injected(|script| {
                    script.rst_at(*role, next(*role));
                });
                if *with_ack {
                    let ack = next(role.other());
                    segment.ack = Some(ack);
                    segment.header.acknowledgment_number = script.seq(role.other(), ack);
                } else {
                    segment.ack = None;
                    segment.header.ack = false;
                }
                script.segments.insert(position, segment);
            }

            // RSTs the endpoints didn't send, before or after the end of the
            // stream of their sender (with an ACK of everything the other
            // side sent, or without one)
            for (role, position, before, distance, with_ack) in &injected {
                let len = data[role_index(*role)].len() as u64;
                let offset = if *before {
                    len.saturating_sub(*distance)
                } else {
                    len + distance
                };
                let mut segment = script.injected(|script| {
                    script.rst_at(*role, offset);
                });
                if false == *with_ack {
                    segment.ack = None;
                    segment.header.ack = false;
                }
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, segment);
            }

            // segments lost in the capture (but no RSTs)
            for index in &lost {
                let i = 3 + index.index(script.segments.len() - 3);
                if false == script.segments[i].header.rst {
                    script.segments.remove(i);
                }
            }

            // a capture of the initiator's direction only (and the SYN-ACK),
            // plus the RSTs
            if one_direction {
                script.segments.retain(|segment| {
                    segment.header.syn || Initiator == segment.sender || segment.header.rst
                });
            }

            // the capture starts after the handshake (but with the RSTs)
            if pickup {
                let mut removed = 0;
                script.segments.retain(|segment| {
                    let remove = removed < 3 && false == segment.header.rst;
                    removed += usize::from(remove);
                    false == remove
                });
            }

            // random receive windows, and RSTs with a window of 0 (which
            // doesn't count)
            for (segment, window) in script.segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = if segment.header.rst { 0 } else { *window };
            }

            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                fallback_window,
                ..config
            });
            let (model, ended) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
                &[false],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up or lie before the first byte captured
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert!(model.received_matches(role, data[i]));
            }

            // in a complete capture without injected RSTs, the receiver
            // accepts the endpoint's RST, unless the connection finished
            // before it
            let undisturbed = false == pickup
                && false == one_direction
                && lost.is_empty()
                && injected.is_empty();
            if let (true, false, Some((role, _, _))) = (undisturbed, rst_dropped, &rst) {
                let end = model.end();
                let reset = TcpConnectionEnd::Reset { by: *role };
                prop_assert!(Some(TcpConnectionEnd::Finished) == end || Some(reset) == end);
            }

            // an ended connection can be read to its end, stepping over the
            // gaps: the FIN ends a stream whose FIN was seen, the reset the
            // others
            if let Some(mut connection) = ended {
                prop_assert_eq!(model.end(), connection.end());
                for role in [Initiator, Responder] {
                    let stream = connection.stream_mut(role);
                    prop_assert_eq!(0, stream.holes().count());
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
                    let end = if model.fin_offset(role).is_some() {
                        TcpStreamEnd::Fin
                    } else {
                        TcpStreamEnd::Reset
                    };
                    prop_assert_eq!(TcpRead::End(end), stream.read_received());
                }
                pool.recycle(connection);
            }
        }

        // both SYNs and SYN-ACKs of a simultaneous open in any order, some
        // not captured, with TCP Fast Open bytes the SYN-ACKs ACK or not
        // (S5, C3, A5)
        #[test]
        fn simultaneous_opens(
            isns in [tcp_isn_any(), tcp_isn_any()],
            fast_open in [stream_data_any(8), stream_data_any(8)],
            syn_ack_payload_kind in 0u8..3,
            acks_fast_open in [any::<bool>(), any::<bool>()],
            data in [stream_data_any(1024), stream_data_any(1024)],
            segment_lens in vec(1usize..300, 1..16),
            directions in vec(any::<bool>(), 1..32),
            order in Just(std::vec![0usize, 1, 2, 3]).prop_shuffle(),
            syn_first in any::<bool>(),
            lost in [any::<bool>(), any::<bool>(), any::<bool>()],
            windows in vec(prop_oneof![1 => 1u16..256, 2 => 256u16..8192, 1 => Just(u16::MAX)], 1..8),
            fallback_window in prop_oneof![Just(4 * 1024 * 1024), 64u32..8192],
            config in tcp_overdue_config_any(),
            resync_after_segments in proptest::option::of(1u32..3),
            consume_lens in vec(0usize..1000, 1..16),
            acked_reads in vec(any::<bool>(), 1..16),
        ) {
            let mut script = ConnectionScript::with_isns(isns[0], isns[1]);
            script.syn_with_data(&fast_open[0]);
            script.syn_ack();
            script.send_uncaptured(Responder, fast_open[1].len() as u64);
            let i_syn = script.segments[0].clone();
            let mut r_syn = script.segments[1].clone();
            r_syn.header.ack = false;
            r_syn.header.acknowledgment_number = 0;
            r_syn.ack = None;
            r_syn.payload = fast_open[1].to_vec();
            let mut r_syn_ack = script.segments[1].clone();
            if false == acks_fast_open[0] {
                r_syn_ack.ack = Some(0);
                r_syn_ack.header.acknowledgment_number = script.seq(Initiator, 0);
            }
            r_syn_ack.payload = match syn_ack_payload_kind {
                0 => Vec::new(),
                1 => fast_open[1].to_vec(),
                _ => fast_open[1].iter().map(|b| b ^ 1).collect(),
            };
            let mut i_syn_ack = script.segments[0].clone();
            i_syn_ack.header.ack = true;
            let acked = if acks_fast_open[1] { fast_open[1].len() as u64 } else { 0 };
            i_syn_ack.ack = Some(acked);
            i_syn_ack.header.acknowledgment_number = script.seq(Responder, acked);
            send_interleaved(&mut script, [&data[0][..], &data[1][..]], &segment_lens, &[0], &directions);
            script.fin(Initiator).fin(Responder).ack(Initiator);
            let rest = script.segments[2..].to_vec();

            let handshake = [i_syn, r_syn, r_syn_ack, i_syn_ack];
            let mut order = order.clone();
            if syn_first {
                order.retain(|i| *i != 0);
                order.insert(0, 0);
            }
            // the model takes the roles from the script, so the first segment
            // must be the initiator's SYN or the responder's SYN-ACK
            if false == (order[0] == 0 || (order[0] == 2 && false == lost[1])) {
                order.retain(|i| *i != 0);
                order.insert(0, 0);
            }
            let mut segments = Vec::new();
            for i in order {
                let dropped = match i {
                    1 => lost[0],
                    2 => lost[1],
                    3 => lost[2],
                    _ => false,
                };
                if false == dropped {
                    segments.push(handshake[i].clone());
                }
            }
            segments.extend(rest);
            for (segment, window) in segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = *window;
            }
            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                fallback_window,
                resync_after_segments,
                ..config
            });
            feed_and_check(&mut pool, &segments, &consume_lens, &acked_reads, &[None], &[false])?;
        }

        #[test]
        fn reconnects(
            isns in [tcp_isn_any(), tcp_isn_any()],
            new_isn_distances in [0u32..(1 << 20), 0u32..(1 << 20)],
            old_data in [stream_data_any(2 * 1024), stream_data_any(2 * 1024)],
            new_data in [stream_data_any(2 * 1024), stream_data_any(2 * 1024)],
            fast_open in stream_data_any(16),
            segment_lens in vec(1usize..500, 1..32),
            directions in vec(any::<bool>(), 1..64),
            old_end in proptest::option::of(proptest::option::of(tcp_role_any())),
            pickup in any::<bool>(),
            lost in vec(any::<Index>(), 0..4),
            swapped in any::<bool>(),
            syn_position in any::<Index>(),
            syn_ack_delay in -4isize..8,
            between in 0usize..4,
            interleaving in vec(any::<bool>(), 1..64),
            retransmitted_syns in vec((any::<bool>(), any::<Index>()), 0..3),
            windows in vec(
                prop_oneof![1 => 1u16..256, 2 => 256u16..8192, 1 => Just(u16::MAX)],
                1..16
            ),
            fallback_window in prop_oneof![Just(4 * 1024 * 1024), 64u32..8192],
            config in tcp_overdue_config_any(),
            consume_lens in vec(0usize..1000, 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // the connection on the key before the reconnect: open, finished
            // (`Some(None)`) or reset by an endpoint, captured from its
            // handshake or picked up in the middle, with lost segments
            let mut old = ConnectionScript::with_isns(isns[0], isns[1]);
            old.handshake();
            let data = [&old_data[0][..], &old_data[1][..]];
            send_interleaved(&mut old, data, &segment_lens, &[0], &directions);
            match old_end {
                Some(None) => {
                    old.fin(Initiator).fin(Responder).ack(Initiator);
                }
                Some(Some(role)) => {
                    old.rst(role);
                }
                None => {}
            }
            for index in &lost {
                if old.segments.len() > 3 {
                    old.segments.remove(3 + index.index(old.segments.len() - 3));
                }
            }
            let old_syn = old.segments[0].clone();
            if pickup {
                old.segments.drain(..3);
            }

            // the reconnect, whose initiator is either endpoint (with TCP Fast
            // Open bytes in its SYN), and whose ISNs lie far away from the
            // ones each endpoint used before
            let endpoints = [addr("10.0.0.1:50000"), addr("10.0.0.2:80")];
            let order = if swapped { [1, 0] } else { [0, 1] };
            let new_isns =
                order.map(|i| isns[i].wrapping_add((1 << 30) + new_isn_distances[i]));
            let [initiator, responder] = order.map(|i| endpoints[i]);
            let mut new = ConnectionScript::new(initiator, responder, new_isns[0], new_isns[1]);
            new.incarnation = 1;
            new.syn_with_data(&fast_open).syn_ack().ack(Initiator);
            let data = [&new_data[0][..], &new_data[1][..]];
            send_interleaved(&mut new, data, &segment_lens, &[0], &directions);
            new.fin(Initiator).fin(Responder).ack(Initiator);

            // the new SYN comes after the old handshake (or the first segment
            // of a pickup), its SYN-ACK a few old segments later (or before
            // the SYN, with a negative delay, as in a capture merged from two
            // taps), a few segments of the reconnect between the two, and
            // then the rest of both connections interleaved (old segments
            // after the reconnect are left out, see `ReferenceModel::predicts`)
            // (a SYN-ACK before the ACK of the old handshake would be dropped
            // while the old responder's SYN is unanswered, S5)
            let first = if pickup {
                1
            } else if syn_ack_delay < 0 {
                3
            } else {
                2
            };
            let first = first.min(old.segments.len());
            let syn_at = first + syn_position.index(old.segments.len() - first + 1);
            let syn_ack_at = (syn_at + syn_ack_delay.unsigned_abs()).min(old.segments.len());
            // (only the first half's sender can have segments between the
            // halves: the other endpoint sends nothing before its own half)
            let [first_half, second_half] = if syn_ack_delay < 0 { [1, 0] } else { [0, 1] };
            let first_sender = new.segments[first_half].sender;
            let (early, late): (Vec<_>, Vec<_>) = new.segments[2..]
                .iter()
                .enumerate()
                .partition(|(i, segment)| {
                    segment.sender == first_sender
                        && new.segments[2..2 + i].iter().filter(|s| s.sender == first_sender).count()
                            < between
                });
            let mut segments = old.segments[..syn_at].to_vec();
            // where the reconnect's handshake starts: old SYN retransmissions
            // come before it (on a tombstone the first half starts the
            // reconnect, and an old SYN kept on it would keep the old
            // connection's late segments with it, which the model can't
            // place)
            let mut handshake_start = segments.len();
            segments.push(new.segments[first_half].clone());
            segments.extend_from_slice(&old.segments[syn_at..syn_ack_at]);
            segments.extend(early.into_iter().map(|(_, segment)| segment.clone()));
            segments.push(new.segments[second_half].clone());
            let mut old_rest = old.segments[syn_ack_at..].iter();
            let late: Vec<_> = late.into_iter().map(|(_, segment)| segment).collect();
            let mut new_rest = late.into_iter();
            for take_old in interleaving.iter().cycle() {
                let next = if *take_old {
                    old_rest.next().or_else(|| new_rest.next())
                } else {
                    new_rest.next().or_else(|| old_rest.next())
                };
                let Some(segment) = next else {
                    break;
                };
                segments.push(segment.clone());
            }

            // retransmissions of the old or the new SYN
            for (retransmit_new, position) in &retransmitted_syns {
                let syn = if *retransmit_new { &new.segments[0] } else { &old_syn };
                let at = if *retransmit_new {
                    1 + position.index(segments.len())
                } else if 0 == handshake_start {
                    0
                } else {
                    1 + position.index(handshake_start)
                };
                segments.insert(at, syn.clone());
                if at <= handshake_start {
                    handshake_start += 1;
                }
            }
            // random receive windows (used once both SYNs were seen)
            for (segment, window) in segments.iter_mut().zip(windows.iter().cycle()) {
                segment.header.window_size = *window;
            }

            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                fallback_window,
                ..config
            });
            let (model, _) = feed_and_check(
                &mut pool,
                &segments,
                &consume_lens,
                &acked_reads,
                &[None],
                &[false],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up or lie before the first byte captured
            let new_initiator_data = [&fast_open[..], &new_data[0][..]].concat();
            let data = match model.incarnation() {
                Some(1) => [&new_initiator_data[..], &new_data[1][..]],
                _ => [&old_data[0][..], &old_data[1][..]],
            };
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                if Some(2) > model.incarnation() {
                    prop_assert!(model.received_matches(role, data[i]));
                }
            }

            // without SYNs between them, the new SYN and its SYN-ACK always
            // start the reconnect, whether the old connection ended or not
            if retransmitted_syns.iter().all(|(new, _)| *new) {
                prop_assert_eq!(Some(1), model.incarnation());
            }
        }

        #[test]
        fn memory_limits(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            data in [stream_data_any(4 * 1024), stream_data_any(4 * 1024)],
            jumps in [
                proptest::option::weighted(0.2, 3000u64..20_000),
                proptest::option::weighted(0.2, 3000u64..20_000),
            ],
            segment_lens in vec(1usize..300, 1..32),
            resent_lens in vec(0usize..200, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            acks in vec((tcp_role_any(), any::<Index>(), any::<Index>()), 0..4),
            lost in vec((any::<Index>(), proptest::option::of(any::<Index>())), 0..16),
            pickup in proptest::option::of(
                (any::<Index>(), vec((any::<Index>(), 0usize..16), 0..4))
            ),
            window in 200u16..1000,
            max_stream_buffer in prop_oneof![0usize..16, 16usize..2048, Just(8 * 1024 * 1024)],
            max_holes_per_stream in prop_oneof![3 => 0usize..4, 1 => Just(256usize)],
            max_total_buffered in proptest::option::of(prop_oneof![0usize..32, 32usize..4096]),
            actions in vec(
                proptest::option::weighted(0.2, prop_oneof![
                    Just(ReaderAction::GiveUpHole),
                    Just(ReaderAction::ConsumeGap),
                    (0u64..64).prop_map(ReaderAction::DiscardAhead),
                    Just(ReaderAction::ForceResync),
                ]),
                1..32
            ),
            consume_lens in vec(prop_oneof![Just(0usize), 0usize..600], 1..32),
            acked_reads in vec(any::<bool>(), 1..32),
        ) {
            // both streams send their bytes in randomly cut and interleaved
            // segments, and some streams jump half way (the bytes in between
            // were not captured), followed by the FINs and their ACKs
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.window_size = window;
            script.handshake();
            let half = [0, 1].map(|i| data[i].len() / 2);
            let before = [0, 1].map(|i| &data[i][..half[i]]);
            let after = [0, 1].map(|i| &data[i][half[i]..]);
            send_interleaved(&mut script, before, &segment_lens, &resent_lens, &directions);
            for (role, jump) in [Initiator, Responder].into_iter().zip(jumps) {
                if let Some(jump) = jump {
                    script.send_uncaptured(role, jump);
                }
            }
            send_interleaved(&mut script, after, &segment_lens, &resent_lens, &directions);
            for role in [Initiator, Responder] {
                if fins[role_index(role)] {
                    script.fin(role);
                }
            }
            script.ack(Initiator).ack(Responder);

            // pure ACKs of random offsets (also after the bytes that were
            // sent) at random positions after the handshake
            for (role, position, offset) in &acks {
                let sent = script.next_offset(role.other()) as usize + 1;
                script.ack_to(*role, offset.index(2 * sent) as u64);
                let ack = script.segments.pop().unwrap();
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, ack);
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

            // the capture starts at a random segment, a few of the segments
            // before it are captured later (e.g. the SYN)
            if let Some((start, late)) = &pickup {
                let missed: Vec<_> = script
                    .segments
                    .drain(..start.index(script.segments.len()))
                    .collect();
                if false == missed.is_empty() {
                    for (index, position) in late {
                        let segment = missed[index.index(missed.len())].clone();
                        let position = (*position).min(script.segments.len());
                        script.segments.insert(position, segment);
                    }
                }
            }

            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                max_stream_buffer,
                max_holes_per_stream,
                max_total_buffered,
                fallback_window: u32::from(window),
                ..Default::default()
            });
            let (model, _) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &actions,
                &[false],
            )?;

            // the received bytes are the ones that were sent, apart from the
            // ones that were given up or lie before the first byte captured
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                let mut sent = before[i].to_vec();
                sent.resize(half[i] + jumps[i].unwrap_or(0) as usize, 0);
                sent.extend_from_slice(after[i]);
                prop_assert!(model.received_matches(role, &sent));
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
                &[false],
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

        #[test]
        fn evictions(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(4 * 1024),
            responder_data in stream_data_any(4 * 1024),
            segment_lens in vec(1usize..600, 1..32),
            resent_lens in vec(0usize..300, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fins in [any::<bool>(), any::<bool>()],
            extra_acks in 0usize..32,
            lost in vec((any::<Index>(), proptest::option::of(any::<Index>())), 0..16),
            rst in proptest::option::of((tcp_role_any(), any::<Index>())),
            max_total_buffered in proptest::option::of(0usize..8192),
            config in tcp_overdue_config_any(),
            evictions in vec(proptest::bool::weighted(0.05), 1..64),
            consume_lens in vec(0usize..1000, 1..32),
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

            // an RST at the end of the bytes sent, at a random position after
            // the handshake (outside of the window before most of them)
            if let Some((role, position)) = &rst {
                let rst = script.injected(|script| {
                    script.rst(*role);
                });
                let position = 3 + position.index(script.segments.len() - 2);
                script.segments.insert(position, rst);
            }

            // the connection is evicted before random segments, so later
            // segments start new connections (mid-stream pickups), and once
            // more at the end
            let mut pool = TcpReassemblyPool::<(), ()>::new(TcpReassemblyConfig {
                max_total_buffered,
                ..config
            });
            let (mut model, _) = feed_and_check(
                &mut pool,
                &script.segments,
                &consume_lens,
                &acked_reads,
                &[None],
                &evictions,
            )?;
            evict_and_check(&mut pool, &mut model)?;
            prop_assert_eq!(
                TcpPoolStats {
                    connections: 0,
                    tombstones: 0,
                    buffered_bytes: 0,
                    ..pool.stats()
                },
                pool.stats()
            );
        }
    }
}
