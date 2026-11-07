use crate::{tcp_reassembly::*, *};
use core::ops::Range;
use std::collections::VecDeque;

/// Bytes sent in one direction of a TCP connection.
///
/// Positions in a stream are 64-bit offsets counted from the stream's first
/// byte, so they never wrap around. If the stream's start was not captured,
/// they count from the first byte that was (see
/// [`TcpStreamStart::MidStreamPickup`]).
///
/// If the sequence numbers jump far after the receiver's window, e.g. after
/// a large capture loss, the stream continues at the new position once an
/// ACK of the other side confirms the jump, or enough segments agree on it
/// (see [`TcpReassemblyConfig::resync_after_segments`]). A gap of unknown
/// length lies in between (see [`TcpStreamStatus::resyncs`] and
/// [`TcpStream::force_resync`]).
#[derive(Clone, Debug)]
pub struct TcpStream {
    /// Sequence number of the byte at offset 0 (`None` while the start of
    /// the stream is unknown).
    start_seq: Option<u32>,

    /// SYN before the stream's observed start, known from the SYN or from
    /// the ACK of the SYN-ACK (`None` without an observed start). A resync
    /// doesn't change it.
    syn: Option<ObservedSyn>,

    /// Last ACK of the receiver that the stream couldn't apply yet, as it
    /// had no start or the ACK lies at or before offset 0 while bytes can
    /// still be prepended (at most as far before it as bytes can be put in
    /// front, A5). It serves several rules until it counts:
    ///
    /// - it is applied after every packet until it counts (K1);
    /// - it tells which segments the receiver accepts while the stream has
    ///   no start: which ones start the stream (A4) and which ones set the
    ///   window (S3);
    /// - a byte ending at it is a keep-alive, not the stream's start (A4);
    /// - it bounds the RSTs the receiver accepts (F4) and the SYNs that
    ///   can be the stream's own (C4).
    ///
    /// It is dropped once a later ACK counted, and when a start overrules
    /// it (A4).
    kept_ack: Option<KeptAck>,

    /// Whether a segment that lay far from the kept ACK was refused as the
    /// stream's start: the segment or the ACK is forged, or the receiver's
    /// window is larger than the fallback window assumes, so the next
    /// segment with bytes and without a FIN starts the stream wherever it
    /// lies.
    start_disputed: bool,

    /// Window scale option in the sender's SYN (`None` while the SYN was
    /// not seen, `Some(None)` for a SYN without the option).
    window_scale: Option<Option<u8>>,

    /// "window" field of the sender's last segment that the receiver
    /// accepts (see [`TcpStream::record_window`]) and whether that segment
    /// was a SYN (`None` before the sender's first segment).
    window: Option<(u16, bool)>,

    /// The received bytes and the missing ones between them.
    buffer: StreamBuffer,

    /// Offset of the FIN (`None` until the first FIN was seen).
    fin_offset: Option<u64>,

    /// Highest offset ACKed by the receiver, where an ACK of the FIN is
    /// `fin_offset + 1` (ACKs that the sender can't have sent bytes for
    /// are ignored).
    seen_ack: u64,

    /// Offset up to which the receiver must have ACKed the bytes, as the
    /// sender sends at most one receive window after the ACK (never moves
    /// back). It is not cut off at offset 0, so it stays exact if offset 0
    /// moves (`None` while no packet implied it).
    implied_ack: Option<i64>,

    /// Largest receive window the receiver advertised (`None` while its
    /// window is unknown).
    largest_window: Option<u64>,

    /// Offset after the furthest byte the stream rejected as it didn't fit
    /// the memory limits (0 without one). Holes before it are overdue.
    rejected_end: u64,

    /// Number of the connection's packet that moved the seen ACK forward
    /// and the seen ACK after it, for the packets of the last
    /// `ack_reorder_tolerance` ones that did so while there were holes, or
    /// while a prepend could add one.
    recent_acks: VecDeque<(u64, u64)>,

    /// Seen ACK as it was `ack_reorder_tolerance` packets ago (holes before
    /// it were covered long enough to be overdue).
    settled_ack: u64,

    /// Latest data segment that started after the receiver's window, where
    /// the stream may have jumped to (`None` once other bytes arrived or the
    /// stream moved forward).
    resync_candidate: Option<ResyncCandidate>,

    /// Last ACK number of the receiver that lay more than one window after
    /// the bytes the sender is known to have sent, which can confirm a jump
    /// (`None` once the stream moved forward).
    resync_ack: Option<u32>,

    /// Offset at which the stream continued after its last resync (0
    /// without one). Bytes, FINs and ACKs before it were sent before the
    /// jump.
    resync_offset: u64,

    /// Whether the next data segment is the stream's new start (see
    /// [`TcpStream::force_resync`]).
    resync_forced: bool,

    /// What reads return once nothing more is readable and the read
    /// position is not at the FIN, as the connection ended (`None` while it
    /// is open).
    connection_end: Option<TcpStreamEnd>,

    status: TcpStreamStatus,
}

impl TcpStream {
    /// Creates a stream whose start is not known yet, with buffers taken
    /// from `free`.
    pub(crate) fn new(free: &mut FreeBuffers) -> TcpStream {
        TcpStream {
            start_seq: None,
            syn: None,
            kept_ack: None,
            start_disputed: false,
            window_scale: None,
            window: None,
            buffer: StreamBuffer::new(free),
            fin_offset: None,
            seen_ack: 0,
            implied_ack: None,
            largest_window: None,
            rejected_end: 0,
            recent_acks: free.acks.take(),
            settled_ack: 0,
            resync_candidate: None,
            resync_ack: None,
            resync_offset: 0,
            resync_forced: false,
            connection_end: None,
            status: TcpStreamStatus {
                start: TcpStreamStart::MidStreamPickup,
                gaps: 0,
                gap_bytes: 0,
                resyncs: 0,
                conflicting_retransmissions: 0,
                rejected_bytes: 0,
                out_of_window_segments: 0,
            },
        }
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte.
    ///
    /// Call [`TcpStream::consume`] with the number of bytes you used to move
    /// the read position forward. Without readable bytes, the result is
    /// [`TcpRead::Pending`] while more bytes can arrive (e.g. to fill a
    /// hole), and [`TcpRead::End`] once all bytes up to the FIN were read,
    /// or once the connection ended (see [`TcpConnection::end`]) and
    /// everything readable was read. At a gap, the result is
    /// [`TcpRead::Gap`] until you call
    /// [`TcpStream::consume_gap`]. A hole becomes a gap when you give it up,
    /// or when the read position reaches it while it is overdue (see
    /// [`TcpStream::holes`]). A resync leaves a gap of unknown length (see
    /// [`TcpStreamStatus::resyncs`]).
    ///
    /// Use [`TcpStream::read_acked`] to read only the bytes the receiver
    /// ACKed.
    pub fn read_received(&mut self) -> TcpRead<'_> {
        self.read_until(u64::MAX)
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte, but only the ones the receiver ACKed (see
    /// [`TcpStream::acked_offset`]).
    ///
    /// Otherwise it works like [`TcpStream::read_received`]. Bytes that were
    /// consumed after reading them with [`TcpStream::read_received`] are
    /// not returned again. Once the connection ended, e.g. by a reset, the
    /// result is [`TcpRead::End`] after the ACKed bytes, while
    /// [`TcpStream::read_received`] still returns the bytes after them.
    pub fn read_acked(&mut self) -> TcpRead<'_> {
        self.read_until(self.acked_offset())
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte, but not after `limit`, or the gap at the read position.
    fn read_until(&mut self, limit: u64) -> TcpRead<'_> {
        let at_fin = Some(self.buffer.read_offset()) == self.fin_offset;
        match self.buffer.read(limit) {
            // the gap of a resync takes no offsets, its length is unknown
            Readable::Gap(gap) => TcpRead::Gap {
                len: (false == gap.is_empty()).then_some(gap.end - gap.start),
            },
            Readable::Bytes(bytes) if false == bytes.is_empty() => TcpRead::Data(bytes),
            Readable::Bytes(_) if at_fin => TcpRead::End(TcpStreamEnd::Fin),
            Readable::Bytes(_) => match self.connection_end {
                Some(end) => TcpRead::End(end),
                None => TcpRead::Pending,
            },
        }
    }

    /// Consumes `len` bytes at the read position.
    ///
    /// At most the bytes returned by the last read are consumed, so bytes
    /// that arrived after the read stay unread. If earlier bytes were put in
    /// front of a mid-stream pickup since the read, nothing is consumed (see
    /// [`TcpStreamStart::MidStreamPickup`]).
    pub fn consume(&mut self, len: usize) {
        self.buffer.consume(len);
        self.give_up_overdue_hole();
    }

    /// Gives up the hole at the read position, if there is one.
    ///
    /// The missing bytes become a gap: reading returns [`TcpRead::Gap`]
    /// until you step over it with [`TcpStream::consume_gap`], and bytes of
    /// the gap that arrive later are ignored. Returns false if the read
    /// position is not at a hole (an overdue hole at the read position is a
    /// gap already).
    pub fn give_up_hole(&mut self) -> bool {
        match self.buffer.hole_at_read_offset() {
            Some(hole) => {
                self.give_up_holes_before(hole.end);
                true
            }
            None => false,
        }
    }

    /// Moves the read position over the gap at the read position (see
    /// [`TcpRead::Gap`]).
    ///
    /// Does nothing if the read position is not at a gap.
    pub fn consume_gap(&mut self) {
        if self.buffer.consume_gap() {
            self.give_up_overdue_hole();
        }
    }

    /// Moves the read position forward to `offset`, discarding the bytes
    /// and holes before it.
    ///
    /// Bytes before the offset that arrive later are ignored. Discarding
    /// keeps the stream clean, also where bytes were missing (they are not
    /// counted as gaps). Offsets after [`TcpStream::highest_offset`] count
    /// as the highest offset, so bytes after it stay readable once they
    /// arrive. A gap of unknown length at `offset` stays (see
    /// [`TcpStreamStatus::resyncs`]).
    pub fn discard_until(&mut self, offset: u64) {
        self.buffer.discard_until(offset);
        self.give_up_overdue_hole();
    }

    /// Discards all buffered bytes and holes, so that the stream continues
    /// with the next new bytes.
    ///
    /// Works like [`TcpStream::discard_until`] with the highest offset.
    pub fn discard_all(&mut self) {
        self.discard_until(self.highest_offset());
    }

    /// Makes the next segment with bytes the stream's new start: the stream
    /// continues with these bytes at the highest offset, behind a gap of
    /// unknown length ([`TcpRead::Gap`] with `len: None`).
    ///
    /// Use it if you know that the stream jumped, e.g. to a new initial
    /// sequence number that lies before the stream's bytes, which a resync
    /// doesn't detect (see [`TcpStreamStatus::resyncs`]). Does nothing
    /// before the stream started, as its first accepted bytes start it
    /// anyway (see [`TcpStreamStart`]), or after the stream's FIN.
    pub fn force_resync(&mut self) {
        if self.start_seq.is_some() && self.fin_offset.is_none() {
            self.resync_forced = true;
        }
    }

    /// Turns the parts of the holes before `offset` into gaps.
    fn give_up_holes_before(&mut self, offset: u64) {
        self.buffer.give_up_holes_before(offset, &mut self.status);
    }

    /// Gives up the hole at the read position if it is overdue: the
    /// receiver must have received its bytes, so they will most likely not
    /// be captured anymore (late segments still fill overdue holes the read
    /// position hasn't reached).
    fn give_up_overdue_hole(&mut self) {
        if let Some(hole) = self.buffer.hole_at_read_offset() {
            if self.is_overdue(&hole) {
                self.give_up_holes_before(hole.end);
            }
        }
    }

    /// Offset up to which the receiver must have ACKed the bytes (0 while no
    /// bytes are implied).
    fn implied_ack(&self) -> u64 {
        self.implied_ack
            .map_or(0, |ack| u64::try_from(ack).unwrap_or(0))
    }

    /// Returns true if all of `hole` lies before the implied ACK, if the
    /// seen ACK has covered all of it for `ack_reorder_tolerance` packets, or
    /// if it lies before rejected bytes.
    fn is_overdue(&self, hole: &Range<u64>) -> bool {
        // once bytes are rejected, the hole they end in grows with every
        // rejected segment, so the implied ACK never passes it
        hole.end
            <= self
                .implied_ack()
                .max(self.settled_ack)
                .max(self.rejected_end)
    }

    /// Offset of the next byte to read.
    ///
    /// It moves back to the FIN offset when a FIN arrives before it, inside
    /// bytes up to an ACK that were given up (see
    /// [`TcpStream::highest_offset`]).
    pub fn read_offset(&self) -> u64 {
        self.buffer.read_offset()
    }

    /// Offset up to which the receiver ACKed the stream's bytes.
    ///
    /// ACKs of bytes more than one receive window after the highest offset
    /// are ignored, as the sender can't have sent these bytes. Without a
    /// higher ACK, it is the implied ACK: the sender sends at most one
    /// window after the ACK, so the receiver must have ACKed the bytes up
    /// to [`TcpReassemblyConfig::hole_give_up_window_factor`] times its
    /// largest window before the highest offset (at most half of
    /// [`TcpReassemblyConfig::max_stream_buffer`], but never less than the
    /// largest window).
    pub fn acked_offset(&self) -> u64 {
        // the ACK of the FIN lies after the highest offset
        self.seen_ack
            .max(self.implied_ack())
            .min(self.highest_offset())
    }

    /// Offset after the furthest byte the sender is known to have sent, as
    /// it was received or ACKed.
    ///
    /// It moves back to the FIN offset, and [`TcpStream::acked_offset`] with
    /// it, when a FIN arrives inside bytes that an earlier ACK covered.
    pub fn highest_offset(&self) -> u64 {
        self.buffer.highest_offset()
    }

    /// Offset of the stream's FIN, which is the number of bytes in the
    /// stream, if a FIN was seen.
    pub fn fin_offset(&self) -> Option<u64> {
        self.fin_offset
    }

    /// Ranges of missing bytes between the read position and the highest
    /// offset that can still arrive, in order.
    ///
    /// Reading stops at the first hole until a retransmission fills it or
    /// it is given up (see [`TcpStream::give_up_hole`]). A hole is also
    /// given up once it is overdue and the read position reaches it. A hole
    /// is overdue if it lies before the implied ACK (see
    /// [`TcpStream::acked_offset`]), or if a seen ACK has covered it for
    /// [`TcpReassemblyConfig::ack_reorder_tolerance`] packets, as the
    /// receiver must have received its bytes. Holes before bytes that the
    /// stream rejected (see [`TcpStreamStatus::rejected_bytes`]) are overdue
    /// too. Late segments still fill overdue holes the read position hasn't
    /// reached.
    pub fn holes(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.buffer.holes().iter().cloned()
    }

    /// Counters that describe the quality of the stream.
    pub fn status(&self) -> &TcpStreamStatus {
        &self.status
    }

    /// Returns true if the stream has no defects so far: no gaps, no
    /// resyncs, no retransmission with differing bytes and no rejected bytes
    /// (see [`TcpStreamStatus`]).
    ///
    /// Holes don't count, as retransmissions can still fill them, and
    /// neither do discarded bytes (see [`TcpStream::discard_until`]).
    pub fn is_clean(&self) -> bool {
        0 == self.status.gaps
            && 0 == self.status.resyncs
            && 0 == self.status.conflicting_retransmissions
            && 0 == self.status.rejected_bytes
    }

    /// Returns true if the stream's FIN was seen and all bytes before it
    /// were received or given up (no holes are left).
    ///
    /// Overdue holes (see [`TcpStream::holes`]) count as holes, as late
    /// segments can still fill them.
    pub fn is_finished(&self) -> bool {
        // the FIN moves the highest offset to it, so all holes lie before it
        self.fin_offset.is_some() && self.buffer.holes().is_empty()
    }

    /// Returns true if the stream is complete: it is clean (see
    /// [`TcpStream::is_clean`]), has an observed start and is finished (see
    /// [`TcpStream::is_finished`]).
    ///
    /// All bytes the sender sent are then delivered exactly once and
    /// unambiguously.
    pub fn is_complete(&self) -> bool {
        self.is_clean() && TcpStreamStart::Observed == self.status.start && self.is_finished()
    }

    /// Returns true if the stream has a start: an observed one or the first
    /// bytes of a mid-stream pickup.
    pub(crate) fn has_start(&self) -> bool {
        self.start_seq.is_some()
    }

    /// Sequence number of the SYN that gave the stream its observed start,
    /// if it has one.
    pub(crate) fn isn(&self) -> Option<u32> {
        self.syn.map(|syn| syn.isn)
    }

    /// SYN that gave the stream its observed start, if it has one.
    pub(crate) fn syn(&self) -> Option<ObservedSyn> {
        self.syn
    }

    /// Returns true if the SYN or SYN-ACK `tcp` of the stream's sender can
    /// be the stream's own, where `window` is the receiver's receive window.
    /// Otherwise it belongs to a reconnect.
    ///
    /// It has to have the ISN of the stream's observed start. Without one,
    /// it has to lie at or before the stream's first byte, at most as far
    /// before it as earlier bytes can be put in front of it. Without a
    /// start, the same holds for the receiver's kept ACK, if there is one.
    pub(crate) fn is_own_syn(
        &self,
        tcp: &TcpSlice<'_>,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> bool {
        let isn = tcp.sequence_number();
        let seq = isn.wrapping_add(1);
        let range = window_range(window, config);
        match (self.isn(), self.start_seq, self.kept_ack) {
            (Some(own), _, _) => own == isn,
            (None, Some(start_seq), _) => self
                .offset(start_seq, seq)
                .is_some_and(|start| start <= 0 && start.unsigned_abs() <= range),
            (None, None, _) => self.kept_ack_allows_syn(seq, window, config),
        }
    }

    /// Returns true if the receiver's kept ACK, if there is one, allows a
    /// stream without a start to start at `seq` with a SYN: the ACK lies at
    /// or after the first byte, at most k windows after it, as the receiver
    /// can't have ACKed bytes before the SYN.
    fn kept_ack_allows_syn(&self, seq: u32, window: u64, config: &TcpReassemblyConfig) -> bool {
        self.kept_ack.is_none_or(|kept| {
            u64::try_from(kept.seq.wrapping_sub(seq) as i32)
                .is_ok_and(|distance| distance <= window_range(window, config))
        })
    }

    /// Puts the stream's buffers into `free` for re-use.
    pub(crate) fn recycle(self, free: &mut FreeBuffers) {
        self.buffer.recycle(free);
        free.acks.put(self.recent_acks);
    }

    /// Returns true if the receiver ACKed the stream's FIN and all holes
    /// left are overdue, so that the stream can end as finished.
    pub(crate) fn can_finish(&self) -> bool {
        self.is_fin_acked()
            && self
                .buffer
                .holes()
                .last()
                .is_none_or(|hole| self.is_overdue(hole))
    }

    /// Returns true if the receiver ACKed the stream's FIN (all holes lie
    /// before it, so the ACK covers them).
    pub(crate) fn is_fin_acked(&self) -> bool {
        self.fin_offset.is_some_and(|fin| fin < self.seen_ack)
    }

    /// Counts `count` retransmissions with differing bytes that happened
    /// before the stream existed (of the SYN kept for a reconnect).
    pub(crate) fn count_conflicting_retransmissions(&mut self, count: u64) {
        self.status.conflicting_retransmissions += count;
    }

    /// Gives up all holes, as the connection ended (late segments are
    /// ignored after the end, so they can't fill them anymore). Once nothing
    /// more is readable, reads return `end` (or [`TcpStreamEnd::Fin`] at
    /// the FIN).
    pub(crate) fn connection_ended(&mut self, end: TcpStreamEnd) {
        self.give_up_holes_before(self.highest_offset());
        self.connection_end = Some(end);
    }

    /// Records the window the sender advertises for the other stream in
    /// `tcp`, a segment the receiver accepts. A SYN counts only while no
    /// window is known, as a retransmitted or late SYN carries the window
    /// from the start of the connection.
    fn record_window(&mut self, tcp: &TcpSlice<'_>) {
        if tcp.syn() && self.window.is_some() {
            return;
        }
        self.window = Some((tcp.window_size(), tcp.syn()));
    }

    /// Lowest offset a segment can start at for the receiver with the
    /// receive window `window` to accept it: the sender retransmits at most
    /// k windows before the bytes it is known to have sent.
    fn lowest_accepted(&self, window: u64, config: &TcpReassemblyConfig) -> i64 {
        let range = window_range(self.sent_into(window), config);
        i64::try_from(self.highest_offset())
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(range).unwrap_or(i64::MAX))
    }

    /// Receive window in bytes that the stream's sender advertised for the
    /// other stream `other`, `None` while it is unknown.
    pub(crate) fn advertised_window(&self, other: &TcpStream) -> Option<u64> {
        // the window scale is only known if both SYNs were seen (RFC 7323)
        match (self.window, self.window_scale, other.window_scale) {
            (Some((window, in_syn)), Some(scale), Some(other_scale)) => {
                // the window of a SYN is never scaled, and both directions
                // are only scaled if both SYNs had the option
                let shift = match (scale, other_scale) {
                    (Some(scale), Some(_)) if false == in_syn => scale.min(14),
                    _ => 0,
                };
                Some(u64::from(window) << shift)
            }
            _ => None,
        }
    }

    /// Offset after which the receiver with the receive window `window`
    /// doesn't accept bytes.
    fn window_end(&self, window: u64, config: &TcpReassemblyConfig) -> u64 {
        self.seen_ack
            .max(self.highest_offset())
            .saturating_add(window_range(self.sent_into(window), config))
    }

    /// Largest window the sender can have sent into, where `window` is the
    /// receiver's current receive window: the sender can have sent bytes
    /// into a larger window before the window shrank (e.g. to 0 when the
    /// receiver's buffer is full), and their ACKs can still come.
    ///
    /// Which window a rule uses:
    ///
    /// - the receiver's last window, what it accepts now: k windows for the
    ///   bytes put in front of a mid-stream pickup and its late SYN (A5,
    ///   C4), one window for the ACK that confirms a jump (R2) and for the
    ///   RST check (F4);
    /// - the largest window, what the sender can have sent into: k windows
    ///   for which segments and their windows count (S3) and for
    ///   out-of-window data (S4), one window for the ACK check (K1), and k
    ///   windows, at most half of the stream's buffer but at least one
    ///   window, for the implied ACK (K2).
    fn sent_into(&self, window: u64) -> u64 {
        window.max(self.largest_window.unwrap_or(0))
    }

    /// Number of bytes buffered from the read position to the furthest
    /// stored byte, with the placeholders of holes.
    pub(crate) fn buffered(&self) -> usize {
        self.buffer.buffered()
    }

    /// Maps the sequence number `seq` to a stream offset, relative to the
    /// highest offset (RFC 1982 serial number arithmetic).
    ///
    /// Offsets before the stream's first byte are negative. A sequence
    /// number 2^31 away from the highest offset lies neither before nor
    /// after it, so it can't be mapped (`None`).
    fn offset(&self, start_seq: u32, seq: u32) -> Option<i64> {
        let highest = self.highest_offset();
        let distance = seq.wrapping_sub(start_seq.wrapping_add(highest as u32)) as i32;
        (i32::MIN != distance).then(|| {
            i64::try_from(highest)
                .unwrap_or(i64::MAX)
                .saturating_add(i64::from(distance))
        })
    }

    /// Applies a segment sent by the stream's sender, whose receiver has the
    /// receive window `window`, in the packet with the number `packet` of
    /// the connection, storing at most `available` more bytes (the pool's
    /// budget, reduced by the bytes stored).
    ///
    /// The segment goes through these steps, each of which can be its last:
    ///
    /// 1. the stream gets a start if it has none yet (A1, A2, A4);
    /// 2. the segment is placed in the stream's offsets, which detects a
    ///    jump (S2, S4, R1 to R4), and its window is recorded (S3);
    /// 3. bytes before the first byte of a mid-stream pickup are put in
    ///    front of it (A5);
    /// 4. the filler byte of a keep-alive is dropped (D3);
    /// 5. the FIN ends the stream, and bytes after it are cut off (F1, D5);
    /// 6. the bytes are stored (D1, D2, D4).
    pub(crate) fn add_segment(
        &mut self,
        tcp: &TcpSlice<'_>,
        window: u64,
        packet: u64,
        other_syn_seen: bool,
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) {
        // the SYN occupies the sequence number before the first byte
        let seq = if tcp.syn() {
            tcp.sequence_number().wrapping_add(1)
        } else {
            tcp.sequence_number()
        };
        let data = tcp.payload();

        // 1. start
        // the receiver drops segments outside of its window, with their
        // window, so a blind segment can't set the window the checks rely on
        // (before the stream has a start, only the receiver's kept ACK tells
        // which sequence numbers it accepts, also for the starting segment)
        let had_start = self.start_seq.is_some();
        let accepted_without_start = false == had_start
            && self.accepts_without_start(tcp, seq, other_syn_seen, window, config);
        let Some(start_seq) =
            self.start_from(tcp, seq, accepted_without_start, window, config, available)
        else {
            if accepted_without_start {
                self.record_window(tcp);
            }
            return;
        };

        // 2. place
        let placed = self.place(tcp, seq, start_seq, window, config);
        let lowest = self.lowest_accepted(window, config);
        let accepted = if had_start {
            false == placed.after_window && placed.start.is_some_and(|start| lowest <= start)
        } else {
            accepted_without_start
        };
        if accepted {
            self.record_window(tcp);
        }
        if (false == data.is_empty() || tcp.fin()) && placed.after_window {
            // a FIN right after the bytes the stream may have jumped to ends
            // it there
            if let Some(candidate) = self
                .resync_candidate
                .as_mut()
                .filter(|candidate| data.is_empty() && seq == candidate.end)
            {
                candidate.fin = true;
            }
            self.status.out_of_window_segments += 1;
            return;
        }
        let Some(start) = placed.start else {
            return;
        };

        // 3. put in front
        let (start, mut out_of_window) =
            self.take_in_front(tcp, start, seq, window, config, available);
        let end = start + data.len() as i64;

        // 4. keep-alive
        if self.is_keep_alive_filler(tcp, start, end) {
            return;
        }

        // 5. FIN
        if tcp.fin() {
            self.apply_fin(end);
        }
        // bytes after the FIN are not part of the stream
        let data = match self.fin_offset {
            Some(fin) if false == data.is_empty() && end > fin as i64 => {
                out_of_window = true;
                let len = (fin as i64 - start).max(0) as usize;
                data.get(..len).unwrap_or_default()
            }
            _ => data,
        };
        if out_of_window {
            self.status.out_of_window_segments += 1;
        }

        // 6. store
        self.store(start, data, config, available);
        // the sender sent all bytes before its FIN
        if let Some(fin) = self.fin_offset {
            self.extend_to(fin);
        }
        // an ACK that confirmed the jump before the bytes arrived counts now
        if let Some(ack) = placed.jump_ack {
            self.add_jump_ack(ack, window, packet, config);
        }
    }

    /// Gives the stream a start if it has none and the segment `tcp`, whose
    /// first byte has the sequence number `seq`, can start it, where
    /// `accepted` tells whether the receiver accepts the segment. Returns
    /// the sequence number of offset 0, or `None` if the segment is done: a
    /// SYN the stream can't take, or a segment of a stream that still has
    /// no start.
    fn start_from(
        &mut self,
        tcp: &TcpSlice<'_>,
        seq: u32,
        accepted: bool,
        window: u64,
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) -> Option<u32> {
        let data = tcp.payload();
        if tcp.syn() {
            // a SYN whose start a mid-stream pickup can't take is not the
            // stream's own one
            if false == self.observe_start(seq, data.len(), window, config, available) {
                self.status.out_of_window_segments += 1;
                return None;
            }
            // the window scale is only known from the sender's SYN, which
            // can arrive after the SYN-ACK that started the stream
            if self.window_scale.is_none() && Some(seq) == self.start_seq {
                self.window_scale = Some(window_scale(tcp));
            }
        } else if self.start_seq.is_none() {
            // without its SYN, the stream starts at its first bytes, or at
            // a FIN without bytes, but not at the filler byte of a
            // keep-alive, which ends at the receiver's ACK
            let keep_alive = is_keep_alive_shaped(tcp)
                && Some(seq.wrapping_add(1)) == self.kept_ack.map(|kept| kept.seq);
            if (false == data.is_empty() || tcp.fin()) && false == keep_alive {
                // a segment far from the ACK the receiver kept for the stream
                // is forged, or the ACK is, or the receiver's window is
                // larger than assumed: the first such segment doesn't start
                // the stream, the next one with bytes does wherever it lies
                // (an ACK before every segment would otherwise keep a stream
                // with more in flight than k fallback windows from starting);
                // a FIN never does, as nothing could recover a stream that a
                // blind FIN ended (a FIN refused without a kept ACK disputes
                // nothing)
                if false == accepted && (tcp.fin() || false == self.start_disputed) {
                    self.status.out_of_window_segments += 1;
                    self.start_disputed = self.kept_ack.is_some();
                    return None;
                }
                // bytes that don't fit start no stream, so that byte 0 of a
                // pickup is always stored (and bytes can be put in front)
                if false == data.is_empty() && 0 == config.max_stream_buffer.min(*available) {
                    self.status.rejected_bytes += data.len() as u64;
                } else {
                    // a kept ACK that the start overrules doesn't fit the
                    // stream, and would otherwise count as the seen ACK or
                    // as resync evidence
                    if false == accepted {
                        self.kept_ack = None;
                    }
                    self.start_seq = Some(seq);
                }
            }
        }
        self.start_seq
    }

    /// Returns true if the receiver with the receive window `window` accepts
    /// the segment `tcp` starting at the sequence number `seq` while the
    /// stream has no start, where `other_syn_seen` tells whether the
    /// receiver's SYN was seen: it accepts a segment at most k windows from
    /// the ACK it kept for the stream, if there is one, but no FIN while its
    /// SYN is unanswered, as it drops everything but the SYN-ACK then and no
    /// ACK of its own is kept yet that could tell a blind FIN apart.
    fn accepts_without_start(
        &self,
        tcp: &TcpSlice<'_>,
        seq: u32,
        other_syn_seen: bool,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> bool {
        if tcp.fin() && other_syn_seen && self.kept_ack.is_none() {
            return false;
        }
        self.accepted_by_kept_ack(seq, window, config)
    }

    /// Returns true if the receiver with the receive window `window` accepts
    /// a segment starting at the sequence number `seq` while the stream has
    /// no start: at most k windows from the ACK it kept for the stream, if
    /// there is one.
    fn accepted_by_kept_ack(&self, seq: u32, window: u64, config: &TcpReassemblyConfig) -> bool {
        let range = window_range(window, config);
        self.kept_ack.is_none_or(|kept| {
            let distance = seq.wrapping_sub(kept.seq).min(kept.seq.wrapping_sub(seq));
            u64::from(distance) <= range
        })
    }

    /// Maps the first byte of the segment `tcp`, with the sequence number
    /// `seq`, to an offset in a stream whose offset 0 has the sequence
    /// number `start_seq`, and checks it against the receiver's window.
    /// Data after the window may be where the stream jumped to: if the
    /// other side or the user confirm the jump, the stream resyncs and the
    /// segment is placed at its new start.
    fn place(
        &mut self,
        tcp: &TcpSlice<'_>,
        seq: u32,
        start_seq: u32,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> Placed {
        let data = tcp.payload();
        let mut placed = Placed {
            start: self.offset(start_seq, seq),
            after_window: false,
            jump_ack: None,
        };
        // the receiver doesn't accept bytes or a FIN starting after its
        // window (or that can't be mapped)
        placed.after_window = placed.start.is_none_or(|start| {
            u64::try_from(start).is_ok_and(|start| start > self.window_end(window, config))
        });
        // data after the window can be where the stream jumped to, other
        // data shows that it didn't (a SYN with another ISN is a reconnect,
        // and nothing follows a FIN)
        if data.is_empty() || tcp.syn() || self.fin_offset.is_some() {
            return placed;
        }
        let candidate = ResyncCandidate::new(seq, data.len(), tcp.fin());
        // an ACK beyond the window that arrived before confirms a jump to
        // bytes within one window of it
        let confirming_ack = self
            .resync_ack
            .filter(|ack| candidate.is_within_window(*ack, window));
        let confirmed = if placed.after_window {
            // so do enough consecutive segments that agree
            self.add_resync_candidate(candidate, window, config) || confirming_ack.is_some()
        } else {
            self.resync_candidate = None;
            false
        };
        // the user or the other side confirm the jump, the segment is the
        // new start
        if (self.resync_forced || confirmed) && self.can_resync(config) {
            let start_seq = self.resync(seq);
            placed = Placed {
                start: self.offset(start_seq, seq),
                after_window: false,
                jump_ack: confirming_ack,
            };
        }
        placed
    }

    /// Puts the bytes of `tcp` at the offset `start` (with the sequence
    /// number `seq`) in front of a mid-stream pickup if they begin before
    /// its first byte and fit, until it is read from. Returns the offset
    /// the bytes are stored at, and whether the segment counts as
    /// out-of-window, as its bytes before offset 0 are outside the stream
    /// (only the filler byte of a keep-alive right before the first byte of
    /// an observed start doesn't count, and nothing does after a resync).
    fn take_in_front(
        &mut self,
        tcp: &TcpSlice<'_>,
        start: i64,
        seq: u32,
        window: u64,
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) -> (i64, bool) {
        let data_len = tcp.payload().len();
        // bytes before a jump are ignored without counting (R2), also ones
        // that map before offset 0
        if 0 <= start || 0 == data_len || 0 < self.status.resyncs {
            return (start, false);
        }
        if TcpStreamStart::Observed == self.status.start {
            let keep_alive_filler = -1 == start && is_keep_alive_shaped(tcp);
            return (start, false == keep_alive_filler);
        }
        if false == self.can_move_start_back(start, window, config) {
            (start, true)
        } else if self
            .buffer
            .fits_in_front(start.unsigned_abs(), data_len, config, *available)
        {
            self.move_start_back(seq, start, available, true);
            (0, false)
        } else {
            // the bytes from offset 0 on are stored as usual
            let before = (data_len as u64).min(start.unsigned_abs());
            self.status.rejected_bytes += before;
            (start, false)
        }
    }

    /// Returns true if the segment `tcp`, with its byte at the offset
    /// `start` and ending at `end`, is a keep-alive probe whose filler byte
    /// would fill an overdue hole (the receiver drops it too).
    fn is_keep_alive_filler(&self, tcp: &TcpSlice<'_>, start: i64, end: i64) -> bool {
        is_keep_alive_shaped(tcp)
            && end == self.seen_ack as i64
            && u64::try_from(start).is_ok_and(|start| {
                self.buffer
                    .hole_at(start)
                    .is_some_and(|hole| self.is_overdue(&hole))
            })
    }

    /// Records the FIN after the byte at `end` if it is the first one: it
    /// can't lie before received bytes (even if bytes before it are missing
    /// or were given up, or the bytes were rejected) or before a jump.
    fn apply_fin(&mut self, end: i64) {
        if self.fin_offset.is_some()
            || end
                < self
                    .buffer
                    .received_end()
                    .max(self.rejected_end)
                    .max(self.resync_offset) as i64
        {
            return;
        }
        self.fin_offset = Some(end as u64);
        // an ACK of the FIN that arrived before it marked the FIN's position
        // as a missing byte
        self.buffer.truncate_to(end as u64);
    }

    /// Stores the bytes of `data` (starting at offset `start`) that were not
    /// received before, as far as they fit the memory limits and the pool's
    /// budget `available`, and counts what didn't fit or differed.
    fn store(
        &mut self,
        start: i64,
        data: &[u8],
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) {
        let highest = self.highest_offset();
        // bytes before a jump are ignored, and the receiver ignores
        // retransmissions of ACKed bytes (e.g. keep-alive probes), so they
        // don't conflict
        let stored = self.buffer.store(
            start,
            data,
            self.resync_offset,
            self.acked_offset(),
            config,
            available,
        );
        if stored.conflicting {
            self.status.conflicting_retransmissions += 1;
        }
        if false == stored.rejected.is_empty() {
            self.status.rejected_bytes += stored.rejected.end - stored.rejected.start;
            self.rejected_end = self.rejected_end.max(stored.rejected.end);
        }
        // the sender sent the rejected bytes too, so the implied ACK moves on
        if self.highest_offset() > highest {
            self.moved_forward();
        }
    }

    /// Moves the highest offset forward to `offset`, the bytes in between
    /// are missing.
    fn extend_to(&mut self, offset: u64) {
        if self.buffer.extend_to(offset) {
            self.moved_forward();
        }
    }

    /// The highest offset moved forward, so the stream didn't jump.
    fn moved_forward(&mut self) {
        self.resync_candidate = None;
        self.resync_ack = None;
    }

    /// Applies an RST of the stream's sender with the sequence number `seq`,
    /// whose receiver has the receive window `window`. Returns true if the
    /// receiver can accept it, so that it ends the connection. Otherwise
    /// the RST counts as out-of-window.
    pub(crate) fn add_reset(&mut self, seq: u32, window: u64) -> bool {
        // the receiver accepts an RST from the next byte it expects up to
        // one window after it (RFC 9293 3.10.7.4), and that byte lies
        // between the receiver's ACK and the bytes sent (and the FIN)
        let accepted = match (self.start_seq, self.kept_ack) {
            (Some(start_seq), kept_ack) => {
                // the receiver's ACK can be kept at or before offset 0 (see
                // `kept_ack`), but no ACK blocks an RST at or after the
                // received bytes (a forged one could)
                let ack = kept_ack
                    .and_then(|kept| self.offset(start_seq, kept.seq))
                    .unwrap_or(self.seen_ack as i64);
                let mut first = ack.min(self.buffer.received_end() as i64);
                // nothing before a jump counts
                if 0 < self.status.resyncs {
                    first = first.max(self.resync_offset as i64);
                }
                let sent_end = self.highest_offset() + u64::from(self.fin_offset.is_some());
                let last = i64::try_from(sent_end.saturating_add(window)).unwrap_or(i64::MAX);
                self.offset(start_seq, seq)
                    .is_some_and(|offset| first <= offset && offset <= last)
            }
            // without a start, the receiver's ACK is the next byte it
            // expects
            (None, Some(kept)) => u64::try_from(seq.wrapping_sub(kept.seq) as i32)
                .is_ok_and(|distance| distance <= window),
            // nothing tells which bytes the receiver expects
            (None, None) => true,
        };
        if false == accepted {
            self.status.out_of_window_segments += 1;
        }
        accepted
    }

    /// Gives the stream an observed start at `seq`, the sequence number
    /// after its SYN, which carries `data_len` bytes, where `window` is the
    /// receiver's receive window and `available` the pool's budget.
    ///
    /// A mid-stream pickup moves its start back to `seq`. Returns false if
    /// it can't, and true if the stream has an observed start afterwards.
    pub(crate) fn observe_start(
        &mut self,
        seq: u32,
        data_len: usize,
        window: u64,
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) -> bool {
        match self.start_seq {
            // the ACK number of a SYN-ACK can give the stream its start (A2),
            // which the receiver's kept ACK has to allow like a late SYN (C4)
            None if false == self.kept_ack_allows_syn(seq, window, config) => return false,
            None => self.start_seq = Some(seq),
            Some(_) if TcpStreamStart::Observed == self.status.start => {
                // a retransmitted SYN can carry more TCP Fast Open bytes
                if let Some(syn) = self
                    .syn
                    .as_mut()
                    .filter(|syn| syn.isn == seq.wrapping_sub(1))
                {
                    syn.len = syn.len.max(data_len as u32);
                }
                return true;
            }
            Some(start_seq) => {
                // a late SYN lies at or before the first byte received
                let Some(start) = self.offset(start_seq, seq) else {
                    return false;
                };
                if false == self.can_move_start_back(start, window, config)
                    || false
                        == self.buffer.fits_in_front(
                            start.unsigned_abs(),
                            data_len,
                            config,
                            *available,
                        )
                {
                    return false;
                }
                self.move_start_back(seq, start, available, false);
            }
        }
        // no more bytes are put in front of an observed start
        self.buffer.drop_room();
        self.syn = Some(ObservedSyn {
            isn: seq.wrapping_sub(1),
            len: data_len as u32,
        });
        self.status.start = TcpStreamStart::Observed;
        true
    }

    /// Returns true if offset 0 of a mid-stream pickup can move back to
    /// `start`: bytes can still be prepended, and `start` lies within the
    /// range of the receiver's receive window `window` before offset 0.
    fn can_move_start_back(&self, start: i64, window: u64, config: &TcpReassemblyConfig) -> bool {
        0 >= start && start.unsigned_abs() <= window_range(window, config) && self.can_prepend()
    }

    /// Moves offset 0 of a mid-stream pickup back to the sequence number
    /// `seq` at offset `start` (see [`TcpStream::can_move_start_back`]),
    /// taking the placeholders of the bytes before it from the pool's
    /// budget `available`. If `more`, further prepends can follow; none
    /// follows the stream's SYN.
    fn move_start_back(&mut self, seq: u32, start: i64, available: &mut usize, more: bool) {
        if start < 0 {
            let len = start.unsigned_abs();
            self.prepend(len, more);
            *available = available.saturating_sub(len as usize);
        }
        self.start_seq = Some(seq);
    }

    /// Returns true if bytes can still be prepended to the stream, as it is
    /// a mid-stream pickup whose offsets no reader has used yet.
    fn can_prepend(&self) -> bool {
        // the read position of a pickup never moves back to 0 (a FIN can't
        // lie before the first byte received), a reader may have read the
        // end of a pickup that starts at its FIN, and prepending would move
        // the gap of a resync
        TcpStreamStart::MidStreamPickup == self.status.start
            && 0 == self.read_offset()
            && Some(0) != self.fin_offset
            && 0 == self.status.resyncs
            && false == self.resync_forced
    }

    /// Moves offset 0 of the mid-stream pickup `len` bytes back, these
    /// bytes are a hole until they arrive, and all offsets grow by `len`.
    fn prepend(&mut self, len: u64, more: bool) {
        self.buffer.prepend(len, more);
        self.fin_offset = self.fin_offset.map(|fin| fin + len);
        // ACKs of offset 0 or before it were ignored, so 0 means none
        if 0 < self.seen_ack {
            self.seen_ack += len;
        }
        if 0 < self.settled_ack {
            self.settled_ack += len;
        }
        if 0 < self.rejected_end {
            self.rejected_end += len;
        }
        for (_, ack) in &mut self.recent_acks {
            *ack += len;
        }
        self.implied_ack = self.implied_ack.map(|ack| ack.saturating_add(len as i64));
    }

    /// Updates what the receiver must have received after the packet with
    /// the number `packet` of the connection, where `window` is the
    /// receiver's receive window (`None` while it is unknown).
    pub(crate) fn after_packet(
        &mut self,
        window: Option<u64>,
        packet: u64,
        config: &TcpReassemblyConfig,
    ) {
        // an ACK that couldn't be applied counts once the stream has a start
        // or its offsets moved (until then, it stays kept)
        if let Some(kept) = self.kept_ack.take() {
            let ack_window = window.unwrap_or(u64::from(config.fallback_window));
            self.add_ack(kept.seq, ack_window, kept.packet, config);
        }
        // the sender can have sent bytes into a larger window before the
        // window shrank (e.g. to 0 when the receiver's buffer is full)
        self.largest_window = self.largest_window.max(window);
        if config.hole_give_up_window_factor.is_some() {
            // allow for several windows, as the window can change, but not
            // more than half of the stream's buffer, so that a reader of the
            // ACKed bytes keeps up before the buffer is full; never less than
            // a known window though, as the sender can have sent that far
            // past the ACK
            let known = self.largest_window.unwrap_or(0);
            let window = self
                .largest_window
                .unwrap_or(u64::from(config.fallback_window));
            let distance = window_range(window, config)
                .min(config.max_stream_buffer as u64 / 2)
                .max(known);
            let implied_ack = i64::try_from(self.highest_offset())
                .unwrap_or(i64::MAX)
                .saturating_sub(i64::try_from(distance).unwrap_or(i64::MAX));
            self.implied_ack = self.implied_ack.max(Some(implied_ack));
        }
        // ACKs reordered against the data in a capture can come first, so
        // a covered hole stays fillable for some packets
        let tolerance = u64::from(config.ack_reorder_tolerance);
        while let Some(&(ack_packet, ack)) = self.recent_acks.front() {
            if ack_packet.saturating_add(tolerance) > packet {
                break;
            }
            self.settled_ack = ack;
            self.recent_acks.pop_front();
        }
        if self.buffer.holes().is_empty() && false == self.can_prepend() {
            // later holes lie after the seen ACK, so they can't be overdue
            // by the ACKs so far (a prepend adds a hole before it)
            self.recent_acks.clear();
        }
        self.give_up_overdue_hole();
    }

    /// Applies the ACK number of a segment sent by the stream's receiver,
    /// whose receive window before that segment was `window`, in the packet
    /// with the number `packet` of the connection.
    pub(crate) fn add_ack(
        &mut self,
        ack_seq: u32,
        window: u64,
        packet: u64,
        config: &TcpReassemblyConfig,
    ) {
        let Some(start_seq) = self.start_seq else {
            self.kept_ack = Some(KeptAck {
                seq: ack_seq,
                packet,
            });
            return;
        };
        // the receiver can only ACK bytes that can't be mapped after a jump
        let Some(ack) = self.offset(start_seq, ack_seq) else {
            self.add_resync_ack(ack_seq, window, packet, config);
            return;
        };
        // an ACK of offset 0 or before it can ACK bytes prepended later,
        // unless a later ACK counted already (a seen ACK of 0 means none);
        // one further before than bytes can be put in front is forged, and
        // would widen the RST check (F4)
        if ack <= 0 && self.can_prepend() && 0 == self.seen_ack {
            if ack.unsigned_abs() <= window_range(window, config) {
                self.kept_ack = Some(KeptAck {
                    seq: ack_seq,
                    packet,
                });
            }
            return;
        }
        // the sender can't have sent more than one window after the bytes
        // it is known to have sent (and its FIN), unless the stream jumped
        let sent_end = self.highest_offset() + u64::from(self.fin_offset.is_some());
        if 0 < ack && ack as u64 > sent_end.saturating_add(self.sent_into(window)) {
            self.add_resync_ack(ack_seq, window, packet, config);
            return;
        }
        // ACKs before a jump don't count after it
        if ack <= self.seen_ack as i64 || ack < self.resync_offset as i64 {
            return;
        }
        self.seen_ack = ack as u64;
        // an ACK kept at or before offset 0 is older than this one
        self.kept_ack = None;
        // the receiver got bytes that were not captured, but none after the
        // FIN
        let end = self
            .fin_offset
            .map_or(self.seen_ack, |fin| fin.min(self.seen_ack));
        self.extend_to(end);
        // only holes can become overdue by the ACK, also ones that a
        // prepend adds before it
        if false == self.buffer.holes().is_empty() || self.can_prepend() {
            self.recent_acks.push_back((packet, self.seen_ack));
        }
    }

    /// Records the data after the receiver's window `candidate` as the latest
    /// candidate of a resync, where `window` is the receiver's receive
    /// window. Returns true if enough consecutive candidates agree that the
    /// stream jumped there (see
    /// [`TcpReassemblyConfig::resync_after_segments`]).
    fn add_resync_candidate(
        &mut self,
        mut candidate: ResyncCandidate,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> bool {
        // consecutive segments after the window agree on the new position
        // if each lies within one window of the one before
        if let Some(previous) = self
            .resync_candidate
            .filter(|previous| previous.is_within_window(candidate.first, window))
        {
            candidate.agreeing = previous.agreeing.saturating_add(1);
        }
        self.resync_candidate = Some(candidate);
        config
            .resync_after_segments
            .is_some_and(|after| candidate.agreeing >= after)
    }

    /// Applies the ACK number `ack_seq` of the receiver that lies more than
    /// the receiver's receive window `window` after the bytes the sender is
    /// known to have sent (or can't be mapped), in the packet with the
    /// number `packet` of the connection.
    ///
    /// If it lies within one window of the latest data after the window,
    /// the stream jumped there and continues after these bytes. Otherwise
    /// it is kept, as such data can still follow.
    fn add_resync_ack(
        &mut self,
        ack_seq: u32,
        window: u64,
        packet: u64,
        config: &TcpReassemblyConfig,
    ) {
        match self.resync_candidate {
            Some(candidate)
                if self.fin_offset.is_none()
                    && candidate.is_within_window(ack_seq, window)
                    && self.can_resync(config) =>
            {
                // the FIN after the candidate's bytes ends the stream there
                self.resync(candidate.end);
                if candidate.fin {
                    self.fin_offset = Some(self.highest_offset());
                }
                self.add_jump_ack(ack_seq, window, packet, config);
            }
            _ => self.resync_ack = Some(ack_seq),
        }
    }

    /// Applies the ACK number `ack_seq` that confirmed a jump after the
    /// resync, like the ACK of [`TcpStream::add_ack`]. It also ACKs all bytes
    /// before the jump, as the receiver ACKed bytes after it.
    fn add_jump_ack(
        &mut self,
        ack_seq: u32,
        window: u64,
        packet: u64,
        config: &TcpReassemblyConfig,
    ) {
        self.add_ack(ack_seq, window, packet, config);
        self.seen_ack = self.seen_ack.max(self.resync_offset);
    }

    /// Returns true if the stream can resync: it has at most
    /// `max_holes_per_stream` gaps the read position didn't step over, as
    /// each resync turns the holes before it into gaps.
    fn can_resync(&self, config: &TcpReassemblyConfig) -> bool {
        self.buffer.gaps().len() <= config.max_holes_per_stream
    }

    /// Continues the stream with the byte that has the sequence number
    /// `seq` at the highest offset, behind a gap of unknown length, and
    /// returns the new sequence number of offset 0.
    fn resync(&mut self, seq: u32) -> u32 {
        // the missing bytes now map elsewhere, so nothing can fill the holes
        let offset = self.highest_offset();
        self.give_up_holes_before(offset);
        self.buffer.add_gap_of_unknown_len();
        let start_seq = seq.wrapping_sub(offset as u32);
        self.start_seq = Some(start_seq);
        self.resync_offset = offset;
        self.resync_candidate = None;
        self.resync_ack = None;
        self.resync_forced = false;
        self.status.resyncs += 1;
        start_seq
    }
}

/// Number of bytes before or after the stream's bytes that a receiver with
/// the receive window `window` accepts: several windows, as the window can
/// change and not all ACKs are captured.
fn window_range(window: u64, config: &TcpReassemblyConfig) -> u64 {
    window.saturating_mul(u64::from(window_factor(config)))
}

/// Number of windows the receiver accepts around the stream's bytes
/// (`hole_give_up_window_factor`, 2 without one, and at least 1: with 0, a
/// stream would take no bytes after a hole).
fn window_factor(config: &TcpReassemblyConfig) -> u32 {
    config.hole_give_up_window_factor.unwrap_or(2).max(1)
}

/// SYN before the first byte of a stream with an observed start.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ObservedSyn {
    /// Sequence number of the SYN.
    pub isn: u32,
    /// Number of bytes the SYN carried (TCP Fast Open).
    pub len: u32,
}

impl ObservedSyn {
    /// Returns true if the ACK number `ack` ACKs the SYN: from its ISN + 1 up
    /// to the end of its bytes (a server ACKs TCP Fast Open bytes it
    /// accepts).
    pub fn is_acked_by(&self, ack: u32) -> bool {
        ack.wrapping_sub(self.isn.wrapping_add(1)) <= self.len
    }
}

/// Where a segment lies in a stream (see [`TcpStream::place`]).
#[derive(Clone, Debug)]
struct Placed {
    /// Offset of the segment's first byte (`None` if its sequence number
    /// can't be mapped).
    start: Option<i64>,
    /// Whether the receiver doesn't accept the segment, as it starts after
    /// the window.
    after_window: bool,
    /// ACK that confirmed the jump the segment is the new start of, before
    /// the segment arrived.
    jump_ack: Option<u32>,
}

/// ACK of the receiver that the stream couldn't apply yet (see
/// [`TcpStream::add_ack`]).
#[derive(Copy, Clone, Debug)]
struct KeptAck {
    /// ACK number.
    seq: u32,
    /// Number of the connection's packet that carried the ACK.
    packet: u64,
}

/// Data segment after the receiver's window that a stream may have jumped
/// to.
#[derive(Copy, Clone, Debug)]
struct ResyncCandidate {
    /// Sequence number of the first byte.
    first: u32,
    /// Sequence number after the last byte.
    end: u32,
    /// Whether a FIN follows the bytes.
    fin: bool,
    /// Number of consecutive data segments after the window up to this one,
    /// each within one window of the one before.
    agreeing: u32,
}

impl ResyncCandidate {
    /// Candidate with `len` bytes from the sequence number `seq` on,
    /// followed by a FIN if `fin`.
    fn new(seq: u32, len: usize, fin: bool) -> ResyncCandidate {
        ResyncCandidate {
            first: seq,
            end: seq.wrapping_add(len as u32),
            fin,
            agreeing: 1,
        }
    }

    /// Returns true if the sequence number `seq` lies at most `window` bytes
    /// before or after the candidate's bytes (RFC 1982 serial number
    /// arithmetic).
    fn is_within_window(&self, seq: u32, window: u64) -> bool {
        let window = i64::try_from(window).unwrap_or(i64::MAX);
        let distance = i64::from(seq.wrapping_sub(self.first) as i32);
        let len = i64::from(self.end.wrapping_sub(self.first));
        -window <= distance && distance <= len.saturating_add(window)
    }
}

/// Returns true if the segment has the shape of a keep-alive probe: one
/// filler byte, without SYN or FIN, that repeats the byte before the
/// receiver's ACK (RFC 1122 4.2.3.6). RSTs carry no bytes of the stream.
fn is_keep_alive_shaped(tcp: &TcpSlice<'_>) -> bool {
    1 == tcp.payload().len() && false == (tcp.syn() || tcp.fin())
}

/// Returns the value of the window scale option (RFC 7323), if present.
fn window_scale(tcp: &TcpSlice<'_>) -> Option<u8> {
    tcp.options_iterator()
        .map_while(Result::ok)
        .find_map(|option| match option {
            TcpOptionElement::WindowScale(scale) => Some(scale),
            _ => None,
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tcp_reassembly::TcpRole::*;
    use std::{format, vec, vec::Vec};

    #[test]
    fn derived_traits() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        let stream = connection.stream_mut(Initiator);

        // clone
        {
            let mut clone = stream.clone();
            assert_eq!(TcpRead::Data(b"abc"), clone.read_received());
            clone.consume(3);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // debug
        assert!(format!("{:?}", stream).starts_with("TcpStream { "));
    }

    #[test]
    fn read_received() {
        // nothing received yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Pending,
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Pending,
                connection.stream_mut(Responder).read_received()
            );
        }

        // in-order data of several segments is read as one slice
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"GET")
                .send(Responder, b"HTTP")
                .send(Initiator, b" /")
                .send(Responder, b"/1.1");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"GET /"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"HTTP/1.1"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // data in the SYN (TCP Fast Open) starts at offset 0
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn_with_data(b"fast")
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b" open");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"fast open"), stream.read_received());
            assert_eq!(0, stream.read_offset());
        }

        // SYNs with options start the streams too
        for options in [
            // window scale
            &[TcpOptionElement::WindowScale(7), TcpOptionElement::Noop][..],
            // window scale after another option
            &[
                TcpOptionElement::MaximumSegmentSize(1460),
                TcpOptionElement::WindowScale(14),
                TcpOptionElement::Noop,
            ][..],
            // no window scale
            &[TcpOptionElement::MaximumSegmentSize(1460)][..],
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            script.segments[0].header.set_options(options).unwrap();
            script.segments[1].header.set_options(options).unwrap();
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

        // SYNs with malformed options start the streams too
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(7), Some(7)];
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            // window scale option with a wrong length
            script.segments[0]
                .header
                .set_options_raw(&[3, 4, 7, 0])
                .unwrap();
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

        // without its SYN, the SYN-ACK starts both streams (the initiator's
        // at the ACK of the SYN, also when it is the first packet)
        for syn_ack_first in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            let syn = script.segments.remove(0);
            if false == syn_ack_first {
                script.segments.insert(0, syn);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            for (role, data) in [(Initiator, b"abc"), (Responder, b"def")] {
                let stream = connection.stream_mut(role);
                assert_eq!(TcpRead::Data(data), stream.read_received());
                assert_eq!(0, stream.read_offset());
            }
        }

        // retransmitted bytes are delivered once (also across a
        // wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                // the same segment again
                .send_at(Initiator, 3, b"def")
                // the same bytes cut differently, with new bytes at the end
                .send_at(Initiator, 1, b"bcdefgh")
                // only bytes received before
                .send_at(Initiator, 0, b"ab");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdefgh"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // reading stops at a hole and continues once it is filled
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"de")
                .send(Initiator, b"fg");
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"defg"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a hole at the start of the stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let missing = script.segments.remove(3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(
                    TcpRead::Pending,
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdef"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // an overdue hole at the read position (its end lies before the
        // implied ACK) is read as one gap, but not while only a part of it
        // is overdue, and never without a hole give up window factor
        for (factor, expected) in [
            (Some(2), TcpRead::Gap { len: Some(3) }),
            (None, TcpRead::Pending),
        ] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .send(Initiator, b"jkl");
            script.segments.remove(2);
            {
                let (connection, _) = script.feed(&mut pool, ..3).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
                // the implied ACK (5) lies inside the hole
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            // the implied ACK (8) lies after the hole
            let (connection, _) = script.feed(&mut pool, 3..).active.unwrap();
            assert_eq!(expected, connection.stream_mut(Initiator).read_received());
        }

        // no limit throws away bytes that were not consumed: the bytes that
        // don't fit are rejected, and the bytes stored before stay readable
        for config in [
            TcpReassemblyConfig {
                max_stream_buffer: 6,
                ..Default::default()
            },
            TcpReassemblyConfig {
                max_holes_per_stream: 0,
                ..Default::default()
            },
            TcpReassemblyConfig {
                max_total_buffered: Some(6),
                ..Default::default()
            },
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            for offset in [8, 20] {
                script.send_at(Initiator, offset, b"XY");
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(0 < stream.status().rejected_bytes);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
        }

        // the stream keeps moving after it rejected bytes: their hole, which
        // every further rejected segment extends to the highest offset (so
        // the implied ACK never passes it), is overdue, and later bytes are
        // stored once the read position is past it
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 4,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"efgh")
                .send(Initiator, b"ijkl")
                .send(Initiator, b"mnop");
            {
                let (connection, _) = script.feed(&mut pool, ..6).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abcd"), stream.read_received());
                stream.consume(4);
                assert_eq!(TcpRead::Gap { len: Some(8) }, stream.read_received());
                stream.consume_gap();
            }
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"mnop"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // holes that end at or before the end of the furthest rejected bytes
        // are overdue, also ones of bytes that were not captured, but late
        // segments still fill them until the read position reaches them
        // (bytes 8..11 don't fit the buffer of 7 bytes)
        for (late, holes, data, gap) in [
            (false, vec![3..5, 7..11], &b"abc"[..], 2),
            (true, vec![7..11], b"abcdefg", 4),
        ] {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 7,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"de")
                .send(Initiator, b"fg")
                .send_at(Initiator, 8, b"xyz");
            let missing = script.segments.remove(4);
            if late {
                script.segments.push(missing);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(holes, stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(data), stream.read_received());
            stream.consume(data.len());
            assert_eq!(TcpRead::Gap { len: Some(gap) }, stream.read_received());
        }

        // a prepend moves the end of the rejected bytes with the offsets (the
        // pickup starts with 2 bytes at 5, bytes at 25 don't fit, 5 bytes at
        // 0 are put in front)
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 10,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcde")
                .send(Initiator, b"fg")
                .send_at(Initiator, 25, b"xy");
            script.segments.drain(..3);
            let earlier = script.segments.remove(0);
            script.segments.push(earlier);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(vec![7..27], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"abcdefg"), stream.read_received());
            stream.consume(7);
            assert_eq!(TcpRead::Gap { len: Some(20) }, stream.read_received());
        }

        // ... but a hole that an ACK extended after the rejected bytes is not
        // (the ACK covers it only for fewer than N packets)
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 4,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"efgh")
                .ack_to(Responder, 20);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(vec![4..20], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"abcd"), stream.read_received());
            stream.consume(4);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // a hole that the seen ACK covers is overdue on the N-th further
        // packet of the connection after the ACK (N is the ACK reorder
        // tolerance, every packet of both directions counts), also without a
        // hole give up window factor
        for (factor, tolerance, packets, expected) in [
            (Some(2), 3, 2, TcpRead::Pending),
            (Some(2), 3, 3, TcpRead::Gap { len: Some(3) }),
            (None, 3, 2, TcpRead::Pending),
            (None, 3, 3, TcpRead::Gap { len: Some(3) }),
            (None, 0, 0, TcpRead::Gap { len: Some(3) }),
        ] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                ack_reorder_tolerance: tolerance,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .ack(Responder);
            script.segments.remove(4);
            for packet in 0..packets {
                match packet % 3 {
                    0 => script.ack(Initiator),
                    1 => script.send(Responder, b"x"),
                    // a retransmission
                    _ => script.send_at(Initiator, 0, b"a"),
                };
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(expected, stream.read_received());
        }

        // a hole that the seen ACK covers stays fillable within the ACK
        // reorder tolerance
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 3,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .ack(Responder)
                .ack(Initiator);
            let late = script.segments.remove(4);
            script.segments.push(late);
            script.ack(Initiator).ack(Initiator).ack(Initiator);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdefghi"), stream.read_received());
            assert!(stream.is_clean());
        }

        // a hole is overdue once the seen ACK, as it was N packets ago,
        // covered all of it (also after a segment cut it from a larger hole)
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 3,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 9, b"jkl")
                // covers a part of the hole 3..9
                .ack_to(Responder, 5)
                .ack_to(Responder, 12)
                // leaves the hole 3..4, covered since the first ACK
                .send_at(Initiator, 4, b"efghi")
                .ack(Initiator);
            script.feed(&mut pool, ..3);
            let expected = [
                TcpRead::Pending,
                TcpRead::Pending,
                TcpRead::Pending,
                TcpRead::Pending,
                TcpRead::Pending,
                TcpRead::Gap { len: Some(1) },
            ];
            for (segment, expected) in script.segments[3..].iter().zip(expected) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                if 0 == stream.read_offset() {
                    stream.read_received();
                    stream.consume(3);
                }
                assert_eq!(expected, stream.read_received());
            }
        }

        // an ACK at the first byte of a mid-stream pickup is kept, as it can
        // cover bytes put in front later: the hole it then covers is overdue
        // N packets after the ACK's packet, not after the prepend (the
        // capture starts at the initiator's byte 11, the ACK of byte 11 is
        // the 3rd packet, and byte 0 arrives with the 4th)
        for (tolerance, expected) in [(1, TcpRead::Gap { len: Some(10) }), (2, TcpRead::Pending)] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: None,
                ack_reorder_tolerance: tolerance,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 11)
                .send(Initiator, b"a")
                .ack_to(Responder, 11)
                .ack_to(Responder, 11)
                .send_at(Initiator, 0, b"b");
            script.segments.drain(..3);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"b"), stream.read_received());
            stream.consume(1);
            assert_eq!(expected, stream.read_received());
        }

        // the first segment far from the ACK the receiver kept for a stream
        // without a start doesn't start it (a blind segment would anchor the
        // stream elsewhere, and a blind FIN would end it); the next segment
        // starts the stream wherever it lies, as the ACK or the segment was
        // forged (the capture starts at the initiator's request, which ACKs
        // the responder's first byte)
        for forged_fin in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            script.segments.drain(..3);
            if forged_fin {
                script.fin_at(Responder, 1 << 30, &[]);
            } else {
                script.send_at(Responder, 1 << 30, b"EVIL!");
            }
            script.send_at(Responder, 0, b"real");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"real"), stream.read_received());
            assert!(false == stream.is_finished());
            assert_eq!(1, stream.status().out_of_window_segments);
        }
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            // the initiator's ACK is forged
            script.segments[3].header.acknowledgment_number = 2001 + (1 << 30);
            script.segments.drain(..3);
            script
                .send_at(Responder, 0, b"aaa")
                .send_at(Responder, 3, b"bbb");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"bbb"), stream.read_received());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // a FIN far from the kept ACK never starts the stream, with or
        // without bytes, as nothing could recover a stream that a blind FIN
        // ended
        for bytes in [&b""[..], &b"x"[..]] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"request");
            script.segments.drain(..3);
            script
                .fin_at(Responder, 1 << 30, &[])
                .fin_at(Responder, 1 << 30, bytes)
                .send_at(Responder, 0, b"real");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"real"), stream.read_received());
            assert!(false == stream.is_finished());
            assert_eq!(2, stream.status().out_of_window_segments);
        }

        // the ACK number of a SYN-ACK gives the other stream its start only
        // if the ACK kept for that stream allows it, like a late SYN (at or
        // before the ACK): forged SYN-ACKs can't anchor the stream elsewhere,
        // and their ACK number is not kept either, so the initiator's bytes
        // start the stream (the responder's data ACKs the initiator's first
        // byte, the SYN-ACKs a far one, one 100 bytes after it, or the same
        // one twice)
        for (offset, repeat) in [(1 << 30, false), (100, false), (1 << 30, true)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 5000);
            script
                .handshake()
                .send(Responder, b"data")
                .send(Initiator, b"aaa")
                .send(Initiator, b"bbb");
            script.segments[1].header.acknowledgment_number = 1001 + offset;
            let syn_ack = script.segments.remove(1);
            script.segments.drain(..2);
            script.segments.insert(1, syn_ack.clone());
            if repeat {
                script.segments.insert(2, syn_ack);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            assert_eq!(TcpRead::Data(b"aaabbb"), stream.read_received());
            assert_eq!(0, stream.status().out_of_window_segments);
        }

        // before the SYN-ACK, the initiator drops everything but the SYN-ACK,
        // and no ACK of its own is kept yet: a blind FIN of the responder,
        // with or without bytes, doesn't start the responder stream (the FIN
        // has no ACK, as a blind one before the SYN-ACK can't have one)
        for bytes in [&b""[..], &b"x"[..]] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut fin = script.injected(|s| {
                s.fin_at(Responder, 1 << 30, bytes);
            });
            fin.header.ack = false;
            fin.ack = None;
            script.segments.push(fin);
            script
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b"request")
                .send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert!(false == stream.is_finished());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // ... and such a FIN disputes nothing: with the SYN-ACK not captured,
        // the initiator's ACK is kept, and the first segment far from it is
        // still refused
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let mut fin = script.injected(|s| {
                s.fin_at(Responder, 1 << 30, b"");
            });
            fin.header.ack = false;
            fin.ack = None;
            script.segments.push(fin);
            script.syn_ack().ack(Initiator);
            script.segments.remove(2);
            script
                .send_at(Responder, 1 << 30, b"zz")
                .send(Responder, b"response");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            assert_eq!(TcpRead::Data(b"response"), stream.read_received());
            assert_eq!(2, stream.status().out_of_window_segments);
        }

        // only the first segment far from the kept ACK is refused: with an
        // ACK before every segment of a stream that has more in flight than
        // k fallback windows allow, the second segment starts the stream
        // (the capture starts at the initiator's request, the responder's
        // segments lie 1000 bytes after the initiator's ACKs)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"request")
                .send_at(Responder, 1000, b"aaa")
                .ack_to(Initiator, 0)
                .send_at(Responder, 1003, b"bbb")
                .ack_to(Initiator, 0)
                .send_at(Responder, 1006, b"ccc");
            script.segments.drain(..3);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"bbbccc"), stream.read_received());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // the kept ACK that the second segment overrules is dropped, so it
        // neither counts as the seen ACK of the started stream (an ACK one
        // window after the segment's 6 bytes, but k windows after its first
        // byte) nor as evidence of a jump (an ACK further after them, which
        // a blind segment within one window of it would otherwise confirm)
        for (ack, blind) in [(105, false), (110, true)] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: Some(1),
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"request")
                .send(Responder, b"aaa")
                .send(Responder, b"bbbbbb");
            script.segments.drain(..3);
            script.segments[0].header.acknowledgment_number = 2001 + ack;
            if blind {
                script.send_at(Responder, ack as u64, b"blind");
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Responder);
            assert_eq!(0, stream.acked_offset());
            assert_eq!(6, stream.highest_offset());
            assert_eq!(0, stream.holes().count());
            assert_eq!(0, stream.status().resyncs);
            assert_eq!(1 + u64::from(blind), stream.status().out_of_window_segments);
        }

        // the SYN of a reconnect counts as a packet of the connection it may
        // replace, so after it, a hole that an ACK covered is overdue
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 6, b"ghi")
                .ack(Responder);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number = 5000;
            let (connection, _) = syn.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Gap { len: Some(3) },
                connection.stream_mut(Initiator).read_received()
            );
        }

        // an ACK that shrinks the window to 0 doesn't make the hole it adds
        // overdue, so the bytes still arrive after it (ACK captured before
        // the data it ACKs)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 10;
            script.handshake().send(Initiator, b"abc");
            script.window_size = 0;
            script.ack_to(Responder, 6).send_at(Initiator, 3, b"def");
            {
                let (connection, _) = script.feed(&mut pool, ..5).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"def"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // late segments still fill an overdue hole that the read position
        // hasn't reached
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .send(Initiator, b"jkl");
            let late = script.segments.remove(2);
            script.segments.push(late);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdefghijkl"), stream.read_received());
            assert!(stream.is_clean());
        }

        // a stream whose SYN was not seen starts at its first bytes (also
        // after packets of the receiver, and across a wrap-around of the
        // sequence numbers)
        for (isn, receiver_first) in [(2000, false), (2000, true), (u32::MAX - 4, false)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, isn);
            script
                .handshake()
                .send(Responder, b"lost")
                .send(Initiator, b"x")
                .send(Responder, b"abc")
                .send(Responder, b"def");
            script.segments.drain(..4);
            if false == receiver_first {
                script.segments.remove(0);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            assert_eq!(0, stream.read_offset());
        }

        // earlier bytes arriving before the read position moved are put in
        // front of a mid-stream pickup, moving the offsets (also when they
        // overlap the first bytes or leave a hole)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghij")
                .send_at(Initiator, 5, b"fgh");
            script.segments.drain(..3);
            for (i, expected) in [
                (2, &b"ghij"[..]),
                (3, b"fghij"),
                (0, b"abc"),
                (1, b"abcdefghij"),
            ] {
                let (connection, _) = script.segments[i].feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(expected), stream.read_received());
                assert_eq!(0, stream.read_offset());
                assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            }
        }

        // the hole a prepend leaves before the seen ACK is overdue once that
        // ACK was seen N packets ago, also if there was no hole when it was
        // seen
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"x")
                .send(Initiator, b"bc")
                .send(Initiator, b"def")
                .ack(Responder)
                .ack(Responder);
            script.segments.drain(..3);
            // without "bc", "x" after the ACKs
            script.segments.remove(1);
            script.segments.rotate_left(1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(vec![1..3], stream.holes().collect::<Vec<_>>());
            stream.read_received();
            stream.consume(1);
            assert_eq!(TcpRead::Gap { len: Some(2) }, stream.read_received());
        }

        // a prepend moves the overdue state with the offsets: the ACK of N
        // packets ago, settled before the prepend or after it
        for (tolerance, acks_after) in [(1, 1), (2, 0)] {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: tolerance,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"lostlostxy")
                .send(Initiator, b"abc")
                .send(Initiator, b"lll")
                .send(Initiator, b"ghi");
            let x = script.injected(|s| {
                s.send_at(Initiator, 8, b"x");
            });
            // ACKs of the bytes up to "ghi", before and after "x"
            for _ in 0..1 + acks_after {
                script.ack_to(Responder, 16);
            }
            script.segments.push(x);
            script.ack_to(Responder, 16);
            script.segments.drain(..4);
            // without "lll"
            script.segments.remove(1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            // "x", hole, "abc", hole, "ghi", where the ACK of the "ghi" covers
            // both holes for long enough
            assert_eq!(vec![1..2, 5..8], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"x"), stream.read_received());
            stream.consume(1);
            assert_eq!(TcpRead::Gap { len: Some(1) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
        }

        // the implied ACK moves with the offsets too, also after a FIN moved
        // the highest offset back (the implied ACK never moves back)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"lostlostxy")
                .send(Initiator, b"abc");
            let x = script.injected(|s| {
                s.send_at(Initiator, 8, b"x");
            });
            // an ACK two bytes after "abc" (one window), then the FIN after
            // "abc", which moves the highest offset back
            script.ack_to(Responder, 15).fin(Initiator);
            script.segments.push(x);
            script.segments.drain(..4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(5), stream.fin_offset());
            assert_eq!(TcpRead::Data(b"x"), stream.read_received());
            stream.consume(1);
            // the implied ACK was 2 windows before the ACK, 3 after "x"
            assert_eq!(TcpRead::Gap { len: Some(1) }, stream.read_received());
        }

        // a keep-alive doesn't start a stream if it ends at the receiver's
        // ACK, but as the first packet it does, with its filler byte
        // (regression test: the old tcp-reassembly branch always started
        // the stream at it)
        for (receiver_first, expected) in [(true, &b"def"[..]), (false, b"xdef")] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"ghi");
            let keep_alive = script.injected(|s| {
                s.send_at(Initiator, 2, b"x");
            });
            script.send(Initiator, b"def");
            // without the handshake and the bytes before the keep-alive
            script.segments.drain(..4);
            script
                .segments
                .insert(usize::from(receiver_first), keep_alive);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(expected),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // other segments at the position of a keep-alive (the byte before
        // the receiver's ACK) start the stream: two bytes and a byte with a
        // FIN. A keep-alive without bytes doesn't (the following bytes start
        // the stream).
        for (payload, fin, expected) in [
            (&b"bc"[..], false, &b"bcd"[..]),
            (b"b", true, b"b"),
            (b"", false, b"cd"),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .send(Responder, b"ghi");
            let segment = script.injected(|s| {
                s.send_at(Initiator, 1, payload);
            });
            script.send_at(Initiator, 2, b"cd");
            script.segments.drain(..4);
            script.segments.insert(1, segment);
            script.segments[1].header.fin = fin;
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(expected),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // the end is reported once all bytes up to the FIN were read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .fin_with_data(Initiator, b"c")
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"c"), stream.read_received());
            stream.consume(1);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            // without bytes
            assert_eq!(
                TcpRead::End(TcpStreamEnd::Fin),
                connection.stream_mut(Responder).read_received()
            );
        }

        // bytes after the FIN are never readable
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .send(Initiator, b"def")
                .send_at(Initiator, 1, b"bcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // no end while bytes before the FIN are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // bytes starting after the receiver's window are never readable
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send_at(Initiator, 201, b"x")
                .send_at(Initiator, 0, &[b'a'; 201]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(&[b'a'; 201]), stream.read_received());
            stream.consume(201);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // a retransmitted SYN changes nothing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn_with_data(b"abc")
                .syn_ack()
                .send(Initiator, b"def");
            let syn = script.segments[0].clone();
            script.segments.push(syn);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdef"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // data far after the receiver's window (e.g. after a large capture
        // loss) continues the stream once an ACK of the other side within
        // one window of it confirms the jump: the bytes after it follow a
        // gap of unknown length, which also covers the confirmed bytes (also
        // across a wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 500] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, b"a.js");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"a.js"), stream.read_received());
        }

        // an ACK beyond the window that arrives before the data confirms the
        // jump once the data arrives, which is then the new start
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 1000)
                .send_at(Initiator, 1000, b"GET /")
                .send(Initiator, b"a.js");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"GET /a.js"), stream.read_received());
        }

        // without an ACK that confirms the jump, the data after the window
        // is not read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .send(Initiator, b"a.js");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // the holes before a jump can't be filled anymore, as their bytes
        // now map elsewhere: they are read as gaps before the gap of the
        // resync
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi");
            script.segments.remove(4);
            script
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, b"a.js");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"ghi"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"a.js"), stream.read_received());
        }

        // resyncs without bytes between them leave one gap, unless the read
        // position stepped over the gap of the first one
        for step_over in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"x")
                .ack(Responder)
                .send_at(Initiator, 5000, b"y")
                .ack(Responder)
                .send(Initiator, b"z");
            {
                let (connection, _) = script.feed(&mut pool, ..6).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                if step_over {
                    assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
                    stream.consume_gap();
                }
            }
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(2, stream.status().resyncs);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"z"), stream.read_received());
        }

        // with resync_after_segments = Some(n), n consecutive segments after
        // the window, each within one window of the one before, continue
        // the stream at the last of them without an ACK, but n - 1 don't
        for (after, resynced) in [(3, true), (4, false)] {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(after),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"x")
                .send(Initiator, b"y")
                .send(Initiator, b"z");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            if resynced {
                assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
                stream.consume_gap();
                assert_eq!(TcpRead::Data(b"z"), stream.read_received());
            } else {
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
        }

        // after a reset, the holes are gaps, every byte received can be
        // read, and then the end is reported
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .rst(Responder);
            script.segments.remove(4);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"ghi"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Reset), stream.read_received());
            assert_eq!(
                TcpRead::End(TcpStreamEnd::Reset),
                connection.stream_mut(Responder).read_received()
            );
        }

        // ... also behind the gap of a resync
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .rst(Initiator);
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::End(TcpStreamEnd::Reset), stream.read_received());
        }

        // a stream whose FIN arrived before the reset ends at its FIN, also
        // with a hole before the FIN
        for lost in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_with_data(Initiator, b"def")
                .rst(Responder);
            if lost {
                script.segments.remove(3);
            }
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            let stream = connection.stream_mut(Initiator);
            if lost {
                assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
                stream.consume_gap();
                assert_eq!(TcpRead::Data(b"def"), stream.read_received());
            } else {
                assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            }
            stream.consume(6);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }
    }

    #[test]
    fn read_acked() {
        // nothing ACKed yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Pending, stream.read_acked());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // bytes up to the ACKed offset (also across a wrap-around of the
        // sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .ack_to(Responder, 4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abcd"), stream.read_acked());
                stream.consume(4);
                assert_eq!(TcpRead::Pending, stream.read_acked());
            }
            script.ack(Responder);
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"ef"),
                connection.stream_mut(Initiator).read_acked()
            );
        }

        // without ACKs (capture of one direction), the bytes up to the
        // implied ACK are readable
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"ab"),
                connection.stream_mut(Initiator).read_acked()
            );
        }

        // regression test (the old tcp-reassembly branch stalled after
        // capture loss): in a capture of one direction, the implied ACK alone
        // delivers the bytes up to two fallback windows before the highest
        // offset, with one gap per lost range
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            for chunk in b"abcdefghijklmnopqrstuvwx".chunks(2) {
                script.send(Initiator, chunk);
            }
            // lose "cd", "ij" and "kl"
            for index in [6, 5, 2] {
                script.segments.remove(index);
            }
            let mut delivered = Vec::new();
            let mut gaps = Vec::new();
            for segment in &script.segments {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                loop {
                    match stream.read_acked() {
                        TcpRead::Data(data) => {
                            delivered.extend_from_slice(data);
                            let len = data.len();
                            stream.consume(len);
                        }
                        TcpRead::Gap { len } => {
                            gaps.push((stream.read_offset(), len));
                            stream.consume_gap();
                        }
                        _ => break,
                    }
                }
            }
            assert_eq!(&b"abefghmnopqrst"[..], &delivered[..]);
            assert_eq!(vec![(2, Some(2)), (8, Some(4))], gaps);
        }

        // consuming is limited to the ACKed bytes that were read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"ab"), stream.read_acked());
            stream.consume(10);
            assert_eq!(2, stream.read_offset());
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
        }

        // reading stops at a hole, even if bytes after it are ACKed
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .ack(Responder);
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(
                    TcpRead::Data(b"abc"),
                    connection.stream_mut(Initiator).read_acked()
                );
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdefghi"),
                connection.stream_mut(Initiator).read_acked()
            );
        }

        // the end is reported once all bytes up to the FIN were read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .ack(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_acked());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_acked());
        }

        // bytes consumed after reading them with read_received
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.consume(4);
            assert_eq!(TcpRead::Pending, stream.read_acked());
            assert_eq!(TcpRead::Data(b"ef"), stream.read_received());
        }

        // the gap of a resync is read at its offset, and the bytes after it
        // once they are ACKed (the ACK of the jump ACKs the bytes before it)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, b"a.js")
                .ack(Responder);
            {
                let (connection, _) = script.feed(&mut pool, ..7).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_acked());
                stream.consume(3);
                assert_eq!(TcpRead::Gap { len: None }, stream.read_acked());
                stream.consume_gap();
                assert_eq!(TcpRead::Pending, stream.read_acked());
            }
            let (connection, _) = script.feed(&mut pool, 7..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"a.js"),
                connection.stream_mut(Initiator).read_acked()
            );
        }

        // after a reset, the end is reported once the ACKed bytes were read,
        // even if bytes that were not ACKed are left (they can still be
        // read with read_received). The ACK of the RST counts.
        for (rst_acks, acked) in [(false, &b"abc"[..]), (true, b"abcdef")] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack(Responder)
                .send(Initiator, b"def")
                .rst(Responder);
            script.segments[6].header.ack = rst_acks;
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(acked), stream.read_acked());
            stream.consume(acked.len());
            assert_eq!(TcpRead::End(TcpStreamEnd::Reset), stream.read_acked());
            if false == rst_acks {
                assert_eq!(TcpRead::Data(b"def"), stream.read_received());
            }
        }

        // a stream whose FIN arrived before the reset ends at the FIN once
        // the bytes before it are ACKed, otherwise the reset ends it before
        // the bytes that were not ACKed
        for (rst_acks, acked, end) in [
            (false, &b"abc"[..], TcpStreamEnd::Reset),
            (true, b"abcdef", TcpStreamEnd::Fin),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack(Responder)
                .fin_with_data(Initiator, b"def")
                .rst(Responder);
            script.segments[6].header.ack = rst_acks;
            let mut connection = script.feed_all(&mut pool).ended.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(acked), stream.read_acked());
            stream.consume(acked.len());
            assert_eq!(TcpRead::End(end), stream.read_acked());
        }
    }

    #[test]
    fn consume() {
        // moving the read position ends putting earlier bytes in front of
        // a mid-stream pickup, consuming nothing doesn't. A consume after
        // bytes were put in front consumes nothing until the next read.
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi");
            script.segments.drain(..3);
            {
                let (connection, _) = script.segments[2].feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"ghi"), stream.read_received());
                stream.consume(0);
            }
            {
                let (connection, _) = script.segments[1].feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.consume(3);
                assert_eq!(0, stream.read_offset());
                assert_eq!(TcpRead::Data(b"defghi"), stream.read_received());
                stream.consume(1);
            }
            let (connection, _) = script.segments[0].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.read_offset());
            assert_eq!(TcpRead::Data(b"efghi"), stream.read_received());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // partial consumes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
            stream.consume(1);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"f"), stream.read_received());
            stream.consume(1);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // consuming is limited to the bytes the last read returned
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                assert_eq!(
                    TcpRead::Data(b"abc"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.consume(10);
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
        }

        // nothing is consumed without a read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // nothing is consumed after a pending read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            {
                let (connection, _) = script.feed(&mut pool, ..3).active.unwrap();
                assert_eq!(
                    TcpRead::Pending,
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = script.feed(&mut pool, 3..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // bytes arriving after a consume follow the unconsumed bytes
        for consumed in 0..=6 {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .send(Initiator, b"gh");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
                stream.consume(consumed);
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            assert_eq!(
                TcpRead::Data(&b"abcdefgh"[consumed..]),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a long stream with swapped segments, consumed in small steps that
        // fall behind the received bytes
        {
            let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            for chunk in data.chunks(1000) {
                script.send(Initiator, chunk);
            }
            for pair in script.segments[3..].chunks_mut(2) {
                pair.reverse();
            }
            let mut delivered = Vec::new();
            for (i, segment) in script.segments.iter().enumerate() {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                // at most 100 reads per segment, all bytes after the last one
                let last = i + 1 == script.segments.len();
                let mut reads = 0;
                while let TcpRead::Data(d) = stream.read_received() {
                    if 100 == reads && false == last {
                        break;
                    }
                    let len = d.len().min(7);
                    delivered.extend_from_slice(&d[..len]);
                    stream.consume(len);
                    reads += 1;
                }
            }
            assert_eq!(data, delivered);
        }

        // consuming up to an overdue hole gives it up right away, as the
        // read position reaches it
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .send(Initiator, b"jkl");
            script.segments.remove(2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(2);
            assert_eq!(&[3..6][..], stream.holes().collect::<Vec<_>>());
            stream.consume(1);
            assert_eq!(0, stream.holes().count());
            assert_eq!((1, 3), (stream.status().gaps, stream.status().gap_bytes));
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
        }

        // retransmissions of consumed bytes are not delivered again
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
            }
            let (connection, _) = script.segments[3].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Pending, stream.read_received());
            assert_eq!(3, stream.read_offset());
        }

        // a stream gives back the room of consumed bytes once they make up
        // half of its buffer, after a consume or a discard: it keeps at most
        // twice the room its bytes need, but at least the pooled buffer
        // capacity, so later bytes beyond that need new room (and allocate);
        // while less than half is consumed, it keeps all its room (the
        // buffer holds 1100 bytes in a capacity of 2000, as it grew for the
        // second segment)
        for (discard, consumed, next, allocates) in [
            // all consumed: the room shrinks to the pooled capacity
            (false, 1100, 400, true),
            (false, 1099, 400, true),
            // half consumed: twice the room of the 500 bytes left stays
            (false, 600, 500, false),
            (false, 600, 501, true),
            (true, 600, 501, true),
            // less than half consumed: all room stays
            (false, 500, 800, false),
        ] {
            let config = TcpReassemblyConfig {
                max_pooled_buffer_capacity: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, &[7; 1000])
                .send(Initiator, &[8; 100])
                .send(Initiator, &[9; 1000]);
            script.segments[5].payload.truncate(next);
            {
                let (connection, _) = script.feed(&mut pool, ..5).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                if discard {
                    stream.discard_until(consumed as u64);
                } else {
                    stream.read_received();
                    stream.consume(consumed);
                }
            }
            let bytes = script.segments[5].to_bytes();
            let (allocations, _) = count_allocations(|| {
                script.segments[5].feed_bytes(&bytes, &mut pool, ());
            });
            assert_eq!(
                allocates,
                0 < allocations,
                "{:?}",
                (discard, consumed, next)
            );
        }

        // the room for prepends before the first byte of a pickup is not
        // consumed, so storing bytes doesn't drop it: bytes put in front and
        // appended by turns cost little on average (the pickup holds 2000
        // bytes with placeholders, then 200 pairs of single bytes come)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 1000)
                .send(Initiator, b"a")
                .send_at(Initiator, 2999, b"b");
            script.segments.drain(..3);
            let mut pairs = script.clone();
            pairs.segments.clear();
            for i in 1..=200u64 {
                pairs
                    .send_at(Initiator, 1000 - i, b"p")
                    .send_at(Initiator, 2999 + i, b"q");
            }
            script.feed_all(&mut pool);
            let bytes: Vec<_> = pairs.segments.iter().map(TestSegment::to_bytes).collect();
            let (allocations, _) = count_allocations(|| {
                for (segment, bytes) in pairs.segments.iter().zip(&bytes) {
                    segment.feed_bytes(bytes, &mut pool, ());
                }
            });
            assert!(allocations < 20, "{} allocations", allocations);
        }

        // prepends alone make room for the next ones, as many bytes as the
        // stream holds each time, so 200 of them allocate a few times
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, 1000)
                .send(Initiator, b"a");
            script.segments.drain(..3);
            let mut prepends = script.clone();
            prepends.segments.clear();
            for i in 1..=200u64 {
                prepends.send_at(Initiator, 1000 - i, b"p");
            }
            script.feed_all(&mut pool);
            let bytes: Vec<_> = prepends
                .segments
                .iter()
                .map(TestSegment::to_bytes)
                .collect();
            let (allocations, _) = count_allocations(|| {
                for (segment, bytes) in prepends.segments.iter().zip(&bytes) {
                    segment.feed_bytes(bytes, &mut pool, ());
                }
            });
            assert!(allocations < 20, "{} allocations", allocations);
        }

        // a late SYN takes exactly the room its placeholder needs, so the
        // bytes that follow need new room (1000 bytes, then the SYN one
        // byte before them, then 900 bytes), and it drops the room left by
        // a prepend before it, so the bytes that follow fit in that room
        // (1000 bytes, a byte put in front, then the SYN, then 900 bytes)
        for (before, prepended, allocations_after) in [(1, false, 1), (2, true, 0)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_uncaptured(Initiator, before)
                .send(Initiator, &[7; 1000]);
            if prepended {
                script.send_at(Initiator, 1, b"x");
            }
            let syn = script.segments.remove(0);
            script.segments.drain(..2);
            script.segments.push(syn);
            script.send(Initiator, &[8; 900]);
            let last = script.segments.pop().unwrap();
            script.feed_all(&mut pool);
            let bytes = last.to_bytes();
            let (allocations, _) = count_allocations(|| {
                last.feed_bytes(&bytes, &mut pool, ());
            });
            assert_eq!(allocations_after, allocations);
        }
    }

    #[test]
    fn give_up_hole() {
        // the hole at the read position becomes a gap, which is read before
        // the bytes after it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi");
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert!(stream.give_up_hole());
            assert_eq!(0, stream.holes().count());
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(6, stream.read_offset());
            assert_eq!(TcpRead::Data(b"ghi"), stream.read_received());
        }

        // no hole at the read position
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 5, b"f");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            // bytes at the read position, the hole lies after them
            assert!(false == stream.give_up_hole());
            assert_eq!(&[3..5][..], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            // a gap at the read position
            assert!(stream.give_up_hole());
            assert!(false == stream.give_up_hole());
            assert_eq!(TcpRead::Gap { len: Some(2) }, stream.read_received());
            stream.consume_gap();
            // no holes at all
            assert!(false == stream.give_up_hole());
            assert_eq!(TcpRead::Data(b"f"), stream.read_received());
            assert_eq!((1, 2), (stream.status().gaps, stream.status().gap_bytes));
        }

        // reading only ACKed bytes returns the gap too
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send_at(Initiator, 3, b"def");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.give_up_hole());
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_acked());
            stream.consume_gap();
            assert_eq!(TcpRead::Pending, stream.read_acked());
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
        }

        // bytes of the gap that arrive later are ignored, also if they differ
        // from the placeholders
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi");
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                assert!(stream.give_up_hole());
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"ghi"), stream.read_received());
        }

        // a hole up to an ACK after the received bytes, whose bytes arrive
        // after it was given up, followed by new bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 6);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                assert!(stream.give_up_hole());
                assert_eq!((1, 3), (stream.status().gaps, stream.status().gap_bytes));
            }
            script
                .send_at(Initiator, 3, b"dX")
                .send_at(Initiator, 4, b"efgh");
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"gh"), stream.read_received());
        }

        // a FIN inside a gap up to an ACK cuts the gap, also after bytes of
        // the gap arrived (they are ignored)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 10);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                assert!(stream.give_up_hole());
            }
            script
                .send_at(Initiator, 3, b"defgh")
                .fin_at(Initiator, 6, &[]);
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(6), stream.fin_offset());
            assert_eq!(6, stream.highest_offset());
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            // the counters keep the bytes that were given up
            assert_eq!((1, 7), (stream.status().gaps, stream.status().gap_bytes));
        }

        // an overdue hole at the read position is a gap already
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send_at(Initiator, 3, b"def")
                .send_at(Initiator, 6, b"ghi");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(false == stream.give_up_hole());
            assert_eq!((1, 3), (stream.status().gaps, stream.status().gap_bytes));
        }

        // a hole at the gap of a resync is given up behind it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send_at(Initiator, 1010, b"s");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(3);
            assert!(stream.give_up_hole());
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Gap { len: Some(5) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"s"), stream.read_received());
        }
    }

    #[test]
    fn consume_gap() {
        // does nothing if the read position is not at a gap
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 5, b"f");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            // at bytes
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume_gap();
            assert_eq!(0, stream.read_offset());
            // at a hole
            stream.read_received();
            stream.consume(3);
            stream.consume_gap();
            assert_eq!(3, stream.read_offset());
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // steps over a gap between received bytes, the bytes after it are
        // read next (also behind further holes and gaps)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"ab")
                .send_at(Initiator, 4, b"ef")
                .send_at(Initiator, 8, b"ij");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            for (offset, data) in [(2, &b"ef"[..]), (6, b"ij")] {
                stream.read_received();
                stream.consume(2);
                assert!(stream.give_up_hole());
                stream.consume_gap();
                assert_eq!(offset + 2, stream.read_offset());
                assert_eq!(TcpRead::Data(data), stream.read_received());
            }
        }

        // steps over a gap after the received bytes, new bytes after it are
        // read next
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 5);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                assert!(stream.give_up_hole());
                stream.consume_gap();
                assert_eq!(5, stream.read_offset());
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            script.send_at(Initiator, 5, b"fg");
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"fg"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // steps over a gap up to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(3);
            assert!(stream.give_up_hole());
            stream.consume_gap();
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // steps onto an overdue hole, which is given up right away
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 5;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 6);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                assert!(stream.give_up_hole());
            }
            // a hole after the gap, overdue once the implied ACK (11) passes
            // it
            script
                .ack_to(Responder, 10)
                .send_at(Initiator, 10, b"klmnopqrstu");
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(&[6..10][..], stream.holes().collect::<Vec<_>>());
            stream.consume_gap();
            assert_eq!(0, stream.holes().count());
            assert_eq!((2, 7), (stream.status().gaps, stream.status().gap_bytes));
            assert_eq!(TcpRead::Gap { len: Some(4) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"klmnopqrstu"), stream.read_received());
        }

        // steps over the gap of a resync, which takes no offsets
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, b"a.js");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(3);
            stream.consume_gap();
            assert_eq!(3, stream.read_offset());
            assert_eq!(TcpRead::Data(b"a.js"), stream.read_received());
            stream.consume_gap();
            assert_eq!(3, stream.read_offset());
        }
    }

    #[test]
    fn discard_until() {
        // discarding ends putting earlier bytes in front of a mid-stream
        // pickup, discarding up to its first byte doesn't
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi");
            script.segments.drain(..3);
            {
                let (connection, _) = script.segments[2].feed(&mut pool, ()).active.unwrap();
                connection.stream_mut(Initiator).discard_until(0);
            }
            {
                let (connection, _) = script.segments[1].feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"defghi"), stream.read_received());
                stream.discard_until(1);
            }
            let (connection, _) = script.segments[0].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"efghi"), stream.read_received());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // an offset inside the received bytes drops the bytes before it,
        // which keeps the stream clean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_until(2);
            assert_eq!(2, stream.read_offset());
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
            stream.discard_until(5);
            assert_eq!(TcpRead::Data(b"f"), stream.read_received());
            assert!(stream.is_clean());
        }

        // offsets at or before the read offset change nothing
        for offset in [0, 1, 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
            stream.discard_until(offset);
            assert_eq!(2, stream.read_offset());
            // the bytes of the last read can still be consumed
            stream.consume(1);
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
        }

        // the bytes of the last read can't be consumed after a discard
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.discard_until(2);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
        }

        // holes before the offset are dropped (a hole containing it only
        // partly) without counting as gaps, the missing bytes after it stay
        // a hole
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"ab")
                .send_at(Initiator, 4, b"ef")
                .send_at(Initiator, 10, b"k");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_until(8);
            assert_eq!(8, stream.read_offset());
            assert_eq!(&[8..10][..], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Pending, stream.read_received());
            assert_eq!((0, 0), (stream.status().gaps, stream.status().gap_bytes));
            assert!(stream.is_clean());
            // the rest of the hole can still be filled
            script.send_at(Initiator, 6, b"ghij");
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"ijk"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // an offset after the highest offset drops all bytes and holes up to
        // the highest offset, the bytes after it are readable once they
        // arrive
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 5);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.discard_until(100);
                assert_eq!(5, stream.read_offset());
                assert_eq!(0, stream.holes().count());
                assert_eq!((0, 0), (stream.status().gaps, stream.status().gap_bytes));
            }
            script.send_at(Initiator, 5, b"fg");
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"fg"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // retransmissions of discarded bytes are ignored
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                connection.stream_mut(Initiator).discard_until(4);
            }
            script.send_at(Initiator, 0, b"XYZWe");
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"ef"), stream.read_received());
            assert!(stream.is_clean());
        }

        // an offset inside a gap at the read position shortens the gap
        // without counting it again
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send_at(Initiator, 5, b"f");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.give_up_hole());
            stream.discard_until(2);
            assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
            assert_eq!((1, 5), (stream.status().gaps, stream.status().gap_bytes));
            stream.discard_until(5);
            assert_eq!(TcpRead::Data(b"f"), stream.read_received());
        }

        // an offset inside an overdue hole gives up the rest of it, as the
        // read position reaches it (the discarded part doesn't count)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 4,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send_at(Initiator, 9, b"jkl")
                .send(Initiator, b"mno")
                .send(Initiator, b"pqr");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_until(5);
            assert_eq!(0, stream.holes().count());
            assert_eq!((1, 4), (stream.status().gaps, stream.status().gap_bytes));
            assert_eq!(TcpRead::Gap { len: Some(4) }, stream.read_received());
        }

        // up to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin_with_data(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_until(10);
            assert_eq!(3, stream.read_offset());
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            assert!(stream.is_complete());
        }

        // keeps the gap of a resync at the offset, and discards it with the
        // bytes after it
        for (offset, expected) in [
            (3, TcpRead::Gap { len: None }),
            (4, TcpRead::Data(&b".js"[..])),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, b"a.js");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_until(offset);
            assert_eq!(expected, stream.read_received());
        }
    }

    #[test]
    fn discard_all() {
        // ends putting earlier bytes in front of a mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            script.segments.drain(..3);
            {
                let (connection, _) = script.segments[1].feed(&mut pool, ()).active.unwrap();
                connection.stream_mut(Initiator).discard_all();
            }
            let (connection, _) = script.segments[0].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(3, stream.read_offset());
            assert_eq!(TcpRead::Pending, stream.read_received());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // drops the received bytes, which keeps the stream clean, and new
        // bytes continue the stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.discard_all();
                assert_eq!(3, stream.read_offset());
                assert_eq!(TcpRead::Pending, stream.read_received());
                assert!(stream.is_clean());
            }
            script.send(Initiator, b"def");
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"def"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // drops the holes without counting them as gaps, and a gap at the
        // read position that was counted when it was given up
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 2, b"c")
                .send_at(Initiator, 5, b"f")
                .ack_to(Responder, 8);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert!(stream.give_up_hole());
                stream.discard_all();
                assert_eq!(8, stream.read_offset());
                assert_eq!(0, stream.holes().count());
                assert_eq!(TcpRead::Pending, stream.read_received());
                assert_eq!((1, 2), (stream.status().gaps, stream.status().gap_bytes));
            }
            script.send_at(Initiator, 6, b"ghij");
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"ij"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // nothing buffered
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_all();
            assert_eq!(0, stream.read_offset());
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // up to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin_with_data(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_all();
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // keeps the gap of a resync without bytes after it
        for (after, expected) in [
            (&b""[..], TcpRead::Gap { len: None }),
            (b"a.js", TcpRead::Pending),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, after);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.discard_all();
            assert_eq!(expected, stream.read_received());
        }
    }

    #[test]
    fn force_resync() {
        // the next segment with bytes is the new start, behind a gap of
        // unknown length, also if it lies in the window
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                connection.stream_mut(Initiator).force_resync();
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().resyncs);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
        }

        // ... such as one with a new initial sequence number before the
        // stream's bytes, which isn't detected otherwise
        for forced in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let jumped = script.seq(Initiator, 0).wrapping_sub(1_000_000);
            for (seq, payload) in [(jumped, b"new"), (jumped.wrapping_add(3), b"er!")] {
                let mut segment = script.injected(|s| {
                    s.send(Initiator, payload);
                });
                segment.header.sequence_number = seq;
                script.segments.push(segment);
            }
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                if forced {
                    connection.stream_mut(Initiator).force_resync();
                }
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            if forced {
                assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
                stream.consume_gap();
                assert_eq!(TcpRead::Data(b"newer!"), stream.read_received());
            } else {
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
        }

        // it stays pending while the stream has more gaps the read position
        // didn't step over than the hole limit, and bytes in the window are
        // stored as usual until then (the first resync gives up the hole
        // 3..4, so there are two gaps)
        {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 4, b"e")
                .send(Initiator, b"fg")
                .send(Initiator, b"hi")
                .send(Initiator, b"jk");
            for range in [0..5, 5..6] {
                let (connection, _) = script.feed(&mut pool, range).active.unwrap();
                connection.stream_mut(Initiator).force_resync();
            }
            {
                let (connection, _) = script.feed(&mut pool, 6..7).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(1, stream.status().resyncs);
                for len in [3, 1] {
                    stream.read_received();
                    stream.consume(len);
                    stream.consume_gap();
                }
                assert_eq!(TcpRead::Data(b"fghi"), stream.read_received());
                stream.consume(4);
            }
            let (connection, _) = script.feed(&mut pool, 7..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(2, stream.status().resyncs);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"jk"), stream.read_received());
        }

        // segments without bytes and SYNs are no new start
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc").ack(Initiator);
            let mut syn = script.segments[0].clone();
            syn.payload = b"abc".to_vec();
            script.segments.push(syn);
            script.send(Initiator, b"def");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                connection.stream_mut(Initiator).force_resync();
            }
            script.feed(&mut pool, 4..6);
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().resyncs);
            stream.read_received();
            stream.consume(3);
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
        }

        // does nothing before the stream started (its first bytes start it
        // anyway), after its FIN, or if its FIN arrives before the next bytes
        let cases: [(fn(&mut ConnectionScript), fn(&mut ConnectionScript)); 3] = [
            (
                |s| {
                    s.handshake().send(Initiator, b"abc");
                    s.segments.drain(..3);
                },
                |s| {
                    s.send(Responder, b"def");
                },
            ),
            (
                |s| {
                    s.handshake().send(Initiator, b"abc").fin(Responder);
                },
                |s| {
                    s.send(Responder, b"def");
                },
            ),
            (
                |s| {
                    s.handshake().send(Initiator, b"abc");
                },
                |s| {
                    s.fin(Responder).send(Responder, b"def");
                },
            ),
        ];
        for (before, after) in cases {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            before(&mut script);
            let fed = script.segments.len();
            after(&mut script);
            {
                let (connection, _) = script.feed(&mut pool, ..fed).active.unwrap();
                connection.stream_mut(Responder).force_resync();
            }
            let (connection, _) = script.feed(&mut pool, fed..).active.unwrap();
            assert_eq!(0, connection.stream(Responder).status().resyncs);
        }

        // ... so after the FIN, earlier bytes are still put in front of a
        // mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_with_data(Initiator, b"def");
            let earlier = script.segments[3].clone();
            script.segments.drain(..4);
            script.segments.push(earlier);
            {
                let (connection, _) = script.feed(&mut pool, ..1).active.unwrap();
                connection.stream_mut(Initiator).force_resync();
            }
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().resyncs);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
        }

        // ends putting earlier bytes or a late SYN in front of a mid-stream
        // pickup: the next bytes are the new start, a late SYN counts as
        // out-of-window
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let syn = script.segments[0].clone();
            let earlier = script.segments[3].clone();
            script.segments.drain(..4);
            script.segments.extend([syn, earlier]);
            {
                let (connection, _) = script.feed(&mut pool, ..1).active.unwrap();
                connection.stream_mut(Initiator).force_resync();
            }
            {
                let (connection, _) = script.feed(&mut pool, 1..2).active.unwrap();
                let status = connection.stream(Initiator).status();
                assert_eq!(TcpStreamStart::MidStreamPickup, status.start);
                assert_eq!(1, status.out_of_window_segments);
            }
            let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }
    }

    #[test]
    fn read_offset() {
        // stays at 0 when earlier bytes are put in front of a mid-stream
        // pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            script.segments.drain(..3);
            script.segments.swap(0, 1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).read_offset());
        }

        // starts at 0 and grows by the consumed bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.read_offset());
            stream.read_received();
            stream.consume(4);
            assert_eq!(4, stream.read_offset());
            stream.consume(4);
            assert_eq!(6, stream.read_offset());
        }

        // keeps growing across several wrap-arounds of the sequence numbers
        {
            const SEGMENT_LEN: usize = 1 << 20;
            const SEGMENTS: u64 = (3 << 32) / (SEGMENT_LEN as u64) + 1;

            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(u32::MAX - 10, 2000);
            script.handshake().send(Initiator, &[0; SEGMENT_LEN]);
            script.feed(&mut pool, ..3);

            // re-use the bytes of the data segment and only change the
            // sequence number and the first payload bytes
            let data = &script.segments[3];
            let mut bytes = data.header.to_bytes().to_vec();
            let header_len = bytes.len();
            bytes.extend_from_slice(&data.payload);

            let mut offset = 0u64;
            for _ in 0..SEGMENTS {
                bytes[4..8].copy_from_slice(&script.seq(Initiator, offset).to_be_bytes());
                bytes[header_len..header_len + 8].copy_from_slice(&offset.to_be_bytes());
                let (connection, _) = pool
                    .process_segment(
                        TcpSegment {
                            vlan_ids: Default::default(),
                            source: data.source.ip(),
                            destination: data.destination.ip(),
                            channel_id: (),
                            tcp: TcpSlice::from_slice(&bytes).unwrap(),
                        },
                        (),
                    )
                    .active
                    .unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(offset, stream.read_offset());
                match stream.read_received() {
                    TcpRead::Data(d) => {
                        assert_eq!(SEGMENT_LEN, d.len());
                        assert_eq!(&offset.to_be_bytes(), &d[..8]);
                    }
                    other => panic!("unexpected read {:?}", other),
                }
                stream.consume(SEGMENT_LEN);
                offset += SEGMENT_LEN as u64;
            }
            assert!(offset > 3 << 32);
        }
    }

    #[test]
    fn acked_offset() {
        // earlier bytes put in front of a mid-stream pickup move the ACKed
        // offset, and an ACK of the pickup's first byte or before it counts
        // once the bytes it ACKs were put in front
        for (ack, expected) in [(6, 6), (3, 3), (2, 2)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .ack_to(Responder, ack);
            script.segments.drain(..3);
            // "def", ACK, "abc"
            script.segments.rotate_left(1);
            {
                let (connection, _) = script.feed(&mut pool, ..2).active.unwrap();
                assert_eq!(
                    ack.saturating_sub(3),
                    connection.stream(Initiator).acked_offset()
                );
            }
            let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
            assert_eq!(expected, connection.stream(Initiator).acked_offset());
        }

        // ... but not after the read position moved
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .ack_to(Responder, 3);
            script.segments.drain(..4);
            {
                let (connection, _) = script.feed(&mut pool, ..1).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(1);
            }
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).acked_offset());
        }

        // the last ACK seen before a mid-stream pickup started counts once
        // it starts ("de" at offset 0), unless it lies more than one window
        // after its bytes, or before its first byte
        for (fallback_window, ack, expected) in [(4, 9, 6), (2, 9, 0), (4, 2, 0)] {
            let config = TcpReassemblyConfig {
                fallback_window,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"x")
                .ack_to(Responder, ack)
                .send(Initiator, b"de");
            script.segments.drain(..4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(expected, connection.stream(Initiator).acked_offset());
        }

        // nothing ACKed yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).acked_offset());
            assert_eq!(0, connection.stream(Responder).acked_offset());
        }

        // the implied ACK lies at most half of the stream's buffer before the
        // highest offset while the window is unknown (the fallback window is
        // 4 MiB), so a reader of the ACKed bytes keeps up before the buffer
        // is full and no bytes are rejected (a pickup of 20 segments of 100
        // bytes, nothing ACKed)
        for (max_stream_buffer, expected) in [(1000, 1500), (3000, 500), (8 << 20, 0)] {
            let config = TcpReassemblyConfig {
                max_stream_buffer,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            for _ in 0..20 {
                script.send(Initiator, &[7; 100]);
            }
            script.segments.drain(..3);
            for segment in &script.segments {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                if let TcpRead::Data(data) = stream.read_acked() {
                    let len = data.len();
                    stream.consume(len);
                }
            }
            let connection = pool.iter_mut().next().unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(expected, stream.acked_offset());
            assert_eq!(expected, stream.read_offset());
            assert_eq!(2000, stream.highest_offset());
            assert_eq!(0, stream.status().rejected_bytes);
        }

        // a hole give up window factor of 0 works like 1, also for the
        // implied ACK (a pickup, so the fallback window of 100 bytes applies)
        {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: Some(0),
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, &[7; 300]);
            script.segments.drain(..3);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(200, connection.stream(Initiator).acked_offset());
        }

        // but the implied ACK never lies less than a known window before the
        // highest offset, as the sender can have sent that far past the
        // ACK, also with a hole give up window factor of 0: the window is
        // 65535 bytes, the buffer 64 KiB, and only the first 4 KiB of 60 KiB
        // are ACKed
        for factor in [Some(2), Some(0)] {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 64 * 1024,
                hole_give_up_window_factor: factor,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, &[7; 4096])
                .ack(Responder);
            for _ in 0..14 {
                script.send(Initiator, &[7; 4096]);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(4096, connection.stream(Initiator).acked_offset());
        }

        // follows the highest ACK, older ACKs arriving later change nothing
        // (also across a wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 2)
                .ack_to(Responder, 5)
                .ack_to(Responder, 3)
                .ack_to(Responder, 6);
            script.feed(&mut pool, ..4);
            for (segment, expected) in script.segments[4..].iter().zip([2, 5, 5, 6]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).acked_offset());
            }
        }

        // an ACK of the FIN ACKs all bytes, but nothing after them
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .ack_to(Responder, 4)
                .ack_to(Responder, 5);
            script.feed(&mut pool, ..4);
            for segment in &script.segments[4..] {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!(3, stream.acked_offset());
                assert_eq!(0, stream.holes().count());
            }
        }

        // ACKs count up to one window after the highest offset, using the
        // largest window the receiver advertised before the ACK: the sender
        // can have sent into it before the window shrank (e.g. to 0)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 104)
                .ack_to(Responder, 103);
            script.window_size = 0;
            script
                .ack_to(Responder, 203)
                .ack_to(Responder, 204)
                .ack_to(Responder, 305);
            script.feed(&mut pool, ..4);
            for (segment, expected) in script.segments[4..].iter().zip([0, 103, 203, 204, 204]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).acked_offset());
            }
        }

        // the implied ACK: the sender sends at most one window after the
        // ACK, so the receiver ACKed the bytes up to the hole give up window
        // factor times the window before the highest offset (it never moves
        // back when the window grows, and a higher seen ACK counts)
        for (factor, expected) in [
            (Some(2), [0, 50, 50, 200]),
            (Some(1), [50, 150, 150, 200]),
            (None, [0, 0, 0, 200]),
        ] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, &[b'a'; 150])
                .send(Initiator, &[b'b'; 100]);
            script.window_size = 1000;
            script.ack_to(Responder, 0).ack_to(Responder, 200);
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip(expected) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).acked_offset());
            }
        }

        // the implied ACK uses the largest window the receiver advertised, so
        // a window that shrinks (e.g. to 0) doesn't move it forward
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, &[b'a'; 150])
                .send(Initiator, &[b'b'; 100]);
            script.window_size = 0;
            script.ack_to(Responder, 0);
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([0, 50, 50]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).acked_offset());
            }
        }

        // ACKs up to 2^31 - 1 after the highest offset count (with a window
        // above 2^31), one 2^31 away can't be mapped, and one 2^31 + 1 after
        // it lies 2^31 - 1 before it
        for (distance, expected) in [
            ((1 << 31) - 1, 2 + (1 << 31)),
            (1 << 31, 0),
            ((1 << 31) + 1, 0),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window: u32::MAX,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 3 + distance);
            script.segments.drain(..3);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(expected, connection.stream(Initiator).acked_offset());
        }

        // after the FIN, ACKs count up to one window after the FIN (the ACK
        // of the FIN even with a window of 0)
        for (window, ack, expected) in [(0, 4, 3), (100, 104, 3), (100, 105, 0)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = window;
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .ack_to(Responder, ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(expected, connection.stream(Initiator).acked_offset());
        }

        // the ACK that confirms a jump counts after it: one after the
        // confirmed bytes ACKs bytes that were not captured
        for (ack, expected) in [(1005, 3), (1008, 6)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack_to(Responder, ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(expected, stream.acked_offset());
            assert_eq!(expected, stream.highest_offset());
        }

        // the ACK that confirms a jump ACKs the bytes before it, also if it
        // maps before the resync point (later data after the window replaced
        // the candidate, the stream continues after "a.js")
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .send(Initiator, b"a.js")
                .ack_to(Responder, 1005);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(3, stream.acked_offset());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_acked());
        }

        // an ACK that confirmed a jump before the data arrived counts after
        // the new start, and ACKs the bytes before the jump
        for (ack, expected) in [(1000, 3), (1003, 6), (1005, 8)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, ack)
                .send_at(Initiator, 1000, b"GET /");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(1, stream.status().resyncs);
            assert_eq!(expected, stream.acked_offset());
        }

        // ACKs before a jump don't count after it (with
        // resync_after_segments, no ACK confirms the jump)
        {
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
                .ack_to(Responder, 998);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(1, stream.status().resyncs);
            assert_eq!(0, stream.acked_offset());
        }

        // an RST outside of the receiver's window doesn't ACK bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .rst_at(Responder, 1 << 30);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).acked_offset());
        }
    }

    #[test]
    fn highest_offset() {
        // moves with earlier bytes put in front of a mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            script.segments.drain(..3);
            script.segments.swap(0, 1);
            {
                let (connection, _) = script.feed(&mut pool, ..1).active.unwrap();
                assert_eq!(3, connection.stream(Initiator).highest_offset());
            }
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(6, connection.stream(Initiator).highest_offset());
        }

        // nothing received yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).highest_offset());
            assert_eq!(0, connection.stream(Responder).highest_offset());
        }

        // follows the furthest received byte, also behind holes (and across
        // a wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"abc")
                // behind a hole
                .send_at(Initiator, 6, b"gh")
                // filling the hole
                .send_at(Initiator, 3, b"def")
                // retransmission
                .send_at(Initiator, 0, b"ab");
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([3, 8, 8, 8]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).highest_offset());
            }
        }

        // reading doesn't move it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(2);
            assert_eq!(3, stream.highest_offset());
        }

        // a FIN behind missing bytes moves it to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(6, connection.stream(Initiator).highest_offset());
        }

        // a segment far after the receiver's window doesn't move it (and
        // allocates no buffer for the bytes before it)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1 << 30, b"x");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(3, stream.highest_offset());
            assert_eq!(0, stream.holes().count());
            assert_eq!(1, stream.status().out_of_window_segments);
        }

        // ACKs within the receiver's window move it, a FIN before it moves it
        // back
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 50)
                // more than one window after it
                .ack_to(Responder, 151)
                .fin_at(Initiator, 20, &[]);
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([3, 50, 50, 20]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).highest_offset());
            }
        }

        // a resync keeps it, the bytes after the jump follow it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send(Initiator, b"a.js");
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([3, 3, 3, 7]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).highest_offset());
            }
        }
    }

    #[test]
    fn holes() {
        // earlier bytes put in front of a mid-stream pickup move the holes,
        // and the bytes in between are a hole (that is not overdue)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .send(Initiator, b"cd")
                .send(Initiator, b"ef")
                .send(Initiator, b"gh")
                .send(Initiator, b"ij");
            script.segments.drain(..3);
            // "ef", "ij", "ab"
            script.segments = vec![
                script.segments[2].clone(),
                script.segments[4].clone(),
                script.segments[0].clone(),
            ];
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(vec![2..4, 6..8], stream.holes().collect::<Vec<_>>());
            stream.read_received();
            stream.consume(2);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // no holes while the bytes arrive in order
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).holes().count());
        }

        // segments create holes and fill them completely or in parts
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let steps: [(u64, &[u8], &[Range<u64>]); 10] = [
                // hole at the start of the stream
                (2, b"c", &[0..2]),
                // hole after received bytes
                (6, b"gh", &[0..2, 3..6]),
                (12, b"m", &[0..2, 3..6, 8..12]),
                // splits a hole
                (4, b"e", &[0..2, 3..4, 5..6, 8..12]),
                (9, b"j", &[0..2, 3..4, 5..6, 8..9, 10..12]),
                // fills the end of one hole and another one completely
                (1, b"bcde", &[0..1, 5..6, 8..9, 10..12]),
                // fills two holes completely
                (5, b"fghij", &[0..1, 10..12]),
                // fills the start of a hole
                (10, b"k", &[0..1, 11..12]),
                // fills a hole and overlaps received bytes
                (11, b"lm", &[0..1]),
                // fills the last hole
                (0, b"a", &[]),
            ];
            for (offset, data, _) in steps {
                script.send_at(Initiator, offset, data);
            }
            script.feed(&mut pool, ..3);
            for (segment, (_, _, expected)) in script.segments[3..].iter().zip(steps) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(expected, stream.holes().collect::<Vec<_>>());
                if expected.is_empty() {
                    assert_eq!(TcpRead::Data(b"abcdefghijklm"), stream.read_received());
                }
            }
        }

        // missing bytes before a FIN, with and without bytes in the FIN
        for fin_data in [&b""[..], b"gh"] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin_with_data(Initiator, fin_data);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                &[3..6][..],
                connection.stream(Initiator).holes().collect::<Vec<_>>()
            );
        }

        // an ACK after the highest offset adds a hole up to it (merged with
        // a hole at the end), and a FIN cuts it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            script
                .send(Initiator, b"abc")
                .send_at(Initiator, 6, b"g")
                .ack_to(Responder, 10)
                .ack_to(Responder, 12)
                .fin_at(Initiator, 9, &[]);
            script.feed(&mut pool, ..3);
            let expected: [&[Range<u64>]; 5] =
                [&[], &[3..6], &[3..6, 7..10], &[3..6, 7..12], &[3..6, 7..9]];
            for (segment, expected) in script.segments[3..].iter().zip(expected) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!(expected, stream.holes().collect::<Vec<_>>());
            }
        }

        // the ACK of a FIN arriving before the FIN adds a hole that the FIN
        // removes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 4)
                .fin(Initiator);
            script.feed(&mut pool, ..4);
            for (segment, expected) in script.segments[4..].iter().zip([&[3..4][..], &[]]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!(expected, stream.holes().collect::<Vec<_>>());
            }
        }

        // an overdue hole is listed until the read position reaches it
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send_at(Initiator, 6, b"ghi")
                .send(Initiator, b"jkl");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(&[3..6][..], stream.holes().collect::<Vec<_>>());
            stream.read_received();
            stream.consume(3);
            assert_eq!(0, stream.holes().count());
        }

        // a keep-alive probe (one byte ending at the seen ACK, without SYN
        // or FIN) doesn't fill an overdue hole, other segments do, and so
        // does a keep-alive before the hole is overdue (a SYN-ACK with
        // another ISN changes nothing)
        for (packets, offset, payload, [syn, fin], expected) in [
            // keep-alive
            (2, 5, &[0][..], [false; 2], &[3..6][..]),
            // keep-alive before the hole is overdue
            (1, 5, &[0], [false; 2], &[3..5]),
            // two bytes
            (2, 4, b"ef", [false; 2], &[3..4]),
            // one byte that doesn't end at the seen ACK
            (2, 4, b"e", [false; 2], &[3..4, 5..6]),
            // SYN-ACK with another ISN, or FIN
            (2, 5, &[0], [true, false], &[3..6]),
            (2, 5, &[0], [false, true], &[3..5]),
        ] {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 6);
            for _ in 0..packets {
                script.ack(Initiator);
            }
            let mut probe = script.injected(|s| {
                s.send_at(Initiator, offset, payload);
            });
            probe.header.syn = syn;
            probe.header.fin = fin;
            if syn {
                // the SYN occupies the sequence number before the byte
                probe.header.sequence_number -= 1;
            }
            script.segments.push(probe);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                expected,
                connection.stream(Initiator).holes().collect::<Vec<_>>()
            );
        }

        // a resync gives up the holes before the jump, as their bytes now
        // map elsewhere
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi");
            script.segments.remove(4);
            script.send_at(Initiator, 1000, b"GET /").ack(Responder);
            {
                let (connection, _) = script.feed(&mut pool, ..6).active.unwrap();
                assert_eq!(
                    vec![3..6],
                    connection.stream(Initiator).holes().collect::<Vec<_>>()
                );
            }
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(0, stream.holes().count());
            assert_eq!((1, 3), (stream.status().gaps, stream.status().gap_bytes));
        }

        // a flood of 1-byte holes is bounded: a segment that would leave
        // more holes than the limit is rejected, its bytes join one more
        // hole at the end, and so do the bytes of every later segment that
        // would leave more holes (regression test: the old tcp-reassembly
        // branch kept every hole)
        {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 3,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            for offset in (0..2000).step_by(2) {
                script.send_at(Initiator, offset, b"x");
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(
                vec![1..2, 3..4, 5..6, 7..1999],
                stream.holes().collect::<Vec<_>>()
            );
            assert_eq!(996, stream.status().rejected_bytes);
        }

        // at the limit, a segment that would split a hole or leave a new one
        // before it is rejected, while segments that fill a hole, cut it at
        // its start or end, or follow the highest offset are stored (2
        // holes, bytes at 0, 4 and 7)
        for (offset, data, expected, rejected) in [
            (2, &b"c"[..], vec![1..4, 5..7], 1),
            (9, b"j", vec![1..4, 5..7, 8..10], 1),
            (1, b"bcd", vec![5..7], 0),
            (1, b"b", vec![2..4, 5..7], 0),
            (3, b"d", vec![1..3, 5..7], 0),
            (8, b"i", vec![1..4, 5..7], 0),
        ] {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"a")
                .send_at(Initiator, 4, b"e")
                .send_at(Initiator, 7, b"h")
                .send_at(Initiator, offset, data);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(expected, stream.holes().collect::<Vec<_>>());
            assert_eq!(rejected, stream.status().rejected_bytes);
        }

        // at the limit, bytes after a hole that ends at the highest offset
        // extend it, so they leave no new hole
        {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"a")
                .ack_to(Responder, 3)
                .send_at(Initiator, 4, b"e");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(vec![1..4], stream.holes().collect::<Vec<_>>());
            assert_eq!(0, stream.status().rejected_bytes);
        }

        // the hole at the end, which an ACK or a FIN that moves the highest
        // offset adds, doesn't count: bytes that fill it from its start are
        // stored at the limit, bytes after a loss that would put it before
        // stored bytes are not (a retransmission changes nothing)
        for fin in [false, true] {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"a")
                .send_at(Initiator, 2, b"c");
            if fin {
                script.fin_at(Initiator, 5, &[]);
            } else {
                script.ack_to(Responder, 5);
            }
            script
                .send_at(Initiator, 0, b"a")
                .send_at(Initiator, 3, b"d");
            if false == fin {
                script.send_at(Initiator, 6, b"x");
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            let (holes, rejected) = if fin {
                (vec![1..2, 4..5], 0)
            } else {
                (vec![1..2, 4..7], 1)
            };
            assert_eq!(holes, stream.holes().collect::<Vec<_>>());
            assert_eq!(rejected, stream.status().rejected_bytes);
        }

        // ... so without any holes allowed, in-order bytes after an ACK that
        // was captured before them are stored
        {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 0,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .ack_to(Responder, 6)
                .send_at(Initiator, 2, b"cd")
                .send_at(Initiator, 4, b"ef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().rejected_bytes);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
        }
    }

    #[test]
    fn fin_offset() {
        // a FIN before the bytes received is still ignored after earlier
        // bytes were put in front of a mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let early_fin = script.injected(|s| {
                s.fin_at(Initiator, 4, &[]);
            });
            script.segments.drain(..3);
            script.segments.swap(0, 1);
            script.segments.push(early_fin);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.stream(Initiator).fin_offset());
        }

        // earlier bytes put in front of a mid-stream pickup move the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.drain(..3);
            // "def", FIN, "abc"
            script.segments.rotate_left(1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(6), connection.stream(Initiator).fin_offset());
        }

        // no FIN yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.stream(Initiator).fin_offset());
            assert_eq!(None, connection.stream(Responder).fin_offset());
        }

        // a FIN up to 2^31 - 1 after the highest offset lies after it (a
        // window above 2^31 takes it), one 2^31 away can't be mapped and
        // counts as out-of-window, and one 2^31 + 1 after it lies 2^31 - 1
        // before it
        for (distance, expected, out_of_window) in [
            ((1 << 31) - 1, Some(2 + (1 << 31)), 0),
            (1 << 31, None, 1),
            ((1 << 31) + 1, None, 0),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window: u32::MAX,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let fin = script.injected(|s| {
                s.fin_at(Initiator, 3 + distance, &[]);
            });
            script.segments.drain(..3);
            script.segments.push(fin);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(expected, stream.fin_offset());
            assert_eq!(out_of_window, stream.status().out_of_window_segments);
        }

        // FIN after the bytes, with and without data (also across a
        // wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 4] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, isn);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .send(Responder, b"de")
                .fin_with_data(Responder, b"fgh");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(3), connection.stream(Initiator).fin_offset());
            assert_eq!(Some(5), connection.stream(Responder).fin_offset());
        }

        // FIN of a stream without bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin(Initiator);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(0), connection.stream(Initiator).fin_offset());
        }

        // FIN behind missing bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(6), connection.stream(Initiator).fin_offset());
        }

        // the first FIN wins, a retransmission of it (offset 2) and later
        // FINs at other offsets change nothing
        for later_offset in [2, 3, 4, 10] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .fin(Initiator)
                .fin_at(Initiator, later_offset, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(2), connection.stream(Initiator).fin_offset());
        }

        // a FIN before already received bytes is ignored
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_at(Initiator, 2, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.stream(Initiator).fin_offset());
        }

        // a FIN before already received bytes is ignored, even if bytes
        // before the FIN are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"defgh")
                .fin_at(Initiator, 6, &[]);
            let missing = script.segments.remove(3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!(None, stream.fin_offset());
                assert_eq!(8, stream.highest_offset());
            }
            // the bytes after it stay readable
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdefgh"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a FIN before bytes that were rejected is ignored too, so a FIN
        // inside them can't cut the stream short while it is full, while the
        // FIN after them counts
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 4,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"efgh")
                .fin_at(Initiator, 6, &[]);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(None, connection.stream(Initiator).fin_offset());
            }
            script.fin_at(Initiator, 4, b"efgh");
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            assert_eq!(Some(8), connection.stream(Initiator).fin_offset());
        }

        // a FIN before bytes that were ACKed, but not received
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 10)
                .fin_at(Initiator, 6, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(6), connection.stream(Initiator).fin_offset());
        }

        // a FIN before the read position, which lies after bytes up to an
        // ACK that were given up, moves the read position back to it (with
        // the ACK of the FIN and a larger ACK)
        let give_ups: [fn(&mut TcpStream); 2] = [
            |stream| {
                assert!(stream.give_up_hole());
                stream.consume_gap();
            },
            |stream| stream.discard_all(),
        ];
        for ((ack, fin), give_up) in [(4, 3), (10, 6)]
            .into_iter()
            .flat_map(|offsets| give_ups.map(|give_up| (offsets, give_up)))
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, ack);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(3);
                give_up(stream);
                assert_eq!(ack, stream.read_offset());
            }
            script.fin_at(Initiator, fin, &[]);
            let (connection, _) = script.feed(&mut pool, 5..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(fin), stream.fin_offset());
            assert_eq!(fin, stream.read_offset());
            assert_eq!(fin, stream.highest_offset());
            assert!(stream.is_finished());
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // a FIN starting after the receiver's window is ignored
        for (offset, expected) in [(201, None), (200, Some(200))] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().fin_at(Initiator, offset, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(expected, connection.stream(Initiator).fin_offset());
        }

        // a FIN without bytes starts a stream whose SYN was not seen, which
        // is then empty and finished
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Responder, b"lost")
                .send(Initiator, b"abc")
                .fin(Responder);
            script.segments.drain(..4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Responder);
            assert_eq!(Some(0), stream.fin_offset());
            assert!(stream.is_finished());
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // a FIN after the bytes that an ACK confirmed as a jump ends the
        // stream at the resync point, in their segment or right after them
        // (but not one further away)
        let fins: [(fn(&mut ConnectionScript), Option<u64>); 3] = [
            (
                |s| {
                    s.fin_at(Initiator, 1000, b"xyz");
                },
                Some(3),
            ),
            (
                |s| {
                    s.send_at(Initiator, 1000, b"xyz")
                        .fin_at(Initiator, 1003, &[]);
                },
                Some(3),
            ),
            (
                |s| {
                    s.send_at(Initiator, 1000, b"xyz")
                        .fin_at(Initiator, 1010, &[]);
                },
                None,
            ),
        ];
        for (jump, expected) in fins {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            jump(&mut script);
            script.ack(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().resyncs);
            assert_eq!(expected, stream.fin_offset());
            assert_eq!(expected.is_some(), stream.is_finished());
            if expected.is_some() {
                stream.read_received();
                stream.consume(3);
                assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
                stream.consume_gap();
                assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            }
        }

        // after a jump, a FIN at the gap of the resync ends the stream there
        // (cutting the hole that the ACK of the jump added), while a FIN
        // before it is ignored, also if bytes before the jump were missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 10)
                .send_at(Initiator, 1000, b"GET /")
                .ack_to(Responder, 1008)
                .fin_at(Initiator, 1002, &[])
                .fin_at(Initiator, 1005, &[]);
            {
                let (connection, _) = script.feed(&mut pool, ..8).active.unwrap();
                assert_eq!(None, connection.stream(Initiator).fin_offset());
            }
            let (connection, _) = script.feed(&mut pool, 8..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(10), stream.fin_offset());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Gap { len: Some(7) }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // after a jump, bytes that arrive in a hole that was given up behind
        // the gap of the resync are ignored, so a FIN in it is accepted (the
        // ACK of 1010 makes the hole 3..8 overdue at once)
        {
            let config = TcpReassemblyConfig {
                ack_reorder_tolerance: 0,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .ack_to(Responder, 1010)
                .send_at(Initiator, 1005, b"a.js/")
                .fin_at(Initiator, 1007, &[]);
            {
                let (connection, _) = script.feed(&mut pool, ..7).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
            }
            let (connection, _) = script.feed(&mut pool, 7..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(5), stream.fin_offset());
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Gap { len: Some(2) }, stream.read_received());
        }
    }

    #[test]
    fn is_finished() {
        // no FIN yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_finished());
        }

        // FIN after all bytes (finished before they were read)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(connection.stream(Initiator).is_finished());
            assert!(connection.stream(Responder).is_finished());
        }

        // FIN behind missing bytes finishes once they arrive, with and
        // without bytes in the FIN
        for fin_data in [&b""[..], b"gh"] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin_with_data(Initiator, fin_data);
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert!(false == connection.stream(Initiator).is_finished());
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.is_finished());
            assert_eq!(
                TcpRead::Data(&[&b"abcdef"[..], fin_data].concat()[..]),
                stream.read_received()
            );
        }

        // FIN behind a hole finishes once the hole is given up
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_at(Initiator, 6, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(3);
            assert!(false == stream.is_finished());
            assert!(stream.give_up_hole());
            assert!(stream.is_finished());
        }

        // FIN behind several holes finishes once the last one is filled
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 1, b"b")
                .fin_at(Initiator, 3, b"d")
                .send_at(Initiator, 0, b"a")
                .send_at(Initiator, 2, b"c");
            script.feed(&mut pool, ..3);
            for (segment, finished) in script.segments[3..].iter().zip([false, false, false, true])
            {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(finished, connection.stream(Initiator).is_finished());
            }
        }

        // an overdue hole before the FIN keeps it unfinished until the read
        // position reaches it, as late segments can still fill it
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send_at(Initiator, 6, b"ghi")
                .fin_with_data(Initiator, b"jkl");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(false == stream.is_finished());
            stream.read_received();
            stream.consume(3);
            assert!(stream.is_finished());
        }

        // a reset finishes a stream whose FIN was seen, as the holes before
        // the FIN become gaps, but not a stream without a FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_with_data(Initiator, b"def")
                .rst(Responder);
            script.segments.remove(3);
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                assert!(false == connection.stream(Initiator).is_finished());
            }
            let connection = script.feed(&mut pool, 4..).ended.unwrap();
            assert!(connection.stream(Initiator).is_finished());
            assert!(false == connection.stream(Responder).is_finished());
        }
    }

    #[test]
    fn status() {
        // new stream, whose SYN gives it an observed start (the other
        // stream's SYN was not seen yet)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                &TcpStreamStatus {
                    start: TcpStreamStart::Observed,
                    gaps: 0,
                    gap_bytes: 0,
                    resyncs: 0,
                    conflicting_retransmissions: 0,
                    rejected_bytes: 0,
                    out_of_window_segments: 0,
                },
                connection.stream(Initiator).status()
            );
            assert_eq!(
                TcpStreamStart::MidStreamPickup,
                connection.stream(Responder).status().start
            );
        }

        // a stream whose SYN was not seen is a mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            script.segments.drain(..2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            for role in [Initiator, Responder] {
                assert_eq!(
                    TcpStreamStart::MidStreamPickup,
                    connection.stream(role).status().start
                );
            }
        }

        // a late SYN gives a mid-stream pickup an observed start before its
        // read position moved, when it lies at most k windows (the hole give
        // up window factor, 2 without one) before the first byte (moving the
        // offsets), or at it
        for (factor, fallback_window, lost, expected) in [
            (Some(2), 2, &b"abcd"[..], &b""[..]),
            (Some(1), 4, b"abcd", b""),
            (None, 2, b"abcd", b""),
            (None, 2, b"", b"abcdef"),
        ] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                fallback_window,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, lost)
                .send(Initiator, b"abcdef"[lost.len()..].as_ref());
            let syn = script.segments[0].clone();
            script.segments.drain(..4);
            script.segments.push(syn);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpStreamStart::Observed, stream.status().start);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(6, stream.highest_offset());
            if expected.is_empty() {
                assert_eq!(TcpRead::Pending, stream.read_received());
            } else {
                assert_eq!(TcpRead::Data(expected), stream.read_received());
            }
        }

        // other SYNs of a mid-stream pickup change nothing, not even with
        // bytes (TCP Fast Open): its own late SYN counts as out-of-window
        // after the read position moved and for a pickup that starts at its
        // FIN, while SYNs more than k windows before the first byte, after
        // the first byte or 2^31 away from the highest offset (can't be
        // mapped) are kept for a reconnect and don't count
        for (factor, fallback_window, lost, consumed, syn_offset, fin, counted) in [
            (None, 3, &b""[..], 1, 0, false, 1),
            (None, 3, b"", 0, 0, true, 1),
            (Some(2), 2, b"abcde", 0, 0, false, 0),
            (Some(1), 4, b"abcde", 0, 0, false, 0),
            (None, 2, b"abcde", 0, 0, false, 0),
            (None, 3, b"", 0, 2, false, 0),
            (None, 3, b"", 0, (1 << 31) + 3, false, 0),
        ] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                fallback_window,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, lost);
            if fin {
                script.fin(Initiator);
            } else {
                script.send(Initiator, b"def");
            }
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number += syn_offset;
            syn.payload = b"XYZ".to_vec();
            script.segments.drain(..4);
            // the responder's bytes start the connection
            script.send(Responder, b"x");
            let responder = script.segments.pop().unwrap();
            script.segments.insert(0, responder);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(consumed);
            }
            let (connection, _) = syn.feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(TcpStreamStart::MidStreamPickup, stream.status().start);
            assert_eq!(counted, stream.status().out_of_window_segments);
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(if fin { 0 } else { 3 }, stream.highest_offset());
        }

        // the ACK of a late SYN-ACK 2^31 away from the bytes of a mid-stream
        // pickup (can't be mapped) gives it no observed start
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let mut syn_ack = script.segments[1].clone();
            syn_ack.header.acknowledgment_number = script.seq(Initiator, 3).wrapping_add(1 << 31);
            script.segments.drain(..3);
            script.segments.push(syn_ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let starts = [Initiator, Responder].map(|role| connection.stream(role).status().start);
            assert_eq!(
                [TcpStreamStart::MidStreamPickup, TcpStreamStart::Observed],
                starts
            );
        }

        // segments without bytes before the first byte of a mid-stream
        // pickup change nothing (e.g. earlier ACKs of its sender, or its
        // keep-alives), before and after the read position moved
        for consumed in [0, 1] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let ack = script.injected(|s| {
                s.send_at(Initiator, 1, &[]);
            });
            script.segments.drain(..4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(consumed);
            }
            let (connection, _) = ack.feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(3, stream.highest_offset());
            assert_eq!(Vec::<Range<u64>>::new(), stream.holes().collect::<Vec<_>>());
        }

        // a late SYN-ACK gives both streams of mid-stream pickups an
        // observed start (the initiator's at its ACK), but not to streams
        // whose read position moved; a SYN after it changes nothing
        for consumed in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            let syn = script.segments[0].clone();
            let syn_ack = script.segments[1].clone();
            script.segments.drain(..3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                for role in [Initiator, Responder] {
                    let stream = connection.stream_mut(role);
                    stream.read_received();
                    stream.consume(usize::from(consumed));
                }
            }
            let expected = if consumed {
                TcpStreamStart::MidStreamPickup
            } else {
                TcpStreamStart::Observed
            };
            for segment in [syn_ack, syn] {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                for role in [Initiator, Responder] {
                    let status = connection.stream(role).status();
                    assert_eq!(expected, status.start);
                }
            }
            // the SYN-ACK counts for the responder's stream, the SYN for
            // the initiator's
            let (connection, _) = script.segments[0].feed(&mut pool, ()).active.unwrap();
            for role in [Initiator, Responder] {
                assert_eq!(
                    u64::from(consumed),
                    connection.stream(role).status().out_of_window_segments
                );
            }
        }

        // bytes before the first byte of a mid-stream pickup count as
        // out-of-window if they can't be put in front: after the read
        // position moved, or more than k windows before. Each segment
        // counts once, also with bytes after the FIN, and its bytes from
        // the read position on are stored.
        for (fallback_window, consumed, earlier, expected) in [
            (3, 1, &b"abcd"[..], &b"fX"[..]),
            (1, 0, b"abcd", b"efX"),
            // put in front, only the bytes after the FIN count
            (3, 0, b"bcd", b"bcdefX"),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"e");
            // the segment fills the missing byte "f"
            let segment = script.injected(|s| {
                s.send_at(
                    Initiator,
                    (4 - earlier.len()) as u64,
                    &[earlier, b"efXh"].concat(),
                );
            });
            script.send_at(Initiator, 6, b"X").fin_at(Initiator, 7, &[]);
            script.segments.drain(..4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(consumed);
            }
            let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(expected), stream.read_received());
        }

        // bytes before the first byte of a stream with an observed start
        // don't count (e.g. the filler byte of a keep-alive before any
        // bytes were sent)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let mut keep_alive = script.injected(|s| {
                s.send(Initiator, b"x");
            });
            keep_alive.header.sequence_number -= 1;
            script.segments.push(keep_alive);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // the SYN-ACK gives the responder's stream an observed start, and
        // the initiator's too if its SYN was not seen
        for syn in [true, false] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn().syn_ack();
            if false == syn {
                script.segments.remove(0);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            for role in [Initiator, Responder] {
                assert_eq!(
                    TcpStreamStart::Observed,
                    connection.stream(role).status().start
                );
            }
        }

        // every given up hole counts as a gap with its missing bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 2, b"c")
                .send_at(Initiator, 7, b"h");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.give_up_hole());
            assert_eq!((1, 2), (stream.status().gaps, stream.status().gap_bytes));
            stream.consume_gap();
            stream.read_received();
            stream.consume(1);
            assert!(stream.give_up_hole());
            assert_eq!((2, 6), (stream.status().gaps, stream.status().gap_bytes));
        }

        // an overdue hole counts as a gap once the read position reaches it
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send_at(Initiator, 2, b"c")
                .send_at(Initiator, 4, b"efgh")
                .send(Initiator, b"ijkl");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            // the hole at the read position, but not the one after it
            assert_eq!((1, 2), (stream.status().gaps, stream.status().gap_bytes));
            stream.consume_gap();
            stream.read_received();
            stream.consume(1);
            assert_eq!((2, 3), (stream.status().gaps, stream.status().gap_bytes));
        }

        // bytes starting 2^31 - 1 after the highest offset lie after the
        // window, ones 2^31 after it can't be mapped and count too, and ones
        // 2^31 + 1 after it lie 2^31 - 1 before it (before the first byte,
        // which counts too)
        for (distance, expected) in [((1 << 31) - 1, 1), (1 << 31, 1), ((1 << 31) + 1, 1)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let segment = script.injected(|s| {
                s.send_at(Initiator, 3 + distance, b"x");
            });
            script.segments.push(segment);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(expected, stream.status().out_of_window_segments);
            assert_eq!(3, stream.highest_offset());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // on a stream with an observed start, bytes before offset 0 count as
        // out-of-window, except the filler byte of a keep-alive right before
        // it (a byte at the ISN, when no bytes were sent yet); the same byte
        // with a FIN is no keep-alive and counts
        for (position, len, fin, expected, highest) in [
            (-1, 1, false, 0, 0),
            (-1, 2, false, 1, 1),
            (-2, 1, false, 1, 0),
            (-1, 1, true, 1, 0),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let mut segment = script.injected(|s| {
                s.send(Initiator, &[7; 2][..len]);
            });
            segment.header.sequence_number = script.seq(Initiator, 0).wrapping_add_signed(position);
            segment.header.fin = fin;
            script.segments.push(segment);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(expected, stream.status().out_of_window_segments);
            assert_eq!(highest, stream.highest_offset());
            assert_eq!(fin.then_some(0), stream.fin_offset());
        }

        // ... while a segment without bytes there changes nothing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let ack = script.injected(|s| {
                s.send_at(Initiator, 3 + (1 << 31), &[]);
            });
            script.segments.push(ack);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(3, stream.highest_offset());
        }

        // every segment with bytes after the FIN counts as out-of-window
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                // bytes after the FIN
                .send(Initiator, b"x")
                // bytes starting at the FIN
                .send_at(Initiator, 3, b"y")
                // retransmitted bytes followed by bytes after the FIN
                .send_at(Initiator, 1, b"bcz");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(3, stream.status().out_of_window_segments);
            assert!(stream.is_finished());
        }

        // segments without bytes after the FIN don't count
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                // ACK after the FIN
                .ack(Initiator)
                // retransmission of the FIN
                .fin_at(Initiator, 0, b"abc")
                // a FIN without bytes at another offset
                .fin_at(Initiator, 7, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                0,
                connection.stream(Initiator).status().out_of_window_segments
            );
        }

        // bytes after the FIN count while bytes before it are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .send(Initiator, b"x");
            let missing = script.segments.remove(4);
            script.segments.push(missing);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.consume(6);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // retransmissions with differing bytes count once per segment, the
        // bytes received first are kept
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                // same bytes
                .send_at(Initiator, 1, b"bcd")
                // one differing byte
                .send_at(Initiator, 0, b"aXc")
                // several differing bytes
                .send_at(Initiator, 2, b"XYZ")
                // differing bytes followed by new bytes
                .send_at(Initiator, 5, b"Xgh");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(3, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abcdefgh"), stream.read_received());
        }

        // bytes in holes are not compared, the received bytes around them
        // are
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"ab")
                .send_at(Initiator, 4, b"ef")
                .send_at(Initiator, 8, b"ij")
                // fills the holes
                .send_at(Initiator, 1, b"bcdefgh")
                // received bytes after a hole differ
                .send_at(Initiator, 5, b"Xghi");
            script.feed(&mut pool, ..3);
            let segments = &script.segments[3..];
            for (i, (segment, expected)) in segments.iter().zip([0, 0, 0, 0, 1]).enumerate() {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(expected, stream.status().conflicting_retransmissions);
                if i + 1 == segments.len() {
                    assert_eq!(TcpRead::Data(b"abcdefghij"), stream.read_received());
                }
            }
        }

        // bytes that were already consumed are not compared
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 0, b"XYc");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(2);
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            assert_eq!(
                0,
                connection
                    .stream(Initiator)
                    .status()
                    .conflicting_retransmissions
            );
        }

        // ACKed bytes are not compared, as the receiver ignores them too
        // (e.g. keep-alive probes)
        for (payload, expected) in [
            // only ACKed bytes differ
            (&b"Xc"[..], 0),
            // ACKed and not ACKed bytes differ
            (&b"XcY"[..], 1),
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 3)
                .send_at(Initiator, 1, payload);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(expected, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
        }

        // bytes before the implied ACK are not compared either
        for (payload, expected) in [(&b"XY"[..], 0), (&b"XYZ"[..], 1)] {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abcdef")
                .send_at(Initiator, 0, payload);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(expected, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
        }

        // differing bytes after the FIN only count as out-of-window, a
        // differing FIN retransmission counts
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .send_at(Initiator, 2, b"cX")
                .fin_at(Initiator, 1, b"Xc");
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([0, 0, 1]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(
                    expected,
                    connection
                        .stream(Initiator)
                        .status()
                        .conflicting_retransmissions
                );
            }
        }

        // bytes beyond the stream buffer, counted from the read position to
        // the furthest stored byte, are rejected and counted each time they
        // arrive: a segment that only partly fits stores its first bytes,
        // the rest becomes a hole, and consuming makes room
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 5,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"defgh")
                .send_at(Initiator, 5, b"fgh")
                .send_at(Initiator, 5, b"fgh");
            {
                let (connection, _) = script.feed(&mut pool, ..6).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(6, stream.status().rejected_bytes);
                assert_eq!(8, stream.highest_offset());
                assert_eq!(vec![5..8], stream.holes().collect::<Vec<_>>());
                assert_eq!(TcpRead::Data(b"abcde"), stream.read_received());
                stream.consume(2);
            }
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(7, stream.status().rejected_bytes);
            assert_eq!(vec![7..8], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"cdefg"), stream.read_received());
        }

        // bytes that fill a hole before the furthest stored byte always fit,
        // while the placeholders of a hole after it count
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 5,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 4, b"e")
                .send_at(Initiator, 0, b"abcd")
                .send_at(Initiator, 6, b"g");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().rejected_bytes);
            assert_eq!(vec![5..7], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"abcde"), stream.read_received());
        }

        // without any room, a stream with an observed start rejects the
        // bytes and moves on (its FIN counts)
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 0,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_with_data(Initiator, b"def");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(6, stream.status().rejected_bytes);
            assert_eq!(Some(6), stream.fin_offset());
            // the hole of the first bytes was given up at once
            for _ in 0..2 {
                assert_eq!(TcpRead::Gap { len: Some(3) }, stream.read_received());
                stream.consume_gap();
            }
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // ... while bytes none of which fit don't start a mid-stream pickup,
        // also with a FIN, and a FIN without bytes does
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 0,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_with_data(Initiator, b"def")
                .fin_at(Initiator, 6, &[]);
            script.segments.drain(..3);
            {
                let (connection, _) = script.feed(&mut pool, ..2).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(6, stream.status().rejected_bytes);
                assert_eq!(None, stream.fin_offset());
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            let (connection, _) = script.feed(&mut pool, 2..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(Some(0), stream.fin_offset());
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // bytes put in front of a mid-stream pickup have to fit the buffer
        // from the new offset 0 on, and the hole they leave before the old
        // offset 0 the hole limit, otherwise the bytes before offset 0 are
        // rejected and offset 0 stays, while the bytes from offset 0 on are
        // stored (the pickup starts with 6 bytes at 4, the bytes in front
        // start at 0 or 2)
        for (max_stream_buffer, max_holes_per_stream, offset, data, rejected, expected) in [
            (10, 1, 0, &b"ab"[..], 0, &b"ab"[..]),
            (9, 1, 0, b"ab", 2, b"efghij"),
            (7, 1, 2, b"cdefghijk", 2, b"efghijk"),
            (10, 0, 0, b"ab", 2, b"efghij"),
            (10, 0, 0, b"abcd", 0, b"abcdefghij"),
        ] {
            let config = TcpReassemblyConfig {
                max_stream_buffer,
                max_holes_per_stream,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"efghij")
                .send_at(Initiator, offset, data);
            script.segments.drain(..4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(rejected, stream.status().rejected_bytes);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(expected), stream.read_received());
        }

        // a late SYN that would need more room than the limits allow counts
        // as out-of-window (its bytes fill the hole up to the old offset 0),
        // and the ACK of a late SYN-ACK gives no observed start then, so the
        // stream stays a mid-stream pickup (the pickup starts with 6 bytes
        // at 4)
        for (max_stream_buffer, max_holes_per_stream, syn, tfo, start, out_of_window) in [
            (10, 1, 0, &b""[..], TcpStreamStart::Observed, 0),
            (9, 1, 0, b"", TcpStreamStart::MidStreamPickup, 1),
            (10, 0, 0, b"", TcpStreamStart::MidStreamPickup, 1),
            (10, 0, 0, b"abcd", TcpStreamStart::Observed, 0),
            (10, 1, 1, b"", TcpStreamStart::Observed, 0),
            (9, 1, 1, b"", TcpStreamStart::MidStreamPickup, 0),
            (10, 0, 1, b"", TcpStreamStart::MidStreamPickup, 0),
        ] {
            let config = TcpReassemblyConfig {
                max_stream_buffer,
                max_holes_per_stream,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"efghij");
            let mut syn = script.segments[syn].clone();
            syn.payload = tfo.to_vec();
            script.segments.drain(..4);
            script.segments.push(syn);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!(start, status.start);
            assert_eq!(out_of_window, status.out_of_window_segments);
        }

        // the hole at the end doesn't count for the hole limit either: a late
        // SYN, or bytes put in front, that leave no new hole are taken (the
        // pickup starts with 4 bytes at 4, bytes at 12 don't fit as they
        // would leave a hole before them)
        for syn in [false, true] {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 0,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send(Initiator, b"efgh")
                .send_at(Initiator, 12, b"xy");
            let mut late = script.segments[if syn { 0 } else { 3 }].clone();
            if syn {
                late.payload = b"abcd".to_vec();
            }
            script.segments.drain(..4);
            script.segments.push(late);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            let expected = if syn {
                TcpStreamStart::Observed
            } else {
                TcpStreamStart::MidStreamPickup
            };
            assert_eq!(expected, stream.status().start);
            assert_eq!(2, stream.status().rejected_bytes);
            assert_eq!(TcpRead::Data(b"abcdefgh"), stream.read_received());
        }

        // a resync happens even if the bytes of its new start don't fit:
        // they become a hole right after the gap of unknown length
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 4,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcd")
                .send_at(Initiator, 1000, b"xy");
            script
                .feed(&mut pool, ..4)
                .active
                .unwrap()
                .0
                .stream_mut(Initiator)
                .force_resync();
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            let status = stream.status();
            assert_eq!((1, 2), (status.resyncs, status.rejected_bytes));
            assert_eq!(vec![4..6], stream.holes().collect::<Vec<_>>());
            assert_eq!(TcpRead::Data(b"abcd"), stream.read_received());
            stream.consume(4);
            assert_eq!(TcpRead::Gap { len: None }, stream.read_received());
            stream.consume_gap();
            assert_eq!(TcpRead::Gap { len: Some(2) }, stream.read_received());
        }

        // bytes starting more than two windows of the receiver after the
        // highest offset count as out-of-window, where the window of the
        // SYN-ACK is never scaled
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(3), Some(3)];
            script.window_size = 100;
            script.handshake();
            assert_window_end(Default::default(), &script, 200);
        }

        // later windows of the receiver are scaled by its window scale if
        // both SYNs had the option (shifts above 14 count as 14), and the
        // largest one counts, as the sender can have sent into it before the
        // window shrank (e.g. to 0)
        for (scales, windows, end) in [
            ([Some(5), Some(3)], &[100][..], 2 * (100 << 3)),
            ([Some(5), Some(3)], &[100, 200][..], 2 * (200 << 3)),
            ([Some(5), Some(3)], &[200, 100][..], 2 * (200 << 3)),
            ([Some(5), Some(3)], &[100, 0][..], 2 * (100 << 3)),
            ([Some(0), Some(14)], &[1][..], 2 * (1 << 14)),
            ([Some(0), Some(15)], &[1][..], 2 * (1 << 14)),
            // one SYN without the option
            ([None, Some(3)], &[100][..], 200),
            ([Some(3), None], &[100][..], 200),
        ] {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = scales;
            // the (unscaled) windows of the SYNs are smaller
            script.window_size = 1;
            script.handshake();
            for window in windows {
                script.window_size = *window;
                script.ack(Responder);
            }
            assert_window_end(Default::default(), &script, end);
        }

        // a SYN with a malformed window scale option has none
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(3), Some(3)];
            script.window_size = 1;
            script.handshake();
            script.window_size = 100;
            script.ack(Responder);
            // window scale option with a wrong length
            script.segments[0]
                .header
                .set_options_raw(&[3, 4, 3, 0])
                .unwrap();
            assert_window_end(Default::default(), &script, 200);
        }

        // the first window scale option counts, also after other options
        for options in [
            &[
                TcpOptionElement::MaximumSegmentSize(1460),
                TcpOptionElement::WindowScale(3),
            ][..],
            &[
                TcpOptionElement::WindowScale(3),
                TcpOptionElement::WindowScale(5),
            ][..],
        ] {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(0), None];
            script.window_size = 1;
            script.handshake();
            script.window_size = 100;
            script.ack(Responder);
            script.segments[1].header.set_options(options).unwrap();
            assert_window_end(Default::default(), &script, 2 * (100 << 3));
        }

        // a hole give up window factor of 0 works like 1 (with 0, no bytes
        // after a hole would fit the window)
        for factor in [Some(1), Some(0)] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            assert_window_end(config, &script, 103);
        }

        // the fallback window is used while the window scale is unknown
        // (without the SYN-ACK, without the SYN, or without both)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 50,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc").ack(Responder);
            script.segments.drain(..3);
            assert_window_end(config, &script, 103);
        }
        for missing in [1, 0] {
            let config = TcpReassemblyConfig {
                fallback_window: 50,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().ack(Responder);
            script.segments.remove(missing);
            assert_window_end(config, &script, 100);
        }

        // a SYN after its SYN-ACK makes the window scale known
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(3), Some(3)];
            script.window_size = 100;
            script.handshake().ack(Responder);
            script.segments.swap(0, 1);
            assert_window_end(Default::default(), &script, 2 * (100 << 3));
        }

        // only the first SYN with the stream's ISN sets its window scale: a
        // retransmitted SYN-ACK with another option doesn't
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(3), Some(3)];
            script.window_size = 100;
            script.handshake();
            let mut syn_ack = script.segments[1].clone();
            syn_ack
                .header
                .set_options(&[TcpOptionElement::WindowScale(5), TcpOptionElement::Noop])
                .unwrap();
            script.segments.push(syn_ack);
            script.ack(Responder);
            assert_window_end(Default::default(), &script, 2 * (100 << 3));
        }

        // ... and neither does a SYN with another ISN after the SYN-ACK
        // started the stream
        {
            let config = TcpReassemblyConfig {
                fallback_window: 50,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(3), Some(3)];
            script.window_size = 100;
            script.handshake().ack(Responder);
            script.segments[0].header.sequence_number += 7;
            script.segments.swap(0, 1);
            assert_window_end(config, &script, 100);
        }

        // ... and neither does the SYN after its stream resynced, as it no
        // longer lies before the stream's first byte (window 50 instead of
        // 100 << 3 after the resync)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 50,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(3), Some(3)];
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"x")
                .ack(Responder);
            let syn = script.segments.remove(0);
            script.segments.push(syn);
            let probe = script.injected(|s| {
                s.send_at(Initiator, 1001 + 101, b"y");
            });
            script.feed_all(&mut pool);
            let (connection, _) = probe.feed(&mut pool, ()).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!((1, 2), (status.resyncs, status.out_of_window_segments));
        }

        // the number of windows is the hole give up window factor
        for (factor, end) in [(Some(1), 100), (Some(3), 300), (None, 200)] {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: factor,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake();
            assert_window_end(config, &script, end);
        }

        // the window starts at the highest offset or at the ACKed offset,
        // whichever is higher
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            assert_window_end(Default::default(), &script, 203);
            script.ack_to(Responder, 50);
            assert_window_end(Default::default(), &script, 250);
        }

        // after the FIN, the window starts at the ACK of the FIN
        for (offset, expected) in [(204, 0), (205, 1)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .ack(Responder);
            let fin = script.injected(|s| {
                s.fin_at(Initiator, offset, &[]);
            });
            script.segments.push(fin);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                expected,
                connection.stream(Initiator).status().out_of_window_segments
            );
        }

        // FINs starting after the window count too, pure ACKs don't
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake();
            let fin = script.injected(|s| {
                s.fin_at(Initiator, 201, &[]);
            });
            let ack = script.injected(|s| {
                s.send_at(Initiator, 201, &[]);
            });
            script.segments.extend([fin, ack]);
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([1, 1]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(
                    expected,
                    connection.stream(Initiator).status().out_of_window_segments
                );
            }
        }

        // a resync counts: data that only became its candidate counts as
        // out-of-window, data that an earlier ACK confirmed is the new start
        // and doesn't
        for (ack_first, out_of_window) in [(false, 1), (true, 0)] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            if ack_first {
                script
                    .ack_to(Responder, 1000)
                    .send_at(Initiator, 1000, b"GET /");
            } else {
                script.send_at(Initiator, 1000, b"GET /").ack(Responder);
            }
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!(1, status.resyncs);
            assert_eq!(out_of_window, status.out_of_window_segments);
        }

        // an ACK more than one window after the bytes sent confirms data
        // after the window if it lies at most one window before its first
        // byte or after its last byte, whichever arrives first (window 100,
        // bytes 1000..1005)
        for ack_first in [false, true] {
            for (ack, resyncs) in [(900, 1), (899, 0), (1105, 1), (1106, 0)] {
                let mut pool = TcpReassemblyPool::<(), ()>::default();
                let mut script = ConnectionScript::with_isns(1000, 2000);
                script.window_size = 100;
                script.handshake().send(Initiator, b"abc");
                if ack_first {
                    script
                        .ack_to(Responder, ack)
                        .send_at(Initiator, 1000, b"GET /");
                } else {
                    script
                        .send_at(Initiator, 1000, b"GET /")
                        .ack_to(Responder, ack);
                }
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(resyncs, connection.stream(Initiator).status().resyncs);
            }
        }

        // the latest data after the window and the latest ACK beyond it
        // count
        for ack_first in [false, true] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            if ack_first {
                script
                    .ack_to(Responder, 1000)
                    .ack_to(Responder, 5000)
                    .send_at(Initiator, 1000, b"x")
                    .send_at(Initiator, 5000, b"y");
            } else {
                script
                    .send_at(Initiator, 1000, b"x")
                    .send_at(Initiator, 5000, b"y")
                    .ack_to(Responder, 1001)
                    .ack_to(Responder, 5001);
            }
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([0, 0, 0, 0, 1]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).status().resyncs);
            }
        }

        // other bytes after the data after the window show that the stream
        // didn't jump, and so does anything that moves the stream forward,
        // so a later ACK doesn't confirm the jump
        let between: [(fn(&mut ConnectionScript), u64); 5] = [
            // bytes in the window
            (
                |s| {
                    s.send_at(Initiator, 3, b"d");
                },
                0,
            ),
            // a retransmission
            (
                |s| {
                    s.send_at(Initiator, 0, b"a");
                },
                0,
            ),
            // an ACK that moves the highest offset
            (
                |s| {
                    s.ack_to(Responder, 50);
                },
                0,
            ),
            // an ACK that doesn't
            (
                |s| {
                    s.ack_to(Responder, 2);
                },
                1,
            ),
            // a segment of the sender without bytes
            (
                |s| {
                    s.ack(Initiator);
                },
                1,
            ),
        ];
        for (step, resyncs) in between {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /");
            step(&mut script);
            script.ack_to(Responder, 1005);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(resyncs, connection.stream(Initiator).status().resyncs);
        }

        // ... while for an ACK that arrived first, only what moves the
        // stream forward shows it
        for (step, resyncs) in between
            .iter()
            .zip([0, 1, 0, 1, 1])
            .map(|((step, _), r)| (step, r))
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 1000);
            step(&mut script);
            script.send_at(Initiator, 1000, b"GET /");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(resyncs, connection.stream(Initiator).status().resyncs);
        }

        // a resync ends the jumps the stream may have made before: an ACK
        // that was kept doesn't confirm data near it after the resync
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 1300)
                .send_at(Initiator, 1000, b"GET /")
                .ack_to(Responder, 1005)
                .send_at(Initiator, 1250, b"x");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!((1, 2), (status.resyncs, status.out_of_window_segments));
        }

        // a SYN with another ISN is kept for a reconnect: it is no jump, and
        // it doesn't count as out-of-window
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            let mut syn = script.segments[0].clone();
            syn.header.sequence_number = script.seq(Initiator, 999);
            syn.payload = b"GET /".to_vec();
            script.segments.push(syn);
            script.ack_to(Responder, 1005);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!(0, status.resyncs);
            assert_eq!(0, status.out_of_window_segments);
        }

        // nothing follows a FIN, so a stream with a FIN doesn't jump, also
        // not to data from before the FIN
        let orders: [fn(&mut ConnectionScript); 3] = [
            |s| {
                s.fin(Initiator)
                    .send_at(Initiator, 1000, b"GET /")
                    .ack_to(Responder, 1005);
            },
            |s| {
                s.fin(Initiator)
                    .ack_to(Responder, 1000)
                    .send_at(Initiator, 1000, b"GET /");
            },
            |s| {
                s.send_at(Initiator, 1000, b"GET /")
                    .fin_at(Initiator, 3, &[])
                    .ack_to(Responder, 1005);
            },
        ];
        for order in orders {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            order(&mut script);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(0, stream.status().resyncs);
            assert_eq!(Some(3), stream.fin_offset());
        }

        // bytes from before a jump that arrive after it are ignored, so they
        // don't conflict with the bytes before it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send_at(Initiator, 999, b"XGEX /");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // bytes that fill a hole at the gap of a resync don't conflict
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send_at(Initiator, 1010, b"s")
                .send_at(Initiator, 1005, b"a.js/");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.status().conflicting_retransmissions);
            stream.read_received();
            stream.consume(3);
            stream.consume_gap();
            assert_eq!(TcpRead::Data(b"a.js/s"), stream.read_received());
        }

        // data 2^31 after the highest offset can be where the stream jumped
        // to (an ACK that maps before it confirms it)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 3 + (1 << 31), b"x")
                .ack_to(Responder, 2 + (1 << 31));
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(1, connection.stream(Initiator).status().resyncs);
        }

        // an ACK 2^31 after the highest offset can't be mapped, but it can
        // confirm a jump near it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, (1 << 31) - 50, b"GET /")
                .ack_to(Responder, 3 + (1 << 31));
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(1, connection.stream(Initiator).status().resyncs);
        }

        // ACKs before the first byte of a mid-stream pickup are old ones, so
        // they don't replace the ACK beyond the window that was kept
        {
            let config = TcpReassemblyConfig {
                fallback_window: 10,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            script.segments.drain(..4);
            script
                .ack_to(Responder, 100)
                .ack_to(Responder, 1)
                .send_at(Initiator, 100, b"xyz");
            {
                let (connection, _) = script.feed(&mut pool, ..1).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(1);
            }
            let (connection, _) = script.feed(&mut pool, 1..).active.unwrap();
            assert_eq!(1, connection.stream(Initiator).status().resyncs);
        }

        // a resync ends putting earlier bytes in front of a mid-stream
        // pickup: like other bytes before the jump, they are ignored without
        // counting (R2)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 10,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            script.segments.drain(..4);
            script
                .ack_to(Responder, 100)
                .send_at(Initiator, 100, b"xyz")
                .send_at(Initiator, 90, b"ab");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(1, stream.status().resyncs);
            assert_eq!(0, stream.status().out_of_window_segments);
            assert_eq!(6, stream.highest_offset());
        }

        // with resync_after_segments, the segments before the one that
        // resyncs count as out-of-window
        {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(3),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"x")
                .send(Initiator, b"y")
                .send(Initiator, b"z");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!((1, 2), (status.resyncs, status.out_of_window_segments));
        }

        // ... a segment after the window agrees with the one before if it
        // starts at most one window before its first byte or after its last
        // byte (window 100, bytes 1000..1001)
        for (second, resyncs) in [(900, 1), (899, 0), (1101, 1), (1102, 0)] {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(2),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"x")
                .send_at(Initiator, second, b"y");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(resyncs, connection.stream(Initiator).status().resyncs);
        }

        // ... the count starts again with a segment that doesn't agree, after
        // other bytes, and after a resync
        let between: [fn(&mut ConnectionScript); 2] = [
            |s| {
                s.send_at(Initiator, 5000, b"w");
            },
            |s| {
                s.send_at(Initiator, 3, b"d");
            },
        ];
        for step in between {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(2),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"x");
            step(&mut script);
            script.send_at(Initiator, 1001, b"y");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).status().resyncs);
        }
        {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(2),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"w")
                .send(Initiator, b"x")
                .send_at(Initiator, 5000, b"y")
                .send(Initiator, b"z");
            script.feed(&mut pool, ..4);
            for (segment, expected) in script.segments[4..].iter().zip([0, 1, 1, 2]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).status().resyncs);
            }
        }

        // ... a resync ends the count, also if the ACK that confirmed it left
        // the stream at the resync point (with a hole give up window factor
        // of 0, the window ends at the highest offset)
        {
            let config = TcpReassemblyConfig {
                hole_give_up_window_factor: Some(0),
                resync_after_segments: Some(2),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack_to(Responder, 1005)
                .send_at(Initiator, 1010, b"x");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(1, connection.stream(Initiator).status().resyncs);
        }

        // ... and Some(0) works like Some(1): the first segment after the
        // window is the new start
        for after in [0, 1] {
            let config = TcpReassemblyConfig {
                resync_after_segments: Some(after),
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!((1, 0), (status.resyncs, status.out_of_window_segments));
        }

        // a stream doesn't resync while it has more gaps the read position
        // didn't step over than the hole limit (each resync turns the holes
        // before it into gaps): the data after the window counts as
        // out-of-window and the ACK is kept until the reader steps over
        // enough gaps (window 100)
        {
            let config = TcpReassemblyConfig {
                max_holes_per_stream: 1,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 6, b"ghi")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder)
                .send_at(Initiator, 3000, b"POST")
                .ack(Responder);
            {
                let (connection, _) = script.feed(&mut pool, ..9).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                let status = stream.status();
                assert_eq!((1, 2), (status.resyncs, status.out_of_window_segments));
                // two gaps: the hole 3..6 and the gap of the resync, one is
                // left after this
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
                stream.consume_gap();
            }
            let (connection, _) = script.feed(&mut pool, 8..).active.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!((2, 2), (status.resyncs, status.out_of_window_segments));
        }

        // a reset gives up all holes, they count as gaps
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .send(Initiator, b"jkl")
                .ack(Responder)
                .rst(Initiator);
            script.segments.remove(6);
            script.segments.remove(4);
            {
                let (connection, _) = script.feed(&mut pool, ..5).active.unwrap();
                assert_eq!(0, connection.stream(Initiator).status().gaps);
            }
            let connection = script.feed(&mut pool, 5..).ended.unwrap();
            let status = connection.stream(Initiator).status();
            assert_eq!((2, 6), (status.gaps, status.gap_bytes));
        }

        // an RST outside of the receiver's window counts for the stream of
        // its sender, and its window doesn't apply
        {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            let mut rst = script.injected(|s| {
                s.rst_at(Responder, 1 << 30);
            });
            rst.header.window_size = 0;
            script.segments.push(rst);
            {
                let mut pool = TcpReassemblyPool::<(), ()>::default();
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let [initiator, responder] =
                    [Initiator, Responder].map(|role| connection.stream(role).status());
                assert_eq!(0, initiator.out_of_window_segments);
                assert_eq!(1, responder.out_of_window_segments);
            }
            assert_window_end(Default::default(), &script, 203);
        }

        // the window of a segment whose sequence number the receiver doesn't
        // accept (more than k windows after or before the bytes its sender
        // is known to have sent) doesn't count, so a blind segment can't set
        // it (the responder sent 300 bytes, k windows are 200 bytes)
        for (position, end) in [
            (99, 300 + 200),
            (100, 300 + 2 * 1000),
            (500, 300 + 2 * 1000),
            (501, 300 + 200),
        ] {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, &[1; 300])
                .send(Responder, &[2; 300]);
            let mut ack = script.injected(|s| {
                s.ack(Responder);
            });
            ack.header.sequence_number = script.seq(Responder, position);
            ack.header.window_size = 1000;
            script.segments.push(ack);
            assert_window_end(Default::default(), &script, end);
        }

        // before a stream has a start, the ACK the receiver kept for it tells
        // which sequence numbers it accepts: k windows around the ACK (the
        // capture starts at the initiator's bytes, which ACK the responder's
        // first byte, and the handshake arrives late)
        for (position, end) in [
            (200, 2 * 1000 + 3),
            (201, 203),
            (-200, 2 * 1000 + 3),
            (-201, 203),
        ] {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            let mut ack = script.injected(|s| {
                s.ack(Responder);
            });
            ack.header.sequence_number = script.seq(Responder, 0).wrapping_add_signed(position);
            ack.header.window_size = 1000;
            let handshake: Vec<_> = script.segments.drain(..3).collect();
            script.segments.push(ack);
            script.segments.extend(handshake);
            assert_window_end(config, &script, end);
        }

        // the same holds for the segment that starts the stream after a
        // refused one (A4): its window doesn't count either, so the late
        // SYN-ACK's window does (the responder's segments advertise 1 byte,
        // the SYN-ACK 60000, and the initiator's byte 30000 after its first
        // ones fits the latter)
        {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 60000;
            script.handshake();
            let handshake: Vec<_> = script.segments.drain(..2).collect();
            script.segments.clear();
            script.window_size = 1;
            script
                .send(Initiator, b"request")
                .send(Responder, b"aaa")
                .send(Responder, b"bbb");
            script.segments[0].header.acknowledgment_number = 2001 + (1 << 30);
            script.segments.extend(handshake);
            script.send_at(Initiator, 7 + 30000, b"x");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(30008, stream.highest_offset());
            assert_eq!(0, stream.status().out_of_window_segments);
        }

        // the same holds for the segment that starts the stream: the
        // responder's first bytes lie far from the ACK the initiator sent
        // for it, so their window doesn't count, and the late SYN-ACK's
        // window does
        {
            let config = TcpReassemblyConfig {
                fallback_window: 100,
                ..Default::default()
            };
            let mut script = ConnectionScript::with_isns(1000, 12000);
            script.window_size = 100;
            script.handshake().send(Initiator, b"abc");
            // the initiator's bytes ACK a sequence number far from the
            // responder's ISN
            script.segments[3].header.acknowledgment_number = 2001;
            script.window_size = 1000;
            script.send(Responder, b"x");
            let handshake: Vec<_> = script.segments.drain(..3).collect();
            script.segments.extend(handshake);
            assert_window_end(config, &script, 203);
        }
    }

    /// Checks that after `script`, bytes of the initiator starting at `end`
    /// are stored, but bytes starting after it count as out-of-window.
    fn assert_window_end(config: TcpReassemblyConfig, script: &ConnectionScript, end: u64) {
        let mut pool = TcpReassemblyPool::<(), ()>::new(config);
        let mut probes = script.clone();
        probes.segments.clear();
        probes
            .send_at(Initiator, end + 1, b"x")
            .send_at(Initiator, end, b"y");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        let highest_offset = connection.stream(Initiator).highest_offset();
        {
            let (connection, _) = probes.segments[0].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(highest_offset, stream.highest_offset());
        }
        let (connection, _) = probes.segments[1].feed(&mut pool, ()).active.unwrap();
        let stream = connection.stream(Initiator);
        assert_eq!(1, stream.status().out_of_window_segments);
        assert_eq!(end + 1, stream.highest_offset());
    }

    #[test]
    fn is_clean() {
        // new stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(connection.stream(Initiator).is_clean());
        }

        // holes, retransmissions with the same bytes and bytes after the FIN
        // keep it clean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .send_at(Initiator, 4, b"efX")
                .send_at(Initiator, 0, b"abc");
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(1, stream.holes().count());
            assert!(stream.is_clean());
        }

        // a Windows keep-alive probe (the last ACKed byte again, with
        // different content) keeps it clean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack(Responder)
                .send_at(Initiator, 2, &[0]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.is_clean());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_acked());
        }

        // a given up hole makes it unclean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send_at(Initiator, 3, b"d");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.give_up_hole());
            assert!(false == stream.is_clean());
        }

        // a conflicting retransmission makes it unclean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 0, b"X");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_clean());
        }

        // a resync makes it unclean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 1000, b"GET /")
                .ack(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_clean());
        }

        // rejected bytes make it unclean, also after a retransmission filled
        // their hole
        {
            let config = TcpReassemblyConfig {
                max_stream_buffer: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 2, b"c");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert!(false == stream.is_clean());
                assert_eq!(TcpRead::Data(b"ab"), stream.read_received());
                stream.consume(1);
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"bc"), stream.read_received());
            assert!(false == stream.is_clean());
        }
    }

    #[test]
    fn is_complete() {
        // no FIN yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_complete());
        }

        // bytes before the FIN are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_complete());
        }

        // all bytes from the SYN to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(connection.stream(Initiator).is_complete());
            assert!(connection.stream(Responder).is_complete());
        }

        // clean and finished, but a mid-stream pickup
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc").fin(Initiator);
            script.segments.drain(..3);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert!(stream.is_clean());
            assert!(stream.is_finished());
            assert!(false == stream.is_complete());
        }

        // finished, but a hole was given up
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin_at(Initiator, 3, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.give_up_hole());
            assert!(stream.is_finished());
            assert!(false == stream.is_complete());
        }

        // finished, but a retransmission had differing bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 0, b"X")
                .fin(Initiator);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert!(stream.is_finished());
            assert!(false == stream.is_complete());
        }

        // an overdue hole before the FIN: incomplete before and after the
        // read position reaches it
        {
            let config = TcpReassemblyConfig {
                fallback_window: 2,
                ..Default::default()
            };
            let mut pool = TcpReassemblyPool::<(), ()>::new(config);
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn()
                .send(Initiator, b"abc")
                .send_at(Initiator, 6, b"ghi")
                .fin_with_data(Initiator, b"jkl");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(false == stream.is_complete());
            stream.read_received();
            stream.consume(3);
            assert!(false == stream.is_complete());
        }
    }
}
