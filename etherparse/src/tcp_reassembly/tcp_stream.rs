use crate::{tcp_reassembly::*, *};
use core::ops::Range;
use std::{collections::VecDeque, vec::Vec};

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
/// length lies in between (see [`TcpStreamStatus::resyncs`]).
#[derive(Clone, Debug)]
pub struct TcpStream {
    /// Sequence number of the byte at offset 0 (`None` while the start of
    /// the stream is unknown).
    start_seq: Option<u32>,

    /// Last ACK number of the receiver that the stream couldn't apply yet,
    /// as it had no start or the ACK lies at or before offset 0 while bytes
    /// can still be prepended. It is applied after every packet until it
    /// counts (a keep-alive ending there doesn't start the stream).
    pending_ack: Option<u32>,

    /// Window scale option in the sender's SYN (`None` while the SYN was
    /// not seen, `Some(None)` for a SYN without the option).
    window_scale: Option<Option<u8>>,

    /// "window" field of the sender's last segment and whether that segment
    /// was a SYN (`None` before the sender's first segment).
    window: Option<(u16, bool)>,

    /// Offset of the byte at `buf[head]`.
    read_offset: u64,

    /// Offset after the furthest byte the sender is known to have sent.
    highest_offset: u64,

    /// Received bytes up to the furthest one, where `buf[head]` is the byte
    /// at `read_offset`. The bytes before `head` are already consumed, and
    /// the bytes in holes are placeholders.
    buf: Vec<u8>,

    /// Number of consumed bytes at the start of `buf`.
    head: usize,

    /// Offset after the furthest received byte that was stored (the read
    /// position can lie after it once the bytes after it were given up).
    received_end: u64,

    /// Missing bytes between `read_offset` and `highest_offset`, sorted and
    /// without overlaps. Missing bytes after the end of `buf` always lie in
    /// a hole.
    holes: Vec<Range<u64>>,

    /// Holes that were given up, sorted and without overlaps. They lie
    /// between `read_offset` and `highest_offset`, apart from `holes`. An
    /// empty range is the gap of unknown length that a resync left in front
    /// of the byte at its offset.
    gaps: Vec<Range<u64>>,

    /// Number of bytes the last read returned that are not consumed yet.
    last_read_len: usize,

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

    /// Number of the connection's packet that moved the seen ACK forward
    /// and the seen ACK after it, for the packets of the last
    /// `ack_reorder_tolerance` ones that did so while there were holes.
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

    status: TcpStreamStatus,
}

impl TcpStream {
    /// Creates a stream whose start is not known yet, storing its bytes in
    /// the empty buffer `buf`.
    pub(crate) fn new(buf: Vec<u8>) -> TcpStream {
        TcpStream {
            start_seq: None,
            pending_ack: None,
            window_scale: None,
            window: None,
            read_offset: 0,
            highest_offset: 0,
            buf,
            head: 0,
            received_end: 0,
            holes: Vec::new(),
            gaps: Vec::new(),
            last_read_len: 0,
            fin_offset: None,
            seen_ack: 0,
            implied_ack: None,
            largest_window: None,
            recent_acks: VecDeque::new(),
            settled_ack: 0,
            resync_candidate: None,
            resync_ack: None,
            resync_offset: 0,
            status: TcpStreamStatus {
                start: TcpStreamStart::MidStreamPickup,
                gaps: 0,
                gap_bytes: 0,
                resyncs: 0,
                conflicting_retransmissions: 0,
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
    /// hole), and [`TcpRead::End`] once all bytes up to the FIN were read.
    /// At a gap, the result is [`TcpRead::Gap`] until you call
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
    /// not returned again.
    pub fn read_acked(&mut self) -> TcpRead<'_> {
        self.read_until(self.acked_offset())
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte, but not after `limit`, or the gap at the read position.
    fn read_until(&mut self, limit: u64) -> TcpRead<'_> {
        if let Some(gap) = self.gap_at_read_offset() {
            self.last_read_len = 0;
            // the gap of a resync takes no offsets, its length is unknown
            let len = (false == gap.is_empty()).then_some(gap.end - gap.start);
            return TcpRead::Gap { len };
        }
        // all bytes before the first hole or gap were received
        let end = self
            .missing()
            .next()
            .map_or(self.highest_offset, |range| range.start)
            .min(limit)
            .max(self.read_offset);
        let data = &self.buf[self.head..self.index(end)];
        self.last_read_len = data.len();
        if false == data.is_empty() {
            TcpRead::Data(data)
        } else if Some(self.read_offset) == self.fin_offset {
            TcpRead::End(TcpStreamEnd::Fin)
        } else {
            TcpRead::Pending
        }
    }

    /// Consumes `len` bytes at the read position.
    ///
    /// At most the bytes returned by the last read are consumed, so bytes
    /// that arrived after the read stay unread. If earlier bytes were put in
    /// front of a mid-stream pickup since the read, nothing is consumed (see
    /// [`TcpStreamStart::MidStreamPickup`]).
    pub fn consume(&mut self, len: usize) {
        let len = len.min(self.last_read_len);
        self.head += len;
        self.read_offset += len as u64;
        self.last_read_len -= len;
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
        match self.hole_at_read_offset() {
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
        if let Some(gap) = self.gap_at_read_offset() {
            self.gaps.remove(0);
            self.advance_to(gap.end);
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
        let offset = offset.min(self.highest_offset);
        if offset <= self.read_offset {
            return;
        }
        remove_before(&mut self.holes, offset);
        remove_before(&mut self.gaps, offset);
        self.advance_to(offset);
        self.give_up_overdue_hole();
    }

    /// Discards all buffered bytes and holes, so that the stream continues
    /// with the next new bytes.
    ///
    /// Works like [`TcpStream::discard_until`] with the highest offset.
    pub fn discard_all(&mut self) {
        self.discard_until(self.highest_offset);
    }

    /// Turns the parts of the holes before `offset` into gaps.
    fn give_up_holes_before(&mut self, offset: u64) {
        for hole in self.holes.iter_mut().take_while(|hole| hole.start < offset) {
            let given_up = hole.start..hole.end.min(offset);
            self.status.gaps += 1;
            self.status.gap_bytes += given_up.end - given_up.start;
            hole.start = given_up.end;
            self.gaps.push(given_up);
        }
        self.holes.retain(|hole| false == hole.is_empty());
        // the gap of a resync comes before a hole given up at its offset
        self.gaps.sort_unstable_by_key(|gap| (gap.start, gap.end));
    }

    /// Gives up the hole at the read position if it is overdue: the
    /// receiver must have received its bytes, so they will most likely not
    /// be captured anymore (late segments still fill overdue holes the read
    /// position hasn't reached).
    fn give_up_overdue_hole(&mut self) {
        if let Some(hole) = self.hole_at_read_offset() {
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

    /// Returns true if all of `hole` lies before the implied ACK, or if the
    /// seen ACK has covered all of it for `ack_reorder_tolerance` packets.
    fn is_overdue(&self, hole: &Range<u64>) -> bool {
        hole.end <= self.implied_ack().max(self.settled_ack)
    }

    /// Returns true if the byte at `offset` lies in an overdue hole.
    fn in_overdue_hole(&self, offset: u64) -> bool {
        let index = self.holes.partition_point(|hole| hole.end <= offset);
        self.holes
            .get(index)
            .is_some_and(|hole| hole.start <= offset && self.is_overdue(hole))
    }

    /// Hole starting at the read position, if any.
    fn hole_at_read_offset(&self) -> Option<Range<u64>> {
        self.holes
            .first()
            .filter(|hole| hole.start == self.read_offset)
            .cloned()
    }

    /// Gap starting at the read position, if any.
    fn gap_at_read_offset(&self) -> Option<Range<u64>> {
        self.gaps
            .first()
            .filter(|gap| gap.start == self.read_offset)
            .cloned()
    }

    /// Moves the read position forward to `offset` (at most the highest
    /// offset), discarding the bytes before it.
    fn advance_to(&mut self, offset: u64) {
        // the buffer ends at the furthest received byte
        self.head = self.index(offset.min(self.buf_end()));
        self.read_offset = offset;
        self.last_read_len = 0;
    }

    /// Offset of the next byte to read.
    ///
    /// It moves back to the FIN offset when a FIN arrives before it, inside
    /// bytes up to an ACK that were given up (see
    /// [`TcpStream::highest_offset`]).
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Offset up to which the receiver ACKed the stream's bytes.
    ///
    /// ACKs of bytes more than one receive window after the highest offset
    /// are ignored, as the sender can't have sent these bytes. Without a
    /// higher ACK, it is the implied ACK: the sender sends at most one
    /// window after the ACK, so the receiver must have ACKed the bytes up
    /// to [`TcpReassemblyConfig::hole_give_up_window_factor`] times its
    /// largest window before the highest offset.
    pub fn acked_offset(&self) -> u64 {
        // the ACK of the FIN lies after the highest offset
        self.seen_ack
            .max(self.implied_ack())
            .min(self.highest_offset)
    }

    /// Offset after the furthest byte the sender is known to have sent, as
    /// it was received or ACKed.
    ///
    /// It moves back to the FIN offset, and [`TcpStream::acked_offset`] with
    /// it, when a FIN arrives inside bytes that an earlier ACK covered.
    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
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
    /// receiver must have received its bytes. Late segments still fill
    /// overdue holes the read position hasn't reached.
    pub fn holes(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.holes.iter().cloned()
    }

    /// Counters that describe the quality of the stream.
    pub fn status(&self) -> &TcpStreamStatus {
        &self.status
    }

    /// Returns true if the stream has no defects so far: no gaps, no
    /// resyncs and no retransmission with differing bytes (see
    /// [`TcpStreamStatus`]).
    ///
    /// Holes don't count, as retransmissions can still fill them, and
    /// neither do discarded bytes (see [`TcpStream::discard_until`]).
    pub fn is_clean(&self) -> bool {
        0 == self.status.gaps
            && 0 == self.status.resyncs
            && 0 == self.status.conflicting_retransmissions
    }

    /// Returns true if the stream's FIN was seen and all bytes before it
    /// were received or given up (no holes are left).
    ///
    /// Overdue holes (see [`TcpStream::holes`]) count as holes, as late
    /// segments can still fill them.
    pub fn is_finished(&self) -> bool {
        // the FIN moves the highest offset to it, so all holes lie before it
        self.fin_offset.is_some() && self.holes.is_empty()
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

    /// Returns the stream's buffer, emptied for re-use.
    pub(crate) fn into_buffer(self) -> Vec<u8> {
        let mut buf = self.buf;
        buf.clear();
        buf
    }

    /// Returns true if the receiver ACKed the stream's FIN and all holes
    /// left are overdue, so that the stream can end as finished.
    pub(crate) fn can_finish(&self) -> bool {
        self.fin_offset.is_some_and(|fin| fin < self.seen_ack)
            && self.holes.last().is_none_or(|hole| self.is_overdue(hole))
    }

    /// Gives up all holes, as the connection ended.
    pub(crate) fn give_up_all_holes(&mut self) {
        self.give_up_holes_before(self.highest_offset);
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
            .max(self.highest_offset)
            .saturating_add(window_range(window, config))
    }

    /// Offset after the last byte in `buf`.
    fn buf_end(&self) -> u64 {
        self.read_offset + (self.buf.len() - self.head) as u64
    }

    /// Index in `buf` of the byte at `offset` (at or after `read_offset`).
    fn index(&self, offset: u64) -> usize {
        self.head + (offset - self.read_offset) as usize
    }

    /// Maps the sequence number `seq` to a stream offset, relative to the
    /// highest offset (RFC 1982 serial number arithmetic).
    ///
    /// Offsets before the stream's first byte are negative. A sequence
    /// number 2^31 away from the highest offset lies neither before nor
    /// after it, so it can't be mapped (`None`).
    fn offset(&self, start_seq: u32, seq: u32) -> Option<i64> {
        let highest = self.highest_offset;
        let distance = seq.wrapping_sub(start_seq.wrapping_add(highest as u32)) as i32;
        (i32::MIN != distance).then(|| highest as i64 + i64::from(distance))
    }

    /// Applies a segment sent by the stream's sender, whose receiver has the
    /// receive window `window`, in the packet with the number `packet` of
    /// the connection.
    pub(crate) fn add_segment(
        &mut self,
        tcp: &TcpSlice<'_>,
        window: u64,
        packet: u64,
        config: &TcpReassemblyConfig,
    ) {
        // the window the sender advertises for the other stream
        self.window = Some((tcp.window_size(), tcp.syn()));

        // the SYN occupies the sequence number before the first byte
        let seq = if tcp.syn() {
            tcp.sequence_number().wrapping_add(1)
        } else {
            tcp.sequence_number()
        };
        let data = tcp.payload();
        if tcp.syn() {
            // a SYN whose start a mid-stream pickup can't take is not the
            // stream's own one
            if false == self.observe_start(seq, window, config) {
                self.status.out_of_window_segments += 1;
                return;
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
            let keep_alive =
                is_keep_alive_shaped(tcp) && Some(seq.wrapping_add(1)) == self.pending_ack;
            if (false == data.is_empty() || tcp.fin()) && false == keep_alive {
                self.start_seq = Some(seq);
            }
        }
        let Some(start_seq) = self.start_seq else {
            return;
        };
        let mut start = self.offset(start_seq, seq);
        // the receiver doesn't accept bytes or a FIN starting after its
        // window (or that can't be mapped)
        let mut after_window = start.is_none_or(|start| {
            u64::try_from(start).is_ok_and(|start| start > self.window_end(window, config))
        });

        // data after the window can be where the stream jumped to, other
        // data shows that it didn't (a SYN with another ISN is a reconnect,
        // and nothing follows a FIN)
        let mut jump_ack = None;
        if false == data.is_empty() && false == tcp.syn() && self.fin_offset.is_none() {
            let candidate = ResyncCandidate::new(seq, data.len(), tcp.fin());
            // an ACK beyond the window that arrived before confirms a jump
            // to bytes within one window of it
            let confirming_ack = self
                .resync_ack
                .filter(|ack| candidate.is_within_window(*ack, window));
            let confirmed = if after_window {
                // so do enough consecutive segments that agree
                self.add_resync_candidate(candidate, window, config) || confirming_ack.is_some()
            } else {
                self.resync_candidate = None;
                false
            };
            // the other side confirms the jump, the segment is the new start
            if confirmed {
                jump_ack = confirming_ack;
                let start_seq = self.resync(seq);
                start = self.offset(start_seq, seq);
                after_window = false;
            }
        }
        if (false == data.is_empty() || tcp.fin()) && after_window {
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
        let Some(mut start) = start else {
            return;
        };

        // bytes before offset 0 of a mid-stream pickup are prepended until
        // it is read from, and are outside of the stream after that
        let mut out_of_window = false;
        if start < 0
            && false == data.is_empty()
            && TcpStreamStart::MidStreamPickup == self.status.start
        {
            if self.move_start_back(seq, start, window, config) {
                start = 0;
            } else {
                out_of_window = true;
            }
        }
        let end = start + data.len() as i64;

        // the filler byte of a keep-alive must not fill an overdue hole
        if is_keep_alive_shaped(tcp)
            && end == self.seen_ack as i64
            && u64::try_from(start).is_ok_and(|start| self.in_overdue_hole(start))
        {
            return;
        }

        // the first FIN wins, but it can't lie before received bytes (even
        // if bytes before it are missing or were given up) or before a jump
        if tcp.fin()
            && self.fin_offset.is_none()
            && end >= self.received_end.max(self.resync_offset) as i64
        {
            self.fin_offset = Some(end as u64);
            // an ACK of the FIN that arrived before it marked the FIN's
            // position as a missing byte
            self.truncate_to(end as u64);
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
        self.add_data(start, data);

        // the sender sent all bytes before its FIN
        if let Some(fin) = self.fin_offset {
            self.extend_to(fin);
        }

        // an ACK that confirmed the jump before the bytes arrived counts now
        if let Some(ack) = jump_ack {
            self.add_jump_ack(ack, window, packet);
        }
    }

    /// Gives the stream an observed start at `seq`, the sequence number
    /// after its SYN, where `window` is the receiver's receive window.
    ///
    /// A mid-stream pickup moves its start back to `seq`. Returns false if
    /// it can't, and true if the stream has an observed start afterwards.
    pub(crate) fn observe_start(
        &mut self,
        seq: u32,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> bool {
        match self.start_seq {
            None => self.start_seq = Some(seq),
            Some(_) if TcpStreamStart::Observed == self.status.start => return true,
            Some(start_seq) => {
                // a late SYN lies at or before the first byte received
                let Some(start) = self.offset(start_seq, seq) else {
                    return false;
                };
                if false == self.move_start_back(seq, start, window, config) {
                    return false;
                }
            }
        }
        self.status.start = TcpStreamStart::Observed;
        true
    }

    /// Moves offset 0 of a mid-stream pickup back to the sequence number
    /// `seq` at offset `start`, if bytes can still be prepended and `seq`
    /// lies within the range of the receiver's receive window `window`
    /// before offset 0. Returns false otherwise.
    fn move_start_back(
        &mut self,
        seq: u32,
        start: i64,
        window: u64,
        config: &TcpReassemblyConfig,
    ) -> bool {
        if 0 < start
            || start.unsigned_abs() > window_range(window, config)
            || false == self.can_prepend()
        {
            return false;
        }
        if start < 0 {
            self.prepend(start.unsigned_abs());
        }
        self.start_seq = Some(seq);
        true
    }

    /// Returns true if bytes can still be prepended to the stream, as it is
    /// a mid-stream pickup whose offsets no reader has used yet.
    fn can_prepend(&self) -> bool {
        // the read position of a pickup never moves back to 0 (a FIN can't
        // lie before the first byte received), a reader may have read the
        // end of a pickup that starts at its FIN, and prepending would move
        // the gap of a resync
        TcpStreamStart::MidStreamPickup == self.status.start
            && 0 == self.read_offset
            && Some(0) != self.fin_offset
            && 0 == self.status.resyncs
    }

    /// Moves offset 0 of the mid-stream pickup `len` bytes back, these
    /// bytes are a hole until they arrive.
    fn prepend(&mut self, len: u64) {
        // nothing was consumed yet, and there are no gaps, as the read
        // position is at the first byte received
        self.buf.splice(..0, core::iter::repeat_n(0, len as usize));
        self.highest_offset += len;
        self.received_end += len;
        for hole in &mut self.holes {
            hole.start += len;
            hole.end += len;
        }
        self.holes.insert(0, 0..len);
        self.fin_offset = self.fin_offset.map(|fin| fin + len);
        // ACKs of offset 0 or before it were ignored, so 0 means none
        if 0 < self.seen_ack {
            self.seen_ack += len;
        }
        if 0 < self.settled_ack {
            self.settled_ack += len;
        }
        for (_, ack) in &mut self.recent_acks {
            *ack += len;
        }
        self.implied_ack = self.implied_ack.map(|ack| ack.saturating_add(len as i64));
        // a read before returned other bytes at the read position
        self.last_read_len = 0;
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
        // or its offsets moved (until then, it stays pending)
        if let Some(ack) = self.pending_ack.take() {
            let ack_window = window.unwrap_or(u64::from(config.fallback_window));
            self.add_ack(ack, ack_window, packet);
        }
        // the sender can have sent bytes into a larger window before the
        // window shrank (e.g. to 0 when the receiver's buffer is full)
        self.largest_window = self.largest_window.max(window);
        if let Some(factor) = config.hole_give_up_window_factor {
            // allow for several windows, as the window can change
            let window = self
                .largest_window
                .unwrap_or(u64::from(config.fallback_window));
            let implied_ack = i64::try_from(self.highest_offset)
                .unwrap_or(i64::MAX)
                .saturating_sub(
                    i64::try_from(window.saturating_mul(u64::from(factor))).unwrap_or(i64::MAX),
                );
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
        if self.holes.is_empty() && false == self.can_prepend() {
            // later holes lie after the seen ACK, so they can't be overdue
            // by the ACKs so far (a prepend adds a hole before it)
            self.recent_acks.clear();
        }
        self.give_up_overdue_hole();
    }

    /// Applies the ACK number of a segment sent by the stream's receiver,
    /// whose receive window before that segment was `window`, in the packet
    /// with the number `packet` of the connection.
    pub(crate) fn add_ack(&mut self, ack_seq: u32, window: u64, packet: u64) {
        let Some(start_seq) = self.start_seq else {
            self.pending_ack = Some(ack_seq);
            return;
        };
        // the receiver can only ACK bytes that can't be mapped after a jump
        let Some(ack) = self.offset(start_seq, ack_seq) else {
            self.add_resync_ack(ack_seq, window, packet);
            return;
        };
        // an ACK of offset 0 or before it can ACK bytes prepended later
        if ack <= 0 && self.can_prepend() {
            self.pending_ack = Some(ack_seq);
            return;
        }
        // the sender can't have sent more than one window after the bytes
        // it is known to have sent (and its FIN), unless the stream jumped
        let sent_end = self.highest_offset + u64::from(self.fin_offset.is_some());
        if 0 < ack && ack as u64 > sent_end.saturating_add(window) {
            self.add_resync_ack(ack_seq, window, packet);
            return;
        }
        // ACKs before a jump don't count after it
        if ack <= self.seen_ack as i64 || ack < self.resync_offset as i64 {
            return;
        }
        self.seen_ack = ack as u64;
        // the receiver got bytes that were not captured, but none after the
        // FIN
        let end = self
            .fin_offset
            .map_or(self.seen_ack, |fin| fin.min(self.seen_ack));
        self.extend_to(end);
        // only holes can become overdue by the ACK, also ones that a
        // prepend adds before it
        if false == self.holes.is_empty() || self.can_prepend() {
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
    fn add_resync_ack(&mut self, ack_seq: u32, window: u64, packet: u64) {
        match self.resync_candidate {
            Some(candidate)
                if self.fin_offset.is_none() && candidate.is_within_window(ack_seq, window) =>
            {
                // the FIN after the candidate's bytes ends the stream there
                self.resync(candidate.end);
                if candidate.fin {
                    self.fin_offset = Some(self.highest_offset);
                }
                self.add_jump_ack(ack_seq, window, packet);
            }
            _ => self.resync_ack = Some(ack_seq),
        }
    }

    /// Applies the ACK number `ack_seq` that confirmed a jump after the
    /// resync, like the ACK of [`TcpStream::add_ack`]. It also ACKs all bytes
    /// before the jump, as the receiver ACKed bytes after it.
    fn add_jump_ack(&mut self, ack_seq: u32, window: u64, packet: u64) {
        self.add_ack(ack_seq, window, packet);
        self.seen_ack = self.seen_ack.max(self.resync_offset);
    }

    /// Continues the stream with the byte that has the sequence number
    /// `seq` at the highest offset, behind a gap of unknown length, and
    /// returns the new sequence number of offset 0.
    fn resync(&mut self, seq: u32) -> u32 {
        // the missing bytes now map elsewhere, so nothing can fill the holes
        self.give_up_holes_before(self.highest_offset);
        let offset = self.highest_offset;
        // resyncs without bytes between them leave one gap
        if Some(&(offset..offset)) != self.gaps.last() {
            self.gaps.push(offset..offset);
        }
        let start_seq = seq.wrapping_sub(offset as u32);
        self.start_seq = Some(start_seq);
        self.resync_offset = offset;
        self.resync_candidate = None;
        self.resync_ack = None;
        self.status.resyncs += 1;
        start_seq
    }

    /// Stores the bytes of `data` (starting at offset `start`) that were not
    /// received before.
    fn add_data(&mut self, start: i64, data: &[u8]) {
        // skip the bytes before the read position (consumed, or before the
        // stream's first byte), in a gap at it (given up) and before a jump
        let skip_end = self
            .gap_at_read_offset()
            .map_or(self.read_offset, |gap| gap.end)
            .max(self.resync_offset);
        let skipped = (skip_end as i64).saturating_sub(start).max(0) as usize;
        let data = match data.get(skipped..) {
            Some(data) if false == data.is_empty() => data,
            _ => return,
        };
        let start = (start + skipped as i64) as u64;
        let end = start + data.len() as u64;

        // bytes received before keep their content
        if self.differs_from_received(start, data) {
            self.status.conflicting_retransmissions += 1;
        }

        // fill the holes in the buffer
        let buf_end = self.buf_end();
        for hole in &self.holes {
            let from = hole.start.max(start);
            let to = hole.end.min(end).min(buf_end);
            if from < to {
                let (buf_from, buf_to) = (self.index(from), self.index(to));
                self.buf[buf_from..buf_to]
                    .copy_from_slice(&data[(from - start) as usize..(to - start) as usize]);
            }
        }

        // append the bytes after the end of the buffer (all missing so far)
        if buf_end < end {
            // drop the consumed bytes once they make up half of the buffer
            if self.head >= self.buf.len() - self.head {
                self.buf.drain(..self.head);
                self.head = 0;
            }
            // placeholders for missing bytes before the segment
            let from = start.max(buf_end);
            self.buf.resize(self.index(from), 0);
            self.buf.extend_from_slice(&data[(from - start) as usize..]);
            self.received_end = end;
        }
        self.extend_to(end);
        self.remove_from_holes(start..end);
    }

    /// Returns true if bytes of `data` (starting at offset `start`, at or
    /// after the read position) differ from the bytes received for the same
    /// offsets, ignoring ACKed bytes.
    fn differs_from_received(&self, start: u64, data: &[u8]) -> bool {
        let end = start + data.len() as u64;
        // the receiver ignores retransmissions of ACKed bytes (e.g. keep-alive
        // probes), so they don't conflict
        let compared_start = start.max(self.acked_offset());
        // the received bytes lie before each hole or gap and before the
        // highest offset (an empty range at the end)
        let mut received_start = self.read_offset;
        let missing = self
            .missing()
            .chain([self.highest_offset..self.highest_offset]);
        for range in missing {
            let from = received_start.max(compared_start);
            let to = range.start.min(end);
            if from < to
                && self.buf[self.index(from)..self.index(to)]
                    != data[(from - start) as usize..(to - start) as usize]
            {
                return true;
            }
            received_start = range.end;
        }
        false
    }

    /// Ranges of missing bytes (holes and gaps) in order.
    fn missing(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        let mut holes = self.holes.iter().peekable();
        let mut gaps = self.gaps.iter().peekable();
        core::iter::from_fn(move || match (holes.peek(), gaps.peek()) {
            // the gap of a resync comes before a hole at its offset
            (Some(hole), Some(gap)) if gap.start <= hole.start => gaps.next(),
            (Some(_), _) => holes.next(),
            (None, _) => gaps.next(),
        })
        .cloned()
    }

    /// Moves the highest offset forward to `offset`, the bytes in between
    /// are missing.
    fn extend_to(&mut self, offset: u64) {
        if offset > self.highest_offset {
            match self.holes.last_mut() {
                Some(hole) if hole.end == self.highest_offset => hole.end = offset,
                _ => self.holes.push(self.highest_offset..offset),
            }
            self.highest_offset = offset;
            // the stream moved forward, so it didn't jump
            self.resync_candidate = None;
            self.resync_ack = None;
        }
    }

    /// Moves the highest offset back to `offset` (at or after the furthest
    /// received byte), the missing bytes after it don't exist.
    fn truncate_to(&mut self, offset: u64) {
        if offset < self.highest_offset {
            truncate_ranges(&mut self.holes, offset);
            truncate_ranges(&mut self.gaps, offset);
            self.highest_offset = offset;
            // the read position can lie after it, in bytes that were given
            // up (no bytes are buffered there)
            self.read_offset = self.read_offset.min(offset);
        }
    }

    /// Removes the bytes in `range` from the holes.
    fn remove_from_holes(&mut self, range: Range<u64>) {
        // holes overlapping the range
        let first = self.holes.partition_point(|hole| hole.end <= range.start);
        let last = self.holes.partition_point(|hole| hole.start < range.end);
        if first >= last {
            return;
        }

        // the parts of these holes before and after the range stay missing
        let before = self.holes[first].start..range.start;
        let after = range.end..self.holes[last - 1].end;
        self.holes.drain(first..last);
        let mut index = first;
        for part in [before, after] {
            if false == part.is_empty() {
                self.holes.insert(index, part);
                index += 1;
            }
        }
    }
}

/// Removes the parts of the sorted `ranges` before `offset`. The empty gap of
/// a resync at `offset` takes no offsets, so it stays.
fn remove_before(ranges: &mut Vec<Range<u64>>, offset: u64) {
    let removed = ranges.partition_point(|range| range.end <= offset && range.start < offset);
    ranges.drain(..removed);
    if let Some(range) = ranges.first_mut() {
        range.start = range.start.max(offset);
    }
}

/// Removes the parts of the sorted `ranges` at or after `offset`. The empty
/// gap of a resync at `offset` takes no offsets, so it stays.
fn truncate_ranges(ranges: &mut Vec<Range<u64>>, offset: u64) {
    let kept = ranges.partition_point(|range| range.start < offset || range.end <= offset);
    ranges.truncate(kept);
    if let Some(range) = ranges.last_mut() {
        range.end = range.end.min(offset);
    }
}

/// Number of bytes before or after the stream's bytes that a receiver with
/// the receive window `window` accepts: several windows, as the window can
/// change and not all ACKs are captured.
fn window_range(window: u64, config: &TcpReassemblyConfig) -> u64 {
    let factor = config.hole_give_up_window_factor.unwrap_or(2);
    window.saturating_mul(u64::from(factor))
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
/// filler byte, without SYN, FIN or RST, that repeats the byte before the
/// receiver's ACK (RFC 1122 4.2.3.6).
fn is_keep_alive_shaped(tcp: &TcpSlice<'_>) -> bool {
    1 == tcp.payload().len() && false == (tcp.syn() || tcp.fin() || tcp.rst())
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
    use std::{format, vec};

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
        // the receiver's ACK) start the stream: two bytes, a byte with a
        // FIN, and a byte with an RST. A keep-alive without bytes doesn't
        // (the following bytes start the stream).
        for (payload, fin, rst, expected) in [
            (&b"bc"[..], false, false, &b"bcd"[..]),
            (b"b", true, false, b"b"),
            (b"b", false, true, b"bcd"),
            (b"", false, false, b"cd"),
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
            script.segments[1].header.rst = rst;
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
        // window the receiver advertised before the ACK
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_size = 100;
            script
                .handshake()
                .send(Initiator, b"abc")
                .ack_to(Responder, 104)
                .ack_to(Responder, 103);
            // a window of 0 limits the next ACK, not the one in its segment
            script.window_size = 0;
            script.ack_to(Responder, 203).ack_to(Responder, 204);
            script.feed(&mut pool, ..4);
            for (segment, expected) in script.segments[4..].iter().zip([0, 103, 203, 203]) {
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

        // a keep-alive probe (one byte ending at the seen ACK, without SYN,
        // FIN or RST) doesn't fill an overdue hole, other segments do, and
        // so does a keep-alive before the hole is overdue
        for (packets, offset, payload, [syn, fin, rst], expected) in [
            // keep-alive
            (2, 5, &[0][..], [false; 3], &[3..6][..]),
            // keep-alive before the hole is overdue
            (1, 5, &[0], [false; 3], &[3..5]),
            // two bytes
            (2, 4, b"ef", [false; 3], &[3..4]),
            // one byte that doesn't end at the seen ACK
            (2, 4, b"e", [false; 3], &[3..4, 5..6]),
            // SYN, FIN or RST
            (2, 5, &[0], [true, false, false], &[3..5]),
            (2, 5, &[0], [false, true, false], &[3..5]),
            (2, 5, &[0], [false, false, true], &[3..5]),
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
            probe.header.rst = rst;
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

        // other SYNs of a mid-stream pickup count as out-of-window and
        // change nothing, not even with bytes (TCP Fast Open): after the
        // read position moved, more than k windows before the first byte,
        // after the first byte, 2^31 away from the highest offset (can't be
        // mapped), and for a pickup that starts at its FIN
        for (factor, fallback_window, lost, consumed, syn_offset, fin) in [
            (None, 3, &b""[..], 1, 0, false),
            (Some(2), 2, b"abcde", 0, 0, false),
            (Some(1), 4, b"abcde", 0, 0, false),
            (None, 2, b"abcde", 0, 0, false),
            (None, 3, b"", 0, 2, false),
            (None, 3, b"", 0, (1 << 31) + 3, false),
            (None, 3, b"", 0, 0, true),
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
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(0, stream.status().conflicting_retransmissions);
            assert_eq!(if fin { 0 } else { 3 }, stream.highest_offset());
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
        // which doesn't count)
        for (distance, expected) in [((1 << 31) - 1, 1), (1 << 31, 1), ((1 << 31) + 1, 0)] {
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
        // last one counts
        for (scales, windows, end) in [
            ([Some(5), Some(3)], &[100][..], 2 * (100 << 3)),
            ([Some(5), Some(3)], &[200, 100][..], 2 * (100 << 3)),
            ([Some(0), Some(14)], &[1][..], 2 * (1 << 14)),
            ([Some(0), Some(15)], &[1][..], 2 * (1 << 14)),
            // one SYN without the option
            ([None, Some(3)], &[100][..], 200),
            ([Some(3), None], &[100][..], 200),
        ] {
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = scales;
            script.window_size = 1000;
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
            script.handshake();
            script.window_size = 100;
            script.ack(Responder);
            script.segments[1].header.set_options(options).unwrap();
            assert_window_end(Default::default(), &script, 2 * (100 << 3));
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

        // a SYN with another ISN is a reconnect, not a jump
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
            assert_eq!(1, status.out_of_window_segments);
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
        // pickup: they count as out-of-window
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
            assert_eq!(1, stream.status().out_of_window_segments);
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
