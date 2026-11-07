use crate::tcp_reassembly::*;
use core::ops::Range;
use std::vec::Vec;

/// Received bytes of a stream and the missing bytes between them, in stream
/// offsets.
///
/// The bytes from the read position to the furthest stored byte lie in one
/// contiguous buffer, with placeholders for the missing bytes. Missing bytes
/// are holes, which later segments can fill, or gaps, which were given up.
/// Holes and gaps lie between the read position and the highest offset,
/// sorted and without overlaps, and together they cover every byte after
/// the end of the buffer.
///
/// The buffer knows nothing about TCP: sequence numbers, ACKs, the FIN and
/// resyncs are [`TcpStream`]'s business, which tells the buffer where bytes
/// go and which holes to give up.
#[derive(Clone, Debug)]
pub(crate) struct StreamBuffer {
    /// Offset of the byte at `buf[head]`.
    read_offset: u64,

    /// Offset after the furthest byte the sender is known to have sent.
    highest_offset: u64,

    /// Received bytes up to the furthest one, where `buf[head]` is the byte
    /// at `read_offset`, and the bytes in holes are placeholders.
    buf: Vec<u8>,

    /// Index in `buf` of the byte at `read_offset`. The bytes before it are
    /// consumed, or room for bytes put in front of a mid-stream pickup.
    head: usize,

    /// Offset after the furthest received byte that was stored (the read
    /// position can lie after it once the bytes after it were given up).
    received_end: u64,

    /// Missing bytes between `read_offset` and `highest_offset` that can
    /// still arrive, sorted and without overlaps.
    holes: Vec<Range<u64>>,

    /// Holes that were given up, sorted and without overlaps. An empty
    /// range is the gap of unknown length that a resync left in front of
    /// the byte at its offset.
    gaps: Vec<Range<u64>>,

    /// Number of bytes the last read returned that are not consumed yet.
    last_read_len: usize,

    /// Capacity that `buf` keeps however few bytes it has left, so that the
    /// memory of the pool's streams follows the bytes they buffer.
    keep_capacity: usize,
}

/// What lies at the read position of a [`StreamBuffer`].
#[derive(Debug)]
pub(crate) enum Readable<'a> {
    /// Received bytes (empty if the next byte is missing or not sent yet).
    Bytes(&'a [u8]),
    /// A gap (an empty range for one of unknown length).
    Gap(Range<u64>),
}

/// What [`StreamBuffer::store`] did with the bytes of a segment.
#[derive(Debug)]
pub(crate) struct Stored {
    /// Whether bytes differed from bytes received before for the same
    /// offsets.
    pub conflicting: bool,
    /// Bytes that didn't fit the limits (empty if all fit).
    pub rejected: Range<u64>,
}

impl StreamBuffer {
    /// Creates an empty buffer, with its vectors taken from `free`.
    pub fn new(free: &mut FreeBuffers) -> StreamBuffer {
        StreamBuffer {
            read_offset: 0,
            highest_offset: 0,
            buf: free.bytes.take(),
            head: 0,
            received_end: 0,
            holes: free.holes.take(),
            gaps: free.gaps.take(),
            last_read_len: 0,
            keep_capacity: free.bytes.max_capacity(),
        }
    }

    /// Puts the vectors into `free` for re-use.
    pub fn recycle(self, free: &mut FreeBuffers) {
        free.bytes.put(self.buf);
        free.holes.put(self.holes);
        free.gaps.put(self.gaps);
    }

    /// Offset of the next byte to read.
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Offset after the furthest byte the sender is known to have sent.
    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
    }

    /// Offset after the furthest received byte that was stored.
    pub fn received_end(&self) -> u64 {
        self.received_end
    }

    /// Missing bytes that can still arrive, in order.
    pub fn holes(&self) -> &[Range<u64>] {
        &self.holes
    }

    /// Missing bytes that were given up, in order.
    pub fn gaps(&self) -> &[Range<u64>] {
        &self.gaps
    }

    /// Number of bytes buffered from the read position to the furthest
    /// stored byte, with the placeholders of holes.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.head
    }

    /// Hole starting at the read position, if any.
    pub fn hole_at_read_offset(&self) -> Option<Range<u64>> {
        self.holes
            .first()
            .filter(|hole| hole.start == self.read_offset)
            .cloned()
    }

    /// Hole that the byte at `offset` lies in, if any.
    pub fn hole_at(&self, offset: u64) -> Option<Range<u64>> {
        let index = self.holes.partition_point(|hole| hole.end <= offset);
        self.holes
            .get(index)
            .filter(|hole| hole.start <= offset)
            .cloned()
    }

    /// Returns the gap at the read position, or the received bytes from the
    /// read position up to the first missing byte, but not after `limit`.
    pub fn read(&mut self, limit: u64) -> Readable<'_> {
        if let Some(gap) = self.gap_at_read_offset() {
            self.last_read_len = 0;
            return Readable::Gap(gap);
        }
        // all bytes before the first hole or gap were received
        let end = self
            .missing()
            .next()
            .map_or(self.highest_offset, |range| range.start)
            .min(limit)
            .max(self.read_offset);
        let bytes = &self.buf[self.head..self.index(end)];
        self.last_read_len = bytes.len();
        Readable::Bytes(bytes)
    }

    /// Consumes `len` bytes at the read position, at most the bytes the
    /// last read returned.
    pub fn consume(&mut self, len: usize) {
        let len = len.min(self.last_read_len);
        self.head += len;
        self.read_offset += len as u64;
        self.last_read_len -= len;
        self.shrink_if_sparse();
    }

    /// Moves the read position over the gap at the read position. Returns
    /// false if there is none.
    pub fn consume_gap(&mut self) -> bool {
        match self.gap_at_read_offset() {
            Some(gap) => {
                self.gaps.remove(0);
                self.advance_to(gap.end);
                true
            }
            None => false,
        }
    }

    /// Moves the read position forward to `offset` (at most the highest
    /// offset), discarding the bytes, holes and gaps before it. The gap of
    /// unknown length at `offset` stays.
    pub fn discard_until(&mut self, offset: u64) {
        let offset = offset.min(self.highest_offset);
        if offset <= self.read_offset {
            return;
        }
        remove_before(&mut self.holes, offset);
        remove_before(&mut self.gaps, offset);
        self.advance_to(offset);
    }

    /// Turns the parts of the holes before `offset` into gaps, counted in
    /// `status`.
    pub fn give_up_holes_before(&mut self, offset: u64, status: &mut TcpStreamStatus) {
        for hole in self.holes.iter_mut().take_while(|hole| hole.start < offset) {
            let given_up = hole.start..hole.end.min(offset);
            status.gaps += 1;
            status.gap_bytes += given_up.end - given_up.start;
            hole.start = given_up.end;
            self.gaps.push(given_up);
        }
        self.holes.retain(|hole| false == hole.is_empty());
        // the gap of a resync comes before a hole given up at its offset
        self.gaps.sort_unstable_by_key(|gap| (gap.start, gap.end));
    }

    /// Adds the gap of unknown length of a resync at the highest offset
    /// (resyncs without bytes between them leave one gap).
    pub fn add_gap_of_unknown_len(&mut self) {
        let offset = self.highest_offset;
        if Some(&(offset..offset)) != self.gaps.last() {
            self.gaps.push(offset..offset);
        }
    }

    /// Moves offset 0 of a mid-stream pickup `len` bytes back, so all
    /// offsets grow by `len`. The new bytes are a hole until they arrive.
    pub fn prepend(&mut self, len: u64) {
        // nothing was consumed yet, and there are no gaps, as the read
        // position is at the first byte received, so the bytes before `head`
        // are room for the placeholders: make room for as many bytes as the
        // stream holds at once, so that a prepend costs little on average
        let placeholders = len as usize;
        if self.head < placeholders {
            let room = placeholders.max(self.buffered()) - self.head;
            self.buf.splice(..0, core::iter::repeat_n(0, room));
            self.head += room;
        }
        self.head -= placeholders;
        self.highest_offset += len;
        self.received_end += len;
        for hole in &mut self.holes {
            hole.start += len;
            hole.end += len;
        }
        self.holes.insert(0, 0..len);
        // a read before returned other bytes at the read position
        self.last_read_len = 0;
    }

    /// Returns true if `len` bytes fit in front of the stream, the first
    /// `data_len` of which are received, with the pool's budget `available`.
    pub fn fits_in_front(
        &self,
        len: u64,
        data_len: usize,
        config: &TcpReassemblyConfig,
        available: usize,
    ) -> bool {
        // the read position is at offset 0, so all buffered bytes count, and
        // the missing bytes before the old offset 0 are a new hole (byte 0
        // of a pickup is always stored)
        let holes = self.counted_holes() + usize::from((data_len as u64) < len);
        len.saturating_add(self.buffered() as u64) <= config.max_stream_buffer as u64
            && len <= available as u64
            && holes <= config.max_holes_per_stream
    }

    /// Moves the highest offset forward to `offset`, the bytes in between
    /// are missing. Returns true if it moved.
    pub fn extend_to(&mut self, offset: u64) -> bool {
        if offset <= self.highest_offset {
            return false;
        }
        match self.holes.last_mut() {
            Some(hole) if hole.end == self.highest_offset => hole.end = offset,
            _ => self.holes.push(self.highest_offset..offset),
        }
        self.highest_offset = offset;
        true
    }

    /// Moves the highest offset back to `offset` (at or after the furthest
    /// received byte), the missing bytes after it don't exist.
    pub fn truncate_to(&mut self, offset: u64) {
        if offset < self.highest_offset {
            truncate_ranges(&mut self.holes, offset);
            truncate_ranges(&mut self.gaps, offset);
            self.highest_offset = offset;
            // the read position can lie after it, in bytes that were given
            // up (no bytes are buffered there)
            self.read_offset = self.read_offset.min(offset);
        }
    }

    /// Stores the bytes of `data` (starting at offset `start`) that were not
    /// received before, as far as they fit the memory limits and the pool's
    /// budget `available`, which they reduce. The bytes that don't fit are
    /// rejected and become a hole. Bytes before `skip_before`, before the
    /// read position and in gaps are ignored, and bytes before
    /// `compare_from` are not compared with the bytes received before.
    pub fn store(
        &mut self,
        start: i64,
        data: &[u8],
        skip_before: u64,
        compare_from: u64,
        config: &TcpReassemblyConfig,
        available: &mut usize,
    ) -> Stored {
        let mut stored = Stored {
            conflicting: false,
            rejected: 0..0,
        };
        // holes are given up only at the read position and before a resync,
        // so all gaps lie before the end of the last one
        let skip_end = self
            .gaps
            .last()
            .map_or(0, |gap| gap.end)
            .max(self.read_offset)
            .max(skip_before);
        let skipped = (skip_end as i64).saturating_sub(start).max(0) as usize;
        let data = match data.get(skipped..) {
            Some(data) if false == data.is_empty() => data,
            _ => return stored,
        };
        let start = (start + skipped as i64) as u64;
        let end = start + data.len() as u64;

        // bytes received before keep their content
        stored.conflicting = self.differs_from_received(start, data, compare_from);

        // bytes after the end of the buffer (and the placeholders before
        // them) must fit the buffer and the pool's budget, the bytes before
        // it fill holes (the buffer never holds more than its limit)
        let buf_end = self.buf_end();
        let limit = self
            .read_offset
            .saturating_add(config.max_stream_buffer as u64)
            .min(buf_end.saturating_add(*available as u64));
        let mut stored_end = end.min(limit).max(start);
        // a segment that would leave too many holes is rejected entirely
        if self.holes_after_storing(start..stored_end) > config.max_holes_per_stream {
            stored_end = start;
        }
        // the bytes after the stored ones are rejected, they are all
        // missing (a segment that would leave too many holes lies in
        // missing bytes, as it adds a hole before stored bytes)
        stored.rejected = stored_end..end;

        // fill the holes in the buffer (the ones that overlap the bytes)
        let filled_end = stored_end.min(buf_end);
        let first = self.holes.partition_point(|hole| hole.end <= start);
        for hole in self.holes[first..]
            .iter()
            .take_while(|hole| hole.start < filled_end)
        {
            let from = hole.start.max(start);
            let to = hole.end.min(filled_end);
            if from < to {
                let (buf_from, buf_to) = (self.index(from), self.index(to));
                self.buf[buf_from..buf_to]
                    .copy_from_slice(&data[(from - start) as usize..(to - start) as usize]);
            }
        }

        // append the bytes after the end of the buffer (all missing so far)
        if buf_end < stored_end && start < stored_end {
            // drop the consumed bytes once they make up half of the buffer,
            // or before the buffer has to grow for the new bytes if that
            // frees a useful share of it (always dropping a few consumed
            // bytes would keep the buffer at its capacity and shift the live
            // bytes for every segment)
            let live = self.buf.len() - self.head;
            let grows = self.index(stored_end) > self.buf.capacity();
            if self.head >= live || (grows && self.head >= live / 8) {
                self.buf.drain(..self.head);
                self.head = 0;
            }
            // placeholders for missing bytes before the segment
            let from = start.max(buf_end);
            self.buf.resize(self.index(from), 0);
            self.buf
                .extend_from_slice(&data[(from - start) as usize..(stored_end - start) as usize]);
            self.received_end = stored_end;
            *available = available.saturating_sub((stored_end - buf_end) as usize);
        }
        // the sender sent the rejected bytes too
        self.extend_to(end);
        self.remove_from_holes(start..stored_end);
        stored
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
        self.shrink_if_sparse();
    }

    /// Gives back the room the buffer doesn't need once the consumed bytes
    /// make up half of it: drops them and keeps at most twice the capacity
    /// its bytes need, but at least `keep_capacity`. Moving the bytes costs
    /// at most as much as consuming them did.
    fn shrink_if_sparse(&mut self) {
        let live = self.buffered();
        let keep = live.saturating_mul(2).max(self.keep_capacity);
        if self.head >= live && self.buf.capacity() > keep {
            self.buf.drain(..self.head);
            self.head = 0;
            self.buf.shrink_to(keep);
        }
    }

    /// Offset after the last byte in `buf`.
    fn buf_end(&self) -> u64 {
        self.read_offset + self.buffered() as u64
    }

    /// Index in `buf` of the byte at `offset` (at or after `read_offset`).
    fn index(&self, offset: u64) -> usize {
        self.head + (offset - self.read_offset) as usize
    }

    /// Returns true if bytes of `data` (starting at offset `start`, at or
    /// after the read position) from `compare_from` on differ from the
    /// bytes received for the same offsets.
    fn differs_from_received(&self, start: u64, data: &[u8], compare_from: u64) -> bool {
        // nothing is received after the end of the buffer
        let compared_start = start.max(compare_from);
        let end = (start + data.len() as u64).min(self.buf_end());
        if compared_start >= end {
            return false;
        }
        // the received bytes lie before each hole or gap and before the end
        // of the buffer (an empty range at the end)
        let mut received_start = self.read_offset;
        let missing = self
            .missing_from(compared_start)
            .take_while(|range| range.start < end)
            .chain(core::iter::once(end..end));
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
        self.missing_from(0)
    }

    /// Ranges of missing bytes (holes and gaps) that end after `offset`, in
    /// order.
    fn missing_from(&self, offset: u64) -> impl Iterator<Item = Range<u64>> + '_ {
        let first_hole = self.holes.partition_point(|hole| hole.end <= offset);
        let first_gap = self.gaps.partition_point(|gap| gap.end <= offset);
        let mut holes = self.holes[first_hole..].iter().peekable();
        let mut gaps = self.gaps[first_gap..].iter().peekable();
        core::iter::from_fn(move || match (holes.peek(), gaps.peek()) {
            // the gap of a resync comes before a hole at its offset
            (Some(hole), Some(gap)) if gap.start <= hole.start => gaps.next(),
            (Some(_), _) => holes.next(),
            (None, _) => gaps.next(),
        })
        .cloned()
    }

    /// Removes the bytes in `range` from the holes.
    fn remove_from_holes(&mut self, range: Range<u64>) {
        // the parts of the holes before and after the range stay missing:
        // they take the place of the cut holes (without allocating)
        let (cut, before, after) = self.cut_holes(&range);
        let mut kept = cut.start;
        for part in [before, after] {
            if part.is_empty() {
                continue;
            }
            if kept < cut.end {
                self.holes[kept] = part;
            } else {
                self.holes.insert(kept, part);
            }
            kept += 1;
        }
        self.holes.drain(kept..cut.end.max(kept));
    }

    /// Number of holes before the furthest stored byte (the ones the hole
    /// limit counts) after storing the bytes in `range`.
    fn holes_after_storing(&self, range: Range<u64>) -> usize {
        // the missing bytes before bytes after the highest offset are a
        // hole, a new one unless they extend the hole at the end
        if range.start > self.highest_offset {
            return self.holes.len() + usize::from(false == self.ends_with_hole());
        }
        let (cut, before, after) = self.cut_holes(&range);
        let holes = self.holes.len() - cut.len()
            + usize::from(false == before.is_empty())
            + usize::from(false == after.is_empty());
        // a part of the hole at the end stays unless the bytes reach the
        // highest offset
        holes - usize::from(range.end < self.highest_offset && self.ends_with_hole())
    }

    /// Number of holes before the furthest stored byte, the ones the hole
    /// limit counts.
    fn counted_holes(&self) -> usize {
        self.holes.len() - usize::from(self.ends_with_hole())
    }

    /// Returns true if the missing bytes after the furthest stored byte
    /// (e.g. rejected ones, or ones that were ACKed but not captured) are a
    /// hole.
    fn ends_with_hole(&self) -> bool {
        self.holes
            .last()
            .is_some_and(|hole| hole.end == self.highest_offset)
    }

    /// Indices of the holes that overlap `range`, and the parts of them
    /// before and after the range (empty if there are none).
    fn cut_holes(&self, range: &Range<u64>) -> (Range<usize>, Range<u64>, Range<u64>) {
        let first = self.holes.partition_point(|hole| hole.end <= range.start);
        let last = self.holes.partition_point(|hole| hole.start < range.end);
        // an empty range overlaps none
        if first >= last || range.is_empty() {
            return (first..first, 0..0, 0..0);
        }
        let before = self.holes[first].start..range.start;
        let after = range.end..self.holes[last - 1].end;
        (first..last, before, after)
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
