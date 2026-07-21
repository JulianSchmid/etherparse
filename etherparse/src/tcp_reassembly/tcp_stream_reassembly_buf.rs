use crate::tcp_reassembly::*;
use std::vec::Vec;

/// Buffer to reconstruct the payload byte stream of a single direction of a
/// TCP connection (re-usable to minimize allocations).
///
/// # Absolute stream offsets & sequence number wrap-around
///
/// TCP sequence numbers are 32 bit values that wrap around at `2^32`. To make
/// the reconstruction robust against wrap-around all internal bookkeeping is
/// done in a monotonic 64 bit "absolute stream offset" space. An incoming
/// sequence number is mapped into this space relative to the current read
/// cursor using the "serial number arithmetic" rule of
/// [RFC 1982](https://www.rfc-editor.org/rfc/rfc1982) (a `2^31` window
/// distinguishes "ahead" from "behind"). As a consequence the wrap-around only
/// ever affects the single [`TcpStreamReassemblyBuf::base_sequence_number`]
/// value and never the stored data or ranges.
///
/// # Typical usage
///
/// * [`TcpStreamReassemblyBuf::add`] feeds the payload of a received segment.
/// * [`TcpStreamReassemblyBuf::contiguous`] returns the in-order bytes that are
///   available starting at the current read cursor.
/// * [`TcpStreamReassemblyBuf::consume`] advances the read cursor and frees the
///   processed bytes so the buffer memory can be re-used.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TcpStreamReassemblyBuf {
    /// Sequence number that is mapped to `base_offset`.
    ///
    /// `None` until the first segment (or SYN) established the base.
    base_seq: Option<u32>,

    /// Absolute stream offset of the first byte in `data` (the read cursor).
    base_offset: u64,

    /// Buffer holding the reconstructed bytes starting at `base_offset`.
    ///
    /// Not yet received gaps are present as zeroed bytes and are only exposed
    /// once they are part of the contiguous prefix (see [`Self::contiguous`]).
    data: Vec<u8>,

    /// Ranges (in absolute stream offsets) that have been filled with data.
    sections: Vec<TcpSegmentRange>,

    /// Absolute stream offset one past the last byte of the stream (set once a
    /// segment with the FIN flag was received).
    fin_offset: Option<u64>,

    /// Maximum number of bytes that may be buffered ahead of the read cursor.
    max_capacity: usize,
}

impl TcpStreamReassemblyBuf {
    /// Creates a new buffer re-using the given (cleared) buffers.
    pub fn new(
        mut data: Vec<u8>,
        mut sections: Vec<TcpSegmentRange>,
        max_capacity: usize,
    ) -> TcpStreamReassemblyBuf {
        data.clear();
        sections.clear();
        TcpStreamReassemblyBuf {
            base_seq: None,
            base_offset: 0,
            data,
            sections,
            fin_offset: None,
            max_capacity,
        }
    }

    /// Sequence number that is currently mapped to the read cursor (start of
    /// the still buffered data), or `None` if no data was added yet.
    #[inline]
    pub fn base_sequence_number(&self) -> Option<u32> {
        self.base_seq
    }

    /// Absolute stream offset of the read cursor (number of bytes that were
    /// already consumed since the base was established).
    #[inline]
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// Raw buffer (including not yet contiguous, zeroed gaps).
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Filled ranges (in absolute stream offsets).
    #[inline]
    pub fn sections(&self) -> &[TcpSegmentRange] {
        &self.sections
    }

    /// Absolute stream offset one past the last byte of the stream (set once a
    /// FIN was received).
    #[inline]
    pub fn fin_offset(&self) -> Option<u64> {
        self.fin_offset
    }

    /// Maximum number of bytes that may be buffered ahead of the read cursor.
    #[inline]
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Re-base the buffer to a new starting sequence number (e.g. after a new
    /// SYN / reconnect) and drop all previously buffered data.
    ///
    /// The underlying allocations are kept for re-use.
    pub fn reset(&mut self, base_seq: u32) {
        self.data.clear();
        self.sections.clear();
        self.base_seq = Some(base_seq);
        self.base_offset = 0;
        self.fin_offset = None;
    }

    /// Shift the whole buffer forward by `shift` bytes and re-anchor it to a
    /// new (lower) base sequence number.
    ///
    /// Only valid while nothing has been consumed yet (`base_offset == 0`).
    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
    fn rebase_backwards(
        &mut self,
        new_base_seq: u32,
        shift: u64,
    ) -> Result<(), TcpReassembleError> {
        use TcpReassembleError::*;

        let old_len = self.data.len();
        let Ok(shift_usize) = usize::try_from(shift) else {
            return Err(SegmentBeyondMaxWindow {
                end_offset: shift,
                max_capacity: self.max_capacity,
            });
        };
        let Some(new_len) = shift_usize.checked_add(old_len) else {
            return Err(SegmentBeyondMaxWindow {
                end_offset: shift,
                max_capacity: self.max_capacity,
            });
        };
        // the whole buffer sits ahead of the (still at 0) read cursor
        if new_len > self.max_capacity {
            return Err(SegmentBeyondMaxWindow {
                end_offset: new_len as u64,
                max_capacity: self.max_capacity,
            });
        }
        if self.data.capacity() < new_len && self.data.try_reserve(new_len - old_len).is_err() {
            return Err(AllocationFailure { len: new_len });
        }

        // move existing data forward and zero the newly exposed front
        self.data.resize(new_len, 0);
        self.data.copy_within(0..old_len, shift_usize);
        for b in &mut self.data[..shift_usize] {
            *b = 0;
        }

        // shift the recorded ranges & fin position
        for s in &mut self.sections {
            s.start += shift;
            s.end += shift;
        }
        if let Some(fin) = &mut self.fin_offset {
            *fin += shift;
        }

        self.base_seq = Some(new_base_seq);
        Ok(())
    }

    /// Maps a sequence number into the absolute stream offset space relative to
    /// the current read cursor.
    ///
    /// Uses RFC 1982 serial number arithmetic so wrap-arounds are handled
    /// transparently. The result can be negative (segment references data that
    /// was already consumed).
    fn seq_to_abs_offset(&self, base_seq: u32, seq: u32) -> i128 {
        let delta = seq.wrapping_sub(base_seq) as u64;
        let rel: i64 = if delta < 0x8000_0000 {
            delta as i64
        } else {
            (delta as i64) - 0x1_0000_0000
        };
        self.base_offset as i128 + rel as i128
    }

    /// Add the payload of a received TCP segment.
    ///
    /// * `seq` is the sequence number of the first payload byte.
    /// * `fin` records that this segment carried the FIN flag (marks the end of
    ///   the stream one byte past the payload).
    ///
    /// Retransmits, re-ordered segments and duplicated / overlapping payloads
    /// are handled silently. Only segments landing more than `max_capacity`
    /// bytes ahead of the read cursor or allocation failures are reported as
    /// errors.
    #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
    pub fn add(&mut self, seq: u32, payload: &[u8], fin: bool) -> Result<(), TcpReassembleError> {
        use TcpReassembleError::*;

        // establish the base on the first ever segment
        if self.base_seq.is_none() {
            self.base_seq = Some(seq);
        }
        let base_seq = self.base_seq.unwrap();

        let mut start_abs = self.seq_to_abs_offset(base_seq, seq);

        // If data arrives that starts before the front of the buffer while
        // nothing has been consumed yet (`base_offset == 0`), the base was
        // anchored too late (e.g. segments arriving highest-sequence-first at
        // the start of the capture). Re-anchor the buffer backwards so the
        // earlier data can be kept.
        if false == payload.is_empty() && self.base_offset == 0 && start_abs < 0 {
            let shift = (-start_abs) as u64;
            self.rebase_backwards(seq, shift)?;
            start_abs = 0;
        }

        let end_abs = start_abs + payload.len() as i128;

        // record the end of the stream if the FIN flag is set (FIN occupies the
        // sequence number right after the payload)
        if fin {
            let fin_pos = if end_abs < 0 { 0 } else { end_abs as u64 };
            self.fin_offset = Some(fin_pos);
        }

        // nothing to store for an empty payload (e.g. pure SYN/ACK/FIN segments)
        if payload.is_empty() {
            return Ok(());
        }

        // trim the part that lies before the read cursor (already consumed /
        // retransmitted data)
        let cursor = self.base_offset as i128;
        let (payload, start_abs) = if start_abs < cursor {
            let trim = (cursor - start_abs) as usize;
            if trim >= payload.len() {
                // fully before the cursor -> nothing to store
                return Ok(());
            }
            (&payload[trim..], cursor)
        } else {
            (payload, start_abs)
        };
        let end_abs = start_abs + payload.len() as i128;

        // enforce the maximum buffer window (measured from the read cursor)
        let end_offset = (end_abs - cursor) as u64;
        if end_offset > self.max_capacity as u64 {
            return Err(SegmentBeyondMaxWindow {
                end_offset,
                max_capacity: self.max_capacity,
            });
        }

        let data_start = (start_abs - self.base_offset as i128) as usize;
        let data_end = data_start + payload.len();

        // grow the buffer if required (gaps are zero filled)
        if self.data.len() < data_end {
            if self.data.capacity() < data_end
                && self.data.try_reserve(data_end - self.data.len()).is_err()
            {
                return Err(AllocationFailure { len: data_end });
            }
            self.data.resize(data_end, 0);
        }

        // write the payload
        self.data[data_start..data_end].copy_from_slice(payload);

        // merge the new range into the existing sections (dedup / overlap)
        let mut new_section = TcpSegmentRange {
            start: start_abs as u64,
            end: end_abs as u64,
        };
        self.sections.retain(|it| -> bool {
            if let Some(merged) = new_section.merge(*it) {
                new_section = merged;
                false
            } else {
                true
            }
        });
        self.sections.push(new_section);

        Ok(())
    }

    /// Length of the in-order data available starting at the read cursor.
    fn contiguous_len(&self) -> usize {
        self.sections
            .iter()
            .find(|s| s.start == self.base_offset)
            .map(|s| (s.end - self.base_offset) as usize)
            .unwrap_or(0)
    }

    /// Returns the in-order bytes that are available starting at the read
    /// cursor.
    ///
    /// Returns an empty slice if the byte at the read cursor has not been
    /// received yet (a gap at the front of the stream).
    #[inline]
    pub fn contiguous(&self) -> &[u8] {
        &self.data[..self.contiguous_len()]
    }

    /// Advance the read cursor by `len` bytes and free the consumed data for
    /// re-use.
    ///
    /// `len` is clamped to the currently available contiguous data so it is not
    /// possible to consume into a not yet received gap.
    pub fn consume(&mut self, len: usize) {
        let len = core::cmp::min(len, self.contiguous_len());
        if len == 0 {
            return;
        }
        self.data.drain(..len);
        self.base_offset += len as u64;
        self.base_seq = self.base_seq.map(|s| s.wrapping_add(len as u32));

        // drop / trim sections that are now before the read cursor
        let base_offset = self.base_offset;
        self.sections.retain_mut(|s| {
            if s.end <= base_offset {
                false
            } else {
                if s.start < base_offset {
                    s.start = base_offset;
                }
                true
            }
        });
    }

    /// Returns `true` once all bytes up to the FIN have been received and are
    /// available as contiguous data.
    pub fn is_fin_reached(&self) -> bool {
        match self.fin_offset {
            Some(fin) => self.base_offset + self.contiguous_len() as u64 >= fin,
            None => false,
        }
    }

    /// Consume the buffer and return the underlying buffers for re-use.
    #[inline]
    pub fn take_bufs(self) -> (Vec<u8>, Vec<TcpSegmentRange>) {
        (self.data, self.sections)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use std::{format, vec, vec::Vec};

    const MAX: usize = 1 << 20;

    fn new_buf() -> TcpStreamReassemblyBuf {
        TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), MAX)
    }

    /// Returns a u8 vec counting up from "start" (truncating to u8).
    fn sequence(start: usize, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in start..start + len {
            result.push((i & 0xff) as u8);
        }
        result
    }

    #[test]
    fn debug_clone_eq_hash() {
        let buf = new_buf();
        let _ = format!("{:?}", buf);
        assert_eq!(buf, buf.clone());

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            buf.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            buf.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn new_clears_bufs() {
        let buf = TcpStreamReassemblyBuf::new(
            vec![1, 2, 3],
            vec![TcpSegmentRange { start: 0, end: 3 }],
            4096,
        );
        assert_eq!(buf.base_sequence_number(), None);
        assert_eq!(buf.base_offset(), 0);
        assert!(buf.data().is_empty());
        assert!(buf.sections().is_empty());
        assert_eq!(buf.fin_offset(), None);
        assert_eq!(buf.max_capacity(), 4096);
    }

    #[test]
    fn in_order() {
        let mut buf = new_buf();
        buf.add(1000, &sequence(0, 4), false).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(1000));
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);

        buf.add(1004, &sequence(4, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);

        // consume the first 6 bytes
        buf.consume(6);
        assert_eq!(buf.base_offset(), 6);
        assert_eq!(buf.base_sequence_number(), Some(1006));
        assert_eq!(buf.contiguous(), &sequence(6, 2)[..]);

        buf.add(1008, &sequence(8, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(6, 6)[..]);
        buf.consume(6);
        assert_eq!(buf.contiguous(), &[]);
    }

    #[test]
    fn out_of_order_with_gap() {
        let mut buf = new_buf();
        // establish the base with the first segment
        buf.add(100, &sequence(0, 4), false).unwrap();
        // segment far ahead (gap between 104 and 200)
        buf.add(200, &sequence(100, 4), false).unwrap();
        // only the first part is contiguous
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        // fill the gap
        buf.add(104, &sequence(4, 96), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 104)[..]);
    }

    #[test]
    fn reverse_order() {
        let mut buf = new_buf();
        // base established from the first (highest) segment
        buf.add(108, &sequence(8, 4), false).unwrap();
        buf.add(104, &sequence(4, 4), false).unwrap();
        buf.add(100, &sequence(0, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 12)[..]);
    }

    #[test]
    fn duplicates_and_overlaps() {
        let mut buf = new_buf();
        buf.add(100, &sequence(0, 8), false).unwrap();
        // exact duplicate
        buf.add(100, &sequence(0, 8), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
        assert_eq!(buf.sections().len(), 1);

        // overlap at the back
        buf.add(104, &sequence(4, 8), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 12)[..]);
        assert_eq!(buf.sections().len(), 1);

        // fully contained
        buf.add(102, &sequence(2, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 12)[..]);
        assert_eq!(buf.sections().len(), 1);
    }

    #[test]
    fn retransmit_of_consumed_data() {
        let mut buf = new_buf();
        buf.add(100, &sequence(0, 8), false).unwrap();
        buf.consume(8);
        assert_eq!(buf.base_offset(), 8);
        // retransmit fully before the cursor -> ignored, no panic
        buf.add(100, &sequence(0, 8), false).unwrap();
        assert_eq!(buf.contiguous(), &[]);
        assert!(buf.sections().is_empty());

        // partial retransmit (4 before cursor, 4 new)
        buf.add(104, &sequence(4, 8), false).unwrap();
        assert_eq!(buf.base_offset(), 8);
        assert_eq!(buf.contiguous(), &sequence(8, 4)[..]);
    }

    #[test]
    fn beyond_max_window() {
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 16);
        buf.add(0, &sequence(0, 4), false).unwrap();
        // just inside the window (ends at 16)
        buf.add(12, &sequence(12, 4), false).unwrap();
        // one past the window (ends at 17)
        let err = buf.add(13, &sequence(13, 4), false).unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                end_offset: 17,
                max_capacity: 16
            }
        );
    }

    #[test]
    fn consume_clamped_to_contiguous() {
        let mut buf = new_buf();
        buf.add(0, &sequence(0, 4), false).unwrap();
        // gap: nothing at offset 4..8, data at 8
        buf.add(8, &sequence(8, 4), false).unwrap();
        // consuming more than contiguous only consumes the contiguous prefix
        buf.consume(100);
        assert_eq!(buf.base_offset(), 4);
        assert_eq!(buf.contiguous(), &[]);
        // fill the gap
        buf.add(4, &sequence(4, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(4, 8)[..]);
    }

    #[test]
    fn consume_into_gap_is_noop() {
        let mut buf = new_buf();
        buf.add(0, &sequence(0, 4), false).unwrap();
        buf.consume(4);
        // front is now a gap
        buf.add(8, &sequence(8, 4), false).unwrap();
        buf.consume(4);
        assert_eq!(buf.base_offset(), 4);
    }

    #[test]
    fn fin_handling() {
        let mut buf = new_buf();
        buf.add(100, &sequence(0, 4), false).unwrap();
        // FIN arrives but there is a gap in front
        buf.add(108, &sequence(8, 4), true).unwrap();
        assert_eq!(buf.fin_offset(), Some(12));
        assert_eq!(false, buf.is_fin_reached());
        // fill the gap
        buf.add(104, &sequence(4, 4), false).unwrap();
        assert!(buf.is_fin_reached());
        assert_eq!(buf.contiguous(), &sequence(0, 12)[..]);
    }

    #[test]
    fn fin_empty_payload() {
        let mut buf = new_buf();
        buf.add(100, &sequence(0, 4), false).unwrap();
        // pure FIN segment (no payload) at seq 104
        buf.add(104, &[], true).unwrap();
        assert_eq!(buf.fin_offset(), Some(4));
        assert!(buf.is_fin_reached());
    }

    #[test]
    fn reset_rebases() {
        let mut buf = new_buf();
        buf.add(100, &sequence(0, 8), false).unwrap();
        buf.reset(5000);
        assert_eq!(buf.base_sequence_number(), Some(5000));
        assert_eq!(buf.base_offset(), 0);
        assert!(buf.contiguous().is_empty());
        assert!(buf.sections().is_empty());
        assert_eq!(buf.fin_offset(), None);
        buf.add(5000, &sequence(0, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn wrap_around_add_and_consume() {
        // base sequence number close to the u32 wrap boundary
        let isn: u32 = 0xFFFF_FFF0;
        let mut buf = new_buf();
        // 8 bytes ending exactly at the wrap boundary
        buf.add(isn, &sequence(0, 8), false).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(isn));
        // next segment's seq wrapped around to a small number (0xFFFFFFF8 + 8 = 0x00000000)
        let seq_after_wrap = isn.wrapping_add(8); // == 0xFFFFFFF8
        buf.add(seq_after_wrap, &sequence(8, 8), false).unwrap();
        // seq that is numerically smaller than the base but actually ahead
        let seq_wrapped = isn.wrapping_add(16); // == 0x00000000
        buf.add(seq_wrapped, &sequence(16, 8), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 24)[..]);

        // consume across the wrap boundary
        buf.consume(20);
        assert_eq!(buf.base_offset(), 20);
        assert_eq!(buf.base_sequence_number(), Some(isn.wrapping_add(20)));
        assert_eq!(buf.contiguous(), &sequence(20, 4)[..]);
    }

    #[test]
    fn wrap_around_retransmit() {
        let isn: u32 = 0xFFFF_FFF8;
        let mut buf = new_buf();
        buf.add(isn, &sequence(0, 16), false).unwrap();
        buf.consume(16);
        // base_seq is now 0x00000008; a retransmit of the pre-wrap data must be
        // recognised as "behind" and ignored.
        buf.add(isn, &sequence(0, 16), false).unwrap();
        assert_eq!(buf.contiguous(), &[]);
        assert!(buf.sections().is_empty());
    }

    #[test]
    fn allocation_and_zero_fill() {
        let mut buf = new_buf();
        // create a gap; the gap bytes must be zero filled and safe to read once
        // filled
        buf.add(0, &[0xAA; 4], false).unwrap();
        buf.add(8, &[0xBB; 4], false).unwrap();
        // the gap (offset 4..8) is currently zeroed in the raw buffer
        assert_eq!(&buf.data()[4..8], &[0, 0, 0, 0]);
        buf.add(4, &[0xCC; 4], false).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0xAA; 4]);
        expected.extend_from_slice(&[0xCC; 4]);
        expected.extend_from_slice(&[0xBB; 4]);
        assert_eq!(buf.contiguous(), &expected[..]);
    }

    #[test]
    fn take_bufs_returns_allocations() {
        let mut buf = new_buf();
        buf.add(0, &sequence(0, 8), false).unwrap();
        let (data, sections) = buf.take_bufs();
        assert!(data.capacity() >= 8);
        // sections vec was used
        assert!(sections.capacity() >= 1);
    }

    #[test]
    fn rebase_backwards_bounds() {
        // a segment that would force a prepend beyond max_capacity is rejected
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 16);
        buf.add(1000, &sequence(0, 4), false).unwrap();
        // seq 980 is 20 bytes behind the anchor -> prepend of 20 > 16
        let err = buf.add(980, &sequence(0, 4), false).unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                end_offset: 24,
                max_capacity: 16
            }
        );
        // the original data is untouched
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn rebase_only_before_consume() {
        // after a consume, earlier data is a retransmit and must NOT re-anchor
        let mut buf = new_buf();
        buf.add(1000, &sequence(0, 4), false).unwrap();
        buf.consume(4);
        buf.add(996, &sequence(0, 4), false).unwrap();
        // ignored (before cursor), nothing buffered
        assert_eq!(buf.base_offset(), 4);
        assert_eq!(buf.contiguous(), &[]);
    }

    proptest! {
        /// Feed a reference byte stream split into random, re-ordered,
        /// duplicated and re-transmitted segments (with an ISN chosen anywhere
        /// in the u32 range, including near the wrap boundary) and assert the
        /// consumed bytes exactly reconstruct the reference stream.
        #[test]
        fn reassemble_random(
            reference in proptest::collection::vec(any::<u8>(), 0..600usize),
            isn in any::<u32>(),
            seed in any::<u64>(),
        ) {
            use std::vec::Vec;

            // simple deterministic xorshift RNG so no extra dependency is needed
            let mut state = seed | 1;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };

            // split the reference into contiguous segments
            let mut segments: Vec<(usize, usize)> = Vec::new(); // (offset, len)
            let mut pos = 0usize;
            while pos < reference.len() {
                let remaining = reference.len() - pos;
                let len = 1 + (next() as usize % remaining.min(40));
                segments.push((pos, len));
                pos += len;
            }

            // duplicate some segments and shuffle the send order
            let mut to_send = segments.clone();
            for seg in &segments {
                if next() & 1 == 0 {
                    to_send.push(*seg);
                }
            }
            for i in (1..to_send.len()).rev() {
                let j = next() as usize % (i + 1);
                to_send.swap(i, j);
            }

            let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 1 << 20);
            // model a known stream start (as if the ISN was learned from a SYN):
            // offset 0 of the reference maps to sequence number `isn`.
            buf.reset(isn);
            let mut collected: Vec<u8> = Vec::new();

            for (offset, len) in to_send {
                let seq = isn.wrapping_add(offset as u32);
                let is_last = offset + len == reference.len();
                buf.add(seq, &reference[offset..offset + len], is_last).unwrap();
                // occasionally drain the available contiguous data
                if next() & 3 == 0 {
                    let avail = buf.contiguous().len();
                    collected.extend_from_slice(buf.contiguous());
                    buf.consume(avail);
                }
            }

            // final drain
            collected.extend_from_slice(buf.contiguous());
            let avail = buf.contiguous().len();
            buf.consume(avail);

            prop_assert_eq!(&collected, &reference);
            if false == reference.is_empty() {
                prop_assert!(buf.is_fin_reached());
            }
        }
    }
}
