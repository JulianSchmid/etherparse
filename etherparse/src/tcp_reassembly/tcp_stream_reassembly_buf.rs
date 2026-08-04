use crate::tcp_reassembly::*;
use alloc::vec::Vec;

/// Number of consumed bytes that have to accumulate at the front of
/// [`TcpStreamReassemblyBuf::data`] before a compaction (copy of the
/// remaining data to the front) is triggered.
const COMPACT_THRESHOLD: usize = 4096;

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
/// * [`TcpStreamReassemblyBuf::add_segment`] feeds a received segment
///   including the interpretation of its `SYN` flag (use
///   [`TcpStreamReassemblyBuf::add`] to feed just the payload).
/// * [`TcpStreamReassemblyBuf::add_ack`] feeds the acknowledgment numbers
///   observed in the **reverse** direction of the connection.
/// * [`TcpStreamReassemblyBuf::contiguous`] returns the in-order bytes that are
///   available starting at the current read cursor.
/// * [`TcpStreamReassemblyBuf::consume`] advances the read cursor and frees the
///   processed bytes so the buffer memory can be re-used.
///
/// # Only acknowledged data is handed out
///
/// By default ([`TcpAckPolicy::Required`]) only data that the receiver
/// acknowledged is returned by [`TcpStreamReassemblyBuf::contiguous`], so
/// segments that never reached the receiver do not end up in the
/// reconstructed stream. This requires feeding the acknowledgment numbers of
/// the reverse direction via [`TcpStreamReassemblyBuf::add_ack`].
///
/// As a capture usually ends before the last data is acknowledged (and may
/// not contain the reverse direction at all), the trailing unacknowledged
/// bytes are still reachable via
/// [`TcpStreamReassemblyBuf::contiguous_unacked`] &
/// [`TcpStreamReassemblyBuf::consume_unacked`]. Set
/// [`TcpAckPolicy::Ignore`] via
/// [`TcpStreamReassemblyBuf::with_ack_policy`] to disable the behavior
/// entirely.
///
/// # Streams without an observed connection setup
///
/// If the start of a stream is unknown (no SYN was observed, e.g. when a
/// capture starts in the middle of a connection) the buffer anchors itself on
/// the first added segment. Such streams are still reconstructed, but their
/// prefix is missing. [`TcpStreamReassemblyBuf::syn_observed`] allows
/// differentiating these streams from streams with a known start (established
/// via [`TcpStreamReassemblyBuf::add_segment`] or
/// [`TcpStreamReassemblyBuf::reset`]).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TcpStreamReassemblyBuf {
    /// Sequence number that is mapped to `base_offset`.
    ///
    /// `None` until the first segment (or SYN) established the base.
    base_seq: Option<u32>,

    /// Absolute stream offset of the read cursor (start of the still
    /// buffered data).
    base_offset: u64,

    /// Number of already consumed bytes at the start of `data` (kept around
    /// to make `consume` cheap, freed in batches via compaction).
    head: usize,

    /// Buffer holding the reconstructed bytes (`data[head]` is the byte at
    /// `base_offset`).
    ///
    /// Not yet received gaps are present as zeroed bytes and are only exposed
    /// once they are part of the contiguous prefix (see [`Self::contiguous`]).
    data: Vec<u8>,

    /// Ranges (in absolute stream offsets) that have been filled with data.
    ///
    /// Sorted by start offset, the ranges are non-overlapping and
    /// non-adjacent (they get merged).
    sections: Vec<TcpStreamRange>,

    /// Absolute stream offset one past the last byte of the stream (set once a
    /// segment with the FIN flag was received).
    fin_offset: Option<u64>,

    /// Absolute stream offset up to which the receiver acknowledged the data
    /// (exclusive).
    ///
    /// Monotonically increasing, only meaningful if `ack_observed` is true.
    ack_offset: u64,

    /// True once an acknowledgment for this direction was observed (via
    /// [`TcpStreamReassemblyBuf::add_ack`]).
    ack_observed: bool,

    /// Decides if data has to be acknowledged before it is handed out by
    /// [`TcpStreamReassemblyBuf::contiguous`].
    ack_policy: TcpAckPolicy,

    /// True if the stream start is known (established via [`Self::reset`],
    /// e.g. from an observed SYN), false if the buffer had to anchor itself
    /// on the first added segment.
    syn_observed: bool,

    /// Maximum number of bytes that may be buffered ahead of the read cursor.
    max_capacity: usize,

    /// Maximum number of separate (non-contiguous) data sections that may
    /// be tracked at the same time.
    max_sections: usize,
}

impl TcpStreamReassemblyBuf {
    /// Creates a new buffer re-using the given (cleared) buffers.
    ///
    /// The maximum number of separately tracked data sections is set to
    /// [`DEFAULT_MAX_TCP_STREAM_SECTIONS`] (adjustable via
    /// [`TcpStreamReassemblyBuf::with_max_sections`]).
    pub fn new(
        mut data: Vec<u8>,
        mut sections: Vec<TcpStreamRange>,
        max_capacity: usize,
    ) -> TcpStreamReassemblyBuf {
        data.clear();
        sections.clear();
        TcpStreamReassemblyBuf {
            base_seq: None,
            base_offset: 0,
            head: 0,
            data,
            sections,
            fin_offset: None,
            ack_offset: 0,
            ack_observed: false,
            ack_policy: TcpAckPolicy::default(),
            syn_observed: false,
            max_capacity,
            max_sections: DEFAULT_MAX_TCP_STREAM_SECTIONS,
        }
    }

    /// Sets the maximum number of separate (non-contiguous) data sections
    /// that may be tracked at the same time (see
    /// [`TcpReassembleError::TooManySections`]).
    pub fn with_max_sections(mut self, max_sections: usize) -> TcpStreamReassemblyBuf {
        self.max_sections = max_sections;
        self
    }

    /// Sets if data has to be acknowledged by the receiver before
    /// [`TcpStreamReassemblyBuf::contiguous`] hands it out (defaults to
    /// [`TcpAckPolicy::Required`]).
    pub fn with_ack_policy(mut self, ack_policy: TcpAckPolicy) -> TcpStreamReassemblyBuf {
        self.ack_policy = ack_policy;
        self
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

    /// Raw buffer starting at the read cursor.
    ///
    /// **This is not the reconstructed stream.** Byte ranges that were not
    /// received yet are present as zeroes, so reading this without consulting
    /// [`TcpStreamReassemblyBuf::sections`] silently mixes fabricated zero
    /// bytes into the data. Use [`TcpStreamReassemblyBuf::contiguous`] to get
    /// the reconstructed stream.
    ///
    /// It is exposed to allow reading data that was received out of order:
    /// the byte at absolute stream offset `o` of a received section is at
    /// `raw_buffer()[o - base_offset()]`.
    #[inline]
    pub fn raw_buffer(&self) -> &[u8] {
        &self.data[self.head..]
    }

    /// Received ranges (in absolute stream offsets), sorted by start offset,
    /// non-overlapping & non-adjacent.
    #[inline]
    pub fn sections(&self) -> &[TcpStreamRange] {
        &self.sections
    }

    /// Absolute stream offset one past the last byte of the stream (set once a
    /// FIN was received).
    #[inline]
    pub fn fin_offset(&self) -> Option<u64> {
        self.fin_offset
    }

    /// True if the stream start is known (established by a SYN via
    /// [`TcpStreamReassemblyBuf::add_segment`] or by
    /// [`TcpStreamReassemblyBuf::reset`]).
    ///
    /// False if the buffer anchored itself on the first added segment (e.g.
    /// the capture started in the middle of a connection). The stream is
    /// still reconstructed in that case, but an unknown prefix is missing.
    ///
    /// Note that data *in front* of a known stream start is not part of the
    /// stream and gets discarded, while a buffer that anchored itself is
    /// re-anchored backwards if earlier data arrives (see
    /// [`TcpStreamReassemblyBuf::add`]).
    #[inline]
    pub fn syn_observed(&self) -> bool {
        self.syn_observed
    }

    /// Absolute stream offset up to which the receiver acknowledged the data
    /// (exclusive), or `None` if no acknowledgment was observed yet.
    #[inline]
    pub fn ack_offset(&self) -> Option<u64> {
        if self.ack_observed {
            Some(self.ack_offset)
        } else {
            None
        }
    }

    /// True once an acknowledgment for this stream direction was observed.
    ///
    /// Under [`TcpAckPolicy::Required`] a stream that never sees an
    /// acknowledgment never hands out data via
    /// [`TcpStreamReassemblyBuf::contiguous`]. This flag allows detecting
    /// that case (e.g. a capture only containing one direction, or a stream
    /// whose two directions did not get matched up).
    #[inline]
    pub fn ack_observed(&self) -> bool {
        self.ack_observed
    }

    /// Policy deciding if data has to be acknowledged before it is handed out.
    #[inline]
    pub fn ack_policy(&self) -> TcpAckPolicy {
        self.ack_policy
    }

    /// Maximum number of bytes that may be buffered ahead of the read cursor.
    #[inline]
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Maximum number of separate (non-contiguous) data sections that may be
    /// tracked at the same time.
    #[inline]
    pub fn max_sections(&self) -> usize {
        self.max_sections
    }

    /// Re-base the buffer to a new known starting sequence number (e.g. from
    /// the SYN of a new connection) and drop all previously buffered data.
    ///
    /// This also marks the stream start as known (see
    /// [`TcpStreamReassemblyBuf::syn_observed`]). The underlying allocations
    /// are kept for re-use.
    pub fn reset(&mut self, base_seq: u32) {
        self.data.clear();
        self.sections.clear();
        self.base_seq = Some(base_seq);
        self.base_offset = 0;
        self.head = 0;
        self.fin_offset = None;
        self.ack_offset = 0;
        self.ack_observed = false;
        self.syn_observed = true;
    }

    /// Record an acknowledgment number observed in the **reverse** direction
    /// of the connection.
    ///
    /// Acknowledgments travel in the opposite direction of the data they
    /// acknowledge, so the value has to be taken from the segments flowing
    /// back to the sender of this stream (it is expressed in this stream's
    /// sequence number space). Only segments with the `ACK` flag set carry a
    /// valid acknowledgment number.
    ///
    /// Under [`TcpAckPolicy::Required`] this is what releases data for
    /// [`TcpStreamReassemblyBuf::contiguous`].
    ///
    /// Acknowledgments that are re-ordered/stale (referencing data before the
    /// read cursor) or that reference data far beyond anything that was
    /// received are ignored.
    pub fn add_ack(&mut self, ack_seq: u32) {
        // even an unusable ack proves that the reverse direction is present
        self.ack_observed = true;

        let Some(base_seq) = self.base_seq else {
            // without an established base the ack cannot be mapped
            return;
        };

        let abs = self.seq_to_abs_offset(base_seq, ack_seq);
        if abs <= self.base_offset as i128 {
            // stale (also catches acks that the serial number arithmetic
            // mapped far into the past)
            return;
        }
        // Guard against nonsense acks (e.g. a wrapped ack that got mapped far
        // into the future) releasing data that was never acknowledged.
        if abs > self.plausible_offset_limit() as i128 {
            return;
        }

        self.ack_offset = core::cmp::max(self.ack_offset, abs as u64);
    }

    /// Absolute stream offset one past the last received byte.
    #[inline]
    fn highest_received_offset(&self) -> u64 {
        self.sections
            .last()
            .map(|s| s.end)
            .unwrap_or(self.base_offset)
    }

    /// Highest absolute stream offset that a received segment may plausibly
    /// reference.
    ///
    /// Referencing data ahead of what was received is normal if the capture
    /// missed segments, hence the generous limit.
    #[inline]
    fn plausible_offset_limit(&self) -> u64 {
        self.highest_received_offset()
            .saturating_add(self.max_capacity as u64)
    }

    /// Returns `true` if `seq` references a plausible position of this stream:
    /// at or after the read cursor and not far beyond the received data.
    ///
    /// Allows rejecting blindly injected segments, e.g. a `RST` carrying an
    /// out of window sequence number. Returns `true` if no segment was
    /// received for this stream yet (nothing to judge against).
    pub fn is_seq_in_window(&self, seq: u32) -> bool {
        let Some(base_seq) = self.base_seq else {
            return true;
        };
        let abs = self.seq_to_abs_offset(base_seq, seq);
        abs >= self.base_offset as i128 && abs <= self.plausible_offset_limit() as i128
    }

    /// Re-anchors the buffer to a now known stream start (from a late SYN)
    /// while keeping the already buffered data.
    ///
    /// `start_abs` is the absolute stream offset `base` maps to and must be
    /// negative (the stream started before the current anchor).
    fn anchor_stream_start(
        &mut self,
        base: u32,
        start_abs: i128,
    ) -> Result<(), TcpReassembleError> {
        use TcpReassembleError::*;
        debug_assert!(start_abs < 0);

        // re-anchoring shifts the buffered data, which is only possible while
        // nothing was consumed yet. If data was already handed out the missing
        // prefix cannot be re-introduced, so the SYN is ignored and the stream
        // keeps being flagged as "start not observed".
        if self.base_offset > 0 {
            return Ok(());
        }

        let buffered_len = self.data.len();
        let Ok(shift) = usize::try_from(-start_abs) else {
            return Err(SegmentBeyondMaxWindow {
                required_capacity: u64::try_from(-start_abs)
                    .unwrap_or(u64::MAX)
                    .saturating_add(buffered_len as u64),
                max_capacity: self.max_capacity,
            });
        };
        let required = match shift.checked_add(buffered_len) {
            Some(required) if required <= self.max_capacity => required,
            _ => {
                return Err(SegmentBeyondMaxWindow {
                    required_capacity: (shift as u64).saturating_add(buffered_len as u64),
                    max_capacity: self.max_capacity,
                });
            }
        };
        if self.data.capacity() < required
            && self.data.try_reserve(required - buffered_len).is_err()
        {
            return Err(AllocationFailure { len: required });
        }

        // -- all checks done, commit --
        self.shift_forward(shift);
        self.base_seq = Some(base);
        self.syn_observed = true;
        Ok(())
    }

    /// Add a received TCP segment, interpreting the `SYN` flag.
    ///
    /// This is the counterpart of [`Self::add`] for callers that want the
    /// connection setup handled for them:
    ///
    /// * A `SYN` establishes the start of the stream (the `SYN` flag consumes
    ///   one sequence number, so the payload starts at `seq + 1`). Duplicated
    ///   and re-transmitted `SYN`s as well as a `SYN` arriving after the first
    ///   data segments are recognized and keep the already buffered data.
    /// * A `SYN` carrying a different initial sequence number belongs to a new
    ///   connection re-using the same addresses & ports. It is reported via
    ///   [`TcpSegmentOutcome::NewConnection`] and leaves the buffer untouched.
    /// * `SYN`s carrying payload (TCP Fast Open) and/or a `FIN` are handled.
    ///
    /// See [`Self::add`] for the error conditions (the buffer is left
    /// unmodified in case of an error).
    pub fn add_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
        syn: bool,
        fin: bool,
    ) -> Result<TcpSegmentOutcome, TcpReassembleError> {
        if false == syn {
            self.add(seq, payload, fin)?;
            return Ok(TcpSegmentOutcome::Continued);
        }

        // the SYN flag consumes one sequence number, the payload starts after it
        let base = seq.wrapping_add(1);

        match self.base_seq {
            None => {
                self.base_seq = Some(base);
                self.syn_observed = true;
            }
            Some(base_seq) => {
                // Position of the stream start indicated by the SYN within the
                // already reconstructed stream (offset 0 is where the buffer is
                // anchored).
                let start_abs = self.seq_to_abs_offset(base_seq, base);

                // If the stream start is already known only an exact match is a
                // duplicated/re-transmitted SYN. Initial sequence numbers are
                // random, so *any* other value (in either direction) belongs to
                // a new connection.
                //
                // If the start is not known yet the buffer anchored itself on
                // the first seen segment, so a SYN at or before that anchor is
                // the (re-ordered) start of the very same stream.
                let same_stream = if self.syn_observed {
                    start_abs == 0
                } else {
                    start_abs <= 0
                };
                if false == same_stream {
                    return Ok(TcpSegmentOutcome::NewConnection);
                }

                if start_abs < 0 {
                    self.anchor_stream_start(base, start_abs)?;
                } else {
                    self.syn_observed = true;
                }
            }
        }

        // TCP Fast Open: a SYN may already carry payload (and a FIN)
        if fin || false == payload.is_empty() {
            self.add(base, payload, fin)?;
        }
        Ok(TcpSegmentOutcome::Continued)
    }

    /// Maps a sequence number into the absolute stream offset space (using
    /// RFC 1982 serial number arithmetic relative to the read cursor), or
    /// `None` if no base was established yet.
    ///
    /// A result of `0` references the start of the stream, negative values
    /// reference positions before the established stream start (e.g. useful
    /// to check if the sequence number of a late SYN matches the already
    /// established stream start).
    pub fn seq_stream_offset(&self, seq: u32) -> Option<i128> {
        self.base_seq.map(|base| self.seq_to_abs_offset(base, seq))
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
    /// are handled silently. Payload bytes that are not part of the stream are
    /// dropped:
    ///
    /// * bytes before the read cursor (already consumed data),
    /// * bytes behind a received FIN (the end of the stream),
    /// * bytes before a *known* stream start (see [`Self::syn_observed`]).
    ///
    /// If the stream start is not known yet and the segment starts before the
    /// buffer anchor, the buffer is re-anchored backwards so the earlier data
    /// can be kept (only possible while nothing was consumed yet).
    ///
    /// Errors are only returned for segments landing more than `max_capacity`
    /// bytes ahead of the read cursor, segments that would require tracking
    /// more than `max_sections` separate data sections and allocation
    /// failures. In case of an error the buffer is left unmodified.
    pub fn add(&mut self, seq: u32, payload: &[u8], fin: bool) -> Result<(), TcpReassembleError> {
        use TcpReassembleError::*;

        // base used for the offset mapping (anchor on the first segment if
        // no base was established, only committed to `self` on success)
        let base_seq = self.base_seq.unwrap_or(seq);

        let start_abs = self.seq_to_abs_offset(base_seq, seq);
        let end_abs = start_abs + payload.len() as i128;
        let cursor = self.base_offset as i128;
        let buffered_len = self.data.len() - self.head;

        // If data arrives that starts before the front of the buffer while
        // nothing has been consumed yet (`base_offset == 0`), the base was
        // anchored too late (e.g. segments arriving highest-sequence-first at
        // the start of the capture). Plan a backwards re-anchoring of the
        // buffer (shift of the buffered data) so the earlier data can be kept.
        //
        // This is only done if the start of the stream is *not* known. Once a
        // SYN established it (see `syn_observed`) data in front of it is not
        // part of this stream (e.g. a retransmit of a previous connection
        // re-using the same ports) and gets trimmed like already consumed
        // data instead.
        //
        // Note that `base_offset == 0` implies `head == 0` (nothing consumed).
        let rebase_shift: usize = if false == payload.is_empty()
            && false == self.syn_observed
            && self.base_offset == 0
            && start_abs < 0
        {
            let Ok(shift) = usize::try_from(-start_abs) else {
                return Err(SegmentBeyondMaxWindow {
                    required_capacity: u64::try_from(-start_abs)
                        .unwrap_or(u64::MAX)
                        .saturating_add(buffered_len as u64),
                    max_capacity: self.max_capacity,
                });
            };
            // the whole shifted buffer sits ahead of the (still at 0)
            // read cursor
            let rebased_len = shift.checked_add(buffered_len);
            match rebased_len {
                Some(rebased_len) if rebased_len <= self.max_capacity => shift,
                _ => {
                    return Err(SegmentBeyondMaxWindow {
                        required_capacity: (shift as u64).saturating_add(buffered_len as u64),
                        max_capacity: self.max_capacity,
                    });
                }
            }
        } else {
            0
        };

        // absolute payload position after the potential re-anchoring (the
        // re-anchoring moves the payload start to offset 0)
        let (eff_start, eff_end) = if rebase_shift > 0 {
            (0i128, payload.len() as i128)
        } else {
            (start_abs, end_abs)
        };

        // the end of the stream indicated by the FIN flag (the FIN occupies
        // the sequence number right after the payload). FINs before the read
        // cursor are stale (e.g. wrapped far-future sequence numbers) and
        // ignored, as is a second FIN at a different position (first wins).
        let planned_fin: Option<u64> = if fin && self.fin_offset.is_none() && eff_end >= cursor {
            Some(eff_end as u64)
        } else {
            None
        };

        // end of the stream after this segment (in the potentially re-anchored
        // coordinates). `planned_fin` is only set while `self.fin_offset` is
        // `None`, so at most one of the two is `Some`.
        let effective_fin: Option<u64> = match (planned_fin, self.fin_offset) {
            (Some(fin_offset), _) => Some(fin_offset),
            (None, Some(fin_offset)) => Some(fin_offset + rebase_shift as u64),
            (None, None) => None,
        };

        // trim the part that lies before the read cursor (already consumed /
        // retransmitted data) & behind the end of the stream (data behind the
        // FIN is not part of the stream) and enforce the maximum buffer window
        let write: Option<(&[u8], i128)> = if payload.is_empty() {
            None
        } else if cursor - eff_start >= payload.len() as i128 {
            // fully before the cursor -> nothing to store
            None
        } else {
            let (p, s) = if eff_start < cursor {
                (&payload[(cursor - eff_start) as usize..], cursor)
            } else {
                (payload, eff_start)
            };
            // `s >= cursor >= 0`, so the cast is lossless
            let p = match effective_fin {
                Some(fin_offset) => {
                    let max_len = fin_offset.saturating_sub(s as u64) as usize;
                    if p.len() > max_len {
                        &p[..max_len]
                    } else {
                        p
                    }
                }
                None => p,
            };
            if p.is_empty() {
                None
            } else {
                let required_capacity = (s + p.len() as i128 - cursor) as u64;
                if required_capacity > self.max_capacity as u64 {
                    return Err(SegmentBeyondMaxWindow {
                        required_capacity,
                        max_capacity: self.max_capacity,
                    });
                }
                Some((p, s))
            }
        };

        // check the section limit (in pre-re-anchoring coordinates, as the
        // recorded sections are not shifted yet)
        if let Some((p, s)) = write {
            let (cur_start, cur_end) = if rebase_shift > 0 {
                // in the re-anchoring case the payload starts at the (still
                // negative) `start_abs` and `s` is the post-shift position
                (start_abs, start_abs + p.len() as i128)
            } else {
                (s, s + p.len() as i128)
            };
            let lo = self
                .sections
                .partition_point(|sec| (sec.end as i128) < cur_start);
            let hi = self
                .sections
                .partition_point(|sec| (sec.start as i128) <= cur_end);
            // `lo == hi` means the payload connects to no existing section
            if lo == hi && self.sections.len() >= self.max_sections {
                return Err(TooManySections {
                    max_sections: self.max_sections,
                });
            }
        }

        // pre-allocate the required space (last fallible step)
        if let Some((p, s)) = write {
            let data_end: usize = if rebase_shift > 0 {
                // head == 0 in the re-anchoring case
                core::cmp::max(rebase_shift + buffered_len, p.len())
            } else {
                // saturates only for absurd `max_capacity` values, in which
                // case the `try_reserve` below fails & reports the error
                self.head
                    .saturating_add((s + p.len() as i128 - cursor) as usize)
            };
            if self.data.len() < data_end
                && self.data.capacity() < data_end
                && self.data.try_reserve(data_end - self.data.len()).is_err()
            {
                return Err(AllocationFailure { len: data_end });
            }
        }

        // -- all checks done, commit (no errors past this point) --

        self.base_seq = Some(base_seq);

        if rebase_shift > 0 {
            self.shift_forward(rebase_shift);
            self.base_seq = Some(seq);
        }

        if let Some(fin_offset) = planned_fin {
            self.fin_offset = Some(fin_offset);
        }

        if let Some((p, s)) = write {
            // grow the buffer if required (gaps are zero filled)
            let data_start = self.head + (s - cursor) as usize;
            let data_end = data_start + p.len();
            if self.data.len() < data_end {
                self.data.resize(data_end, 0);
            }

            // Only write the bytes that were not received before ("first
            // writer wins"). Overlapping segments carrying differing content
            // are a known way to de-synchronize a reassembly from the actual
            // receiver, so they are resolved deterministically instead of
            // depending on when the caller happened to call `consume`.
            let start = s as u64;
            let end = start + p.len() as u64;
            let mut pos = start;
            let lo = self.sections.partition_point(|sec| sec.end <= start);
            for idx in lo..self.sections.len() {
                let sec = self.sections[idx];
                if sec.start >= end {
                    break;
                }
                if sec.start > pos {
                    // gap in front of an already received section
                    let from = (pos - start) as usize;
                    let to = (sec.start - start) as usize;
                    self.data[data_start + from..data_start + to]
                        .copy_from_slice(&p[from..to]);
                }
                pos = core::cmp::max(pos, sec.end);
                if pos >= end {
                    break;
                }
            }
            if pos < end {
                let from = (pos - start) as usize;
                self.data[data_start + from..data_end].copy_from_slice(&p[from..]);
            }

            self.insert_section(TcpStreamRange { start, end });
        }

        Ok(())
    }

    /// Moves the buffered data `shift` bytes forward (making room for earlier
    /// data at the front) and shifts every recorded offset accordingly.
    ///
    /// Only valid while nothing was consumed yet (`base_offset == 0`, which
    /// implies `head == 0`). The caller has to make sure the required capacity
    /// was reserved beforehand.
    fn shift_forward(&mut self, shift: usize) {
        debug_assert_eq!(0, self.base_offset);
        debug_assert_eq!(0, self.head);

        // move the existing data forward & zero the newly exposed front
        let old_len = self.data.len();
        self.data.resize(old_len + shift, 0);
        self.data.copy_within(0..old_len, shift);
        for b in &mut self.data[..shift] {
            *b = 0;
        }

        for sec in &mut self.sections {
            sec.start += shift as u64;
            sec.end += shift as u64;
        }
        if let Some(fin_offset) = &mut self.fin_offset {
            *fin_offset += shift as u64;
        }
        // the acknowledged data is now `shift` bytes further into the stream
        // (the newly exposed prefix sits in front of it, so it was
        // acknowledged as well). Only meaningful once an ack was observed.
        if self.ack_observed {
            self.ack_offset += shift as u64;
        }
    }

    /// Insert a filled range into the sorted section list (merging it with
    /// overlapping or directly adjacent sections).
    fn insert_section(&mut self, mut range: TcpStreamRange) {
        // sections connected to the new range (sections are sorted by start
        // & disjoint, so they are also sorted by end)
        let lo = self.sections.partition_point(|s| s.end < range.start);
        let hi = self.sections.partition_point(|s| s.start <= range.end);
        if lo < hi {
            range.start = core::cmp::min(range.start, self.sections[lo].start);
            range.end = core::cmp::max(range.end, self.sections[hi - 1].end);
            self.sections[lo] = range;
            self.sections.drain(lo + 1..hi);
        } else {
            self.sections.insert(lo, range);
        }
    }

    /// Moves the still buffered data to the front of `data` (freeing the
    /// memory of the already consumed prefix for re-use).
    fn compact(&mut self) {
        if self.head > 0 {
            let len = self.data.len();
            self.data.copy_within(self.head..len, 0);
            self.data.truncate(len - self.head);
            self.head = 0;
        }
    }

    /// Length of the in-order data received at the read cursor (ignoring the
    /// [`TcpAckPolicy`]).
    fn in_order_len(&self) -> usize {
        let len = match self.sections.first() {
            Some(s) if s.start == self.base_offset => (s.end - self.base_offset) as usize,
            _ => 0,
        };
        // never hand out data behind the end of the stream (a FIN can be
        // received after data behind it was already buffered)
        match self.fin_offset {
            Some(fin_offset) => {
                core::cmp::min(len, fin_offset.saturating_sub(self.base_offset) as usize)
            }
            None => len,
        }
    }

    /// Length of the in-order data available at the read cursor after applying
    /// the [`TcpAckPolicy`].
    fn contiguous_len(&self) -> usize {
        match self.ack_policy {
            TcpAckPolicy::Ignore => self.in_order_len(),
            TcpAckPolicy::Required => core::cmp::min(
                self.in_order_len(),
                self.ack_offset.saturating_sub(self.base_offset) as usize,
            ),
        }
    }

    /// Returns the in-order bytes that are available starting at the read
    /// cursor.
    ///
    /// Returns an empty slice if the byte at the read cursor has not been
    /// received yet (a gap at the front of the stream, see
    /// [`TcpStreamReassemblyBuf::skip_gap`]) or, under the default
    /// [`TcpAckPolicy::Required`], if the receiver did not acknowledge it yet
    /// (see [`TcpStreamReassemblyBuf::add_ack`] &
    /// [`TcpStreamReassemblyBuf::contiguous_unacked`]).
    #[inline]
    pub fn contiguous(&self) -> &[u8] {
        &self.data[self.head..self.head + self.contiguous_len()]
    }

    /// Returns the in-order bytes at the read cursor **ignoring** the
    /// [`TcpAckPolicy`].
    ///
    /// The end of a capture usually cuts off the acknowledgments of the last
    /// received data, so under [`TcpAckPolicy::Required`] a trailing part of
    /// each stream stays unacknowledged. This is the escape hatch to still
    /// get at it (together with
    /// [`TcpStreamReassemblyBuf::consume_unacked`]), e.g. when draining all
    /// streams at the end of a capture or for captures that contain no
    /// acknowledgments at all (see
    /// [`TcpStreamReassemblyBuf::ack_observed`]).
    #[inline]
    pub fn contiguous_unacked(&self) -> &[u8] {
        &self.data[self.head..self.head + self.in_order_len()]
    }

    /// Advance the read cursor by `len` bytes and free the consumed data for
    /// re-use.
    ///
    /// `len` is clamped to the data currently returned by
    /// [`TcpStreamReassemblyBuf::contiguous`], so it is not possible to
    /// consume into a not yet received gap or past the acknowledged data.
    pub fn consume(&mut self, len: usize) {
        self.consume_clamped(core::cmp::min(len, self.contiguous_len()));
    }

    /// Advance the read cursor by `len` bytes **ignoring** the
    /// [`TcpAckPolicy`] (clamped to
    /// [`TcpStreamReassemblyBuf::contiguous_unacked`]).
    pub fn consume_unacked(&mut self, len: usize) {
        self.consume_clamped(core::cmp::min(len, self.in_order_len()));
    }

    /// Hands the available in-order data to `f` and consumes the number of
    /// bytes it reports as processed.
    ///
    /// Convenience for the "read [`TcpStreamReassemblyBuf::contiguous`], then
    /// [`TcpStreamReassemblyBuf::consume`] what was processed" cycle, which
    /// cannot be written as a single expression because the data is borrowed
    /// from the buffer. Returning less than `bytes.len()` keeps the remainder
    /// buffered, which is what a parser that can only handle complete
    /// messages wants:
    ///
    /// ```
    /// # use etherparse::tcp_reassembly::*;
    /// # let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 4096)
    /// #     .with_ack_policy(TcpAckPolicy::Ignore);
    /// # buf.add(1000, b"ab\ncd", false).unwrap();
    /// // only consume up to the last complete line
    /// let consumed = buf.drain(|bytes| match bytes.iter().rposition(|b| *b == b'\n') {
    ///     Some(end) => {
    ///         // ... process &bytes[..end + 1] ...
    ///         end + 1
    ///     }
    ///     None => 0,
    /// });
    /// assert_eq!(consumed, 3);
    /// ```
    ///
    /// Returns the number of consumed bytes (clamped to what was available).
    pub fn drain<F: FnOnce(&[u8]) -> usize>(&mut self, f: F) -> usize {
        let len = core::cmp::min(f(self.contiguous()), self.contiguous_len());
        self.consume_clamped(len);
        len
    }

    /// Like [`TcpStreamReassemblyBuf::drain`] but **ignoring** the
    /// [`TcpAckPolicy`] (operates on
    /// [`TcpStreamReassemblyBuf::contiguous_unacked`]).
    pub fn drain_unacked<F: FnOnce(&[u8]) -> usize>(&mut self, f: F) -> usize {
        let len = core::cmp::min(f(self.contiguous_unacked()), self.in_order_len());
        self.consume_clamped(len);
        len
    }

    /// Advance the read cursor by an already clamped `len`.
    fn consume_clamped(&mut self, len: usize) {
        if len == 0 {
            return;
        }
        self.head += len;
        self.base_offset += len as u64;
        self.base_seq = self.base_seq.map(|s| s.wrapping_add(len as u32));

        // `len` was clamped to the contiguous prefix, so only the first
        // section is affected
        if self.sections[0].end == self.base_offset {
            self.sections.remove(0);
        } else {
            self.sections[0].start = self.base_offset;
        }

        // free the consumed prefix once it dominates the buffer
        if self.head == self.data.len() {
            self.data.clear();
            self.head = 0;
        } else if self.head >= COMPACT_THRESHOLD && self.head >= self.data.len() - self.head {
            self.compact();
        }
    }

    /// Skip a gap at the read cursor by advancing it to the start of the next
    /// received data section & free the skipped bytes.
    ///
    /// Segments that are lost and never re-transmitted (e.g. dropped by the
    /// capture) would otherwise stall the stream forever: the missing bytes
    /// never arrive, so [`Self::contiguous`] stays empty while the following
    /// data keeps accumulating until `max_capacity` is reached and every
    /// further segment is rejected with
    /// [`TcpReassembleError::SegmentBeyondMaxWindow`]. Skipping the gap gives
    /// up on the missing bytes and lets the reconstruction continue.
    ///
    /// Returns the number of skipped (permanently lost) bytes. Returns `0` if
    /// there is no gap at the read cursor, either because in-order data is
    /// available (check [`Self::contiguous`] first) or because nothing is
    /// buffered at all.
    pub fn skip_gap(&mut self) -> u64 {
        let Some(first) = self.sections.first() else {
            return 0;
        };
        if first.start <= self.base_offset {
            return 0;
        }

        let skipped = first.start - self.base_offset;
        // the buffer covers all data up to the last section, so the skipped
        // range is guaranteed to be present in `data`
        self.head += skipped as usize;
        self.base_offset = first.start;
        // truncating cast is the intended "mod 2^32" mapping back into the
        // 32 bit sequence number space
        self.base_seq = self.base_seq.map(|s| s.wrapping_add(skipped as u32));

        // free the skipped prefix once it dominates the buffer
        if self.head == self.data.len() {
            self.data.clear();
            self.head = 0;
        } else if self.head >= COMPACT_THRESHOLD && self.head >= self.data.len() - self.head {
            self.compact();
        }

        skipped
    }

    /// Returns `true` once all bytes up to the FIN have been received and are
    /// available as contiguous data.
    ///
    /// This is about *reception* and ignores the [`TcpAckPolicy`]: under
    /// [`TcpAckPolicy::Required`] the last bytes of the stream may be
    /// complete here while [`TcpStreamReassemblyBuf::contiguous`] still holds
    /// them back because their acknowledgment was not captured.
    pub fn is_fin_reached(&self) -> bool {
        match self.fin_offset {
            Some(fin) => self.base_offset + self.in_order_len() as u64 >= fin,
            None => false,
        }
    }

    /// Consume the buffer and return the underlying buffers for re-use.
    #[inline]
    pub fn take_bufs(self) -> (Vec<u8>, Vec<TcpStreamRange>) {
        (self.data, self.sections)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use std::{format, vec, vec::Vec};

    const MAX: usize = 1 << 20;

    /// Buffer with the given capacity that hands out data without requiring
    /// acknowledgments (the tests below target the reassembly itself, the ack
    /// gating has its own tests).
    fn new_buf_capacity(max_capacity: usize) -> TcpStreamReassemblyBuf {
        TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), max_capacity)
            .with_ack_policy(TcpAckPolicy::Ignore)
    }

    fn new_buf() -> TcpStreamReassemblyBuf {
        new_buf_capacity(MAX)
    }

    /// Returns a u8 vec counting up from "start" (truncating to u8).
    fn sequence(start: usize, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in start..start + len {
            result.push((i & 0xff) as u8);
        }
        result
    }

    /// Checks the section invariants (sorted, non-overlapping, non-adjacent).
    fn assert_section_invariants(buf: &TcpStreamReassemblyBuf) {
        for w in buf.sections().windows(2) {
            assert!(w[0].end < w[1].start);
        }
        for s in buf.sections() {
            assert!(s.start < s.end);
        }
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
            vec![TcpStreamRange { start: 0, end: 3 }],
            4096,
        );
        assert_eq!(buf.base_sequence_number(), None);
        assert_eq!(buf.base_offset(), 0);
        assert!(buf.raw_buffer().is_empty());
        assert!(buf.sections().is_empty());
        assert_eq!(buf.fin_offset(), None);
        assert_eq!(false, buf.syn_observed());
        assert_eq!(false, buf.ack_observed());
        assert_eq!(buf.ack_offset(), None);
        assert_eq!(buf.ack_policy(), TcpAckPolicy::Required);
        assert_eq!(buf.max_capacity(), 4096);
        assert_eq!(buf.max_sections(), DEFAULT_MAX_TCP_STREAM_SECTIONS);
        let buf = buf.with_max_sections(3);
        assert_eq!(buf.max_sections(), 3);
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
        let mut buf = new_buf_capacity(16);
        buf.add(0, &sequence(0, 4), false).unwrap();
        // just inside the window (ends at 16)
        buf.add(12, &sequence(12, 4), false).unwrap();
        // one past the window (ends at 17)
        let err = buf.add(13, &sequence(13, 4), false).unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 17,
                max_capacity: 16
            }
        );
    }

    #[test]
    fn error_leaves_state_unchanged() {
        let mut buf = new_buf_capacity(16);
        buf.add(0, &sequence(0, 4), false).unwrap();
        // segment (with FIN) beyond the window -> error & no state change
        let err = buf.add(20, &sequence(20, 8), true).unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 28,
                max_capacity: 16
            }
        );
        assert_eq!(buf.fin_offset(), None);
        assert_eq!(buf.sections().len(), 1);
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert_eq!(buf.base_sequence_number(), Some(0));
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
    fn stale_fin_is_ignored() {
        // FIN behind the read cursor (e.g. from a wrapped far-future
        // sequence number that serial arithmetic interprets as "behind")
        let mut buf = new_buf();
        buf.add(1000, &sequence(0, 8), false).unwrap();
        buf.consume(8);
        buf.add(900, &[], true).unwrap();
        assert_eq!(buf.fin_offset(), None);
        assert_eq!(false, buf.is_fin_reached());

        // a FIN exactly at the read cursor is still valid (retransmit of
        // the FIN after everything was consumed)
        buf.add(1008, &[], true).unwrap();
        assert_eq!(buf.fin_offset(), Some(8));
        assert!(buf.is_fin_reached());
    }

    #[test]
    fn first_fin_wins() {
        let mut buf = new_buf();
        buf.add(100, &sequence(0, 4), true).unwrap();
        assert_eq!(buf.fin_offset(), Some(4));
        // a second FIN at a different position does not overwrite the first
        buf.add(100, &sequence(0, 8), true).unwrap();
        assert_eq!(buf.fin_offset(), Some(4));
    }

    #[test]
    fn syn_observed_flag() {
        // anchored on the first segment -> stream start unknown
        let mut buf = new_buf();
        assert_eq!(false, buf.syn_observed());
        buf.add(1000, &sequence(0, 4), false).unwrap();
        assert_eq!(false, buf.syn_observed());

        // re-based to a known start -> stream start known
        buf.reset(2000);
        assert!(buf.syn_observed());

        // late SYN matching the anchor marks the start as known without
        // dropping the buffered data
        let mut buf = new_buf();
        buf.add(1000, &sequence(0, 4), false).unwrap();
        assert_eq!(
            buf.add_segment(999, &[], true, false).unwrap(),
            TcpSegmentOutcome::Continued
        );
        assert!(buf.syn_observed());
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn seq_stream_offset() {
        let mut buf = new_buf();
        assert_eq!(buf.seq_stream_offset(123), None);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();
        buf.consume(8);
        assert_eq!(buf.seq_stream_offset(1000), Some(0));
        assert_eq!(buf.seq_stream_offset(1008), Some(8));
        assert_eq!(buf.seq_stream_offset(996), Some(-4));
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
        assert_eq!(&buf.raw_buffer()[4..8], &[0, 0, 0, 0]);
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
        let mut buf = new_buf_capacity(16);
        buf.add(1000, &sequence(0, 4), false).unwrap();
        // seq 980 is 20 bytes behind the anchor -> prepend of 20 + 4 buffered > 16
        let err = buf.add(980, &sequence(0, 4), false).unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 24,
                max_capacity: 16
            }
        );
        // the original data is untouched
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert_eq!(buf.base_sequence_number(), Some(1000));
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

    #[test]
    fn rebase_with_fin_and_overlap() {
        let mut buf = new_buf();
        // anchor at seq 1000 & record a FIN at relative offset 8
        buf.add(1000, &sequence(10, 4), false).unwrap();
        buf.add(1004, &sequence(14, 4), true).unwrap();
        assert_eq!(buf.fin_offset(), Some(8));
        // earlier data re-anchors the buffer; the recorded fin must shift
        buf.add(990, &sequence(0, 10), false).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(990));
        assert_eq!(buf.fin_offset(), Some(18));
        assert_eq!(buf.contiguous(), &sequence(0, 18)[..]);
        assert!(buf.is_fin_reached());
        assert_section_invariants(&buf);
    }

    #[test]
    fn too_many_sections() {
        let mut buf =
            new_buf_capacity(1 << 16).with_max_sections(2);
        buf.add(0, &sequence(0, 1), false).unwrap();
        buf.add(10, &sequence(10, 1), false).unwrap();
        assert_eq!(buf.sections().len(), 2);
        // a third separate section is rejected ...
        let err = buf.add(20, &sequence(20, 1), false).unwrap_err();
        assert_eq!(err, TcpReassembleError::TooManySections { max_sections: 2 });
        // ... while extending / merging existing sections still works
        buf.add(1, &sequence(1, 1), false).unwrap();
        buf.add(2, &sequence(2, 8), false).unwrap();
        assert_eq!(buf.sections().len(), 1);
        assert_eq!(buf.contiguous(), &sequence(0, 11)[..]);
        assert_section_invariants(&buf);
    }

    #[test]
    fn consume_compaction() {
        let mut buf = new_buf();
        let payload = sequence(0, 3 * COMPACT_THRESHOLD);
        buf.add(0, &payload, false).unwrap();

        // small consumes below the compaction threshold
        buf.consume(100);
        assert_eq!(buf.contiguous(), &payload[100..]);

        // consume enough that the consumed prefix dominates the buffer
        buf.consume(2 * COMPACT_THRESHOLD);
        let consumed = 100 + 2 * COMPACT_THRESHOLD;
        assert_eq!(buf.contiguous(), &payload[consumed..]);
        assert_eq!(buf.raw_buffer().len(), payload.len() - consumed);

        // adding & consuming afterwards still works
        let extra = sequence(payload.len(), 32);
        buf.add(payload.len() as u32, &extra, false).unwrap();
        buf.consume(payload.len() - consumed);
        assert_eq!(buf.contiguous(), &extra[..]);
        buf.consume(32);
        assert_eq!(buf.contiguous(), &[]);
    }

    #[test]
    fn rebase_ignores_known_stream_start() {
        // if the stream start is known (SYN observed) data before it is not
        // part of the stream and must not re-anchor the buffer
        let mut buf = new_buf();
        buf.reset(1000);
        buf.add(1000, &sequence(0, 4), false).unwrap();

        buf.add(996, &sequence(100, 4), false).unwrap();

        assert_eq!(buf.base_sequence_number(), Some(1000));
        assert_eq!(buf.base_offset(), 0);
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert_section_invariants(&buf);
    }

    #[test]
    fn data_past_fin_is_ignored() {
        // the FIN marks the end of the stream, bytes behind it are not part
        // of it and must not be handed out
        let mut buf = new_buf();
        buf.reset(1000);
        buf.add(1000, &sequence(0, 4), true).unwrap();
        assert_eq!(buf.fin_offset(), Some(4));

        buf.add(1004, &sequence(100, 8), false).unwrap();

        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert!(buf.is_fin_reached());
        assert_section_invariants(&buf);
    }

    #[test]
    fn overlap_keeps_first_received_bytes() {
        // overlapping segments with differing content must resolve
        // deterministically (first writer wins) instead of depending on when
        // the caller happened to call `consume`
        let mut buf = new_buf();
        buf.add(1000, b"AAAA", false).unwrap();

        // full overlap with different content
        buf.add(1000, b"BBBB", false).unwrap();
        assert_eq!(buf.contiguous(), b"AAAA");

        // partial overlap: only the not yet received bytes are taken
        buf.add(1002, b"CCCC", false).unwrap();
        assert_eq!(buf.contiguous(), b"AAAACC");
        assert_section_invariants(&buf);
    }

    #[test]
    fn drain_consumes_what_was_processed() {
        let mut buf = new_buf();
        buf.add(1000, &sequence(0, 8), false).unwrap();

        // consuming only a part keeps the rest buffered
        let consumed = buf.drain(|bytes| {
            assert_eq!(bytes, &sequence(0, 8)[..]);
            3
        });
        assert_eq!(consumed, 3);
        assert_eq!(buf.base_offset(), 3);
        assert_eq!(buf.contiguous(), &sequence(3, 5)[..]);

        // consuming nothing is fine
        assert_eq!(buf.drain(|_| 0), 0);
        assert_eq!(buf.base_offset(), 3);

        // over-reporting is clamped to what was available
        assert_eq!(buf.drain(|_| 1000), 5);
        assert_eq!(buf.base_offset(), 8);
        assert!(buf.contiguous().is_empty());
    }

    #[test]
    fn drain_respects_the_ack_policy() {
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), MAX);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();

        // nothing acknowledged -> `drain` sees nothing
        assert_eq!(buf.drain(|bytes| bytes.len()), 0);
        assert_eq!(buf.base_offset(), 0);

        // ... while `drain_unacked` sees everything
        assert_eq!(buf.drain_unacked(|bytes| bytes.len()), 8);
        assert_eq!(buf.base_offset(), 8);
    }

    #[test]
    fn raw_buffer_exposes_out_of_order_data() {
        let mut buf = new_buf();
        buf.add(1000, &[0xAA; 4], false).unwrap();
        // out of order segment behind a gap
        buf.add(1008, &[0xBB; 4], false).unwrap();

        // the gap is zero filled in the raw buffer & not part of `contiguous`
        assert_eq!(buf.contiguous(), &[0xAA; 4]);
        assert_eq!(&buf.raw_buffer()[4..8], &[0, 0, 0, 0]);

        // the received section can be located via `sections` & `base_offset`
        let section = buf.sections()[1];
        assert_eq!((section.start, section.end), (8, 12));
        let base = buf.base_offset();
        assert_eq!(
            &buf.raw_buffer()[(section.start - base) as usize..(section.end - base) as usize],
            &[0xBB; 4]
        );
    }

    #[test]
    fn ack_gating_is_the_default() {
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), MAX);
        assert_eq!(buf.ack_policy(), TcpAckPolicy::Required);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();

        // nothing acknowledged yet -> nothing handed out
        assert_eq!(false, buf.ack_observed());
        assert_eq!(buf.ack_offset(), None);
        assert_eq!(buf.contiguous(), &[]);
        // ... while the data itself is available via the escape hatch
        assert_eq!(buf.contiguous_unacked(), &sequence(0, 8)[..]);

        // the receiver acknowledges the first 4 bytes
        buf.add_ack(1004);
        assert!(buf.ack_observed());
        assert_eq!(buf.ack_offset(), Some(4));
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);

        // consume is clamped to the acknowledged data
        buf.consume(8);
        assert_eq!(buf.base_offset(), 4);
        assert_eq!(buf.contiguous(), &[]);
        assert_eq!(buf.contiguous_unacked(), &sequence(4, 4)[..]);

        // acknowledging the rest releases it
        buf.add_ack(1008);
        assert_eq!(buf.ack_offset(), Some(8));
        assert_eq!(buf.contiguous(), &sequence(4, 4)[..]);
    }

    #[test]
    fn ack_unacked_escape_hatch() {
        // e.g. at the end of a capture: the last data is never acknowledged
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), MAX);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), true).unwrap();

        // the FIN is "reached" even though nothing was acknowledged
        assert!(buf.is_fin_reached());
        assert_eq!(buf.contiguous(), &[]);

        assert_eq!(buf.contiguous_unacked(), &sequence(0, 8)[..]);
        buf.consume_unacked(8);
        assert_eq!(buf.base_offset(), 8);
        assert!(buf.contiguous_unacked().is_empty());
    }

    #[test]
    fn ack_policy_ignore() {
        let mut buf = new_buf();
        assert_eq!(buf.ack_policy(), TcpAckPolicy::Ignore);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();
        assert_eq!(false, buf.ack_observed());
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
    }

    #[test]
    fn ack_stale_and_nonsense_are_ignored() {
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 64);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();
        buf.add_ack(1008);
        assert_eq!(buf.ack_offset(), Some(8));

        // a re-ordered / older ack does not move the offset backwards
        buf.add_ack(1004);
        assert_eq!(buf.ack_offset(), Some(8));

        // an ack far beyond anything that was received is ignored
        buf.add_ack(1000u32.wrapping_add(10_000));
        assert_eq!(buf.ack_offset(), Some(8));

        // an ack that the serial number arithmetic maps far into the past
        buf.add_ack(1000u32.wrapping_sub(1_000_000));
        assert_eq!(buf.ack_offset(), Some(8));

        // an ack without an established base only records the observation
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 64);
        buf.add_ack(1234);
        assert!(buf.ack_observed());
        assert_eq!(buf.ack_offset(), Some(0));
    }

    #[test]
    fn ack_offset_shifts_on_reanchor() {
        // a backwards re-anchor has to move the ack offset with the data
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), MAX);
        buf.add(1000, &sequence(10, 4), false).unwrap();
        buf.add_ack(1004);
        assert_eq!(buf.ack_offset(), Some(4));
        assert_eq!(buf.contiguous(), &sequence(10, 4)[..]);

        // earlier data re-anchors the buffer by 10 bytes, the acknowledged
        // data moves with it (the prefix is in front of the ack, so it is
        // acknowledged as well)
        buf.add(990, &sequence(0, 10), false).unwrap();
        assert_eq!(buf.ack_offset(), Some(14));
        assert_eq!(buf.contiguous(), &sequence(0, 14)[..]);
    }

    #[test]
    fn ack_state_cleared_by_reset() {
        let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), MAX);
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();
        buf.add_ack(1008);
        assert_eq!(buf.ack_offset(), Some(8));

        buf.reset(5000);
        assert_eq!(false, buf.ack_observed());
        assert_eq!(buf.ack_offset(), None);
        buf.add(5000, &sequence(0, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &[]);
        buf.add_ack(5004);
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn overlap_spanning_multiple_sections() {
        let mut buf = new_buf();
        // three separate sections with gaps in between
        buf.add(1000, b"AA", false).unwrap();
        buf.add(1004, b"BB", false).unwrap();
        buf.add(1008, b"CC", false).unwrap();
        assert_eq!(buf.sections().len(), 3);

        // a big segment overlapping all of them with differing content: the
        // already received bytes are kept, only the gaps get filled
        buf.add(1000, b"xxxxxxxxxxxx", false).unwrap();
        assert_eq!(buf.contiguous(), b"AAxxBBxxCCxx");
        assert_eq!(buf.sections().len(), 1);
        assert_section_invariants(&buf);
    }

    #[test]
    fn skip_gap_recovers_from_permanently_lost_segment() {
        let mut buf = new_buf();
        buf.reset(1000);
        buf.add(1000, &sequence(0, 8), false).unwrap();
        buf.consume(8);

        // the segment at 1008..1016 is lost & never re-transmitted
        buf.add(1016, &sequence(16, 8), false).unwrap();
        assert_eq!(buf.contiguous(), &[]);

        // skipping the hole lets the stream continue
        assert_eq!(buf.skip_gap(), 8);
        assert_eq!(buf.base_offset(), 16);
        assert_eq!(buf.base_sequence_number(), Some(1016));
        assert_eq!(buf.contiguous(), &sequence(16, 8)[..]);
        assert_section_invariants(&buf);

        // no gap at the read cursor -> nothing to skip
        assert_eq!(buf.skip_gap(), 0);
        buf.consume(8);
        // nothing buffered at all -> nothing to skip
        assert_eq!(buf.skip_gap(), 0);
        assert_eq!(buf.base_offset(), 24);
    }

    #[test]
    fn skip_gap_frees_the_max_window() {
        // a permanent gap eventually fills up the whole window
        let mut buf = new_buf_capacity(16);
        buf.add(1000, &sequence(0, 4), false).unwrap();
        buf.consume(4);

        // gap at 1004..1008, followed by data filling the window
        buf.add(1008, &sequence(8, 12), false).unwrap();
        assert_eq!(buf.contiguous(), &[]);
        assert!(buf.add(1020, &sequence(20, 4), false).is_err());

        // skipping the gap moves the window forward again
        assert_eq!(buf.skip_gap(), 4);
        buf.add(1020, &sequence(20, 4), false).unwrap();
        assert_eq!(buf.contiguous(), &sequence(8, 16)[..]);
        assert_section_invariants(&buf);
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

            let mut next = xorshift(seed);
            let to_send = split_and_shuffle(&reference, &mut next, true);

            let mut buf = new_buf_capacity(1 << 20);
            // model a known stream start (as if the ISN was learned from a SYN):
            // offset 0 of the reference maps to sequence number `isn`.
            buf.reset(isn);
            let mut collected: Vec<u8> = Vec::new();

            for (offset, len) in to_send {
                let seq = isn.wrapping_add(offset as u32);
                let is_last = offset + len == reference.len();
                buf.add(seq, &reference[offset..offset + len], is_last).unwrap();

                // section invariants: sorted, non-overlapping, non-adjacent
                for w in buf.sections().windows(2) {
                    prop_assert!(w[0].end < w[1].start);
                }

                // occasionally drain a random part of the contiguous data
                if next() & 3 == 0 {
                    let avail = buf.contiguous().len();
                    let take = if avail == 0 { 0 } else { next() as usize % (avail + 1) };
                    collected.extend_from_slice(&buf.contiguous()[..take]);
                    buf.consume(take);
                }
            }

            // final drain
            collected.extend_from_slice(buf.contiguous());
            let avail = buf.contiguous().len();
            buf.consume(avail);

            prop_assert_eq!(&collected, &reference);
            prop_assert!(buf.syn_observed());
            if false == reference.is_empty() {
                prop_assert!(buf.is_fin_reached());
            }
        }

        /// Same as `reassemble_random`, but without a known stream start: the
        /// buffer has to anchor itself on whichever segment arrives first and
        /// re-anchor backwards for every earlier one.
        ///
        /// Nothing is consumed while the segments arrive, as consuming would
        /// (correctly) drop the data in front of the read cursor.
        #[test]
        fn reassemble_random_mid_stream_anchor(
            reference in proptest::collection::vec(any::<u8>(), 1..600usize),
            isn in any::<u32>(),
            seed in any::<u64>(),
        ) {
            let mut next = xorshift(seed);
            let to_send = split_and_shuffle(&reference, &mut next, true);

            let mut buf = new_buf_capacity(1 << 20);
            for (offset, len) in to_send {
                let seq = isn.wrapping_add(offset as u32);
                let is_last = offset + len == reference.len();
                buf.add(seq, &reference[offset..offset + len], is_last).unwrap();

                for w in buf.sections().windows(2) {
                    prop_assert!(w[0].end < w[1].start);
                }
            }

            // the stream start was never announced, but the re-anchoring kept
            // every byte
            prop_assert_eq!(false, buf.syn_observed());
            prop_assert_eq!(buf.contiguous(), &reference[..]);
            prop_assert!(buf.is_fin_reached());
        }

        /// Feeds acknowledgments interleaved with the segments and checks that
        /// nothing beyond the acknowledged offset is ever handed out.
        #[test]
        fn reassemble_random_with_acks(
            reference in proptest::collection::vec(any::<u8>(), 1..600usize),
            isn in any::<u32>(),
            seed in any::<u64>(),
        ) {
            let mut next = xorshift(seed);
            let to_send = split_and_shuffle(&reference, &mut next, true);

            let mut buf = TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 1 << 20);
            buf.reset(isn);
            let mut collected: Vec<u8> = Vec::new();

            for (offset, len) in to_send {
                let seq = isn.wrapping_add(offset as u32);
                let is_last = offset + len == reference.len();
                buf.add(seq, &reference[offset..offset + len], is_last).unwrap();

                // acknowledge a random position of the stream
                if next() & 1 == 0 {
                    let acked = next() as usize % (reference.len() + 1);
                    buf.add_ack(isn.wrapping_add(acked as u32));
                }

                // never hand out more than what was acknowledged
                match buf.ack_offset() {
                    Some(ack_offset) => prop_assert!(
                        buf.base_offset() + buf.contiguous().len() as u64 <= ack_offset
                    ),
                    None => prop_assert!(buf.contiguous().is_empty()),
                }

                if next() & 3 == 0 {
                    let avail = buf.contiguous().len();
                    let take = if avail == 0 { 0 } else { next() as usize % (avail + 1) };
                    collected.extend_from_slice(&buf.contiguous()[..take]);
                    buf.consume(take);
                }
            }

            // acknowledging everything releases the rest
            buf.add_ack(isn.wrapping_add(reference.len() as u32));
            collected.extend_from_slice(buf.contiguous());
            let avail = buf.contiguous().len();
            buf.consume(avail);

            prop_assert_eq!(&collected, &reference);
            prop_assert!(buf.is_fin_reached());
        }

        /// Re-transmits carrying *different* content must never change bytes
        /// that were already received ("first writer wins").
        #[test]
        fn corrupted_retransmits_do_not_change_received_data(
            reference in proptest::collection::vec(any::<u8>(), 1..600usize),
            isn in any::<u32>(),
            seed in any::<u64>(),
        ) {
            let mut next = xorshift(seed);
            let segments = split_and_shuffle(&reference, &mut next, false);

            let mut buf = new_buf_capacity(1 << 20);
            buf.reset(isn);

            // the genuine data first (shuffled, but no duplicates) ...
            for (offset, len) in &segments {
                let seq = isn.wrapping_add(*offset as u32);
                buf.add(seq, &reference[*offset..*offset + *len], false).unwrap();
            }

            // ... then re-transmits of the same ranges with corrupted content
            for (offset, len) in &segments {
                let corrupted: Vec<u8> = reference[*offset..*offset + *len]
                    .iter()
                    .map(|b| !*b)
                    .collect();
                let seq = isn.wrapping_add(*offset as u32);
                buf.add(seq, &corrupted, false).unwrap();
            }

            prop_assert_eq!(buf.contiguous(), &reference[..]);
        }
    }

    /// Simple deterministic xorshift RNG so no extra dependency is needed.
    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed | 1;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        }
    }

    /// Splits `reference` into contiguous `(offset, len)` segments and
    /// shuffles the send order (optionally duplicating some of them).
    fn split_and_shuffle(
        reference: &[u8],
        next: &mut impl FnMut() -> u64,
        duplicate: bool,
    ) -> Vec<(usize, usize)> {
        let mut segments: Vec<(usize, usize)> = Vec::new();
        let mut pos = 0usize;
        while pos < reference.len() {
            let remaining = reference.len() - pos;
            let len = 1 + (next() as usize % remaining.min(40));
            segments.push((pos, len));
            pos += len;
        }

        let mut to_send = segments.clone();
        if duplicate {
            for seg in &segments {
                if next() & 1 == 0 {
                    to_send.push(*seg);
                }
            }
        }
        for i in (1..to_send.len()).rev() {
            let j = next() as usize % (i + 1);
            to_send.swap(i, j);
        }
        to_send
    }
}
