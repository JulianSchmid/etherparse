# 08: Resync after large sequence jumps

Parent: ../spec.md

**What to build:** A stream that jumps far beyond any plausible window without a SYN recovers:
- Out-of-window data records a candidate position.
- An ACK from the other direction within one window of the candidate triggers a resync. The stream continues behind a `Gap { len: None }`, and `resyncs` is incremented.
- `resync_after_segments = Some(n)` opts in to resyncing after n consecutive agreeing segments, for one-direction captures.
- `force_resync()` makes the next data segment the new anchor.

Rules: R1–R4, S2 (unmappable distances), ADR-0002.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [ ] Without confirmation the stream never resyncs; random out-of-window segments are only counted
- [ ] An ACK-confirmed resync delivers the following bytes exactly, after `Gap { len: None }`
- [ ] `resync_after_segments` has exact tests at n − 1 and n; the count resets when a segment doesn't fit
- [ ] `force_resync()` anchors the stream at the next segment
- [ ] Distances of 2^31 or more are counted as out-of-window, with exact tests at the boundary
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 04:**
- R1: out-of-window data returns early in `TcpStream::add_segment`, right after `status.out_of_window_segments += 1`. That is where the candidate is recorded.
- R2: implausible ACKs return early in `TcpStream::add_ack` (`ack > sent_end + window`). They have to be kept as resync evidence there. The window is the one the receiver advertised before the ACK's segment.

**2026-10-11 — carry-over from ticket 05:** `TcpRead::Gap { len: Option<u64> }` exists, but only `Some` is produced so far.
- Gaps are stored as `Range<u64>` in `TcpStream::gaps`. A resync gap takes no offsets (the stream continues right after the highest offset), so it needs a marker, e.g. an empty range plus a flag. `read_until`, `consume_gap()` and `gap_at_read_offset()` have to handle it.
- Decide what `gap_bytes` counts for a gap of unknown length (probably nothing).

**2026-10-11 — carry-over from ticket 07:**
- A resync before the first read of a mid-stream pickup: prepending afterwards would move the offsets under the resync's gap. A resync (R2, R4) should end prepending (`TcpStream::can_prepend`), or `prepend` has to move the resync gap too. The same goes for `force_resync()` before the first read.
- Bytes before offset 0 of a pickup that can't take them count as out-of-window (ticket 07, decision 5). Decide whether only S4's forward out-of-window data records a resync candidate (R1), not bytes before offset 0 or after the FIN.
- `pending_ack` is applied again after every packet. If R2 keeps implausible ACKs as evidence, a pending ACK must not count as new evidence each time.

**2026-10-11 — user decisions (asked before implementing):**
1. **Where an ACK-confirmed resync continues:** right after the candidate's bytes. They are not stored (S4) and are part of `Gap { len: None }`, so reading doesn't stall and no extra memory is needed. That one segment is lost. Rejected: continuing at the candidate's first byte (its bytes become a hole that stalls reading until it is overdue, then a second gap), and keeping a copy of the candidate's bytes (a copy of every out-of-window segment, plus one segment of memory per stream).
2. **An ACK before the data confirms it too:** the last ACK beyond the window is kept as evidence. Out-of-window data within one window of it resyncs at once, and that segment becomes the stream's new start, with its bytes stored. A resync, or the stream moving forward, clears the kept ACK.
3. **Forward jumps only:** only data after the window (S4) or at an unmappable distance (S2) becomes a candidate. A new ISN that maps behind the stream (half of all ISN changes) is not detected: bytes before offset 0 stay ignored on an observed start (counted on a pickup), and ACKs behind the seen ACK stay ignored. `force_resync()` recovers such streams. Known limit for the docs (ticket 16).

spec.md R1 and R2 are updated.

**2026-10-11 — user decisions after the review (asked before fixing):**
4. **Decision 1 corrected:** with the ACK after the data, not one segment but all out-of-window data before the first confirming ACK is lost, up to about one window (one round trip). The illustration of decision 1 showed only one segment. The user keeps the decision: these bytes are part of `Gap { len: None }`, and no copies are kept (rejected: copies of the agreeing out-of-window segments, up to one window per stream). A FIN in the candidate's segment, or a FIN without bytes right after it, ends the stream at the resync point, so the stream still finishes (the review found that the FIN was lost and its ACK left a 1-byte hole that never closed).
5. **The ACK that confirms a jump ACKs the bytes before it:** also when it maps before the resync point (it ACKs bytes that fell into the gap). Otherwise `read_acked()` stalls in front of the gap if no later ACK comes.

spec.md R2 is updated.
