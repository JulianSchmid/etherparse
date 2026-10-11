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
