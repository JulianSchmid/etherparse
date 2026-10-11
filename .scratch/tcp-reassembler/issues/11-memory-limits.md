# 11: Memory limits

Parent: ../spec.md

**What to build:** Memory use stays bounded:
- Bytes beyond `max_stream_buffer` are rejected and counted as `rejected_bytes`, but the segment's position still moves the implied ACK forward, so the stream doesn't stall.
- A segment that would exceed `max_holes_per_stream` is rejected entirely.
- The optional pool-wide `max_total_buffered` rejects in the same way.
- The optional `max_connections` rejects new connections with `TooManyConnections`. Tombstones count towards it.
- Data the user hasn't consumed is never thrown away automatically.

Rules: D4, P3 (tombstones count), Q1.

**Blocked by:** 02, 06

**Status:** ready-for-agent

- [ ] Per-stream buffer limit: rejected bytes are counted, a segment that only partly fits is tested, and the stream keeps moving
- [ ] Regression test (old branch): a flood of 1-byte holes keeps memory bounded, and segments that would create an extra hole are rejected
- [ ] `max_total_buffered` is enforced pool-wide
- [ ] `max_connections` rejects with `TooManyConnections`, and tombstones count
- [ ] Unconsumed data is never discarded by any limit
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 04:**
- ACK holes (K1) move the highest offset without allocating, but a later segment behind such a hole zero-fills the buffer up to it, up to `k × window` (about 2 GiB with window scale 14) ahead. D4's `max_stream_buffer` must bound that. A hole added by an ACK also counts towards `max_holes_per_stream`.
- The test "a segment far after the receiver's window doesn't move it" in `tcp_stream.rs` only shows "allocates nothing" implicitly. If ticket 11 or 12 adds a way to observe allocations, make it explicit.

**2026-10-11 — carry-over from ticket 05:**
- `discard_until()` and `discard_all()` move the read position, and `max_stream_buffer` counts from it, so discarding makes room in the buffer.
- Bytes that arrive in a gap at the read position, or after they were consumed or discarded, are not stored.
- Holes created by rejected bytes must stay holes that the user can give up.

**2026-10-11 — carry-over from the ticket-06 grilling (lazy gaps):** overdue holes are holes. They count towards `max_holes_per_stream`, and their placeholders towards `max_stream_buffer`, until the read position reaches them or the connection ends (ADR-0002 consequences). While a connection is open, gaps exist only at the read position.

**2026-10-11 — carry-over from ticket 06 (review finding):** while a stream has holes, `TcpStream::recent_acks` keeps one entry (16 bytes) per ACK-advancing packet, for up to `ack_reorder_tolerance` packets. `max_total_buffered` doesn't count these entries. With a large tolerance (the `reordered_streams` proptest uses `u32::MAX`), forged 1-byte ACK advances grow the queue with every packet. Decide whether to count or cap it.

**2026-10-11 — carry-over from ticket 07:**
- `TcpStream::prepend` zero-fills up to k windows (2 × the 4 MiB fallback window on a pickup, user decision on ticket 07) at the front of the buffer, and a pickup takes earlier bytes until its first read. D4's `max_stream_buffer` has to cover bytes put in front too.
- `prepend` assumes that byte 0 of a pickup was received: there is no gap at the read position, and the new hole doesn't touch a hole at the old offset 0. If D4 rejects the bytes of the segment that starts a pickup, both break. Either shift the gaps and merge the holes, or don't start a pickup with rejected bytes.
- While a pickup can still prepend, it keeps the K4(b) ACK history also without holes (memory per pickup until its first read).
