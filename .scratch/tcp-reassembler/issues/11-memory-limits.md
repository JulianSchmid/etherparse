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

- [x] Per-stream buffer limit: rejected bytes are counted, a segment that only partly fits is tested, and the stream keeps moving
- [x] Regression test (old branch): a flood of 1-byte holes keeps memory bounded, and segments that would create an extra hole are rejected
- [x] `max_total_buffered` is enforced pool-wide
- [x] `max_connections` rejects with `TooManyConnections`, and tombstones count
- [x] Unconsumed data is never discarded by any limit
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

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

**2026-10-11 — carry-over from ticket 08:**
- A resync gives up all holes before the resync point. Once bytes arrive after it, `add_data` zero-fills the buffer from the end of the received bytes to the resync point (e.g. an ACK hole of up to k windows before the jump). `max_stream_buffer` has to bound that, as it does for other placeholders.
- Bytes that reach the stream at a resync (R3/R4, or an ACK that arrived first) are stored like any other bytes and count towards the limits. Candidates are not stored, so they need nothing.
- If D4 rejects the bytes of a segment that becomes the new start, the resync still happened (gap, counter). Decide whether that is fine or whether the resync should wait for bytes that fit.

**2026-10-11 — carry-over from ticket 10:** a connection (or its tombstone) can keep a copy of one SYN for a reconnect (`ReconnectSyn` in `tcp_connection.rs`, up to one segment with TCP Fast Open bytes). It counts towards no limit yet; decide whether `max_total_buffered` covers it.

**2026-10-12 — user decisions (asked before implementing):**
1. **One extra hole at the end:** a segment that would leave more than `max_holes_per_stream` holes is rejected, and its position still moves the highest offset. That can add one hole after the furthest stored byte, as can an ACK or a FIN, so `holes()` lists at most the limit + 1. The implied ACK keeps moving, so the reader gets gaps and holes are freed. Rejected: a strict limit, under which rejected segments don't move the highest offset, so a stream without captured ACKs stalls at its first hole until the user gives it up.
2. **Bytes that don't fit in front of a pickup are rejected:** they count in `rejected_bytes` and offset 0 stays. A late SYN (or the ACK of a late SYN-ACK) that would need the room is ignored like one A5 can't take: the SYN counts as out-of-window, and the stream stays a pickup. Rejected: counting both as out-of-window.
3. **A pickup's first segment none of whose bytes fit doesn't start the stream** (like a keep-alive, also with a FIN); its bytes count as rejected, the next segment that fits starts the stream, and a retransmission of the rejected bytes can still be put in front. Byte 0 of a pickup is thus always stored, and `prepend` keeps its assumptions. Rejected: starting the stream with a hole at offset 0 and no prepends while it is missing.
4. **A resync happens even if the bytes of its new start are rejected:** they become a hole right after the `Gap { len: None }`. Rejected: the resync waits for a segment that fits.
5. **The kept SYN of a reconnect doesn't count towards `max_total_buffered`:** each connection and tombstone keeps at most one, so `max_connections` bounds them, and detecting reconnects never depends on the budget. Rejected: counting it, so that a SYN that doesn't fit isn't kept and its reconnect continues the old connection behind a resync.
6. **The K4(b) ACK history stays bounded by `ack_reorder_tolerance` only** (16 bytes per packet and stream), and the config doc says so. Rejected: also capping it at `max_holes_per_stream` entries, which would make holes overdue early under ACK floods.
7. **Resyncs wait while a stream has more than `max_holes_per_stream` unread gaps:** the candidate stays (its bytes count as out-of-window) and a forced resync stays pending until the reader steps over gaps, so a stream has fewer than about 2 × the limit + 2 gaps. Rejected: no limit, under which forged resync sequences add about 2 gaps per 3 packets while the reader doesn't read.

spec.md D4, A4, A5, R2 and the config table are updated.

**2026-10-12 — user decision (asked while implementing):**
8. **Holes up to the end of the furthest rejected bytes are overdue (K4(c)):** rejected bytes at the end of a stream join one hole that each rejected segment extends to the highest offset, so the implied ACK never passes it, and in a continuous flow the reader would stall there (e.g. a reader that fell behind by more than `max_stream_buffer`, or a window larger than the buffer). Late segments still fill such holes until the reader reaches them; capture-loss holes before the rejected bytes are overdue too, as waiting is futile once the stream overflowed. Rejected: only holes made entirely of rejected bytes (rejected bytes would become their own hole next to missing bytes, with state per hole), and no change (stalls until the flow pauses).

spec.md K4 is updated.

**2026-10-12 — user decisions after the review (asked before fixing):**
9. **Rejected bytes count as received for F1:** a FIN before the end of the furthest rejected bytes is ignored, as one before stored bytes is, so a forged FIN inside them can't cut a full stream short; the real FIN after them counts. A forged segment far ahead can block the real FIN, as it already can with stored bytes. Rejected: accepting such a FIN (the spec review found that it brought back the old branch's "an injected FIN blocks the real one" while a stream is full).
10. **Only holes before the furthest stored byte count towards `max_holes_per_stream`:** the hole after it (rejected bytes, or bytes an ACK or a FIN shows were sent) doesn't, so in-order bytes that fill it from its start are stored, and so are late SYNs and bytes in front of a pickup that add no hole. `holes()` still lists at most the limit + 1. Rejected: counting all holes literally, under which such stores were rejected whenever that hole existed, and with a limit of 0 every ACK that arrived before its data lost the ACKed range.

spec.md D4 and F1 are updated.

**2026-10-12 — implemented** (decisions in `addc5fe` and `caa05de`):
- `c22684c` (refactor): `TcpStream::can_move_start_back` checks a prepend before `move_start_back` does it.
- `fa5b9ed`: `max_stream_buffer` in `TcpStream::add_data`, the new counter `TcpStreamStatus::rejected_bytes` (Q1), and rejected bytes that still move the highest offset.
- `15640cd`: prepends, late SYNs and the ACK of a late SYN-ACK must fit (`fits_in_front`, decision 2); a first segment without room starts no pickup (decision 3).
- `5564b47`: K4(c) with `TcpStream::rejected_end` (decision 8), and FINs before rejected bytes are ignored (decision 9).
- `da388cd` (refactor): `cut_holes`, which `remove_from_holes` and the hole count share.
- `c6d59b3`: `max_holes_per_stream`, counting the holes before the furthest stored byte (`holes_after_storing`, `counted_holes`, decisions 1 and 10). Regression test "a flood of 1-byte holes" in `TcpStream::holes`.
- `4ec1904` (refactor): the ACK functions of a stream get the configuration.
- `b0d0657`: resyncs wait while a stream has more unread gaps than the hole limit (`can_resync`, decision 7).
- `aaace6d`: `max_total_buffered`. The pool keeps the accounted total (`buffered`) and the key of the connection it handed out last (`handed_out`), and accounts for that connection again at the next call, so reading makes room at once. Ended and replaced connections leave the total (`TcpConnection::account_buffered` / `release_buffered`). The budget travels as `available: &mut usize`. Kept SYNs don't count (decision 5).
- `ad88d35`: the docs of `ack_reorder_tolerance` state what it keeps (decision 6).
- `1f10387`: `max_connections` and `TcpIgnoreReason::TooManyConnections` (P3: tombstones count; reconnects on known keys don't).
- `304c678`: a bug fix of ticket 08 that the new proptest found. Bytes in a hole given up right behind the empty gap of a resync were stored, because the skip stopped at the first gap at the read position; a FIN before them was then ignored. Bytes are now skipped up to the end of the last gap, as all gaps lie at the read position or before a jump.
- `20fa538`: the reference model applies all limits, the harness asserts the bounds at every step (holes at most limit + 1, holes before the furthest stored byte at most the limit, the buffer, and unread gaps at most 2 × limit + 2 while open), `received_matches` skips discarded bytes, and the proptest `memory_limits` (small limits, jumps, loss, pickups, a slow reader with actions) is green at 3000 cases.

The library code of the module is fully covered (merged view of `cargo cov`). Manual mutants of every new condition are killed by the module tests, apart from these equivalent ones:
- In the fill loop of `add_data`, `.min(stored_end)` → `.min(end)`: a rejected segment then writes into placeholders whose hole stays, which nothing can observe.
- `if self.config.max_total_buffered.is_some()` → `if true` for `handed_out`: it only skips the extra lookup when the pool has no budget.

Implementation decisions (not asked):
- `max_total_buffered` counts each stream as `max_stream_buffer` does, from the read position to the furthest stored byte.
- Rejected bytes are counted each time they arrive.
- Bytes filling a hole before the furthest stored byte always fit, as their placeholders exist.
- With the hole rule of decision 10, a rejected segment never overlaps stored bytes, so its rejected bytes are `end − stored_end`. The model counts only missing bytes, so the proptest checks this.

Review (standards and spec, both axes):
- The spec review led to decisions 9 and 10 (asked, see above).
- The standards review's findings are fixed:
  - the constant comes first in `0 >= start`;
  - the old buffer-limit commit is split three ways (limit, pickups, K4(c));
  - the tolerance doc has its own commit;
  - the docs leave out the implementation;
  - `buf_end` uses `buffered`, and `missing_bytes` is gone;
  - the pool names `kept_syn_acked` / `replayed_syn`, and the bare `0` has a comment.
- Judgement calls left as they are:
  - `config` and `available` travel together (the budget is per call, the config per pool);
  - the check, fit and move sequence of prepends appears twice (each failure counts differently);
  - `cut_holes` returns a tuple;
  - the model commit follows the behaviour commits, as in tickets 03–10.

Note: proptest wrote no failure seeds to `proptest-regressions/` for the failures found here. The cases are covered by unit tests (`fin_offset`, `holes`).
