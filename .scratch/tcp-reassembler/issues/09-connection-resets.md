# 09: Connection resets

Parent: ../spec.md

**What to build:**
- An RST whose sequence number lies within one window of the sender stream's highest offset ends the connection. So does an RST from a direction never seen.
- The connection is handed over in `ended` with `Reset { by }`. Its remaining holes become gaps, so every buffered byte can still be read, and reading then returns `End(Reset)`.
- A tombstone absorbs late segments.
- Out-of-window RSTs are ignored.

Rules: F4, F5, F6 (`End(Reset)`), P3.

**Blocked by:** 02, 04, 05

**Status:** ready-for-agent

- [x] An in-window RST hands the connection over as `Reset { by }`; leftover bytes and gaps are readable, followed by `End(Reset)`
- [x] Regression test (old branch): an injected out-of-window RST is ignored and the connection stays open
- [x] An RST from a direction never seen is accepted
- [x] Late segments after a reset are ignored with `AfterEnd`
- [x] The reference model is extended with RSTs, both real and injected
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 02:** a connection ends by setting `TcpConnection::end` in `add_segment`. The pool hands over every connection whose `end()` is set, through `hand_over()`, which leaves the tombstone. `TcpStreamEnd` and `TcpConnectionEnd` only have `Fin` and `Finished` so far. For `End(Reset)`, the streams also need to know how the connection ended.

**2026-10-11 — carry-over from ticket 05:** for F5 (all holes become gaps), use `TcpStream::give_up_holes_before(highest_offset)`. It counts the gaps and keeps them sorted. Reading then returns `Gap { len: Some(n) }` at each of them, and `consume_gap()` steps over it.

**2026-10-11 — carry-over from ticket 06:**
- F5 can use `TcpStream::give_up_all_holes()`, which the `Finished` end already calls.
- The keep-alive filter test in `TcpStream::holes()` feeds a 1-byte segment with the RST flag and expects it to fill the hole, because RSTs are not handled yet. Adapt it once an in-window RST ends the connection.

**2026-10-11 — carry-over from ticket 07:**
- F4 accepts an RST "if that stream has never been seen". A stream can now have been seen (pure ACKs) without a start (`start_seq` is `None`). Decide which one F4 means.
- The `read_received` test block "other segments at the position of a keep-alive" pins that a 1-byte segment with RST starts a stream with its byte as data. Adapt it when RSTs end connections.
- RSTs of unknown keys start no connection, also with bytes or a SYN (`process_segment` test).

**2026-10-11 — carry-over from ticket 08:**
- RSTs are still handled like other segments, so an RST with bytes after the window can become a resync candidate or a new start, and an RST with bytes in the window clears the candidate. F4 should keep RSTs out of the resync rules (`TcpStream::add_segment`, the block before the S4 count).
- After a resync, the sender stream's sequence numbers map relative to the new start (`start_seq`), so an RST from before the jump maps far away and is ignored as out-of-window; that is presumably right.
- F5 (`give_up_all_holes`) keeps the resync's gap, an empty range in `TcpStream::gaps`, so reads show `Gap { len: None }` before `End(Reset)`.

**2026-10-11 — user decisions (asked before implementing):**
1. **Which RSTs are in the window:** from the seen ACK of the sender's stream up to one window after the bytes it is known to have sent (highest offset, plus 1 once the FIN is known), with the receiver's last window (S3). These are exactly the RSTs the receiver can accept (RFC 9293: RCV.NXT ≤ seq ≤ RCV.NXT + RCV.WND, where RCV.NXT lies between the receiver's ACK and the bytes sent). It works with a window of 0: Linux then sends its RST at SND.UNA, which is the receiver's ACK. Rejected: the highest offset ± one window, the literal F4. It accepts RSTs before the receiver's ACK, which the receiver rejects, and with a window of 0 it ignores an RST at SND.UNA or at the ACK of the FIN. Also rejected: the union of both ranges.
2. **"Never seen" means no reference point:** a stream without a start is checked against the last ACK the other side sent for it (the pending ACK), from that ACK up to one window after it. Only without a start and without such an ACK is any RST accepted, e.g. SYN → RST/ACK on a closed port. Rejected: any RST on a stream without a start (a pickup whose client only ACKs could be reset by a blind RST), and "no packet from that direction".
3. **Ignored RSTs count in `out_of_window_segments`** of the sender's stream, like injected FINs and data after the window.
4. **End reason after a reset:** `End(Fin)` once the read position reaches the FIN, otherwise `End(Reset)`, also when `read_acked()` stops before un-ACKed bytes (F6). Streams without a FIN end with `End(Reset)`. Rejected: always `End(Reset)`, and `End(Fin)` whenever the FIN was seen.

spec.md F4 and F6 are updated.

**2026-10-11 — user decisions after the review (asked before fixing):**
5. **No ACK blocks an RST at or after the received bytes:** the lower bound is min(seen ACK, end of the received bytes). The spec review found that one forged in-window ACK otherwise keeps every real RST below it from counting, for good. After a FIN that cut the forged ACK's hole, with a window of 0, no RST could count at all. F1 prevents the same for FINs. Rejected: the seen ACK as decided in 1.
6. **An ACK that a pickup keeps before offset 0 counts** as the receiver's ACK, so an RST at it resets the connection (e.g. Linux sends its RST at SND.UNA with a window of 0). Rejected: offset 0 as the floor.
7. **After a resync, RSTs before the resync point are ignored** and counted, as R2 ignores bytes, FINs and ACKs there. This holds also after R3/R4, where no ACK raised the seen ACK to the resync point. Rejected: accepting them from the seen ACK on.
8. **An RST stores nothing but the reset:** its bytes are diagnostic (RFC 9293 3.5.3, RFC 1122 4.2.2.12) and its SYN and FIN flags are ignored, so the stream ends with `End(Reset)`. Rejected: storing its bytes and FIN first.
9. **An RST's ACK counts only if the RST is accepted.** An ignored RST is dropped with its ACK and its window (RSTs often carry a window of 0). Rejected: never, and always.
10. **Reset wins over Finished:** an RST whose ACK ACKs the last FIN ends the connection as `Reset { by }`. Both streams are still read to `End(Fin)`.
11. **Ignored RSTs count as packets** for `last_seen` (P7) and `ack_reorder_tolerance` (K4(b)), like out-of-window data.

spec.md F4 is updated.

**2026-10-11 — implemented** (commits `b0e95f4`, `af7de5a`, `4afb99d`):
- `b0e95f4` (refactor): `TcpConnection::add_segment` applies a segment's ACK (`add_ack`) and the rest of it (`add_data_segment`) in their own functions.
- `af7de5a`: F4–F6 with all decisions above.
  - `TcpConnection::add_reset` checks an RST with `TcpStream::add_reset`, which counts ignored ones, then applies its ACK and sets `end`.
  - Every end then goes through `TcpStream::connection_ended(TcpStreamEnd)`, which replaces `give_up_all_holes()`. It gives up all holes (F5) and stores the end that reads return away from the FIN (F6).
  - New variants `TcpConnectionEnd::Reset { by }` and `TcpStreamEnd::Reset`.
  - RSTs never reach `TcpStream::add_segment`, so `is_keep_alive_shaped` no longer looks at the RST flag. The two keep-alive tests lost their RST rows (carry-overs of tickets 06 and 07).
- `4afb99d`: the model ends connections by F4. The proptest `resets` adds an endpoint's RST (from the SYN on, with or without an ACK) and injected RSTs, with loss, one-direction captures and pickups. It is green at 3000 cases.

The module is fully covered (merged view of `cargo cov`). Manual mutants of every new condition are killed by the module tests, apart from two equivalent ones:
- `TcpConnectionEnd::Finished => TcpStreamEnd::Fin` → `Reset`: a finished connection has both FINs ACKed and no holes, so reading always reaches the FIN before the stored end matters.
- The kept ACK before offset 0 was first `min`'d with the seen ACK. That `min` was equivalent, as such an ACK always maps at or before offset 0, so it was removed.

Run against `resets` alone, the proptest misses the boundary mutants: an RST exactly one window after the bytes, the +1 after a FIN with a window of 0, an RST exactly one window after a kept ACK, and the guard that keeps `Reset` from becoming `Finished`. The unit tests in `TcpConnection::end()` pin them all.

Standards review:
- The RFC reference lists and the changelog are ticket 16.
- The stream field `end` was renamed to `connection_end`.
- Not changed (judgement calls): the `Finished → Fin` match repeated in the model (it is the oracle), the `(sender, tcp, config)` parameters, repeated test assertion blocks, and positional tuples in the proptest.
- Glossary gap for /domain-modeling: "an RST the receiver can accept" and "injected RST" have no term in CONTEXT.md.

Known limits (documentation for ticket 16):
- A blind RST inside the window resets the connection. RFC 5961's challenge ACK can't be observed passively.
- On a pickup without any ACK of the receiver, RSTs before the first byte captured are ignored.
