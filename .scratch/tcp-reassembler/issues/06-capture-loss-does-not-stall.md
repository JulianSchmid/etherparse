# 06: Capture loss no longer stalls streams

Parent: ../spec.md

**What to build:** Streams keep flowing after packets were lost in the capture, without dropping bytes the reader hasn't reached:
- The implied ACK is `highest offset − k × window`, and the ACKed offset becomes the maximum of the seen and implied ACK.
- A hole becomes **overdue** once its end lies at or before the implied ACK (window rule) or the seen ACK as it was `ack_reorder_tolerance` packets ago (ACK rule). The ACK rule tolerates directions reordered against each other in merged captures.
- Gaps are lazy: late segments still fill overdue holes. The overdue hole at the read position becomes one gap, over its whole length, as soon as it is overdue.
- A connection whose two FINs are ACKed ends as `Finished` once all its remaining holes are overdue, and these holes become counted gaps at hand-over.
- In an overdue hole, a 1-byte keep-alive that ends at the seen ACK is ignored.
- `hole_give_up_window_factor = None` switches the window rule off.

Rules: K2, K3, K4, D3, F2, F3, F5, ADR-0002.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [x] Regression test (old branch stall): in a one-direction capture with lost segments, the implied ACK alone eventually delivers all bytes up to `highest offset − k × window` through `read_acked`, with one gap per lost range
- [x] A late segment fills an overdue hole that the read position hasn't reached; its bytes are delivered as data and no gap is counted
- [x] An ACK-covered hole at the read position becomes a gap after exactly N further packets and not after N − 1; a hole filled within the tolerance never becomes a gap
- [x] A hole that lies only partly before the implied ACK stays a hole; once it is overdue as a whole, it is read as one `Gap` with its full length
- [x] The overdue hole at the read position is a gap without any read call: `holes()`, `status()`, `give_up_hole()` and `consume_gap()` agree right after the packet or read-position move that made it one
- [x] `is_finished()` and `is_complete()` stay false while an overdue hole remains before the FIN
- [x] A connection with both FINs ACKed and only overdue holes left ends as `Finished`; its holes are handed over as counted gaps, and reads end in `End(Fin)`
- [x] A 1-byte keep-alive ending at the seen ACK doesn't fill an overdue hole; the same segment still fills a hole that isn't overdue yet (D3 known limit); a 1-byte segment with FIN, or a 2-byte segment, still fills an overdue hole
- [x] With the factor set to `None`, only the ACK rule makes holes overdue
- [x] The reference model is extended with dropped segments and lazy gaps, giving the expected gaps. It states K4 itself instead of mirroring the code
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 04:**
- `TcpStream::acked_offset()` is `min(seen ACK, highest offset)`. Add the implied ACK there (K3). `read_acked()` and the D3 comparison in `differs_from_received` both go through `acked_offset()`, so they pick it up. Update the doc of `acked_offset()` to mention it.
- `TcpStream::window_end` already uses `hole_give_up_window_factor.unwrap_or(2)` × window; the implied ACK applies only for `Some(k)` (K2). The window comes from `TcpConnection::window(role, config)`.
- ACKs after the highest offset now add holes (K1). These are exactly the ACK-covered holes that K4(b) gives up after `ack_reorder_tolerance` packets, and they can be filled until then (D3 only skips bytes that were already received).
- Each accepted ACK can move the highest offset by one window without data, so forged ACKs can walk it, and with it the implied ACK, forward.

**2026-10-11 — carry-over from ticket 05:**
- `TcpStream::give_up_holes_before(offset)` turns the parts of all holes before an offset into gaps and counts them. It fits K4(a). K4(b) gives up single holes that need not be first, so it needs a variant that gives up one hole.
- So far a gap only ever exists at the read position. These places already handle gaps anywhere, so 06 makes them observable (they are equivalent mutants today):
  - `read_until` stops bytes at the first hole or gap (`missing()`);
  - `differs_from_received` skips gaps;
  - `give_up_holes_before` sorts the gaps.
- `add_data` skips only the bytes in the gap *at the read position*. Inside the buffer, bytes of other gaps are not written, because only holes are filled. But bytes of a gap after the end of the buffer that is not at the read position would be appended, and they would move `received_end`, the end of the received bytes that the FIN check (F1) uses. Skip the bytes of every gap.
- Reference model:
  - `received` extends over gaps with placeholders and stops at the first hole;
  - `holes()` assumes that gaps lie inside `received`, which is only true while gaps start at the read offset;
  - `read` stops at the next gap.
  - With gaps behind holes, `holes()` must leave out the gap offsets, and `extend_received` stays correct.
- The ticket-04 "hole" at a FIN's position (the ACK of the FIN arrived first) becomes a gap under K4(b) if the FIN is delayed by more than `ack_reorder_tolerance` packets. The FIN still finishes the stream (ticket 05, decision 2: the read position moves back to it), but the stream counts a gap and is no longer clean.

**2026-10-11 — user decision (from ticket 05): lazy gaps.** A hole that K4 may give up stays a hole, and late segments still fill it, until the read position reaches it. Only then does it become a gap: it is read as `Gap` and counted (Q4: the counters never decrease). The reassembler must never drop bytes that the reader hasn't reached yet. See spec.md K4 and F2.
- This replaces the first bullet of the carry-over above. K4 doesn't call `give_up_holes_before`; instead, reading at a hole checks K4 and turns that hole into a gap. Ticket 09's F5 still uses `give_up_holes_before(highest_offset)`.
- `is_finished()` (F2) and the connection end (F3) must treat holes that K4 may give up as given up, so connections with capture loss still end as `Finished`. Decide how `holes()` reports them, e.g. still as holes.
- `read_acked()` should present the gap even when the hole lies before the ACKed offset (ticket 05 decision 5).
- The 1-byte hole at a FIN's position whose ACK came first: if the FIN arrives before the reader reaches it, it is cut and never counted. This mostly removes the false gap noted above.
- Check whether the wording of ADR-0002 ("Holes before X − k×window become gaps") and of "Gap" in CONTEXT.md needs to say "once the reader reaches them".
- Reference model: holes that K4 may give up stay in `bytes` as missing and become gaps in `read` when the read offset reaches them.

**2026-10-11 — grilling decisions (lazy gaps), confirmed by the user.** They are in spec.md (K4, D3, F2, F3, F5, P6, API), `CONTEXT.md` (**Overdue hole**, plus the reworded **Hole**, **Gap**, **Finished connection**) and ADR-0002:
1. The term is **overdue hole**. It replaces "holes that K4 may give up" in the comments above.
2. A hole is overdue as a whole: its end lies at or before max(implied ACK, seen ACK as it was N packets ago). There are no partial gaps, so one lost range gives one gap.
3. N counts every packet applied to the connection, in either direction, as for `last_seen` (P7). The packet whose ACK covers the hole doesn't count.
4. The overdue hole at the read position becomes a gap as soon as it is overdue, not on the next `read_*()` call. Check this:
   - after every packet, for both streams, because packets of either direction advance the count;
   - after every move of the read position (`consume`, `consume_gap`, `discard_until`, `discard_all`).
5. `is_finished()` stays strict (no holes, overdue ones included), so `is_complete()` never turns from true to false because of a gap. This replaces the bullet above that has F2 treat these holes as given up.
6. F3: both FINs seen and ACKed and every remaining hole overdue → `Finished`. F5 now applies to every end, including `Finished`: all holes become gaps and are counted at hand-over (`give_up_holes_before(highest_offset)`).
7. At eviction, every ACK-covered hole counts as overdue (P6, carried over to ticket 12).
8. Keep-alive filter (D3): in an overdue hole, ignore a segment without SYN, FIN or RST that carries exactly 1 byte and ends at the seen ACK. It touches no counter.
9. `holes()` keeps its API and lists overdue holes. Its doc says that they may be overdue.

Implementation notes:
- While a connection is open, gaps exist only at the read position (apart from ticket 08's resync marker), and after an end the tombstone absorbs all segments. So the ticket-05 carry-over "skip the bytes of every gap in `add_data`" is moot.
- Tracking K4(b): N is a user-set `u32`, so a per-stream history of up to N ACK advances is unbounded in practice. A stamp per hole is bounded by `max_holes_per_stream`: the connection's packet number when the seen ACK first reached the hole's end, renewed when an ACK hole grows. But stamps are conservative for the front part of a hole that a fill splits. The seen ACK may have reached that part's end earlier than the stamp says, so the part becomes overdue later than K4(b) states. Example: ACK 70 at packet 1 and ACK 100 at packet 10 stamp hole [0, 100) with 10; a fill of [60, 100) leaves [0, 60), which K4(b) makes overdue at 1 + N, but the stamp only at 10 + N. Either keep K4(b) exact or change the spec to match the stamps; check with the user before changing the spec.
- Docs to reword in the code:
  - `hole_give_up_window_factor` ("after which a hole is given up") and `ack_reorder_tolerance` ("during which … can still be filled"): the hole becomes overdue;
  - `holes()` and `is_finished()`;
  - `give_up_hole()`: it returns false at an overdue hole at the read position, which is already a gap;
  - `read_received()`.
- The 1-byte hole at a FIN's position whose ACK came first becomes a gap only if it is at the read position and overdue before the FIN arrives. The FIN then moves the read position back (ticket 05), and the gap stays counted (Q4).
- Reference model: overdue holes stay missing in `bytes`. After each step, if the read offset is at a missing range that is overdue as a whole, record a gap there. Compute the implied ACK and the seen ACK of N packets ago from the model's own state, in separate fields as with the highest offset.

**2026-10-11 — implemented** (commits `b1078c1` through `418aee0`). Decisions taken while implementing, for the user to confirm:
1. **The implied ACK never moves back.** It is the running maximum of `highest offset − k × window`, because bytes sent earlier still prove what the receiver had ACKed then. K2's formula alone would let it fall when the window grows. Once confirmed, add this to K2.
2. **K4 timing within a packet.** The bytes of a packet are applied before that packet's overdue check. So a hole is overdue *after* the N-th further packet, and the N-th packet's own bytes still fill it (a keep-alive in it too). This matches the acceptance criterion ("after exactly N further packets"). K4 says "overdue on the N-th packet", so only its wording needs a fix.
3. **The implied ACK's timing.** It is updated after every packet, with the receiver's current window. D2/D3 checks inside a packet use the implied ACK from before that packet.

**Open, needs a user decision (review finding): zero or shrinking windows.**
- The implied ACK uses the receiver's last advertised window. An ACK segment that advertises window 0 sets the implied ACK to the highest offset in the same packet.
- So the hole that this ACK created (K1) is overdue at once, and `ack_reorder_tolerance` is skipped. That is the merged-capture case K4(b) should tolerate.
- S3 already checks an ACK against the window from before its segment. For K2, using the window from before the packet only delays the problem by one packet.
- Options:
  - (a) use the largest window the receiver advertised, which is conservative and robust to shrinking;
  - (b) use the window from before the packet;
  - (c) accept it and document it.

Implementation notes:
- K4(b) is exact: each stream keeps a queue of `(packet number, seen ACK)` for the last N packets, but only while it has holes. The per-hole stamps from the grilling comment were not needed, so spec.md stays as it is.
- F3/F5: `TcpStream::can_finish()` and `TcpStream::give_up_all_holes()`. Tickets 09, 10 and 12 can reuse the latter for F5.
- Equivalent mutants:
  - clearing `recent_acks` when there are no holes, and recording ACKs only while there are holes. Both only bound memory, because later holes lie after the seen ACK;
  - `hole.start <= offset` in `in_overdue_hole`. A keep-alive byte that was already received lies before the ACKed offset, so it is neither stored nor compared either way.
- Proptests:
  - `random_acks` and `out_of_window_segments` now check the received bytes outside the gaps only, because their ACKs run ahead of the data.
  - `reordered_streams` switches the ACK rule off (`ack_reorder_tolerance = u32::MAX`), because its retransmissions at random positions ACK bytes sent much later.
  - The new `capture_loss` test uses a random factor and tolerance (`tcp_overdue_config_any`), small windows, lost or late segments and keep-alives. On its own it kills every non-equivalent mutant tried.
- Known: a connection whose last hole was covered fewer than N packets before its last packet stays open until eviction. Ticket 12 makes it end as `Finished` there.
- Review judgement calls left as they are:
  - the docs of `acked_offset()` and `ack_reorder_tolerance` explain the implied ACK and the memory cost to users;
  - the `(u64, u64)` tuple in `recent_acks` is private and documented;
  - `first_hole()` in the reference model came with the behaviour commit that needed it.

**2026-10-11 — user decisions on the points above.** All three follow the recommendation:
1. The implied ACK never moves back. Confirmed, and now in K2.
2. A hole is overdue *after* the N-th packet, and that packet's bytes still fill it. Confirmed; K4's wording is fixed.
3. Zero or shrinking windows: the implied ACK uses the **largest window the receiver advertised**. The fallback window applies only while no window is known: if it counted towards the maximum, the 4 MiB assumed before the SYN-ACK would stick for the whole connection. This is implemented in `ed0ac57` and recorded in K2 and ADR-0002. The regression test in `read_received()` covers an ACK with window 0 that arrives before its data.
