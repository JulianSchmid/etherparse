# 06: Capture loss no longer stalls streams

Parent: ../spec.md

**What to build:** Streams keep flowing after packets were lost in the capture:
- The implied ACK is `highest offset − k × window`, and the ACKed offset becomes the maximum of the seen and implied ACK.
- Holes before the implied ACK become gaps automatically (window rule).
- A hole covered by a seen ACK becomes a gap after `ack_reorder_tolerance` further packets of the connection. This tolerates directions reordered against each other in merged captures.
- `hole_give_up_window_factor = None` switches the window rule off.

Rules: K2, K3, K4, ADR-0002.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [ ] Regression test (old branch stall): in a one-direction capture with lost segments, the implied ACK alone eventually delivers everything after the loss through `read_acked`
- [ ] An ACK-covered hole becomes a gap after exactly N packets and not after N − 1; a hole filled within the tolerance never becomes a gap
- [ ] With the factor set to `None`, only the ACK rule gives up holes
- [ ] The reference model is extended with dropped segments, giving the expected gaps
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

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

