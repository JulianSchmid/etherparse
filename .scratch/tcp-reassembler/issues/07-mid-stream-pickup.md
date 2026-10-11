# 07: Mid-stream pickup

Parent: ../spec.md

**What to build:** Connections whose handshake was not captured are reassembled too.
- The first data segment of a stream sets its offset 0. The stream reports `MidStreamPickup`.
- Roles are guessed: the lower port is the responder; with equal ports, the sender of the first packet is the initiator. `roles_guessed()` reports this.
- A SYN-ACK without its SYN still gives both streams an observed start.
- Until the first consume or discard, earlier bytes within the window are prepended (offsets shift), and a late SYN upgrades the stream to an observed start.
- Pure ACKs, FIN-only segments and RSTs of unknown connections stay ignored with `NoConnection`.

Rules: A2, A4, A5, A6, A7.

**Blocked by:** 03, 04

**Status:** ready-for-agent

- [x] Role guessing has exact tests: lower port, equal ports, and the handshake case
- [x] A late SYN before the first consume upgrades the stream to an observed start; after a consume the same SYN only counts as out-of-window
- [x] Earlier data arriving before the first consume is prepended
- [x] Regression test (old branch): a keep-alive probe that is the first segment of a stream behaves as documented by A4
- [x] A pure ACK of an unknown connection creates no entry
- [x] The reference model is extended with random pickup points
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 01:** two tests pin ticket-01 behaviour and need replacing:
- the block "data of a stream whose start was not seen is ignored" in `tcp_stream.rs` `read_received`;
- the first block of `process_segment` in `tcp_reassembly_pool.rs`, which expects `NoConnection` for every non-SYN segment, including the SYN-ACK.

Any SYN from a stream that isn't anchored yet currently anchors it, including a SYN without ACK from the responder. The spec leaves that case open.

**2026-10-10 — carry-over from ticket 04:**
- Add the "no handshake uses the fallback window" test from ticket 04: so far it is only tested with the SYN-ACK missing.
- `TcpStream::window_scale` is `Some(..)` only once the sender's SYN was seen; keep it tied to the SYN, not to `start_seq`. When A2 anchors the initiator stream from the SYN-ACK's ACK number, the initiator's SYN was still not seen, so the fallback window applies (A3).
- `TcpConnection::add_segment` applies a segment's ACK before its data, and `add_ack` ignores ACKs of streams without `start_seq`. A2's anchoring by the SYN-ACK's ACK number has to happen before `add_ack`, or that ACK is lost.
- `add_segment` records the sender's advertised window even when its stream isn't anchored yet; A5's "within the window" can use the `window` parameter.

**2026-10-11 — carry-over from ticket 05:** A5 says "until the first consume or discard". `discard_until()`, `discard_all()` and `consume_gap()` also move the read position, so they presumably end the prepend window like `consume()`. Also decide whether `give_up_hole()` alone ends it: it doesn't move the read position, but it gives up bytes at offset 0 that prepended bytes could precede.

**2026-10-11 — carry-over from ticket 06:**
- When A5 prepends bytes and shifts the offsets, shift the overdue state of `TcpStream` with them:
  - `implied_ack` and `settled_ack`;
  - the ACK values in `recent_acks`;
  - the seen ACK, holes and gaps, as before.
- A mid-stream pickup has no known window scale, so `largest_window` stays `None` and the implied ACK uses `fallback_window` (2 × 4 MiB by default). A late SYN upgrade (A5) still doesn't make the scale known unless both SYNs are seen (A3).

**2026-10-11 — user decisions (asked before implementing):**
1. **Late handshake and guessed roles:** a late SYN from the guessed initiator, or a late SYN-ACK from the guessed responder, that gives a stream an observed start confirms the roles: `roles_guessed()` becomes false. A late handshake that contradicts the guess leaves the roles as they are, and they stay guessed; the streams still get their observed starts (as the illustration of the chosen option showed). Roles never change after the connection was created.
2. **Keep-alive as the first segment:** if the other side's ACK was seen while the stream had no start, a 1-byte segment without SYN, FIN or RST that ends at that ACK is a keep-alive. It is ignored and doesn't start the stream, as in D3. A keep-alive that is the connection's very first packet starts the stream with its filler byte (A4, documented limit).
3. **FIN without bytes:** on an existing connection, a FIN without bytes starts a stream that has no start yet, with offset 0 at the FIN. The stream is empty and finished, so the connection can end as `Finished`. It takes no earlier bytes and no late SYN afterwards (A5 is closed), because a reader may already have read `End(Fin)`.

**2026-10-11 — implemented** (commits `5a06b67` through `eef6fdd`):
- `5a06b67`: the implied ACK is kept as an `Option<i64>`, not cut off at 0, so it stays exact when offset 0 moves.
- `93d1989`: `TcpStreamStart` and `TcpStreamStatus::start`.
- `fd2d41d`: A2, a SYN-ACK starts a connection; its ACK starts the initiator's stream.
- `5484104`: A4, A6, A7 guess, `roles_guessed()`, keep-alive and FIN-only starts, pending ACKs before the start.
- `3ea7d47`: A5, prepending, late SYNs, out-of-window before offset 0.
- `266f9d9`: A7, a late handshake confirms guessed roles.
- `eef6fdd`: reference model with pickups, proptest `mid_stream_pickups` (green at 3000 cases).

The reassembly code of this ticket is fully covered (merged view of `cargo cov`). Manual mutants of every new condition are killed, apart from the equivalent ones listed below. A two-axis review (standards and spec) ran, and its fixes are folded into the commits above. Each rebuilt commit passed the module tests.

Decisions taken while implementing, for the user to confirm (spec.md is unchanged for these):
1. **A stream without a start reports `MidStreamPickup`.** The value only ever changes to `Observed`, e.g. for the responder's stream between SYN and SYN-ACK.
2. **"Within the window" (A5):** the bytes' first byte, or the SYN's ISN + 1, lies at most one receiver window before offset 0. The window is the one used for S4, so the fallback window on a pickup.
3. **"The first consume or discard" (A5) is the first forward move of the read position:** `consume` of at least 1 byte, `consume_gap`, or `discard_until`/`discard_all` that move it. `consume(0)` and `discard_until(0)` don't end it. `give_up_hole()` can't, because byte 0 of a pickup is always a received byte (until ticket 11, see its carry-over).
4. **A2 + A5:** the ACK number of a late SYN-ACK acts as a late SYN of the other stream if that stream is a pickup.
5. **Bytes before offset 0** of a pickup that can't take them count as out-of-window, once per segment (also with bytes after the FIN), and the segment's bytes from the read position on are still stored. On an observed start they stay ignored without counting, because the filler byte of a keep-alive of a stream without bytes lies there.
6. **A SYN that a pickup can't take** (after the read position moved, more than one window before offset 0, after offset 0, or on a pickup that started at its FIN) counts as out-of-window and is ignored, its TCP Fast Open bytes included, until ticket 10 looks at it (C4 → C2).
7. **Pending ACK (found by the spec review):** the last ACK that a stream couldn't apply is kept and applied after every packet until it counts. That is an ACK seen before the stream had a start, or one of offset 0 or before it while bytes can still be prepended. Without it, a pickup that started at its FIN never finished when the FIN's ACK was captured first. An ACK of a pickup's first byte was also lost when earlier bytes were prepended. It is the *last* such ACK, not the highest, because ACKs before a start can't be compared.
8. **`consume()` after a prepend consumes nothing until the next read.** The bytes the last read returned are no longer at the read position. A reader that copied them, fed more packets and only then consumed sees the prepended bytes in front of them on the next read, so it handles them again. The alternative, consuming the prepended bytes, would drop bytes the reader never saw.
9. **ACK history while prepending is possible:** the K4(b) queue of `(packet, seen ACK)` is kept also without holes while the stream can still prepend, because a prepend adds a hole before the seen ACK. The proptest found this.
10. **RSTs of unknown keys** start no connection, also with bytes or a SYN. A 1-byte segment with RST is not a keep-alive.

Equivalent mutants:
- `start <= 0` instead of `start < 0` before `prepend` in `move_start_back`: the empty hole that `prepend(0)` inserts is dropped by the overdue check after the packet.
- `can_prepend()` in `add_ack`'s pending condition, and the pickup check in `can_prepend()` where it guards the ACK history: without them, ACKs that can never count stay pending, or ACKs are recorded without holes. Both only cost memory.

Known limits (documentation for ticket 16):
- A keep-alive that is a connection's very first packet starts the stream with its filler byte.
- A SYN with TCP Fast Open bytes that its SYN-ACK ACKs: if the SYN is captured after the SYN-ACK, the SYN-ACK's ACK starts the initiator's stream after the TFO bytes as an observed start. The late SYN can't move it back, so the TFO bytes are lost.
- Contradicting late handshakes give observed starts to streams whose roles stay wrongly guessed. `is_complete()` judges the stream, not the role labels.

Review judgement calls left as they are:
- The reference model comes in its own commit after the behaviour commits (as in tickets 03–06); the per-method unit tests come with the code.
- "a SYN-ACK is sent by the responder" is written out in the pool (endpoint) and in the connection (role); they pick different things.
- `(initiator, roles_guessed)` travel together into `TcpConnection::new` only.
- `observe_start` keeps its name; its doc says when it refuses.

**2026-10-11 — user decisions on the points above.** The user went through all of them, with illustrated scenarios. Everything follows the recommendation, except decision 2:
- **Decision 2 changed:** earlier bytes and late SYNs may lie up to k windows before offset 0, the same range that limits bytes after the stream (S4, k = `hole_give_up_window_factor`, 2 without one), instead of one window. Implemented in `9612fc5`.
- Decisions 1, 3–10 are confirmed as implemented, and so is accepting the TCP Fast Open limit as documented.
- spec.md is updated: the API (`start` of a stream without a start), A2 (late SYN-ACK, TFO limit), A5 (what ends prepending, the k-window range, out-of-window counting, `consume` after a prepend), A6 (RSTs with bytes or SYN), K1 (pending ACKs), and K4 (ACK history for prepended holes).

