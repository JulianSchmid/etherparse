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

- [ ] Role guessing has exact tests: lower port, equal ports, and the handshake case
- [ ] A late SYN before the first consume upgrades the stream to an observed start; after a consume the same SYN only counts as out-of-window
- [ ] Earlier data arriving before the first consume is prepended
- [ ] Regression test (old branch): a keep-alive probe that is the first segment of a stream behaves as documented by A4
- [ ] A pure ACK of an unknown connection creates no entry
- [ ] The reference model is extended with random pickup points
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

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
