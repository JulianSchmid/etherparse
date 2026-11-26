# 04: Reading only ACKed data, and the receiver window

Parent: ../spec.md

**What to build:**
- ACKs from the other direction set a stream's seen ACK. Implausible ACKs (beyond highest offset + window) are ignored.
- `read_acked()` and `acked_offset()` deliver only ACKed bytes. The implied ACK stays 0 until ticket 06.
- The receiver window is tracked from the advertised window and the negotiated scale. The scale is known only if both SYN and SYN-ACK were seen, and a missing option means scale 0. `fallback_window` is used whenever the window is unknown.
- Data and FINs beyond `max(seen ACK, highest offset) + k × window` are not stored and are counted in `out_of_window_segments`.
- An ACK beyond the captured data, but within the window, turns the uncaptured bytes into a hole.
- Retransmissions of ACKed bytes are ignored without comparison (keep-alives), so conflicts only count for un-ACKed bytes.

Rules: K1, K3 (seen ACK only), S3, A3, S4, F1 (window check), D2 (refined), D3.

**Blocked by:** 03

**Status:** ready-for-agent

- [x] Proptest with random ACKs: `read_acked` never returns bytes beyond `acked_offset`, and `read_received` is unaffected
- [x] A Windows-style keep-alive (1 garbage byte at seen ACK − 1) leaves the stream clean
- [x] Regression test (old branch): an injected FIN beyond the window does not block the real FIN
- [x] Out-of-window data is counted and never readable, with exact tests at the window boundary
- [x] Window scale: both options present gives a scaled window; one missing gives scale 0; no handshake uses the fallback window
- [x] An ACK beyond highest offset + window is ignored; an ACK beyond the highest offset but within the window creates a hole
- [x] The reference model is extended with ACK generation
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 01:** `TcpStream::window_scale` is parsed from SYN/SYN-ACK (the first window scale option before any malformed option) and sits behind `#[allow(dead_code)]`. Remove the allow when the window is tracked. Also add tests that check the parsed value through window behaviour, since ticket 01 could only check that SYNs with options still start their streams. RFC 7323's clamp of shifts above 14 to 14 is not implemented yet.

**2026-10-10 — carry-over from ticket 02:** the seen ACK already exists privately as `TcpStream::seen_ack`, updated by `add_ack`. It is used only to detect that a FIN was ACKed. Add the K1 plausibility check. An ACK of `fin_offset + 1` must neither create a hole nor move `acked_offset()` past the FIN. ACKs beyond `fin_offset + 1` are accepted today, and the reference-model proptest relies on that: late bytes beyond the FIN move the script's ACKs past the FIN.

**2026-10-10 — carry-over from ticket 03:**
- Since ticket 03, a segment far ahead (up to 2^31 bytes) is stored, and the hole before it is zero-filled in the buffer. Memory use is unbounded until S4 (here) and D4 (ticket 11). Add an explicit test: a forged segment far beyond the window is counted as out-of-window and allocates nothing.
- `TcpStream::extend_to` pushes a new hole without merging it with a last hole that ends at the highest offset. That can't happen in ticket 03, because only a FIN moves the highest offset without data, and nothing lies beyond a FIN. K1 ("an ACK beyond the highest offset turns the uncaptured bytes into a hole") makes it reachable, so merge then.
- D2 compares every buffered byte from the read offset on (`TcpStream::differs_from_received`). D3 must skip the bytes before the ACKed offset. Update the doc of `TcpStreamStatus::conflicting_retransmissions` to match.

**2026-10-10 — implemented** on `tcp-reassembler` in four commits:
- `de69b3f`: `read_acked()` and `acked_offset()`. `acked_offset()` is `min(seen ACK, highest offset)`, so an ACK of the FIN ACKs all bytes but nothing after them. The reference model checks both reads after every segment and consumes after either one. The new proptest `random_acks` adds pure ACKs of random offsets at random positions.
- `cb2a718`: the receiver window (S3, A3) and out-of-window data and FINs (S4, F1). The `#[allow(dead_code)]` on `window_scale` is gone, and shifts above 14 count as 14. The model tracks the advertised windows (unscaled: the proptests send no window scale options). The new proptest `out_of_window_segments` injects bytes and FINs after the end of the streams into connections with random windows.
- `d3d81f0`: K1. Implausible ACKs are ignored, an ACK after the highest offset adds a hole (merged with a hole at the end, the ticket-03 carry-over), and a FIN cuts the holes an ACK of it created. `random_acks` gets random windows.
- `c9177e5`: D3. Bytes before the ACKed offset are not compared; the doc of `conflicting_retransmissions` is updated.

The full suite, the documented `cargo test --no-default-features`, the bare-metal no_std build, `cargo +1.83.0 check` and `cargo fmt --check` pass. Each commit passes the module tests on its own. With `PROPTEST_CASES=3000` the module tests finish in about 8.3 s; the tests run in parallel. Run alone, the slowest is `reordered_streams` (~8 s, was ~6.6 s), then `random_acks` (~4 s) and `out_of_window_segments` (~4 s). To get there, the reference model keeps the highest offset apart from its per-byte vector, so trailing missing bytes cost nothing. Every library line and region of the module is covered in the merged `cargo cov show` view. Hand-made mutants were each caught:
- no FIN position in the ACK limit;
- `>=` instead of `>` at the ACK and window limits;
- no hole merging, no FIN truncation, and no cut of the last hole;
- the FIN checked against the highest offset;
- no FIN clamp for ACK holes;
- a wrong window factor;
- the window starting at the highest offset only;
- the last window scale option instead of the first;
- ACKed bytes compared again.

Exact window boundaries are pinned only by unit tests; the proptests rarely hit them. A two-axis review (standards and spec) ran, and its fixes are folded into the commits above.

Decisions made while implementing (please confirm; spec.md is unchanged):
- **ACK limit includes the FIN position.** An ACK counts if it is at most `highest offset + window`, plus 1 once the FIN is known (K1 says `highest offset + window`). This way the ACK of the FIN counts even with a window of 0. ACKs after `fin + 1` within that limit count, but never move `acked_offset()` past the FIN or add holes after it.
- **The window used for an ACK is the one advertised before the ACK's segment.** S3 says "the receiver's last advertised window". The window in the ACK's own segment can already have shrunk (to 0 when the receiver's buffer is full), while the sender could send up to the previous window. Data (S4) is checked against the receiver's last window, as written.
- **S4 boundary.** "Starts beyond" means `start > max(seen ACK, highest offset) + k × window`. A segment starting exactly at the limit is stored, so a window of 0 doesn't reject in-order bytes. FIN-only segments after the window count as out-of-window; pure ACKs never count.
- **An ACK never blocks a FIN.** FINs are now checked against the received bytes (the end of the buffer), not the highest offset, which ACK holes can move. When the ACK of a FIN arrives before the FIN, the FIN's position first counts as a missing byte: `highest_offset()` grows by 1 and `holes()` lists it. The FIN then removes it, and `highest_offset()` moves back by 1. A FIN inside an ACK hole is accepted and cuts the hole. Example: bytes 0..3 received, ACK of 10, FIN at 6. The FIN is accepted, the hole becomes 3..6, and the FIN counts as ACKed, because 10 > 6, although that ACK contradicts the FIN. The spec review asked the user to confirm this. The alternative (FINs can't lie before the seen ACK − 1) lets one forged ACK within the window block the real FIN forever.
- **Holes before the ACKed offset can still be filled (D3 vs K4(b)).** Only bytes that were already received are skipped without comparison. Known limit: if the last data segment wasn't captured but was ACKed, a Windows keep-alive's garbage byte at seen ACK − 1 lands in that hole and is stored as data.
- **Each accepted ACK can move the highest offset by up to one window, without data.** Forged ACKs can walk it forward. This allocates nothing (holes after the buffer are not stored), but it widens the S4 limit and will feed the implied ACK of ticket 06 (see ADR-0002's consequences).
- **The ACK of a segment is applied before its data** in `TcpConnection::add_segment`, because the ACK check needs the sender's window from before the segment.
- `hole_give_up_window_factor`'s doc now also says that it limits which bytes are accepted (2 windows with `None`).
- **The "allocates nothing" test is implicit.** A forged segment 1 GiB ahead must leave `highest_offset()` and `holes()` unchanged; before this ticket the test zero-filled 1 GiB. Nothing public counts allocations yet.
- **"No handshake uses the fallback window"** is tested as "SYN-ACK not captured", because a stream without a SYN can't carry data before ticket 07.
- Review findings left as they are (judgement calls):
  - `advertised_window(&self, other)` reads the other stream's SYN option. Window-scale negotiation is a connection-level property, but the fields are private to `TcpStream`.
  - The three-state `window_scale: Option<Option<u8>>` and `window: Option<(u16, bool)>`.
  - Some repetition between the proptests `random_acks` and `out_of_window_segments`.
  - The window tests live in `status()`, because `out_of_window_segments` is where the window is observable.

**2026-10-11 — user confirmed** the four open decisions:
- the ACK limit is one higher once the FIN is known;
- an ACK is checked against the window from before its segment;
- an ACK never blocks a FIN;
- holes before the ACKed offset can still be filled.

spec.md S1, S3, D3, K1 and F1 are updated. The doc of `highest_offset()` now says it moves back to the FIN offset, and `acked_offset()` with it, when a FIN arrives inside bytes that an earlier ACK covered.
