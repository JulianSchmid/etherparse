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

- [ ] An in-window RST hands the connection over as `Reset { by }`; leftover bytes and gaps are readable, followed by `End(Reset)`
- [ ] Regression test (old branch): an injected out-of-window RST is ignored and the connection stays open
- [ ] An RST from a direction never seen is accepted
- [ ] Late segments after a reset are ignored with `AfterEnd`
- [ ] The reference model is extended with RSTs, both real and injected
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 02:** a connection ends by setting `TcpConnection::end` in `add_segment`. The pool hands over every connection whose `end()` is set, through `hand_over()`, which leaves the tombstone. `TcpStreamEnd` and `TcpConnectionEnd` only have `Fin` and `Finished` so far. For `End(Reset)`, the streams also need to know how the connection ended.

**2026-10-11 — carry-over from ticket 05:** for F5 (all holes become gaps), use `TcpStream::give_up_holes_before(highest_offset)`. It counts the gaps and keeps them sorted. Reading then returns `Gap { len: Some(n) }` at each of them, and `consume_gap()` steps over it.

**2026-10-11 — carry-over from ticket 06:**
- F5 can use `TcpStream::give_up_all_holes()`, which the `Finished` end already calls.
- The keep-alive filter test in `TcpStream::holes()` feeds a 1-byte segment with the RST flag and expects it to fill the hole, because RSTs are not handled yet. Adapt it once an in-window RST ends the connection.
