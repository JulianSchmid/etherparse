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

**2026-10-11 — carry-over from ticket 07:**
- F4 accepts an RST "if that stream has never been seen". A stream can now have been seen (pure ACKs) without a start (`start_seq` is `None`). Decide which one F4 means.
- The `read_received` test block "other segments at the position of a keep-alive" pins that a 1-byte segment with RST starts a stream with its byte as data. Adapt it when RSTs end connections.
- RSTs of unknown keys start no connection, also with bytes or a SYN (`process_segment` test).

**2026-10-11 — carry-over from ticket 08:**
- RSTs are still handled like other segments, so an RST with bytes after the window can become a resync candidate or a new start, and an RST with bytes in the window clears the candidate. F4 should keep RSTs out of the resync rules (`TcpStream::add_segment`, the block before the S4 count).
- After a resync, the sender stream's sequence numbers map relative to the new start (`start_seq`), so an RST from before the jump maps far away and is ignored as out-of-window; that is presumably right.
- F5 (`give_up_all_holes`) keeps the resync's gap, an empty range in `TcpStream::gaps`, so reads show `Gap { len: None }` before `End(Reset)`.
