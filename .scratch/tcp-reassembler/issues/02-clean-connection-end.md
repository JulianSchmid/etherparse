# 02: Connections end cleanly and late packets are absorbed

Parent: ../spec.md

**What to build:**
- The first FIN of a stream sets its FIN offset. Data beyond it is never readable and is counted as out-of-window.
- Once all bytes up to the FIN have been read, reading returns `End(Fin)`.
- When both FINs are ACKed, the connection is finished: the pool hands it over as an owned value in `TcpProcessed::ended`, with the end `Finished`.
- `is_finished()` and `is_complete()` work.
- `recycle()` takes an ended connection back.
- A tombstone keeps the key, so late segments of the ended connection are ignored with `AfterEnd` instead of creating a new connection.

Checking a FIN against the window is added in ticket 04.

Rules: F1 (first FIN wins), F2, F3, F6 (`End(Fin)`), D5, P3.

**Blocked by:** 01

**Status:** ready-for-agent

- [x] Full lifecycle (handshake, data, both FINs, final ACKs): the connection is handed over as `Finished`, both streams read `End(Fin)`, and `is_complete()` is true
- [x] If the last ACK is missing, the connection stays open while both streams report finished
- [x] Every FIN order is tested (initiator first, responder first, simultaneous)
- [x] Data after the FIN is never readable and is counted in `out_of_window_segments`; a second FIN at another offset is ignored
- [x] A late retransmission after the end is ignored with `AfterEnd` and creates no connection
- [x] `recycle()` accepts an ended connection
- [x] The reference model is extended with FIN and close
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — implemented** on `tcp-reassembler` in six commits:
- `2091cec`: value types `TcpStreamEnd`, `TcpConnectionEnd` and `TcpStreamStatus`, plus a generator;
- `1ec455c`: refactor that maps sequence numbers to offsets in one place;
- `b750bce`: test-only refactor of `ConnectionScript` (`segment()` + `push(segment)`), and the reference model state grouped per stream;
- `6f013fc`: FIN handling (F1, F2, D5, `End(Fin)`);
- `6102349`: hand-over as `Finished`, tombstone, `AfterEnd`;
- `35c2b2b`: `recycle()`.

The full suite, the documented `cargo test --no-default-features`, the bare-metal no_std build and `cargo +1.83.0 check` pass. The module tests stay green at `PROPTEST_CASES=3000` (~2.4 s). Every library line and region of the module is covered in the merged `cargo cov show` view. The summary report still lists misses for single instantiations of the generic pool. A review on both axes (standards and spec) ran, and its fixes are folded into the commits above.

Decisions made while implementing:
- **A FIN that lies before bytes already received is ignored**, and not counted. Downside, from the spec review: bytes injected beyond the real FIN, before that FIN arrives, block it. The stream then never finishes, and the injected bytes stay readable. The alternative is to accept such a FIN as long as it lies at or after `read_offset`, and to drop and count the unread bytes beyond it. But that lets an injected FIN cut off real bytes that were received and not read yet, which goes against user story 44. **The user decided on 2026-10-10 to keep ignoring it.**
- Only segments with payload bytes after the FIN count as out-of-window. Pure ACKs and FIN-only segments after the FIN don't count. A second FIN at another offset is ignored without counting; ticket 04 adds counting for FINs beyond the window.
- `status()` and `TcpStreamStatus` (so far with only `out_of_window_segments`) were pulled forward from ticket 03, so that the counter is observable.
- Each stream keeps a private seen ACK (`TcpStream::seen_ack`): the highest ACKed offset, mapped relative to the end of the received bytes, with no plausibility check yet. This way an ACK captured before its FIN still counts. The ACK of a FIN is `fin_offset + 1`.
- **The tombstone is a `TcpConnection`** with `end` set and empty streams. `TcpConnection::hand_over` leaves it in the same map. It keeps the key, id and timestamps. An enum entry would have needed unreachable match arms: the borrow checker doesn't allow conditionally returning `&mut` into the entry and then replacing the entry (NLL problem case 3).
- A segment that finishes the connection returns `active: None` and the connection in `ended`.
- Every segment on a tombstone returns `AfterEnd`, SYNs included; C1 is ticket 10. Late segments don't refresh the tombstone's `last_seen`.
- `recycle()` puts the emptied buffers in an unbounded free list, and new connections take their buffers from it. The tests only check that no old bytes leak into a new connection. Whether a buffer is actually re-used can't be observed yet.
- `is_complete()` equals `is_finished()` for now.
