# 14: Reference-model chaos test and old-branch regressions

Parent: ../spec.md

**What to build:** A single proptest runs whole connections through the pool with every transformation from the spec's testing decisions at once:
- random ISNs (including ISNs near 2^32), with and without the handshake;
- reordering, duplication, and drops (with and without a later retransmission);
- corrupted retransmissions, and reordering of the two directions against each other;
- keep-alives, window changes and reconnects;
- injected out-of-window segments, RSTs and FINs;
- captures with only one direction.

The reference model's expected delivered bytes, gaps, status counters and end reasons must match. This ticket also checks that every failure mode of the old branch has a regression test.

**Blocked by:** 06, 07, 08, 09, 10, 11, 12, 13

**Status:** ready-for-agent

- [ ] The combined proptest is green with `PROPTEST_CASES=3000` and runs in under 30 s with the default case count
- [ ] Each of these failure modes of the old branch has a named regression test, whether here or in an earlier ticket:
  - a stall after capture loss;
  - an invisible reconnect;
  - an injected FIN blocking the real one;
  - an injected RST closing the connection;
  - a 1-byte hole flood;
  - a pure ACK creating an entry;
  - a keep-alive as the first segment
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-11 — carry-over from ticket 07:** the reference model handles pickups: a base per stream, prepends, pending ACKs, guessed roles. It assumes ports that make the guess right; wrong guesses are only unit-tested. `mid_stream_pickups` shows how to start a capture at a random segment and capture lost segments later.

**2026-10-11 — carry-over from ticket 08:** the proptest `resyncs` in `reference_model.rs` covers jumps (with and without ACKs, pickups, loss, reordering, injected segments, `resync_after_segments`, forced resyncs). The combined proptest should include jumps too. The model works on true offsets, so it can't express jumps to sequence numbers behind a stream or 2^31 away; unit tests cover these. The spec review noted that the model states the resync rules much like the code does (candidate list, clearing, kept ACK); only its offset mapping is independent of the code.

**2026-10-11 — carry-over from ticket 09:**
- The model handles RSTs (`ModelStream::accepts_reset`, `ReferenceModel::apply`).
- The proptest `resets` shows how to place an endpoint's RST at a point in time: its sequence number and ACK come from the segments before it.
- The combined proptest should include real and injected RSTs. Random windows rarely hit the exact boundaries; the unit tests in `TcpConnection::end()` pin them.
- The regression test "an injected RST closing the connection" is in `TcpConnection::end()`.

**2026-10-11 — carry-over from ticket 10:**
- The model handles several connections on one key: segments carry `ConnectionScript::incarnation`, and the model starts again as a new connection on C1 and on a confirmed reconnect (`ReferenceModel::apply` returns the replaced one). ISNs of different scripts must lie far apart per endpoint (the `reconnects` proptest adds 2^30 to the old ISN of the same endpoint), as the model assumes they never map into each other's streams.
- `ReferenceModel::predicts` leaves out segments it can't predict: segments of another script on an open connection apart from SYNs and SYN-ACKs, and those too while a stream has neither a start nor a kept ACK (its role in the old connection is unknown to the model). The combined proptest should feed through `feed_and_check`, which applies this filter.
- The regression test "an invisible reconnect" is the drained-reader block in `TcpReassemblyPool::process_segment`.
- The final check of `reconnects` only holds without spoofed SYNs and old SYN retransmissions: those can start connections on tombstones of pickups (decision 4).

**2026-10-12 — carry-over from ticket 11:** the model applies all memory limits (proptest `memory_limits`), so the combined proptest can draw small limits too. The harness asserts the bounds at every step. Proptest wrote no failure seeds for the failures found in ticket 11; check whether the seed persistence still works.

**2026-10-12 — carry-over from ticket 12:**
- The harness can evict. `feed_and_check` takes `evictions: &[bool]` (evict all before a segment), and `evict_and_check` checks the evicted connection against `ReferenceModel::evict` and reads it to its end with `check_to_end`. The model then starts again as a new connection on the key.
- The chaos test should evict at random points, and evict once more at the end, then check that `stats()` shows an empty pool (as the proptest `evictions` does).
- The harness uses `()` timestamps, so only `evict_all` is model-checked. `evict_older_than`'s strict `<` and the tombstone refresh of late segments are unit-tested.
