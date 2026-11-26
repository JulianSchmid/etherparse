# 03: Out-of-order data, retransmissions and holes

Parent: ../spec.md

**What to build:**
- Segments that arrive out of order, duplicated, or re-cut with overlaps are put back in order and delivered exactly once.
- Missing ranges are holes. `holes()` lists them, and reading returns `Pending` at a hole until it is filled.
- For overlapping bytes, the first received content wins. A retransmission with differing bytes increments `conflicting_retransmissions` once per segment. All bytes count as not ACKed until ticket 04.
- `highest_offset()`, `status()` and `is_clean()` report the stream state.
- A stream with a hole before its FIN is not finished.

Rules: D1, D2, F2 (holes), Q1.

**Blocked by:** 01

**Status:** ready-for-agent

- [x] Proptest against the reference model: random segmentation, reordering within a bounded distance, duplicates, and overlapping retransmissions that are cut differently; the result is byte-exact
- [x] Corrupted retransmissions: the first received bytes are delivered, and the counter equals the number of conflicting segments
- [x] `read_received` returns `Pending` at a hole and continues once the hole is filled; `holes()` and `highest_offset()` are checked exactly
- [x] A stream with a FIN but a hole before it becomes finished only once the hole is filled
- [x] A long stream that is consumed in small steps is delivered correctly (exercises buffer compaction)
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 01:** `TcpStream::add_data` maps sequence numbers relative to the end of the contiguous received bytes, and drops data that lies behind missing bytes. S2 asks for mapping relative to the highest offset. This ticket has to switch to that, otherwise one lost segment stalls the stream. Overlap trimming (first wins) already exists; conflict counting (D2) does not. The test block "reading stops at missing bytes" in `tcp_stream.rs` covers today's hole path.

**2026-10-10 — carry-over from ticket 02:** three places rely on data behind missing bytes not being stored:
- `TcpStream::add_segment` checks a new FIN against `received_end()`;
- `is_finished()` compares `received_end()` with the FIN offset;
- `offset()` maps relative to `received_end()`.

Switch them to the highest offset, and to "no holes before the FIN" (F2). The reference model's `ModelStream::add_segment` uses `received.len()` for the FIN check too. `is_complete()` is still just `is_finished()`, so it has to add `is_clean()`. Until then, a stream whose retransmissions carried different bytes (dropped by first-wins) still reports complete.

**2026-10-10 — user decision:** a FIN that arrives before the bytes in front of it is recorded, and the stream finishes as soon as those bytes arrive. A FIN without payload already does this: see "FIN behind missing bytes finishes once they arrive" in `tcp_stream.rs`, and "both FINs are ACKed, but bytes before a FIN are missing" in `tcp_connection.rs`. A FIN segment that carries its own payload behind a hole still loses that payload, because the payload is not stored. This ticket must keep that payload, and test the case at connection level too: the connection ends as `Finished` once the hole is filled.

**2026-10-10 — user decision:** a FIN that lies before bytes already received is ignored (F1). Example: bytes 0..10 are received and a FIN arrives at offset 6; the FIN is dropped and bytes 6..10 stay readable. A real sender never moves its FIN, so either the FIN or the bytes are forged or corrupted. Accepting the FIN would let a forged FIN cut off real bytes that haven't been read yet (user story 44). When the FIN check moves to the highest offset, keep this rule: a FIN before the highest received offset is ignored, even if the bytes in front of it have holes.

**2026-10-10 — implemented** on `tcp-reassembler` in three commits:
- `1993162`: test-only refactor. The reference model tracks the read offsets, and the feed-and-check loop and the interleaved segment cutting move into helpers.
- `823cdbc`: holes. Sequence numbers map relative to the highest offset, bytes behind missing bytes are stored, and `holes()` and `highest_offset()` are added. A FIN behind missing bytes moves the highest offset to it, F2 applies, and the proptest `reordered_streams` covers reordering, duplicates and re-cut retransmissions.
- `5f8cae5`: `conflicting_retransmissions`, `is_clean()`, and `is_complete()` = clean and finished. Corrupted retransmissions are added to `reordered_streams`, and the new proptest `conflicting_retransmissions` checks the counter against an independent count. The regression seeds are committed.

The full suite, the documented `cargo test --no-default-features`, the bare-metal no_std build and `cargo +1.83.0 check` pass. Each commit passes the module tests on its own. With `PROPTEST_CASES=3000` the module tests take about 8.5 s; `reordered_streams` is the slowest at about 6.6 s. Every library line and region of the module is covered in the merged `cargo cov show` view. Hand-made mutants were each caught: no split of a hole, `>` instead of `>=` in the FIN check, no hole before the FIN, broken compaction, and conflict comparison skipping or including hole bytes. A two-axis review ran (standards and spec), and its fixes are folded into the commits above.

Decisions made while implementing:
- **Bytes the user already consumed are not compared for conflicts.** They are no longer buffered. The user decided this on 2026-10-10. D2 in spec.md and "Conflicting retransmission" in CONTEXT.md now say so. For `read_acked()` users nothing changes: their consumed bytes are ACKed, and D3 skips those anyway.
- A FIN behind missing bytes moves the highest offset to the FIN offset, and the missing range is a hole listed by `holes()`. Once the FIN is set, nothing lies beyond it, so `is_finished()` is just "FIN seen and no holes". CONTEXT.md's "Hole" ("with later bytes already received behind them") doesn't quite cover a FIN without payload behind the hole. It was left unchanged.
- Segments without payload (pure ACKs) don't move the highest offset. Otherwise a single injected empty segment could open a large hole.
- `holes()` returns `impl Iterator<Item = Range<u64>> + '_`.
- Holes are zero-filled placeholders in the contiguous buffer (ADR-0001). The buffer only reaches the furthest received byte; a hole up to a FIN beyond it allocates nothing.
- Mapping relative to the highest offset (S2) differs from mapping relative to the end of the contiguous bytes only for distances near 2^31. No test pins it directly.
- `TcpStreamStatus` is now 128 bits, which is the coding-style limit for `Copy`. The spec requires `Copy`, but the counters added by tickets 05, 08 and 11 push it past 128 bits. That conflicts with the coding style, so the user needs to decide.

**2026-10-11 — user decision:** `TcpStreamStatus` no longer derives `Copy`, and `status()` returns `&TcpStreamStatus`. Commit `f9db588`. spec.md is updated.
