# 05: Users give up holes and discard data

Parent: ../spec.md

**What to build:** Users decide themselves when data gets dropped:
- `give_up_hole()` turns the hole at the read position into a gap.
- Reading returns `Gap { len: Some(n) }` until the user steps over it with `consume_gap()`.
- `discard_until(offset)` drops unread bytes and gives up holes before `offset`.
- `discard_all()` drops everything buffered, and the stream continues with the next new bytes.
- The status counts gaps and gap bytes.
- Discarding bytes that are present keeps the stream clean; giving up holes does not.

Rules: Q1, Q3, the gap half of F6.

**Blocked by:** 03

**Status:** ready-for-agent

- [x] `Gap` is returned until `consume_gap()` is called; the bytes after the gap are then delivered
- [x] `give_up_hole()` returns false when there is no hole at the read position; `consume_gap()` does nothing when the read position is not at a gap
- [x] `discard_until` is tested with an offset inside the buffer, beyond the highest offset, and before the read offset (no-op)
- [x] After `discard_all()`, new segments continue the stream
- [x] Discarding present bytes keeps `is_clean()` true; giving up a hole makes it false; `gaps`/`gap_bytes` are checked exactly
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-11 — implemented** on `tcp-reassembler` in three commits:
- `826cc69`: refactor, no behaviour change. `truncate_to` cuts the holes with the new function `truncate_ranges`.
- `9da916f`: giving up holes:
  - `give_up_hole()`, `consume_gap()` and `TcpRead::Gap { len: Option<u64> }`;
  - `TcpStreamStatus::gaps` and `gap_bytes`;
  - `is_clean()` checks gaps;
  - the reference model learns gaps, and the new proptest `reader_actions` loses and delays segments, adds ACKs after the sent bytes, and lets the reader give up holes and step over gaps. Afterwards, giving up every hole must let both streams be read to their highest offset, and a captured FIN must end its stream.
- `fca3f9d`: `discard_until()` and `discard_all()`. The model and `reader_actions` learn discarding, at offsets shortly or far after the read position.

Checks:
- The full suite, the documented `cargo test --no-default-features`, the bare-metal no_std build, `cargo +1.83.0 check` and `cargo fmt --check` pass.
- Each commit passes the module tests and `cargo fmt --check` on its own (checked in a scratch worktree).
- With `PROPTEST_CASES=3000` the module tests take about 10 s. Run alone, `reordered_streams` takes 9.5–10 s; at `f9db588` it took 7.9–9.2 s on the same machine, so the model's per-byte gap checks cost at most about 10%. `reader_actions` takes about 6 s.
- Every library line and region of the module is covered in the merged `cargo cov show` view.

Hand-made mutants were each caught. The ones in the gap code:
- no gap bytes counted;
- no cutting of gaps at a FIN;
- no clamp in `discard_until`;
- gaps not removed by discards;
- `discard_all` one byte short;
- holes and gaps merged in the wrong order.

The ones in the review fixes:
- empty holes left behind (this one hung the drain loop until it got a step limit);
- `head` not clamped to the end of the buffer;
- the FIN checked against the end of the buffer instead of the received bytes;
- no move back of the read position;
- bytes in a gap not skipped.

Equivalent mutants in this ticket, because a gap only ever exists at the read position:
- `read_until` ignoring gaps: a gap at the read position is returned first;
- `differs_from_received` comparing gap bytes: bytes in the gap at the read position are skipped before the comparison;
- the sort in `give_up_holes_before`: new gaps always lie after the only gap;
- `give_up_holes_before` giving up whole holes instead of the parts before the offset: since discards no longer count gaps, `give_up_hole()` is its only caller, and it always passes the end of the first hole. F5 (ticket 09) is the next caller.

A two-axis review (standards and spec) ran, and its fixes are folded into the commits above:
- the field doc of `Gap.len`;
- "discard" instead of "drop" (CONTEXT.md avoids "dropped bytes");
- one helper `give_up_holes_before` instead of duplicated counting;
- the test-side `ReaderAction` enum, generated directly;
- the refactor in its own commit;
- the model tests in the commits of the code they test;
- a FIN lost after a give-up (decision 2);
- bytes in a gap no longer appended to the buffer;
- an accurate `gap_bytes` doc;
- a strict FIN check in `reader_actions`, which used to pass vacuously.

Decisions made while implementing (please confirm; spec.md is unchanged):
1. **`discard_until(offset)` clamps `offset` to `highest_offset()`.** It never discards bytes that haven't arrived yet; `discard_until(u64::MAX)` equals `discard_all()`. This keeps the read position at or before the highest offset, which the holes, the ACK holes and the window checks are based on. Users who want to skip bytes that haven't arrived yet (e.g. the rest of a long message body) call it again once they arrived. The alternative, a read position after the highest offset, would need the highest offset moved with it (widening the window checks), or holes that start at the read position.
2. **F1 refined: a FIN only has to lie at or after the received bytes.** If it lies before the read position, the read position moves back to it. This happens when the user gave up or discarded bytes up to an ACK after the FIN. The bytes in between never existed. S1 says offsets only grow, so it needs this as a second exception, next to the highest offset that moves back to the FIN.
   - Found by the spec review: the ACK of a FIN arrives before the FIN (ticket 04 makes the FIN's position a 1-byte hole), and the user calls `discard_all()`, or `give_up_hole()` plus `consume_gap()`. The real FIN then lay before the read position and was ignored, so the stream never finished.
   - Test: "a FIN before the read position, ..." in `fin_offset()`, and at connection level in `end()`.
3. **Bytes that arrive after they were consumed or given up are ignored entirely.** They are not stored, not compared for conflicts, and they don't count as received bytes in the F1 check. Example: a gap 3..10 from an ACK, then bytes 3..8 arrive. A FIN at 6 is still accepted.
4. **The counters never decrease.**
   - `gaps` counts each hole that was given up; a hole given up in parts (first partly discarded, then given up) counts once per part.
   - `gap_bytes` counts the bytes when they were given up. A FIN that later cuts a gap doesn't reduce it; the doc says "Number of bytes in the holes that were given up".
   - Consequence: giving up the 1-byte hole at a FIN's position, whose ACK arrived first, counts a gap and makes the stream unclean, although no byte was missing.
5. **`read_acked()` returns the gap at the read position whatever the ACKed offset is.** A gap is a permanent break, so there's nothing to wait for.
6. **The connection only notices a give-up with its next segment.** Giving up the last hole can finish a stream, and with both FINs ACKed the connection too. The pool only notices with the connection's next segment (pinned in `end()`). In real captures that segment often never comes, so the connection stays in the pool until it is evicted, as `Evicted` once ticket 12 lands. See the carry-over on ticket 12.
7. **Gaps are kept in their own sorted `Vec<Range<u64>>` next to the holes.**
   - `missing()` merges holes and gaps;
   - `give_up_holes_before(offset)` moves the parts of holes before an offset into the gaps and counts them;
   - both already work for gaps anywhere, which tickets 06 and 09 need.
8. `consume_gap()` doesn't need a read before it, and it clears the last read like `discard_until()` does.

Review findings left as they are (judgement calls):
- No doc tests on the new methods; ticket 16 adds the examples.
- `feed_and_check(pool, segments, consume_lens, acked_reads, actions)` has a long parameter list, and four proptests pass `&[None]`.
- Repeated `(status.gaps, status.gap_bytes)` tuple asserts in the tests.
- `TcpStream::gaps` (the ranges) next to `TcpStreamStatus::gaps` (the count).

**2026-10-11 — user confirmed** the decisions:
- `discard_until` clamps to the highest offset (1);
- a FIN before the read position moves the read position back to it (2); S1 gets this as a second exception;
- the counters never decrease (4);
- `read_acked()` returns a gap whatever the ACKed offset (5);
- for decision 6, eviction checks F3 first, so a connection the user finished ends as `Finished` (P6, ticket 12).

spec.md is updated: API (reading and dropping data), S1, F1, P6 and the new Q4. The doc of `read_offset()` now says it can move back, folded into `9da916f`.

**2026-10-11 — user decisions on reordering** (the core target: the reassembler does the heavy lifting when segments arrive out of order, so readers reconstruct streams easily):
- **Discards don't count as gaps.** `discard_until()` and `discard_all()` drop the holes before the offset without counting them, so the stream stays clean (Q3 in spec.md). Otherwise a parser that skips data while it still arrives out of order would turn a merely late segment into a gap. This replaces decision 4's "a hole given up in parts counts once per part": parts can't be given up through the API any more. Folded into `fca3f9d` (was `2bd3e2a`), with a reworded commit message.
- **Gaps from the K4 rules are lazy** (ticket 06): a hole that K4 may give up stays fillable until the read position reaches it. Recorded in spec.md K4 and F2, and on ticket 06.
- `give_up_hole()` stays immediate and final: the user gives up the hole they are waiting at.

