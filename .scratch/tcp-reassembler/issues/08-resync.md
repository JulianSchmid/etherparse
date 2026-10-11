# 08: Resync after large sequence jumps

Parent: ../spec.md

**What to build:** A stream that jumps far beyond any plausible window without a SYN recovers:
- Out-of-window data records a candidate position.
- An ACK from the other direction within one window of the candidate triggers a resync. The stream continues behind a `Gap { len: None }`, and `resyncs` is incremented.
- `resync_after_segments = Some(n)` opts in to resyncing after n consecutive agreeing segments, for one-direction captures.
- `force_resync()` makes the next data segment the new anchor.

Rules: R1–R4, S2 (unmappable distances), ADR-0002.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [x] Without confirmation the stream never resyncs; random out-of-window segments are only counted
- [x] An ACK-confirmed resync delivers the following bytes exactly, after `Gap { len: None }`
- [x] `resync_after_segments` has exact tests at n − 1 and n; the count resets when a segment doesn't fit
- [x] `force_resync()` anchors the stream at the next segment
- [x] Distances of 2^31 or more are counted as out-of-window, with exact tests at the boundary
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 04:**
- R1: out-of-window data returns early in `TcpStream::add_segment`, right after `status.out_of_window_segments += 1`. That is where the candidate is recorded.
- R2: implausible ACKs return early in `TcpStream::add_ack` (`ack > sent_end + window`). They have to be kept as resync evidence there. The window is the one the receiver advertised before the ACK's segment.

**2026-10-11 — carry-over from ticket 05:** `TcpRead::Gap { len: Option<u64> }` exists, but only `Some` is produced so far.
- Gaps are stored as `Range<u64>` in `TcpStream::gaps`. A resync gap takes no offsets (the stream continues right after the highest offset), so it needs a marker, e.g. an empty range plus a flag. `read_until`, `consume_gap()` and `gap_at_read_offset()` have to handle it.
- Decide what `gap_bytes` counts for a gap of unknown length (probably nothing).

**2026-10-11 — carry-over from ticket 07:**
- A resync before the first read of a mid-stream pickup: prepending afterwards would move the offsets under the resync's gap. A resync (R2, R4) should end prepending (`TcpStream::can_prepend`), or `prepend` has to move the resync gap too. The same goes for `force_resync()` before the first read.
- Bytes before offset 0 of a pickup that can't take them count as out-of-window (ticket 07, decision 5). Decide whether only S4's forward out-of-window data records a resync candidate (R1), not bytes before offset 0 or after the FIN.
- `pending_ack` is applied again after every packet. If R2 keeps implausible ACKs as evidence, a pending ACK must not count as new evidence each time.

**2026-10-11 — user decisions (asked before implementing):**
1. **Where an ACK-confirmed resync continues:** right after the candidate's bytes. They are not stored (S4) and are part of `Gap { len: None }`, so reading doesn't stall and no extra memory is needed. That one segment is lost. Rejected: continuing at the candidate's first byte (its bytes become a hole that stalls reading until it is overdue, then a second gap), and keeping a copy of the candidate's bytes (a copy of every out-of-window segment, plus one segment of memory per stream).
2. **An ACK before the data confirms it too:** the last ACK beyond the window is kept as evidence. Out-of-window data within one window of it resyncs at once, and that segment becomes the stream's new start, with its bytes stored. A resync, or the stream moving forward, clears the kept ACK.
3. **Forward jumps only:** only data after the window (S4) or at an unmappable distance (S2) becomes a candidate. A new ISN that maps behind the stream (half of all ISN changes) is not detected: bytes before offset 0 stay ignored on an observed start (counted on a pickup), and ACKs behind the seen ACK stay ignored. `force_resync()` recovers such streams. Known limit for the docs (ticket 16).

spec.md R1 and R2 are updated.

**2026-10-11 — user decisions after the review (asked before fixing):**
4. **Decision 1 corrected:** with the ACK after the data, not one segment but all out-of-window data before the first confirming ACK is lost, up to about one window (one round trip). The illustration of decision 1 showed only one segment. The user keeps the decision: these bytes are part of `Gap { len: None }`, and no copies are kept (rejected: copies of the agreeing out-of-window segments, up to one window per stream). A FIN in the candidate's segment, or a FIN without bytes right after it, ends the stream at the resync point, so the stream still finishes (the review found that the FIN was lost and its ACK left a 1-byte hole that never closed).
5. **The ACK that confirms a jump ACKs the bytes before it:** also when it maps before the resync point (it ACKs bytes that fell into the gap). Otherwise `read_acked()` stalls in front of the gap if no later ACK comes.

spec.md R2 is updated.

**2026-10-11 — implemented** (commits `a98d09f` through `1d47c20`):
- `a98d09f`: S2, a sequence number exactly 2^31 from the highest offset can't be mapped. Its bytes or FIN count as out-of-window, an ACK there is kept as resync evidence, and a pickup refuses a SYN there. "2^31 or more" is only this one distance, because serial arithmetic maps every other one before or after the highest offset.
- `7db6015`: `TcpStreamStatus::resyncs`, part of `is_clean()`.
- `16c6c2c`: R1/R2 with the decisions above:
  - `Gap { len: None }` is an empty range in `TcpStream::gaps`;
  - resyncing gives up the holes before the jump;
  - a floor (`resync_offset`) for bytes and FINs from before the jump;
  - a resync ends prepending (A5);
  - the reference model follows R2, because the existing proptests produce such resyncs with their small windows.
- `58d203c`: R3, plus the ACK floor that a resync without a confirming ACK needs.
- `8ba954d`: R4, `force_resync()`.
- `1d47c20`: the model for R3/R4 and the proptest `resyncs`. It covers jumps with and without ACKs, pickups, loss, reordering, injected segments after the window that don't agree, `resync_after_segments` and forced resyncs, and is green at 3000 cases.

The module is fully covered (merged view of `cargo cov`). Manual mutants of every new condition are killed, apart from the equivalent one below. A two-axis review (standards and spec) ran. Its spec review found four real problems; two of them led to the user decisions 4 and 5 above:
- a lost FIN of the candidate;
- an ACK that arrived first and was dropped;
- `read_acked()` stalling in front of the gap;
- more than one lost segment.

The fixes are folded into the commits above, and so are its standards points (commit structure, glossary, a candidate type instead of a tuple). Each rewritten commit passed the module tests.

Decisions taken while implementing, for the user to confirm (spec.md is unchanged for these):
1. **The candidate** is the latest data segment after the window: one with bytes that is not a SYN, while the FIN is unknown. Any other data segment clears it, as does any forward move of the highest offset (data, an ACK or a FIN) and a resync. So with reordering, an earlier segment arriving after the jump's first one clears it; the next bytes after the jump (or an ACK that was kept) restore it.
2. **"Within one window"**: an ACK, or the next segment's first byte (R3), lies at most one receive window before the candidate's first byte or after its last byte. The window is the one S4 uses, i.e. the one advertised before the segment.
3. **The kept ACK** is the latest ACK more than one window after the bytes sent, or one that can't be mapped. ACKs before offset 0 are old ones and don't replace it. Only a resync or a forward move clears it: plausible ACKs that don't move the stream leave it.
4. **At a resync, all holes before the resync point become gaps** and are counted in `gaps`/`gap_bytes`, as nothing can fill them anymore (their sequence numbers map elsewhere).
5. **The resync's gap counts only in `resyncs`**, not in `gaps`/`gap_bytes` (Q4). Resyncs without bytes between them leave one `Gap { len: None }` but count each, unless the reader stepped over the first gap.
6. **After a resync, bytes and FINs before the resync point are ignored without counting**, and are not compared for conflicts. ACKs before it don't count either; this only matters after R3/R4, since a confirming ACK ACKs everything before the jump.
7. **The segment that becomes the new start doesn't count as out-of-window** (its bytes are stored); candidates do.
8. **An ACK that arrived first counts after the new start's bytes**, like the confirming ACK (it ACKs everything before the jump).
9. **FIN without bytes after the window:** it is the candidate's FIN if it starts at the candidate's end. Otherwise it is only counted: it neither counts towards R3 nor clears the candidate.
10. **R3:** other bytes reset the count, `Some(0)` works like `Some(1)`, and the n-th segment becomes the new start with its bytes stored.
11. **`force_resync()`:** the next segment with bytes that isn't a SYN becomes the new start, wherever it lies (in the window, a retransmission, before offset 0). It does nothing before the stream started or after its FIN. While pending, it ends prepending. A keep-alive's filler byte would become data.
12. **`discard_until(offset)` / `discard_all()` keep a resync's gap at `offset`**; discarding past it removes it.
13. **A late SYN after its stream resynced doesn't make the window scale known**, as its ISN no longer lies before the stream's first byte; the fallback window applies.
14. **No resync once the FIN is known**, also not for a candidate recorded before the FIN.
15. **SYNs are never candidates or new starts** (reconnects are C2, ticket 10).

Equivalent mutant:
- Sorting the gaps by start only instead of `(start, end)` in `give_up_holes_before`. Holes are given up from the front and always pushed after the existing gaps, so the sort never reorders anything. The key keeps the order right for any sort algorithm.

Known limits (documentation for ticket 16):
- A jump to a new ISN that maps behind the stream (half of all ISN changes) isn't detected; `force_resync()` recovers it. Streams past 2 GiB can't even tell such a jump from consumed bytes.
- With the ACK after the data, all out-of-window data before the first confirming ACK is lost, up to about one window.
- Spoofed ACKs plus data after the window can force a resync (ADR-0002).
- A FIN without bytes after the window and without a candidate before it is lost.

**2026-10-11 — user decisions on the points above.** The user went through all 15 implementation decisions as illustrated questions, and confirmed every one as implemented:
- Decision 2 was discussed first. The user leaned towards the largest advertised window for "within one window", and asked for pros and cons:
  - pro: busy receivers that advertise window 0 still confirm a jump, as K2 argues;
  - con: the range never shrinks again, so stray or forged ACKs confirm junk more easily, and a false resync makes the real bytes be ignored;
  - con: R3 lets unrelated segments agree.

  The user then kept the last window.
- spec.md now records all of them in R1–R4, A3 and the API (`discard_until`).

Side finding of that discussion, left as it is (known limit for ticket 16): S4 and K1 judge data and ACKs with the receiver's last window. A receiver that shrinks its window's right edge, which RFC 9293 discourages, can make data that was sent into the earlier, larger window count as out-of-window. Such data can then even become a resync candidate.
