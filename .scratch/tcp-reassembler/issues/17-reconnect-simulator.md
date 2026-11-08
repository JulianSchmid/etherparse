# 17: Ground-truth simulator for reconnects and late segments, with a trace view

Parent: ../spec.md

**Why:** Council rounds 24 to 32 each found one more benign scenario in the same area, late segments of a replaced connection after a reconnect with a nearby ISN, and each fix was followed by a neighbouring scenario (the TIME-WAIT ACK, its RST, a lost FIN, the RST captured first, new ISNs inside the old spans). The scenario space is a product of several dimensions, and two properties of the test setup kept it dark: the model proptests never generate near-ISN reconnects (ISNs of different scripts lie 2^30 apart, a decision of ticket 10), and the reference model mirrors the code's rules, so it can only catch code-versus-model mismatches, never a wrong rule. The fixes also made C1 long. A simulator with ground truth replaces the reviewers as the source of scenarios, and a trace view lets a human see what the pool did with a failing case.

**What to build:**

1. **A world generator** (`etherparse/src/tcp_reassembly/simulator.rs`, test-only like `reference_model.rs`): endpoints that behave like TCP stacks do, producing the true segment sequence of a *history* of connections on one four-tuple, each segment labelled with the real connection it belongs to and the offsets of its bytes. Per connection: handshake (or none: the capture starts mid-stream), data in both directions with window scaling, close (FIN exchange with the last ACK, simultaneous close, or an RST by either side, or no close), and then a reuse of the four-tuple by the next connection with an ISN chosen like stacks choose it:
   - far away (random), as today;
   - Linux TIME-WAIT reuse: the new client ISN is the old `snd_nxt + 65537` and the server accepts;
   - near and below the old end (RFC 6528 clock behind a fast stream): the server in TIME-WAIT answers the SYN with an ACK of the old FIN, the client replies `<SEQ=SEG.ACK><CTL=RST>` without ACK flag and retransmits the SYN with the same ISN after the TIME-WAIT socket died;
   - reuse after an RST or a crash without TIME-WAIT: ISNs drawn inside the old spans;
   - ISNs near 2^32 so the numbers wrap.
   The world also emits what real stacks emit late: a retransmitted FIN in LAST-ACK, an older pure ACK, bytes in flight when the peer aborted, retransmissions of the handshake.
2. **A capture layer** that turns the true sequence into what a capture shows: loss of any segment (also the SYN-ACK, the FINs and the last ACK), reordering with a bounded skew (merged taps), the capture starting at a random segment (pickup), one direction only, duplicates. Every captured segment keeps its label.
3. **A truth oracle**, independent of the rules in `reference_model.rs`: after feeding the capture, for every real connection whose handshake (or first bytes) was captured, exactly one pool connection carries it, with its captured bytes readable in order, without fake gaps (a gap only where the capture lost bytes), with the end the world produced (`Finished`, `Reset`, `Reconnect` when the next connection started before the close was captured), and no ghost connection exists (every pool connection maps to a real one; ids are consecutive). Cases that are genuinely ambiguous for a passive observer are excluded by the generator, each exclusion with a comment naming the spec's known limit. The generator never produces hostile traffic.
4. **A trace view**: a text timeline of a scenario, one line per segment with its time, direction, flags, sequence and ACK numbers relative to each real connection's ISNs, the real connection it belongs to, and the pool's decision (which connection took it, dropped by S5, absorbed as a late segment, started a reconnect, out-of-window) with each stream's state after it (start, highest, acked, holes, end). The proptest prints the trace of the minimal failing case. An HTML sequence diagram rendered from the same trace is the second step, once the text form is useful.
5. **Coverage**: the generator enumerates the near-ISN dimensions deliberately (the ISN relations above × which close packets were lost × the capture order of the late segments) rather than hoping random draws hit them; the random dimensions stay random.

**Then:** with the simulator green, try removing rules of C1 one by one (mutation testing against the simulator) and keep only the ones a scenario needs. Rewrite C1 from the surviving rules.

**Blocked by:** none (the code of tickets 01 to 12 is implemented; 14 overlaps, the simulator is its reconnect half with a truth oracle)

**Status:** ready-for-agent

- [ ] `simulator.rs` generates histories with all ISN relations listed above and the late segments stacks emit, with labels
- [ ] the capture layer applies loss, skewed reordering, pickup, one-direction capture and duplicates, keeping labels
- [ ] the truth oracle checks delivery, gaps, ends, ids and ghost connections per real connection; every generator exclusion names a known limit of the spec
- [ ] the trace view prints the timeline of a failing minimal case; the HTML diagram is a follow-up
- [ ] the simulator proptest is green with `PROPTEST_CASES=3000` and the enumerated dimensions are each hit by at least one case per run (asserted, not hoped)
- [ ] rules of C1 that no scenario needs are removed, C1 is rewritten from what remains, and the council reviews the result
- [ ] `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-11-08 — created during the council review (rounds 24 to 32).** The round 32 fixes (expected-position precedence, the span rule gated on an incomplete handshake, the SYN-SENT RST) are the last rule patches before this ticket; the unit tests written during the rounds (TIME-WAIT with and without the lost close, both capture orders, the merged-tap last ACK, older ACKs, in-flight bytes, FIN retransmissions, overlapping spans after a reset, the one-direction FIN) are the seed scenarios the simulator has to reproduce. The owner decided on 2026-11-08 to build the simulator instead of continuing the round-by-round fixes.

**2026-11-08 — simulator results (`simulator.rs`, tests `reconnect_matrix` and `reconnect_histories`):** the 960-scenario matrix and the random histories pass at 3000 cases and on ten fixed seeds, with an eager reader. What the simulator found and what was done:
- Rules the code needed (C1): late segments are absorbed only while the sender's stream has no start in the reconnect (on one path, an endpoint's old segments can't arrive after its first new one), which replaced the "sent nothing" condition and the handshake gate; the SYN-SENT RST rule wins over the expected-position precedence (an absorbed ACK can move the expected position onto the RST); the old spans extend by k windows past their ends for bytes the capture lost (which subsumed the earlier "at the end or one after it" rule and the move of the end by absorbed bytes, both removed); a stream the capture never saw has no first byte but stands at its peer's kept ACK (K1). C4: a SYN in a pickup's A5 range after a FIN of the connection starts a reconnect (a late own SYN never arrives after a FIN).
- Rules removed as redundant: a mutant check against the simulator at 3000 cases decides; the kept-ACK position survived such a check once and was then needed by a later case, so a surviving mutant is evidence, not proof.
- World constraints (realism, not limits): an endpoint's late segments arrive before its first segment of the next connection; the capture's skew keeps each direction's order; a client in SYN-SENT drops an ACK that ACKs its SYN instead of answering with an RST (RFC 9293 3.10.7.3); a reuse never repeats the old ISN exactly; the pool runs without a hole limit (losses of single bytes exceed the default, and the limits are the reference model's domain).
- Known limits the oracle skips, each named in `known_limit` and in C1/C4 of the spec: a lost SYN with the SYN-ACK captured after the client's bytes (the tombstone absorbs them); late segments of a connection the pool never saw (the capture started at its close); the old end coinciding with the new ISN + 1; both new ISNs inside the old spans with a lost handshake half (and lost bytes); a handshake half in the A5 range of a pickup without a FIN before it (the reconnect starts at the other half or not at all).
- Oracle shape: eager reading after every segment (so C4's "read from" condition is live); ends and bytes are sets of acceptable outcomes where a close completes after a replacing SYN; a single byte right before the peer's ACK arriving at a stream without a start is a keep-alive filler (D3) and not expected.
- Reference model: two mismatches of its offset mapping after a resync (the span's first byte can lie before offset 0) were fixed on the way.

**Open (owner):** the simulator's default windows are large (4 MiB fallback), so the k-window tolerances are 8 MiB; a run with small windows and window scaling is a follow-up, as is the HTML sequence diagram of the trace.
