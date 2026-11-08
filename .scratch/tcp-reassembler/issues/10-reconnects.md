# 10: Reconnects

Parent: ../spec.md

**What to build:**
- A SYN on a tombstone starts a new connection with a new connection id.
- A SYN with a new ISN on an open connection is kept as pending. The connection is replaced only when a SYN-ACK ACKs the new ISN + 1:
  - the old connection is handed over as `Reconnect`, with its holes turned into gaps and its reads ending in `End(Reconnect)`;
  - the new connection becomes `active` with a new id.
- A retransmitted SYN with the same ISN changes nothing.
- A SYN on a mid-stream pickup follows A5 if it qualifies, and the pending-SYN rule otherwise.

Rules: C1–C4, F5, F6 (`End(Reconnect)`).

**Blocked by:** 02, 05, 07

**Status:** ready-for-agent

- [x] SYN on a tombstone: new connection with a new id
- [x] Regression test (old branch): a new-ISN SYN plus the confirming SYN-ACK always hands over the old connection as `Reconnect` and starts a new id, even when the caller drained everything eagerly
- [x] A new-ISN SYN without a SYN-ACK has no effect (a spoofed SYN can't split a live connection)
- [x] A retransmitted SYN changes nothing; a SYN on a mid-stream pickup follows C4
- [x] The reference model is extended with reconnects on the same key
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 02:** every segment on a tombstone returns `AfterEnd`, SYNs included. The late-segment test in `TcpReassemblyPool::process_segment` feeds `segments[1..]`, so it doesn't pin this for the SYN. A tombstone is a `TcpConnection` with `end()` set, so C1 can replace it in place.

**2026-10-11 — carry-over from ticket 05:** F5 for `Reconnect` works like for resets: `TcpStream::give_up_holes_before(highest_offset)` (see ticket 09).

**2026-10-11 — carry-over from ticket 06:**
- The keep-alive filter test in `TcpStream::holes()` feeds a 1-byte segment with the SYN flag into an open connection and expects it to fill the hole. Adapt it once SYNs on open connections go through C2/C3.
- The old connection's holes become gaps through `TcpStream::give_up_all_holes()`.

**2026-10-11 — carry-over from ticket 07:**
- C4: `TcpStream::add_segment` counts a SYN that `observe_start` refuses as out-of-window and returns early. That is where a pickup's SYN goes through C2. Counters never decrease (Q4), so decide whether such SYNs still count.
- A SYN with another ISN on a stream with an observed start is still applied as an ordinary segment (its TCP Fast Open bytes are stored at their mapped offset). C2/C3 must catch it first.
- `observe_start` returns true without a change on streams with an observed start, also for the ACK of a SYN-ACK with a new ISN, so C2's check has to come before it in `TcpConnection::add_segment`.
- A reconnect of a connection with guessed roles starts with observed roles.

**2026-10-11 — carry-over from ticket 08:**
- After a resync, `TcpStream::start_seq` no longer belongs to the stream's ISN. C2/C3 must compare a SYN's ISN with the ISN of the observed start, not with `start_seq`, or a retransmitted SYN after a resync looks like a reconnect. A late SYN after a resync doesn't make the window scale known (test in `status()`), which C3 must keep.
- SYNs are excluded from resyncs (no candidate, no new start, no clearing), so C2 decides alone what a SYN with a new ISN does.

**2026-10-11 — carry-over from ticket 09:**
- `TcpConnection::add_segment` ends every connection through `self.end`: after `after_packet`, `TcpStream::connection_ended(TcpStreamEnd)` gives up the holes of both streams (F5) and stores the end for reads (F6). `Reconnect` needs an arm in the `TcpConnectionEnd → TcpStreamEnd` match there. `give_up_all_holes()`, which the carry-overs of tickets 05 and 06 name, is gone.
- `Finished` is only set while `end` is `None`, so an end set during the packet wins.
- An RST with the SYN flag is handled as an RST before any SYN logic (`add_reset` vs `add_data_segment`), so C2 never sees it.

**2026-10-11 — user decisions (asked before implementing):**
1. **A SYN that a pickup can't take is judged by its position (C4):** a SYN whose ISN + 1 lies at or before offset 0 and at most k windows before it (the A5 range) is the stream's own late SYN. A5 takes it if it can; otherwise it is counted as out-of-window and ignored, as decided on ticket 07. Any other SYN on a pickup goes through C2. Rejected: every SYN that A5 doesn't take goes through C2. A late handshake in a reordered capture after a consume would then split the connection in two, and the bytes after the split would lie behind a gap in the new connection.
2. **A stream without a start checks the kept ACK:** a SYN is the stream's own late SYN if the other side's kept ACK of the stream (K1) lies at or after ISN + 1 and at most k windows after it, or if no such ACK was seen. Otherwise it goes through C2. This detects a reconnect after a pickup in which the client only sent ACKs. Rejected: any SYN on a stream without a start is its own (as implemented in ticket 07); the new connection's bytes then end up in the old connection behind a resync.
3. **A pending SYN is not counted:** it touches no stream and no counter, but it counts as a packet of the old connection for `last_seen` (P7) and `ack_reorder_tolerance` (K4(b)), like an ignored RST, and is returned in `active`. A confirmed reconnect leaves no trace in the old streams. Rejected: counting it in `out_of_window_segments` on arrival (a confirmed reconnect would leave a count of the new connection's SYN on the old stream), and counting it once it led to no reconnect (the count would change on a later packet).
4. **Only a new ISN starts a connection on a tombstone (C1):** a SYN or SYN-ACK starts a new connection unless its ISN equals the ISN of its sender's stream in the ended connection. Such a late retransmission stays `AfterEnd`, so late duplicates of the old handshake create no ghost connections. Tombstones of pickups know no ISN, so any SYN or SYN-ACK starts a new connection there. Rejected: every SYN and SYN-ACK (ghost connections), and only pure SYNs (a reconnect whose SYN was not captured would be absorbed until the tombstone is evicted).

spec.md C1, C2 and C4 are updated.

**2026-10-11 — user decisions after the review (asked before fixing):**
5. **A SYN-ACK whose ISN isn't its stream's own changes nothing** unless it confirms a reconnect: it counts as a packet (`last_seen`, `ack_reorder_tolerance`), like a kept SYN, and its bytes, ACK, window and A2 start are ignored. "Own" is judged as for SYNs (C3/C4: the ISN of an observed start, otherwise by position). A reconnect whose SYN was not captured still resyncs the old streams, one packet later. Rejected: applying it as an ordinary segment (its ACK could give a stream without a start an observed start at the foreign ISN, and its bytes were stored where they mapped), and applying only its ACK (it would replace the kept ACK that C4 compares SYNs against).
6. **Any kept SYN arms the reconnect:** while a SYN is kept, a SYN-ACK of the other endpoint confirms the reconnect if it ACKs the kept SYN and doesn't repeat the ISN of its sender's stream (C3), or if it isn't its sender stream's own SYN-ACK at all. The reconnect starts with the kept SYN if the SYN-ACK ACKs it, otherwise at the SYN-ACK, as on a tombstone. A lone spoofed SYN still changes nothing, and a SYN in the gap between the real SYN and its SYN-ACK no longer hides the reconnect. Rejected: the last SYN wins (the reconnect's bytes would merge into the old connection behind a resync, against story 41), and keeping the last 4 SYNs.
7. **The tombstone keeps the kept SYN:** a connection that ends while a SYN is kept (an RST, or the kept SYN is the packet that makes its last hole overdue for F3) leaves it in its tombstone. A SYN-ACK on the tombstone that ACKs it starts the reconnect with the SYN (TCP Fast Open bytes, window scale, `first_seen`); a SYN on the tombstone starts it with that SYN (C1). Rejected: the end drops the kept SYN.
8. **A reconnect ends a connection whose two FINs were both ACKed as `Finished`**, as eviction does (P6): no more packets of it come, so every hole the seen ACK covers counts as overdue. Otherwise it ends as `Reconnect`. Rejected: always `Reconnect`.
9. **A SYN-ACK that ACKs the SYN of the other stream belongs to the old handshake on a tombstone** (`AfterEnd`), besides one with the ISN of its sender's stream. The `resets` proptest found the ghost connection that decision 4 alone left: SYN, RST, late SYN-ACK whose stream had no start yet.
10. **The SYN-ACK replays the kept SYN if it ACKs from ISN + 1 up to the end of the SYN's bytes**, so a server that accepts the TCP Fast Open bytes doesn't lose them. Rejected: exactly ISN + 1.
11. **Late segments of a replaced connection count as out-of-window in the reconnect**, as no tombstone is left after a confirmed reconnect; they map far away from its ISNs and store nothing. Rejected: absorbing them silently (extra state per reconnect).

spec.md C1, C2 and C4 are updated.

**2026-10-11 — implemented** (commits `b92333a` through `8ed51fb`, decisions in `6aa508d` and `9c74b73`):
- `b92333a` (refactor): the pool picks the initiator of a new connection (`new_connection_initiator`, `handshake_initiator`) and creates connections (`new_connection`) in one function each; `TcpConnection` gets `end_with` and `role`; the reference model gets `end_with` and `range`.
- `f5bb559`: C1. Streams remember the ISN of their observed start (`TcpStream::isn`), and tombstones keep it (`TcpStream::tombstone`). `TcpConnection::is_own_handshake` tells late segments of the old handshake (decisions 4 and 9).
- `810247d`: C2/C3 with decisions 3 and 5–11. `TcpConnection` keeps a SYN that is not its stream's own (`ReconnectSyn`, a copy of the segment); `confirms_reconnect` decides on SYN-ACKs; the pool starts the reconnect (replaying the kept SYN if the SYN-ACK ACKs it) on tombstones and in place of open connections in one path; `end_replaced` ends the old one as `Finished` or `Reconnect`. New variants `TcpConnectionEnd::Reconnect` and `TcpStreamEnd::Reconnect`.
- `692a4c7`: C4 with decisions 1 and 2 (`TcpStream::is_own_syn` by position, for SYNs and SYN-ACKs). The reference model keeps SYNs, confirms reconnects and starts again as the new connection; the harness checks the connection a reconnect hands over.
- `8ed51fb`: `ConnectionScript::incarnation` and the proptest `reconnects` (old connection open, finished or reset, captured or picked up, with loss; reconnect from either endpoint with TCP Fast Open bytes; retransmitted and spoofed SYNs). Green at 3000 cases.

The module is fully covered (merged view of `cargo cov`). Manual mutants of every new condition are killed by the module tests, apart from these equivalent or not yet observable ones:
- `false` → `true` for the roles of the reconnect in `new_connection(.., false, ..)`: the SYN or SYN-ACK it starts with gives a stream an observed start from the role A7 expects, so the roles are confirmed anyway.
- `observe_start` returning `true` instead of `false` for a sequence number it can't map: SYNs that can't be mapped no longer reach it (C4 keeps them), and the SYN-ACK path ignores the result. The test that such an ACK gives no observed start kills a mutant that maps it anyway.
- Dropping the push of the kept SYN's buffer to the free list: not observable until the allocation test of ticket 12.

Review (standards and spec, both axes):
- The spec review led to decisions 5–8 (asked, see above) and to the confirmation of 9–11. A model bug it didn't name was found by the new proptest: `predicts` accepted a data segment that "ACKed" the kept SYN.
- The standards review's commit findings are fixed: the refactors moved into `b92333a`, the fixups are squashed, and long lines are wrapped. `initiator` is renamed `new_connection_initiator` (it was shadowed by a local), the model builds its next connection in one function, and `ReconnectSyn` hides its fields behind `is_acked_by`, `timestamp` and `into_buffer`.
- Judgement calls left as they are: the `(initiator, roles_guessed)` and `(next_id, free_buffers)` pairs (three call sites, borrows of different pool fields); `ReconnectSyn` parses its copy again (`.ok()` can't fail; a parsed copy would duplicate `TcpSlice`); the repeated TCP flag checks; the reference model's own `TcpConnectionEnd → TcpStreamEnd` match (it is the oracle); the proptest in its own commit after the behaviour commits (as in tickets 03–09).

Decisions taken while implementing, confirmed by the user on 2026-10-11 via illustrated questions (C2 in spec.md now names 1):
1. **Ids and timestamps of a reconnect:** its id is assigned when it starts (C1 or a confirming SYN-ACK), so SYNs that are never confirmed use no ids. Its `first_seen` is the replayed SYN's timestamp, otherwise the starting segment's. The replaced connection's `last_seen` is its last packet, which can be the kept SYN; the confirming SYN-ACK is a packet of the reconnect only.
2. **A retransmission of the kept SYN keeps the first one**, so `first_seen` is the first SYN's timestamp.
3. **The kept SYN is a copy of its segment:** one allocation per connection that keeps one, re-used for later SYNs, and returned to the free list when the reconnect starts. It is replayed through `TcpSlice::from_slice` and `add_segment`.

Known limits (documentation for ticket 16):
- A reconnect whose SYN and SYN-ACK were both not captured continues the old connection behind a resync, once the ACKs confirm the jump (R2).
- A reconnect SYN whose ISN lies by chance within k windows before a pickup's first byte, or before the kept ACK of a stream without a start, is taken as the stream's late SYN (probability about k × window / 2^32, 0.2 % with the defaults).
- Late segments of a replaced connection count as out-of-window in the reconnect (decision 11).
- A kept SYN that no SYN-ACK confirms stays until the connection ends; it has no timeout.

**2026-11-08 — council review:** the kept SYN of a reconnect (decisions 3, 5–11, the known limits above about kept SYNs) is gone: a SYN or SYN-ACK with a new ISN from an endpoint of an open connection starts the reconnect right away, in either capture order, and the connection that replaced another absorbs late duplicates of the replaced handshake like a tombstone (spec C1, C2 with the decision history). The only kept SYN left is the simultaneous open's (S5).
