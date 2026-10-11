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

- [ ] SYN on a tombstone: new connection with a new id
- [ ] Regression test (old branch): a new-ISN SYN plus the confirming SYN-ACK always hands over the old connection as `Reconnect` and starts a new id, even when the caller drained everything eagerly
- [ ] A new-ISN SYN without a SYN-ACK has no effect (a spoofed SYN can't split a live connection)
- [ ] A retransmitted SYN changes nothing; a SYN on a mid-stream pickup follows C4
- [ ] The reference model is extended with reconnects on the same key
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

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
