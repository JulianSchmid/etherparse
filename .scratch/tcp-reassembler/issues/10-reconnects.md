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
