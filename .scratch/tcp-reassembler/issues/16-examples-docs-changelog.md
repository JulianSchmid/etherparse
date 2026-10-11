# 16: Examples, docs and changelog

Parent: ../spec.md

**What to build:**
- A self-contained example builds a connection with `PacketBuilder` and reads it back with `read_acked`.
- A second example uses `pcap-parser` 0.17 (a dev-dependency) to read pcap and pcapng without copying packets. It prints each connection's id, roles (observed or guessed), status, end and byte counts.
- The crate docs and the README (generated from them) get a TCP reassembly section.
- RFC 9293, 7323, 5961 and 1982 are added to both reference lists.
- The changelog gets an entry under Unreleased.

**Blocked by:** 08, 09, 10, 11, 12, 13

**Status:** ready-for-agent

- [ ] Both examples build as part of `cargo test`; the pcap example gives plausible output on a real capture, and the capture is described in the PR
- [ ] The crate-docs example is a passing doc-test; the README matches the crate docs, and its docs.rs links point at the current version
- [ ] The RFC lists and the changelog are updated
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — noted in ticket 01's review:** the crate docs (`lib.rs`: "Special attention has been paid to not use allocations or syscalls.") and `README.md` ("... except in the "defragmentation" code.") were already out of sync before this branch. Neither mentions `tcp_reassembly`, which now allocates too. `tcp_stream.rs` cites RFC 1982, and RFC 7323 is used for the window scale option. The `TcpReassemblyPool` doc example currently builds segments from `TcpHeader`s by hand.

**2026-10-11 — carry-over from ticket 05:** the standards review noted that `give_up_hole()`, `consume_gap()`, `discard_until()` and `discard_all()` have no doc test. They are part of the user-facing reading API, so the examples should show the `Gap` / `consume_gap()` loop.
