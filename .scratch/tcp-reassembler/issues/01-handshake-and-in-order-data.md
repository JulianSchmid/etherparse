# 01: Handshake and in-order data reach the reader

Parent: ../spec.md

**What to build:** A user creates a `TcpReassemblyPool` with the default `TcpReassemblyConfig` and feeds it, through `process_segment`, the segments of a connection whose handshake was captured. The pool groups both directions under one connection and returns it in `TcpProcessed::active`, together with the role of the sender. The connection has:
- a sorted connection key;
- a pool-assigned connection id, starting at 0;
- observed initiator and responder roles;
- first-seen and last-seen timestamps.

Each stream delivers its in-order bytes as one contiguous slice through `read_received()`, and `consume()` accepts partial amounts. Sequence numbers map to 64-bit offsets that keep growing across 2^32 wrap-around. Window scale options in the SYN and SYN-ACK are parsed and stored for later tickets. Data in the SYN (TCP Fast Open) is delivered at offset 0.

Segments of connections whose handshake was not seen are ignored with `NoConnection` for now; ticket 07 changes that.

This slice also lays the groundwork:
- the `std`-gated `tcp_reassembly` module;
- the value types this slice needs;
- the config with the spec's defaults;
- a test-only builder that writes connections as scripts and produces segments for both directions;
- the reference model, starting with in-order random streams;
- the `AGENTS.md` allocation rule extended to name the new module.

Rules: S1, S2, A1, A3 (parsing only), A7 (observed roles), P4, P7.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [x] A handshake followed by in-order data in both directions delivers both streams byte-exact through `read_received`/`consume`, including partial consumes
- [x] Proptest against the reference model: random ISNs (including ISNs within 2^16 of 2^32) and random in-order segmentation
- [x] Offsets keep growing across several full 2^32 wraps
- [x] TCP Fast Open data in the SYN is delivered at offset 0
- [x] `TcpConnectionKey::new(a, b)` and `TcpConnectionKey::new(b, a)` are equal and hash equally; the config defaults are pinned; the derived traits are tested
- [x] Connection ids start at 0 and increase per connection; `first_seen`/`last_seen` follow the timestamps fed in
- [x] Segments with a different key create a separate connection
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — implemented** on `tcp-reassembler` in three commits: `3a0ffea` (value types + generators), `b9ff8f1` (pool, connection, stream, connection script, reference model), `495c44d` (AGENTS.md allocation rule). Full suite, the documented `cargo test --no-default-features`, the bare-metal no_std build and `cargo +1.83.0 check` pass; module tests stay green at `PROPTEST_CASES=3000` (~2 s). Library code in the module has 100% line/region coverage.

Decisions made while implementing:
- `TcpConnectionKey` keeps its fields private with getters, so the sorted-endpoint invariant can't be broken.
- `read_received()` takes `&mut self` (it records the length for the `consume` clamp), so both streams of a connection can't be borrowed for reading at the same time.
- `TcpProcessed`, `TcpIgnoreReason` and `TcpRead` only have the fields/variants this ticket needs; later tickets add `ended`, the other ignore reasons, `Gap` and `End`.
- The window scale is parsed and stored on `TcpStream` behind `#[allow(dead_code)]`. Its value can't be observed through the public API yet (see ticket 04).
- Overlapping retransmissions are already trimmed (first wins, no conflict counting). Without that, a re-cut segment would lose its new bytes. Wrap handling only shows up for overlaps that cross 2^32, so the proptest re-sends overlapping bytes. A naive `seq > end_seq` comparison is caught by both the unit test and the proptest.
- The spec never defines simultaneous open. The code anchors the responder stream on any SYN from it, but no test pins this.
