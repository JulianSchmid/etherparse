# TCP reassembler

Status: ready-for-agent

Vocabulary: `CONTEXT.md`. Decisions with lasting impact: ADR-0001 (contiguous buffers that users pull from) and ADR-0002 (inferring the receiver's state). Terms in **bold** are defined in `CONTEXT.md`.

## Problem Statement

Users of etherparse who analyse captured traffic, such as protocol analysers, IDS-style monitors and forensic tools, get TCP segments one packet at a time. What they actually need is the byte **streams** of each **connection**. Today they have to build a reassembler themselves, and doing that robustly is hard:

- Captures lose packets.
- Segments arrive out of order, duplicated, or retransmitted with different content.
- Captures start in the middle of connections.
- Sequence numbers wrap around.
- The same ports get reused by a **reconnect**.
- Only one direction may have been captured.
- Attackers can inject segments or try to exhaust memory.

A naive reassembler either stalls forever after capture loss, silently merges a connection with its reconnect, or hands out bytes the receiver never accepted. etherparse already solves the equivalent problem for IP fragments with `IpDefragPool`, but has nothing for TCP.

## Solution

A new `tcp_reassembly` module, gated on the `std` feature, provides a `TcpReassemblyPool`.

**Feeding and identifying connections**
- Users feed it every captured packet, either already sliced or as a TCP segment built from parts after IP defragmentation.
- The pool groups segments into connections by **connection key**. The key consists of the VLAN IDs, both endpoints, and an optional user-defined **channel id**.

**Reading**
- Each connection exposes two streams, one per role (**initiator** and **responder**).
- Users pull the readable bytes of a stream as one contiguous slice. They choose per call whether they want all received bytes or only the ACKed ones.
- **Gaps** are reported explicitly so parsers can reset.
- Reading tells the user when no more bytes can come and why.

**Robustness**
- The pool handles retransmissions, reordering, sequence-number wrap-around and **mid-stream pickup**.
- It gives up **holes** automatically when the reader reaches them, once the receiver must already have the missing bytes (**implied ACK**). Until then, late segments still fill them.
- It recovers from large sequence jumps (**resync**) and detects reconnects.
- Every stream reports how it started and ended, and whether it is **clean** or **complete**.

**User control and lifecycle**
- Users can drop data themselves at any time.
- Ended connections are handed over as owned values; their buffers can be returned to the pool for re-use.
- Configurable limits bound memory use.
- Processing never fails and never panics on input data.

## User Stories

1. As a tool developer, I want to feed every captured packet into one reassembly pool, so that I get the streams of all TCP connections without managing connection state myself.
2. As a tool developer, I want to pass a `SlicedPacket` directly to the pool, so that reassembly fits into my existing parsing loop.
3. As a tool developer, I want to pass a `LaxSlicedPacket` to the pool, so that truncated or partly broken captures can still be reassembled.
4. As a tool developer, I want to pass a TCP segment built from parts (VLAN IDs, IP addresses, channel id, TCP slice), so that I can reassemble TCP that was IP-fragmented and put back together by `IpDefragPool` first.
5. As a tool developer, I want non-TCP packets and IP-fragmented TCP to be ignored with a stated reason, so that I can feed the pool every packet without filtering first.
6. As a tool developer, I want to add my own channel id to the connection key, so that identical connections from different capture interfaces or tunnels stay apart.
7. As a tool developer, I want the VLAN IDs to be part of the connection key, so that connections in different VLANs stay apart. I also want to be able to leave them out, so that captures where a device rewrites VLAN tags still pair up both directions.
8. As a tool developer, I want both directions of a connection to map to the same connection, so that I can see request and response side by side.
9. As a tool developer, I want every connection to get a unique connection id from the pool, so that the per-connection state I keep never merges a connection with its reconnect.
10. As a tool developer, I want to know which endpoint is the initiator and which is the responder, so that I can tell client data from server data.
11. As a tool developer, I want to know whether the roles were observed from the handshake or guessed from the ports, so that I know how much to trust them.
12. As a protocol parser author, I want to read the contiguous received bytes of a stream as one slice, so that my parser can work on contiguous memory without copying.
13. As a protocol parser author, I want to consume only as many bytes as my parser used, so that incomplete messages stay buffered until more data arrives.
14. As a tool developer, I want to read only the bytes the receiver has ACKed, so that I only process data the receiver actually accepted.
15. As a tool developer, I want to choose per read whether I get received or ACKed bytes, so that one pool serves both kinds of consumers.
16. As a protocol parser author, I want gaps to be reported explicitly and to have to step over them, so that my parser never joins bytes from both sides of a gap.
17. As a protocol parser author, I want to know a gap's length when it is known, and to see that it is unknown after a resync, so that I can decide whether to resynchronise my parser by length.
18. As a protocol parser author, I want reading to tell me that a stream has ended and whether it ended by FIN, reset, eviction or reconnect, so that I can tell a clean end from an abort.
19. As a protocol parser author, I want "nothing readable yet" to be clearly different from "nothing more will come", so that I know whether to wait or finish up.
20. As a tool developer, I want streams to be reconstructed from their first byte when the handshake was captured, so that I get complete application data.
21. As a tool developer, I want streams to be reconstructed when the capture starts in the middle of a connection, so that long-running connections are not lost.
22. As a tool developer, I want to know whether a stream has an observed start or is a mid-stream pickup, so that I know whether its first bytes are a message boundary.
23. As a tool developer, I want a stream to still get an observed start when the capture briefly reorders its first packets (late SYN, earlier data arriving later), as long as I haven't read from it yet, so that merged captures from two tap ports don't lose their starts.
24. As a tool developer, I want retransmitted bytes to be delivered only once, so that my output contains no duplicates.
25. As a tool developer, I want out-of-order segments to be put back in order, so that the stream is delivered as it was sent.
26. As a security monitoring developer, I want retransmissions that change not-yet-ACKed bytes to be flagged, with the first received bytes kept, so that I notice ambiguous streams that could be evasion attempts.
27. As a tool developer, I want keep-alive probes and other retransmissions of ACKed bytes to be ignored, so that idle connections don't get flagged as conflicting.
28. As a tool developer, I want sequence-number wrap-around to be handled transparently, so that very long or very fast connections are reassembled correctly.
29. As a tool developer, I want all stream positions as 64-bit offsets from the stream's first byte, so that positions never wrap and are easy to compare.
30. As a tool developer, I want holes caused by capture loss to become gaps automatically when my reader reaches them, once the receiver has ACKed past them or must have received them (implied ACK), so that streams never stall after packets were lost in the capture, while late segments still fill the holes my reader hasn't reached.
31. As a tool developer, I want a hole that an ACK covers to stay fillable for at least a configurable number of packets, so that reordering between the two directions in a merged capture doesn't create false gaps.
32. As a tool developer, I want to configure how many windows of later data make a hole permanent, or switch that rule off, so that I can tune or disable inference for my traffic.
33. As a tool developer, I want to configure the window that is assumed when the real one is unknown (mid-stream pickup, one-direction capture), so that inference still works with a size that suits my traffic.
34. As a tool developer, I want the window scale option to be honoured when the handshake was captured, so that inference uses the real receiver window.
35. As a tool developer, I want to give up the hole at the read position myself, so that I decide when waiting for a retransmission is no longer worth it.
36. As a tool developer, I want to discard all data and holes before a given offset, so that I can skip to a point I care about.
37. As a tool developer, I want to discard everything buffered and continue with the next new bytes, so that I can drop data I'm not interested in.
38. As a tool developer, I want to force a resync, so that I can recover a stream I know has jumped.
39. As a tool developer, I want a large sequence jump without a SYN to be resynced automatically once the other direction's ACKs confirm it, so that streams continue after a missed reconnect or huge capture loss.
40. As a tool developer analysing one-direction captures, I want an opt-in rule that resyncs after a number of consecutive segments agree on the new position, so that streams recover even without ACKs.
41. As a tool developer, I want a reconnect (a SYN with a new ISN on the same key) to end the old connection and start a new one with a new id, so that the two are never merged.
42. As a security monitoring developer, I want a SYN with a new ISN on an open connection to replace it only once a SYN-ACK confirms the new ISN, so that a spoofed SYN can't split a live connection.
43. As a security monitoring developer, I want RSTs to end a connection only when their sequence number lies within the window, so that blindly injected RSTs are ignored.
44. As a security monitoring developer, I want FINs outside the window to be ignored and the first plausible FIN to win, so that an injected FIN can't block or truncate the real stream.
45. As a tool developer, I want a connection to count as finished only once both FINs are ACKed, so that reading ACKed bytes never loses the last bytes of the connection.
46. As a tool developer, I want ended connections (finished, reset, replaced by a reconnect, evicted) to be handed to me as owned values, so that I can read leftover bytes at my own pace.
47. As a tool developer, I want all remaining holes of a connection that ended without finishing to become gaps, so that I can still read every buffered byte.
48. As a performance-conscious developer, I want to return an ended connection to the pool, so that its buffers are reused instead of new ones being allocated.
49. As a tool developer, I want late packets of an ended connection to be absorbed instead of starting a new mid-stream connection, so that no ghost connections appear.
50. As a tool developer, I want pure ACKs, FIN-only segments and RSTs of unknown connections not to create connections, so that stray packets don't fill the pool.
51. As a tool developer, I want to evict connections idle since before a timestamp of my choice, with a callback that lets me drain them first, so that I control timeouts with my own clock type.
52. As a tool developer, I want to evict all connections at the end of a capture with the same callback, so that I can flush everything that's left.
53. As a tool developer, I want to use my own timestamp type, so that the pool works with whatever clock or capture timestamps I have.
54. As a tool developer, I want each connection's first-seen and last-seen timestamps, so that I can report durations and pick idle connections.
55. As a tool developer, I want each stream to report counts of gaps, missing bytes, resyncs, conflicting retransmissions, rejected bytes and out-of-window segments, so that I can judge its quality.
56. As a tool developer, I want to ask whether a stream is clean (no defects so far) and whether it is complete (clean, observed start, finished), so that I can classify streams at a glance.
57. As a tool developer, I want to ask whether a stream is finished, so that I know whether bytes before its FIN can still arrive.
58. As a tool developer, I want to see a stream's current holes and its read, ACKed, highest and FIN offsets, so that I can debug or visualise reassembly.
59. As a security monitoring developer, I want per-stream limits on buffered bytes and on the number of holes, so that one hostile connection can't exhaust memory, even with 1-byte holes.
60. As a security monitoring developer, I want optional pool-wide limits on the number of connections and on total buffered bytes, so that memory stays bounded however many connections an attacker opens.
61. As a tool developer, I want bytes that don't fit a limit to be rejected and counted, with nothing I haven't consumed thrown away automatically, so that data loss is always visible and under my control.
62. As an operator, I want pool statistics (connections, tombstones, buffered bytes, rejected connections, ignored packets), so that I can monitor the reassembler.
63. As a performance-conscious developer, I want steady-state processing with recycled connections to allocate no new buffers, so that throughput stays predictable.
64. As a tool developer, I want processing to never return an error and never panic on input data, so that hostile or broken traffic can't crash my tool.
65. As a security monitoring developer, I want the connection table to resist attacker-chosen keys, so that hash flooding can't degrade performance.
66. As a no_std user of etherparse, I want the reassembler to be gated on the `std` feature, so that my builds are not affected.
67. As an etherparse user, I want the reassembler to add no runtime dependencies, so that my dependency tree doesn't grow.
68. As a new user, I want a self-contained example that builds a connection and reads it back, so that I can learn the API quickly.
69. As a tool developer, I want an example that reassembles a real pcap or pcapng file and prints each connection's roles, status, end and byte counts, so that I can try the reassembler on my own captures.
70. As an etherparse maintainer, I want the reassembler to be checked against a reference model, mutation testing and fuzzing, so that its correctness doesn't depend on hand-picked cases.
71. As an etherparse maintainer, I want the crate docs, README, changelog and RFC reference lists updated, so that the feature is discoverable and its standards are traceable.

## Implementation Decisions

### Scope and constraints

- A new public module `tcp_reassembly`, gated on `std` in the same way as `defrag`. The `AGENTS.md` rule "no allocations outside `defrag`" is extended to name it.
- No new `[dependencies]`. Dev-dependencies for examples and test frameworks are fine.
- MSRV stays 1.83. It may be raised to a release that is at least a year old (up to 1.90 as of 2026-10) when that simplifies the code noticeably, e.g. `HashMap::get_disjoint_mut` (1.86) or `HashMap::extract_if` (1.88). A raise is its own commit and updates `rust-version` in both crates.
- Processing is infallible: it returns no `Result`. Library code never panics on input data.
- The code is written from scratch. The old `tcp-reassembly` branch is only a source of failure modes (see Testing Decisions).
- The repo's coding style applies: one public type per file, `false == x`, its rules for derives and docs, and one test function per method.

### Architecture

- **One pool entry per connection.** It holds both streams, so the ACKs and window from one direction update the other stream with a single lookup.
- **Contiguous buffers that users pull from** (ADR-0001). Each stream keeps one contiguous buffer, and users read it as a slice and then consume it. Buffers come from the pool's free list and go back to it.
- **Inferred receiver state** (ADR-0002). Holes become **overdue** by implied ACK and by ACK coverage, and become gaps once the reader reaches them. A large jump is followed by a resync once ACKs confirm it.
- **Ended connections are handed to the user as owned values.** The pool keeps a **tombstone** for the key, without buffers, so late segments are absorbed. A reconnect SYN or eviction removes the tombstone.
- **Unique connection ids.** The pool numbers connections in creation order, so a connection and its reconnect never share an id.
- **The connection table uses std's `RandomState` hasher**, because the keys are attacker-controlled.

### Public API

The generic parameters are named `Timestamp` and `CustomChannelId`, as in `IpDefragPool`. Both default to `()`.

**`TcpReassemblyPool<Timestamp, CustomChannelId>`**
- `new(config)` and `Default`. `config()` returns the configuration.
- `process_sliced_packet(packet, timestamp, channel_id)`, `process_lax_sliced_packet(packet, timestamp, channel_id)` and `process_segment(segment, timestamp)` all return `TcpProcessed`.
- `get_mut(key)` and `iter_mut()`.
- `evict_older_than(cutoff, callback)` (requires `Timestamp: PartialOrd`) and `evict_all(callback)` both return the number of evicted connections. The callback gets `&mut TcpConnection` before the pool recycles the buffers.
- `recycle(connection)` returns an ended connection's buffers to the pool.
- `stats()` returns `TcpPoolStats`.

**Processing results**
- `TcpProcessed` has three public fields:
  - `active`: the connection the segment was applied to, plus the role of its sender;
  - `ended`: an owned connection ended by this packet;
  - `ignored`: a `TcpIgnoreReason`, set when the packet was applied to no connection.
- `TcpIgnoreReason` is one of `NotTcp`, `NoConnection`, `AfterEnd` or `TooManyConnections`.
- `TcpPoolStats` contains connections, tombstones, buffered bytes, rejected connections and ignored packets.

**Inputs and identity**
- `TcpSegment<CustomChannelId>` has the fields VLAN IDs (up to 3), source and destination `IpAddr`, channel id, and the `TcpSlice`.
- `TcpConnectionKey<CustomChannelId>` has the fields VLAN IDs, `[SocketAddr; 2]` sorted lower first, and channel id. Its `new` constructor sorts the endpoints.
- `TcpConnectionId` is a value newtype over `u64`.
- `TcpRole` is `Initiator | Responder`, with `other()`.

**`TcpConnection<Timestamp, CustomChannelId>`**
- `id()` and `key()`.
- `endpoint(role)` and `roles_guessed()`.
- `stream(role)` and `stream_mut(role)`.
- `first_seen()` and `last_seen()`.
- `end()` returns an `Option<TcpConnectionEnd>`, where `TcpConnectionEnd` is `Finished | Reset { by: TcpRole } | Evicted | Reconnect`.

**`TcpStream`**
- Reading:
  - `read_received()` and `read_acked()` return `TcpRead`. Both return a gap at the read position, whatever the ACKed offset (user decision, 2026-10-11).
  - `consume(len)` is clamped to the bytes the last read returned.
  - `consume_gap()` does nothing unless the read position is at a gap.
- Dropping data: `give_up_hole()` returns a `bool`, plus `discard_until(offset)`, `discard_all()` and `force_resync()`. `discard_until` treats offsets after the highest offset as the highest offset, so it never discards bytes that haven't arrived yet; `discard_all()` equals `discard_until(highest offset)` (user decision, 2026-10-11).
- Positions: `read_offset()`, `acked_offset()`, `highest_offset()` and `fin_offset()`, plus `holes()`, an iterator of offset ranges. `holes()` lists overdue holes too, as late segments can still fill them; it doesn't mark them (user decision, 2026-10-11).
- Classification: `status()`, `is_finished()`, `is_clean()` and `is_complete()`. `is_finished()` follows F2, so an overdue hole before the FIN keeps it and `is_complete()` false.

**Reading and status types**
- `TcpRead` has four variants:
  - `Data(&[u8])`;
  - `Gap { len: Option<u64> }`, where `len` is `None` after a resync;
  - `Pending`;
  - `End(TcpStreamEnd)`, where `TcpStreamEnd` is `Fin | Reset | Evicted | Reconnect`.
- `TcpStreamStatus` is not `Copy`, because it is larger than the 128 bits the coding style allows for `Copy`. `status()` returns a reference. It contains:
  - `start` (`TcpStreamStart`: `Observed | MidStreamPickup`). A stream without a start yet reports `MidStreamPickup`, so the value only ever changes to `Observed` (user decision, 2026-10-11);
  - `gaps` and `gap_bytes`;
  - `resyncs`;
  - `conflicting_retransmissions`, counting segments;
  - `rejected_bytes`;
  - `out_of_window_segments`.

**Derives**
- Value enums and newtypes: `Copy, Clone, Debug, Eq, PartialEq, Hash`, plus `Ord` where meaningful.
- `TcpConnection` and `TcpStream` own buffers and derive `Clone, Debug`.

### Configuration (`TcpReassemblyConfig`, with these defaults)

| Field | Default | Meaning |
|---|---|---|
| `max_stream_buffer` | 8 MiB | per stream, from the read position to the furthest buffered byte |
| `max_holes_per_stream` | 256 | |
| `hole_give_up_window_factor` | `Some(2)` | k in the implied-ACK rule; `None` switches the window rule off |
| `fallback_window` | 4 MiB | used whenever the receiver's window is unknown |
| `ack_reorder_tolerance` | 16 packets | after how many packets an ACK-covered hole becomes overdue |
| `resync_after_segments` | `None` | opt-in resync without ACK confirmation |
| `max_connections` | `None` | tombstones count towards it |
| `max_total_buffered` | `None` | pool-wide |
| `max_pooled_buffers` | 64 | buffers kept per kind in the free list |
| `max_pooled_buffer_capacity` | 64 KiB | recycled buffers are shrunk to this |

### Behaviour rules

The rule ids are for referencing from tickets and test names.

**Sequence space (S)**
- **S1** Each stream maps 32-bit sequence numbers to `u64` stream offsets. Offset 0 is the first byte: ISN + 1 on an observed start, or the first byte seen on a mid-stream pickup. Offsets only grow. The highest offset moves back only when a FIN cuts a hole an ACK created (F1), and the read offset with it if the user gave up the bytes after the FIN (user decision, 2026-10-11).
- **S2** Sequence numbers are mapped with RFC 1982 serial arithmetic relative to the highest offset seen. A distance of 2^31 or more cannot be mapped and counts as out-of-window.
- **S3** The window is the receiver's last advertised window shifted by its window scale. It is used only when the scale is known (A3) and at least one packet of the receiver was seen. Otherwise `fallback_window` is used. An ACK is checked against the window the receiver advertised before the ACK's segment, because the sender could only send into that window. The window in the ACK's own segment may already have shrunk, to 0 when the receiver's buffer is full (user decision, 2026-10-11).
- **S4** Data is out-of-window if it starts beyond `max(seen ACK, highest offset) + k × window`, where k = `hole_give_up_window_factor`, or 2 when that is `None`. Such data is not stored, increments `out_of_window_segments`, and becomes a resync candidate (R1).

**Anchoring (A)**
- **A1** A SYN gives the initiator stream an observed start. Payload in the SYN (TCP Fast Open) is data at offset 0.
- **A2** A SYN-ACK gives the responder stream an observed start. If the SYN was not seen, its ACK number also gives the initiator stream an observed start; on a mid-stream pickup it counts as the initiator's late SYN (A5) (user decision, 2026-10-11).
  - Known limit: if the SYN carried TCP Fast Open bytes that the SYN-ACK ACKs, and the SYN is captured after the SYN-ACK, the initiator stream starts after these bytes and they are lost. This is documented (user decision, 2026-10-11).
- **A3** The window scale is known only if both SYN and SYN-ACK were seen. Per RFC 7323, a missing option on either side means scale 0 for both directions.
- **A4** On a mid-stream pickup, the first data segment of a stream puts offset 0 at its first byte.
  - A FIN without bytes puts offset 0 at the FIN, so the stream is empty and finished, and the connection can finish. Such a stream takes nothing in front afterwards (A5), as a reader may have read its end (user decision, 2026-10-11).
  - A 1-byte segment without SYN, FIN or RST that ends at the last ACK the other side sent before the stream had a start is a keep-alive and doesn't start the stream. As a connection's very first packet, the ACK is not known, so its filler byte becomes byte 0 (user decision, 2026-10-11).
- **A5** Until the read position of a mid-stream pickup first moves forward (a consume of at least 1 byte, `consume_gap`, or a discard that moves it; reads, `consume(0)` and `discard_until(0)` don't count):
  - bytes that start at most k × window before offset 0 (k and window as in S4) are prepended, and the offsets shift, with the FIN, the holes, the seen and implied ACK and the ACKs of K4(b);
  - a late SYN under the same conditions, or the ACK number of a late SYN-ACK (A2), upgrades the stream to observed start.

  A pickup that started at a FIN without bytes takes nothing in front (A4). After that, such bytes count as out-of-window, once per segment, and the segment's bytes from the read position on are still stored. Such a SYN counts as out-of-window and is ignored with its bytes, until C4 sends it through C2. On a stream with an observed start, bytes before offset 0 are ignored without counting, because the filler byte of a keep-alive lies there when no bytes were sent yet. A `consume(n)` after a prepend consumes nothing until the next read, because the bytes the last read returned are no longer at the read position (user decisions, 2026-10-11).
- **A6** Pure ACKs, FIN-only segments and RSTs (also with bytes or a SYN) for unknown keys never create a connection (`NoConnection`) (user decision, 2026-10-11).
- **A7** Roles: the SYN sender is the initiator and the SYN-ACK sender is the responder. Without a handshake the roles are guessed: the lower port is the responder, and on equal ports the sender of the first packet is the initiator. A late SYN or SYN-ACK that gives a stream an observed start confirms guessed roles if its sender has the role the guess gave it. One that contradicts the guess leaves the roles guessed; roles never change (user decision, 2026-10-11).

**Data (D)**
- **D1** First wins: overlapping bytes keep the content received first.
- **D2** A retransmission whose overlapping not-yet-ACKed bytes differ increments `conflicting_retransmissions` once per segment. ACKed means a seen ACK or the implied ACK. Bytes the user already consumed are not compared, because they are no longer buffered (user decision, 2026-10-10).
- **D3** Bytes before the ACKed offset in a retransmission are ignored without comparison. This covers keep-alive probes. Missing bytes before the ACKed offset are still stored, because captures can show an ACK before the data it acknowledges. Known limit: if an ACKed segment was not captured, a keep-alive's garbage byte at seen ACK − 1 fills the last byte of its hole while that hole is not overdue yet (user decision, 2026-10-11).
  - In an overdue hole (K4), a segment without SYN, FIN or RST that carries exactly 1 byte and ends at the seen ACK is ignored and touches no counter. It has the shape of a keep-alive, whose byte is filler (RFC 1122 4.2.3.6), and a receiver discards it too. Without this rule, lazy gaps would let a keep-alive put a garbage byte into the stream until the reader reaches the hole (user decision, 2026-10-11).
- **D4** Limits:
  - Bytes beyond `max_stream_buffer` are rejected and counted as `rejected_bytes`.
  - A segment that would exceed `max_holes_per_stream` is rejected entirely.
  - `max_total_buffered` rejects in the same way pool-wide.
  - A rejected segment's position still advances the highest offset, so the implied ACK keeps moving; the bytes it didn't store become a hole.
- **D5** Data beyond the FIN offset is out-of-window.
- **D6** With truncated payload (lax input or a short snapshot length), only the captured bytes are added; the rest stays a hole. The FIN flag of a truncated segment is ignored.

**ACK and implied ACK (K)**
- **K1** A stream's seen ACK is the highest plausible ACK number seen in the other direction.
  - An ACK beyond `highest offset + window` is ignored, except as resync evidence (R2). Once the FIN offset is known, the limit is one higher, so the ACK of the FIN counts even with a window of 0. The window is the one from before the ACK's segment (S3) (user decision, 2026-10-11).
  - An ACK beyond the highest offset turns the uncaptured bytes up to it into a hole.
  - An ACK never moves the ACKed offset past the FIN offset and never adds holes after it.
  - An ACK that a stream can't apply yet, because it has no start, or because the ACK lies at or before offset 0 while bytes can still be prepended (A5), is kept and applied after every packet until it counts. The last such ACK is kept, as ACKs before a start can't be ordered, and a forged one is then replaced by the next real one (user decision, 2026-10-11).
- **K2** The implied ACK is `highest offset − k × window`, saturating at 0. It applies only while `hole_give_up_window_factor` is `Some(k)`. It is updated after every packet of the connection, and the checks inside a packet use its value from before that packet.
  - The window is the largest window the receiver has advertised, as the sender can have sent bytes into a larger window before the window shrank, e.g. to 0 when the receiver's buffer is full. The fallback window applies only while no window is known (S3). With the last window, an ACK that advertises window 0 would make the hole it adds overdue at once, without waiting for `ack_reorder_tolerance` (user decision, 2026-10-11).
  - The implied ACK never moves back, e.g. when the window grows: bytes sent earlier still prove what the receiver had ACKed then (user decision, 2026-10-11).
- **K3** The ACKed offset is `max(seen ACK, implied ACK)`. `read_acked()` returns contiguous bytes up to it.
- **K4** A hole is **overdue** once its end lies at or before either:
  - (a) the implied ACK, or
  - (b) the seen ACK as it was `ack_reorder_tolerance` packets ago. Every packet applied to the connection counts, in either direction, as for `last_seen` (P7). The packet whose ACK covers the hole doesn't count, so the hole is overdue after the N-th packet after it. The bytes of a packet are stored before the packet's overdue check, so the N-th packet still fills the hole (user decision, 2026-10-11).

  A hole is overdue as a whole, never in parts: a hole that is only partly before these offsets is not overdue. One lost range thus gives one gap (user decision, 2026-10-11).

  K4(b) also holds for a hole that a prepend (A5) adds before an ACK seen earlier, so a pickup that can still prepend keeps the ACKs of the last `ack_reorder_tolerance` packets even without holes (user decision, 2026-10-11).

  Gaps are lazy (user decision, 2026-10-11):
  - an overdue hole stays a hole, and late segments still fill it, so the reassembler never drops bytes the reader hasn't reached;
  - the overdue hole at the read position becomes a gap as soon as it is overdue. This is checked after every packet and after every move of the read position, so reads, `holes()`, `status()` and `consume_gap()` always agree, whether or not the user has called `read_*()`. The gap is read as `Gap` and counted;
  - when a connection ends, its remaining holes become gaps (F5);
  - at eviction (P6), no more packets come, so every hole that the seen ACK covers counts as overdue.

**Resync (R)**
- **R1** Out-of-window data records the latest candidate: data after the window (S4) or at a distance that can't be mapped (S2). Bytes before offset 0 (A5) or after the FIN (D5) are no candidates. So a jump to a new ISN that maps behind the stream, half of all ISN changes, is not detected; `force_resync()` recovers such a stream (user decision, 2026-10-11).
- **R2** An ACK from the other direction within one window of the candidate triggers a resync. The stream continues right after the candidate's bytes, mapped to the highest offset, behind a `Gap { len: None }`. The candidate's bytes are not stored (S4) and are part of that gap, so reading doesn't stall and no extra memory is needed. So is all out-of-window data before the confirming ACK, up to about one window (user decisions, 2026-10-11). A FIN in the candidate's segment, or a FIN without bytes right after it, ends the stream at the resync point. `resyncs` is incremented.
  - An ACK beyond the window that arrives before the data counts too. The last such ACK is kept until a resync or until the stream moves forward. Out-of-window data within one window of it triggers the resync at once and becomes the new start, with its bytes stored (user decision, 2026-10-11).
  - The ACK that confirms a jump counts after the resync, and it ACKs at least all bytes before the resync point: the receiver ACKed bytes after the jump, so it has the ones before it, or they belong to a connection that is over (user decision, 2026-10-11).
- **R3** With `resync_after_segments = Some(n)`, n consecutive out-of-window segments that each lie within one window of the previous one also trigger a resync.
- **R4** `force_resync()` makes the next data segment the new anchor, the same as R2.

**FIN, RST and ends (F)**
- **F1** The first FIN within the window sets the FIN offset. Later FINs at other offsets are ignored. A FIN that lies before bytes already received is ignored.
  - An ACK never blocks a FIN. A FIN inside a hole that an ACK created is accepted, cuts the hole, and moves the highest offset back to the FIN offset. It counts as ACKed if the seen ACK lies after it. Otherwise one forged ACK within the window could keep the stream from ever finishing (user decision, 2026-10-11).
  - "Received" means stored: bytes that arrive after they were consumed or given up are ignored and don't count. A FIN that lies before the read position, because the user gave up or discarded bytes up to an ACK after it, is accepted and moves the read position back to it. Example: the ACK of a FIN arrives before the FIN, and the user gives up the FIN's position (user decision, 2026-10-11).
- **F2** A finished stream has its FIN seen and no holes before the FIN offset. Overdue holes count as holes, because late segments can still fill them, and because otherwise `is_complete()` would turn from true to false once the reader reaches such a hole (user decision, 2026-10-11).
- **F3** A finished connection has both FINs seen and ACKed, and every hole it has left is overdue. It ends as `Finished`, and its remaining holes become gaps (F5), so both streams are then finished (user decision, 2026-10-11).
- **F4** An RST is accepted if its sequence number lies within one window of the sender stream's highest offset, or if that stream has never been seen. It ends the connection as `Reset { by }`.
- **F5** When a connection ends, for any reason, all its holes become gaps and are counted, so its status is final when it is handed over. Late segments go to the tombstone (P3) and can't fill them anymore (user decision, 2026-10-11).
- **F6** `read_*()` returns `End(..)` once everything readable has been read and no more bytes can come. On an ended connection, `read_acked()` returns `End` even if un-ACKed bytes remain; `read_received()` still returns them.

**Reconnect (C)**
- **C1** A SYN on a tombstone creates a new connection right away.
- **C2** A SYN with a new ISN on an open connection is kept as pending. A SYN-ACK that ACKs the new ISN + 1 replaces the connection: the old one comes back in `ended` as `Reconnect`, and the new one is `active`. Without that SYN-ACK the pending SYN has no effect.
- **C3** A SYN with the same ISN is a retransmission and changes nothing.
- **C4** A SYN on a mid-stream pickup goes through A5 if it qualifies, and through C2 otherwise.

**Pool (P)**
- **P1** The key comes from the packet's VLAN IDs, IP addresses and ports, plus the channel id. The endpoints are sorted.
- **P2** Non-TCP packets and IP-fragmented TCP are ignored with `NotTcp`.
- **P3** A connection that ends other than by eviction leaves a tombstone with its key, id and last-seen time. Late segments are ignored with `AfterEnd`. A SYN (C1) or eviction removes the tombstone. Tombstones count towards `max_connections`.
- **P4** Connection ids start at 0 and increase by one for each new connection.
- **P5** The free list keeps at most `max_pooled_buffers` buffers per kind. Recycled buffers are shrunk to `max_pooled_buffer_capacity`.
- **P6** `evict_older_than` ends connections with `last_seen < cutoff` as `Evicted` (F5). A connection that is already finished (F3), e.g. because the user gave up its last hole after both FINs were ACKed, ends as `Finished` instead; `evict_all` does the same (user decision, 2026-10-11). For this check, every hole that the seen ACK covers counts as overdue (K4). Otherwise a connection that closed cleanly, with fewer than `ack_reorder_tolerance` packets after the ACK that covered its last hole, would end as `Evicted` (user decision, 2026-10-11). It calls the callback and then recycles their buffers. It also removes tombstones older than the cutoff. The return value counts evicted connections only, not tombstones.
- **P7** Every processed packet of a connection updates `last_seen`. `first_seen` is the timestamp of its first packet.

**Status (Q)**
- **Q1** `is_clean()` holds when there are no gaps, resyncs, conflicting retransmissions or rejected bytes.
- **Q2** `is_complete()` holds when the stream is clean, has an observed start, and is finished.
- **Q3** Discarding doesn't affect cleanliness, also where bytes were missing: discarded holes are not gaps. The user doesn't want these bytes, and a parser that skips data that still arrives out of order would otherwise turn a merely late segment into a gap (user decision, 2026-10-11). Holes given up with `give_up_hole()` or by K4 are gaps and do affect it.
- **Q4** Status counters never decrease. `gaps` counts every hole given up, and `gap_bytes` its bytes at that time, even if a later FIN shows that fewer bytes existed (user decision, 2026-10-11).

### Examples and docs

- A self-contained example builds a connection with `PacketBuilder` and reads it back with `read_acked`, in the style of the existing IP defragmentation example.
- A pcap example reads pcap and pcapng through the `pcap-parser` 0.17 dev-dependency, using its streaming reader that doesn't copy packets. It prints each connection's id, roles (observed or guessed), status, end and byte counts.
- The crate-level docs and the README (generated from them) get a TCP reassembly section. RFC 9293, RFC 7323, RFC 5961 and RFC 1982 are added to both reference lists.
- The changelog gets an entry under Unreleased.

## Testing Decisions

- **A good test only checks behaviour a user can observe.** It feeds segments in and checks what comes out. It never inspects internal fields or private helpers, so internals (sequence-space mapping, hole bookkeeping, buffer compaction) can be refactored without breaking tests. Results are checked with exact `assert_eq!` on values and on status counters.
- **One seam: the pool's public API.**
  - Every behaviour test drives `process_segment`, `process_sliced_packet` or `process_lax_sliced_packet`.
  - It observes `TcpProcessed`, `TcpConnection`, `TcpStream` (reads, offsets, holes, status, end), `stats()` and the eviction callbacks.
  - Pure value types (key sorting, config defaults, derived traits) are tested directly, because they are public API in their own right and not an extra seam.
- **Per-method tests follow the coding style.** Each public method has one test function in its type's file, covering every branch in commented blocks. These functions set up their state through the pool.
- **A test-only connection script builder** describes both directions as steps (e.g. "initiator sends N bytes at ISN+1", "responder ACKs", "drop", "reorder") and produces segments for the pool. Proptest strategies for the new types are added to the crate-internal generators module.
- **Prior art:**
  - the `IpDefragPool` tests (a `build_packet` helper plus one test function per method that covers every branch);
  - the shared `TestPacket` helper;
  - the existing proptest generators;
  - the proptest regression seeds, which are committed.
- **Reference-model proptests** run random byte streams in both directions through the pool. Each case uses random ISNs (including near 2^32) and either includes or skips the handshake. The stream is cut into segments, and then:
  - segments are reordered within a bounded distance, duplicated, or dropped (with and without a later retransmission);
  - retransmissions are corrupted;
  - the two directions are reordered against each other;
  - keep-alives, window changes and reconnects are added;
  - out-of-window segments, RSTs and FINs are injected;
  - some captures are one-direction only.

  A simple model computes the expected delivered bytes, gap positions and lengths, status counters and end reasons. The tests must stay green with `PROPTEST_CASES=3000`.
- **Each failure mode of the old branch gets an explicit regression test:**
  - a stream stalls after capture loss larger than the buffer;
  - a reconnect is invisible to a caller that reads eagerly;
  - an injected FIN blocks the real one;
  - an injected out-of-window RST closes a connection;
  - 1-byte holes exhaust memory;
  - a pure ACK of an unknown connection creates an entry;
  - a keep-alive probe that is the first segment of a stream gets anchored as data.
- **Steady-state allocation:** after warm-up, a run with recycling allocates no new buffers.
- **Coverage:** full branch coverage per the coverage script, with every error and limit branch hit.
- **Mutation testing:** `cargo mutants` on the module, with no surviving mutant left unexplained. Equivalent mutants are listed with a reason.
- **Fuzzing:** a `cargo-fuzz` crate outside the workspace and outside CI feeds arbitrary packet sequences and config values. It asserts there are no panics and that the limits hold.
- **CI targets:** the no_std test run, the bare-metal no_std build and the big-endian cross tests keep passing.

## Out of Scope

- Using `TcpConnection` without the pool (a standalone constructor and `process_segment`). It can be added later without a breaking change.
- IP defragmentation inside the TCP pool. Users run `IpDefragPool` first and pass the result as a `TcpSegment`.
- Verifying TCP checksums. Checksum offloading makes them wrong in many captures, so users filter beforehand if they need this.
- Using SACK, TCP timestamps (PAWS) or MSS. Only the window scale option is used.
- Separate handling of urgent data. It stays in line with the other bytes.
- A public mapping between sequence numbers and offsets.
- A custom hasher for the connection table.
- Automatic timeouts and LRU eviction. Eviction is driven by the caller.
- Overlap policies per target OS. First wins everywhere.
- A no_std or alloc-only variant of the module.
- Application-layer parsing, and writing or generating TCP streams.

## Further Notes

- The spec is cut into 16 tracer-bullet tickets under `issues/`. All of them are implemented on the `tcp-reassembler` branch, which is merged into master only once every ticket is done.
- Commits are structured for review commit by commit, as the coding style requires. The history may be reordered before the PR so that it reads well.
- Choice of pcap reader: on 2026-10-10 the readers were benchmarked on an M2 Max with the page cache hot, using 1.8 GB and 6.5 GB captures in pcap and pcapng format. `pcap-parser` 0.17 reached about 10.2 GB/s (pcap) and 9.3 GB/s (pcapng). For comparison, `pcap-file` 2.0 reached about 8.0 / 7.4 GB/s, `pcap-file` 3.0-rc about 7.1 / 7.2 GB/s, and `rpcap` about 9.9 GB/s (pcap only). None of the readers allocated per packet. A pcapng packet block that carries options allocates a `Vec` in both `pcap-parser` and `pcap-file`.
- Assumptions accepted in the design session:
  - the RST window check (F4) and the first FIN winning (F1);
  - a SYN-ACK giving both streams an observed start (A2);
  - only the window scale option being used;
  - discarding present bytes not affecting cleanliness (Q3);
  - tombstones counting towards `max_connections`;
  - truncated payload handled per D6.
