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
42. As a tool developer, I want a SYN or SYN-ACK with a new ISN on an open connection to replace it right away, in either order of the handshake's capture, so that the reconnect's bytes never count against the old connection (the protection of a live connection against a spoofed SYN was given up for this, see C2).
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
- `evict_older_than(cutoff, callback)` (requires `Timestamp: PartialOrd`) and `evict_all(callback)` both return the number of evicted connections: every connection passed to the callback, also one that ends as `Finished` (P6). The callback gets `&mut TcpConnection` before the pool recycles the buffers.
- `recycle(connection)` returns an ended connection's buffers to the pool.
- `stats()` returns `TcpPoolStats`. It walks the connection table, so it takes time proportional to the number of connections and tombstones, and costs nothing per packet (user decision, 2026-10-12).

**Processing results**
- `TcpProcessed` has three public fields:
  - `active`: the connection the segment was applied to, plus the role of its sender;
  - `ended`: an owned connection ended by this packet;
  - `ignored`: a `TcpIgnoreReason`, set when the packet was applied to no connection.
- `TcpIgnoreReason` is one of `NotTcp`, `NoConnection`, `AfterEnd` or `TooManyConnections`.
- `TcpPoolStats` contains connections, tombstones, buffered bytes, rejected connections and ignored packets. Ignored packets are all packets with `ignored` set, and rejected connections the `TooManyConnections` ones among them (user decision, 2026-10-12).

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
- Dropping data: `give_up_hole()` returns a `bool`, plus `discard_until(offset)`, `discard_all()` and `force_resync()`. `discard_until` treats offsets after the highest offset as the highest offset, so it never discards bytes that haven't arrived yet; `discard_all()` equals `discard_until(highest offset)` (user decision, 2026-10-11). The gap of a resync at the offset stays, as it belongs to the bytes from the offset on; discarding past it removes it (user decision, 2026-10-11).
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
| `ack_reorder_tolerance` | 256 packets | after how many packets an ACK-covered hole becomes overdue |
| `resync_after_segments` | `None` | opt-in resync without ACK confirmation |
| `max_connections` | `None` | tombstones count towards it |
| `max_total_buffered` | `None` | pool-wide, counted as for `max_stream_buffer` |
| `max_pooled_buffers` | 64 | buffers kept per kind in the free list |
| `max_pooled_buffer_capacity` | 64 KiB | recycled buffers are shrunk to this, and a stream keeps at least this much room once half of its buffer is consumed |

### Behaviour rules

The rule ids are for referencing from tickets and test names.

**Sequence space (S)**
- **S1** Each stream maps 32-bit sequence numbers to `u64` stream offsets. Offset 0 is the first byte: ISN + 1 on an observed start, or the first byte seen on a mid-stream pickup. Offsets only grow. The highest offset moves back only when a FIN cuts a hole an ACK created (F1), and the read offset with it if the user gave up the bytes after the FIN (user decision, 2026-10-11).
- **S2** Sequence numbers are mapped with RFC 1982 serial arithmetic relative to the highest offset seen. A distance of 2^31 or more cannot be mapped and counts as out-of-window.
- **S3** The window is the receiver's last advertised window shifted by its window scale. It is used only when the scale is known (A3) and at least one packet of the receiver was seen. Otherwise `fallback_window` is used.
  - An ACK is checked against the window the receiver advertised before the ACK's segment, because the sender could only send into that window. The window in the ACK's own segment may already have shrunk, to 0 when the receiver's buffer is full (user decision, 2026-10-11).
  - Only the window of a segment the receiver accepts counts: one that starts at most k windows (S4, with the largest window) after the bytes its sender is known to have sent, or before them, measured from the highest offset; before a stream has a start, the ACK the receiver kept for it (K1) takes the place of its bytes. The receiver drops other segments with their window, and a blind segment with a random sequence number could otherwise set the window that S4, K1, K2 and F4 rely on (council review, 2026-11-07).
  - A retransmitted or late SYN carries the window from the start of the connection, so its window counts only while none is known (council review, 2026-11-07).
  - The ACK of a segment the receiver doesn't accept still counts (K1): after a jump of both directions, the segments of both streams are implausible until they resync, and their ACKs are what confirms the jumps (R2) (council review, 2026-11-07).
- **S4** Data is out-of-window if it starts beyond `max(seen ACK, highest offset) + k × window`, where k = `hole_give_up_window_factor`, or 2 when that is `None`, and at least 1 (with 0, no bytes after a hole would fit; council review, 2026-11-07). Such data is not stored, increments `out_of_window_segments`, and becomes a resync candidate (R1). The window is the largest one the receiver advertised (as in K2): segments in flight when the window shrank, e.g. to 0, were sent into the larger window, and with the last window a lost one among them made the rest out-of-window and let their ACK resync the stream (council review, 2026-11-07).

- **S5** A side whose SYN was seen but not answered yet is in SYN-SENT or SYN-RECEIVED (RFC 9293 3.10.7.3 and 3.10.7.4) and drops most segments of the other side; the reassembler does the same before anything else looks at the segment, also before the reconnect check (C2) (council review, 2026-11-07):
  - Dropped: every segment of the other side that doesn't ACK the SYN exactly or as below, also a FIN and a SYN with a FIN or RST. It counts as out-of-window for its sender's stream and changes nothing else, not even with its ACK or window, and starts no reconnect.
  - Not dropped: a segment whose ACK number lies from the SYN's first byte up to k windows after it (the SYN-ACK or the ACK of the SYN-ACK may not have been captured); a SYN-ACK without RST and FIN, always: it answers the SYN if it ACKs it (plus TCP Fast Open bytes; also a kept SYN of a simultaneous open), and otherwise answers another SYN and starts a reconnect (C2; with an RST it is an RST that F4 would accept blindly, with a FIN it would end the stream); a segment other than an RST or FIN whose ACK number lies within one window of the stream's resync candidate, if that carries no FIN (the bytes jumped and the other side ACKs them, R2; a blind pair of segments could land an RST or FIN there, or a FIN with the jump); a SYN without ACK, FIN and RST (a simultaneous open); an RST while the SYN's sender is in SYN-RECEIVED (the other side's stream has a start), which F4 checks by its sequence number instead.
  - The wait ends with: a segment of the other side that ACKs the SYN as above, apart from an RST that F4 ignores (it is dropped with its ACK); a segment of the SYN's sender that its stream accepts (S2–S4), apart from a SYN, as the sender received an answer that was not captured; with `resync_after_segments = Some(n)`, n consecutive dropped segments of the other side that each lie within one window of the one before (as in R3, within the receive window of their own stream), as the other side moved on; this exit admits segments with bytes or an ACK only. After any exit, an RST or FIN of a side with neither a start nor a kept ACK still has to ACK the SYN, as F4 and A4 would take any RST or FIN of such a side. A late SYN (A5) and the start a SYN-ACK's ACK number gives (A2) never wait. A segment of the sender outside of what its receiver accepts (S2–S4), e.g. an RST far from its stream, ends nothing; a SYN of the sender with a new ISN starts a reconnect (C2).
  - A SYN-ACK or RST that ACKs the receiver's observed SYN knows its ISN, so it overrules an ACK kept for its sender's stream without a start (A4/K1), e.g. from a blind segment with the SYN sender's address, also when C2 asks whether the SYN-ACK is its sender's own; an RST drops that ACK, a SYN-ACK only one that doesn't allow it (C4), as the kept ACK of a reordered capture ACKs its bytes. The SYN-ACK that confirms a kept SYN likewise overrules an ACK kept for the kept SYN's stream that doesn't allow the SYN. A SYN whose kept ACK (K1) allows it (it ACKs the SYN or bytes up to k windows after it, as it arrived before the SYN in a reordered capture) waits for nothing. Once the kept SYN's stream has a start, the SYN is kept no longer: it is applied as a late SYN (A5) if the stream started from bytes (the bytes stored first win over its differing bytes, D1; a SYN's bytes retransmitted differently are no concern of benign traffic, owner decision 2026-11-08), and dropped as out-of-window if the stream started at another SYN (C3; also through the other side's SYN-ACK, A2) or lies too far before the bytes; it is never applied to a stream that started at another SYN. Its conflicting retransmissions count only if it is taken.
  - A SYN without ACK of a side without a start, while the other side's SYN is unanswered, may be blind and doesn't anchor its stream (it would wait for an ACK that never comes, and drop every segment of the other side): it is kept until a SYN-ACK confirms it. A simultaneous open's SYN-ACK repeats its ISN and anchors the stream, or the other side's SYN-ACK that ACKs it does (A2); that SYN-ACK confirms the kept SYN as the stream's own, which is applied then, so its window scale and window count (A3, S3).
  - Known limits: a blind segment whose ACK number hits the range by chance (k windows in 2^32) answers the SYN; a blind SYN-ACK replaces the connection (C2); a SYN with a FIN of a simultaneous open is dropped like a blind one, as nothing could recover a stream a blind FIN ended; a blind data segment spoofed with the sender's address and a blind ACK of it from the other side answer the SYN and resync the stream, as R2 would without S5 (ADR-0002), which `resyncs` shows; without `resync_after_segments`, the wait doesn't end while all captured bytes of the sender map more than k windows before offset 0 (a stale SYN with a lower new ISN) or no segment of the sender is captured while the other side's ACKs lie beyond k windows, until `force_resync()` on the sender's stream lets its next bytes answer.
  - In short, for a segment of the other side X while Y's SYN is unanswered (Y's stream has `syn_unacked`):

    | segment of X | ACKs Y's SYN exactly | ACKs within k windows after it, or a resync candidate without FIN | other ACK number or no ACK |
    |---|---|---|---|
    | SYN-ACK (no RST, FIN) | applied: anchors X, answers Y's SYN; applies a kept SYN of a side without start first | starts a reconnect (C2), unless it ACKs the kept SYN of a simultaneous open or repeats X's observed ISN (X's own retransmission, applied) | same (a SYN-ACK always has an ACK number) |
    | SYN without ACK, FIN, RST | — | — | kept, or applied if it retransmits X's own SYN (C3) |
    | SYN with FIN or RST | applied: it knows the ISN (the FIN ends the anchored stream, the RST resets, F4) | dropped; with RST by sequence number if Y is in SYN-RECEIVED (F4) | dropped; with RST by sequence number if Y is in SYN-RECEIVED (F4) |
    | RST | reset (F4), answers | dropped (SYN-SENT); by sequence number if Y is in SYN-RECEIVED (F4) | dropped (SYN-SENT); by sequence number if Y is in SYN-RECEIVED |
    | data, pure ACK | applied, answers | applied, answers | dropped |
    | FIN | applied, answers | applied, answers (not through the candidate) | dropped |

    Y's own accepted segments other than a SYN answer its SYN too, and so do `resync_after_segments` agreeing dropped segments of X for X's data and ACKs; an RST or FIN of X while X has neither a start nor a kept ACK keeps needing the ACK of Y's SYN after any exit.
- **S6** Every receiver drops a segment without the ACK flag that is no SYN or RST (RFC 9293 3.10.7.4), in every state after its own SYN; the reassembler does the same, before S5: the segment counts as out-of-window for its sender's stream and changes nothing else, and it starts no connection (A6). Without it, a blind data segment without ACK from the responder's address before the SYN started a pickup that swallowed the real SYN-ACK, and a blind FIN without ACK needed S5 to be dropped (council review, 2026-11-07).

**Anchoring (A)**
- **A1** A SYN gives the initiator stream an observed start. Payload in the SYN (TCP Fast Open) is data at offset 0. A SYN without ACK of the other side while this SYN is unanswered is only kept (S5).
- **A2** A SYN-ACK gives the responder stream an observed start. If the SYN was not seen, its ACK number also gives the initiator stream an observed start; on a mid-stream pickup it counts as the initiator's late SYN (A5) (user decision, 2026-10-11).
  - Known limit: if the SYN carried TCP Fast Open bytes that the SYN-ACK ACKs, and the SYN is captured after the SYN-ACK, the initiator stream starts after these bytes and they are lost. This is documented (user decision, 2026-10-11).
  - Known limit: if the responder's first bytes are captured before its SYN-ACK (and the initiator's SYN was seen), the responder stream starts at those bytes as a pickup; the SYN-ACK then moves the start back only while nothing was read (A5), so an eager reader loses the bytes between the SYN-ACK and the first ones captured (council review, 2026-11-08).
- **A3** The window scale is known only if both SYN and SYN-ACK were seen. Per RFC 7323, a missing option on either side means scale 0 for both directions. Only the SYN right before the stream's first byte counts, so a SYN that arrives after its stream resynced doesn't, and the fallback window applies (user decision, 2026-10-11).
- **A4** On a mid-stream pickup, the first data segment of a stream puts offset 0 at its first byte.
  - It does so only if it lies within k windows (S4) of the ACK the receiver kept for the stream (K1), or no ACK was kept. A segment further away is forged, or the kept ACK is, or the receiver's window is larger than the fallback window assumes: the first such segment counts as out-of-window and doesn't start the stream, as a blind segment could otherwise anchor the stream elsewhere while it stays clean (council review, 2026-11-07).
  - The next segment with bytes starts the stream wherever it lies and drops the kept ACK, which it overrules: an ACK before every segment of a stream with more in flight than k fallback windows allow would otherwise keep the stream from starting, and the ACK would otherwise count as the started stream's seen ACK or as resync evidence. Two blind segments thus still anchor a stream elsewhere, a known limit that `force_resync()` recovers (council review, 2026-11-07).
  - No FIN far from the kept ACK starts the stream, with or without bytes, as nothing could recover a stream that a blind FIN ended; `force_resync()` does nothing after a FIN. Known limit: a forged ACK and a FIN near it, or two blind data segments and a FIN near them, still end a pickup for good (council review, 2026-11-07).
  - Segments the receiver drops while its SYN is unanswered start nothing (S5); without that rule a blind FIN ended the responder stream before the SYN-ACK, as the SYN keeps no ACK for it (council review, 2026-11-07).
  - The ACK number of a SYN-ACK (A2) anchors the initiator stream only where its kept ACK allows it to start, as a late SYN does (C4): at or before the kept ACK, at most k windows before it, as the receiver can't have ACKed bytes before the SYN. A SYN-ACK whose ACK number lies elsewhere leaves the stream without a start, and its ACK number is not kept, so the stream starts as without it. Known limit: a forged ACK followed by a SYN-ACK with the same ACK number anchors the stream there, as the kept ACK is the last one (K1) (council review, 2026-11-07).
  - A FIN without bytes puts offset 0 at the FIN, so the stream is empty and finished, and the connection can finish. Such a stream takes nothing in front afterwards (A5), as a reader may have read its end (user decision, 2026-10-11).
  - A 1-byte segment without SYN, FIN or RST that ends at the last ACK the other side sent before the stream had a start is a keep-alive and doesn't start the stream. As a connection's very first packet, the ACK is not known, so its filler byte becomes byte 0 (user decision, 2026-10-11).
  - A segment none of whose bytes fit the limits (D4), e.g. as other connections use up `max_total_buffered`, doesn't start the stream either, also with a FIN. Its bytes count as rejected, and the next segment whose bytes fit starts the stream, so byte 0 of a pickup is always stored. A later retransmission of the rejected bytes can still be put in front (A5) (user decision, 2026-10-12).
- **A5** Until the read position of a mid-stream pickup first moves forward (a consume of at least 1 byte, `consume_gap`, or a discard that moves it; reads, `consume(0)` and `discard_until(0)` don't count):
  - bytes that start at most k × window before offset 0 (k as in S4, and the receiver's last window, which is the fallback window while the scale is unknown) are prepended, and the offsets shift, with the FIN, the holes, the seen and implied ACK and the ACKs of K4(b);
  - a late SYN under the same conditions, or the ACK number of a late SYN-ACK (A2), upgrades the stream to observed start.

  A pickup that started at a FIN without bytes takes nothing in front (A4). After that, such bytes count as out-of-window, once per segment, and the segment's bytes from the read position on are still stored. Such a SYN counts as out-of-window and is ignored (C4). On a stream with an observed start, bytes before offset 0 count as out-of-window too, so late segments with bytes of a replaced connection count in the new one (C2), except the filler byte of a keep-alive (a 1-byte segment without SYN or FIN) right before offset 0, which lies there when no bytes were sent yet and is ignored without counting. After a resync, bytes that map before offset 0 are ignored without counting like all bytes before the resync point (R2), on both kinds of start (council review, 2026-11-07). A `consume(n)` after a prepend consumes nothing until the next read, because the bytes the last read returned are no longer at the read position (user decisions, 2026-10-11).

  Prepending has to fit the limits (D4): the buffer from the new offset 0 to the furthest stored byte, the pool's budget for the placeholders, and the hole limit for the hole left between the bytes and the old offset 0. Bytes that don't fit are rejected and counted, offset 0 stays, and the segment's bytes from offset 0 on are stored as usual. A late SYN, or the ACK number of a late SYN-ACK, that would need more room is ignored like one A5 can't take, so a SYN counts as out-of-window and the stream stays a pickup (user decision, 2026-10-12).
- **A6** Pure ACKs, FIN-only segments and RSTs (also with bytes or a SYN) for unknown keys never create a connection (`NoConnection`), and neither do bytes without the ACK flag (S6) (user decision, 2026-10-11; council review, 2026-11-07).
- **A7** Roles: the SYN sender is the initiator and the SYN-ACK sender is the responder. Without a handshake the roles are guessed: the lower port is the responder, and on equal ports the sender of the first packet is the initiator. A late SYN or SYN-ACK that gives a stream an observed start confirms guessed roles if its sender has the role the guess gave it. One that contradicts the guess leaves the roles guessed; roles never change (user decision, 2026-10-11).

**Data (D)**
- **D1** First wins: overlapping bytes keep the content received first.
- **D2** A retransmission whose overlapping not-yet-ACKed bytes differ increments `conflicting_retransmissions` once per segment. ACKed means a seen ACK or the implied ACK. Bytes the user already consumed are not compared, because they are no longer buffered (user decision, 2026-10-10).
- **D3** Bytes before the ACKed offset in a retransmission are ignored without comparison. This covers keep-alive probes. Missing bytes before the ACKed offset are still stored, because captures can show an ACK before the data it acknowledges. Known limit: if an ACKed segment was not captured, a keep-alive's garbage byte at seen ACK − 1 fills the last byte of its hole while that hole is not overdue yet (user decision, 2026-10-11).
  - In an overdue hole (K4), a segment without SYN, FIN or RST that carries exactly 1 byte and ends at the seen ACK is ignored and touches no counter. It has the shape of a keep-alive, whose byte is filler (RFC 1122 4.2.3.6), and a receiver discards it too. Without this rule, lazy gaps would let a keep-alive put a garbage byte into the stream until the reader reaches the hole (user decision, 2026-10-11).
- **D4** Limits:
  - Bytes beyond `max_stream_buffer` are rejected and counted as `rejected_bytes`, each time they arrive. The buffer counts from the read position to the furthest stored byte, with the placeholders of holes, so bytes that fill a hole before that byte always fit.
  - A segment that would leave more than `max_holes_per_stream` holes before the furthest stored byte is rejected entirely. The hole after the furthest stored byte (rejected bytes, or bytes an ACK or a FIN shows were sent) doesn't count, so in-order bytes after an ACK that arrived first are stored, and so are a late SYN and bytes in front of a pickup (A5) that add no hole. Counting it would reject them whenever such a hole exists, and with a limit of 0 every ACK that arrives before its data would lose the ACKed range (user decision after the review, 2026-10-12).
  - `max_total_buffered` rejects in the same way pool-wide. It counts the streams of the pool's open connections as `max_stream_buffer` does, so consuming makes room at once; connections handed over as ended don't count. The SYN that a connection keeps while a simultaneous open's handshake is unanswered (S5) doesn't count either: each connection keeps at most one, so `max_connections` bounds them, and detecting reconnects never depends on the budget (user decision, 2026-10-12).
  - A rejected segment's position still advances the highest offset, so the implied ACK keeps moving; the bytes it didn't store become a hole. This can add a hole after the furthest stored byte, as can an ACK (K1) or a FIN that moves the highest offset, which the limit doesn't count, so `holes()` lists at most `max_holes_per_stream` + 1 holes. A strict limit would let the stream stall where no ACKs were captured (user decision, 2026-10-12).
  - Bytes that don't fit in front of a mid-stream pickup are rejected (A5), and a first segment none of whose bytes fit doesn't start one (A4).
  - A resync (R2–R4) happens even if the bytes of its new start are rejected: they become a hole right after its `Gap { len: None }`, as the sequence numbers prove the jump, not the storage (user decision, 2026-10-12).
  - While a stream has more than `max_holes_per_stream` gaps the reader hasn't stepped over, it doesn't resync: the candidate stays (its bytes count as out-of-window) and a forced resync stays pending, until the reader steps over gaps. Each resync turns the holes before it into gaps, so a reader that doesn't read would otherwise let forged resyncs add gaps without limit; this way, a stream has fewer than about 2 × `max_holes_per_stream` + 2 gaps (user decision, 2026-10-12).
  - `max_connections` counts open connections and tombstones (P3). A segment that would start a connection with a new key in a full pool is ignored with `TooManyConnections`; a reconnect on a key the pool has doesn't count as new.
  - The ACKs that K4(b) keeps are bounded by `ack_reorder_tolerance` (one 16-byte entry per packet and stream), which its doc states; no limit counts them (user decision, 2026-10-12).
  - No limit throws away bytes the user hasn't consumed.
- **D5** Data beyond the FIN offset is out-of-window.
- **D6** With truncated payload (lax input or a short snapshot length), only the captured bytes are added; the rest stays a hole. The FIN flag of a truncated segment is ignored.

**ACK and implied ACK (K)**
- **K1** A stream's seen ACK is the highest plausible ACK number seen in the other direction.
  - An ACK beyond `highest offset + window` is ignored, except as resync evidence (R2). Once the FIN offset is known, the limit is one higher, so the ACK of the FIN counts even with a window of 0. The window is the largest one the receiver advertised before the ACK's segment (S3, S4), as the sender can have sent into it before the window shrank (user decision, 2026-10-11; largest window after the council review, 2026-11-07).
  - An ACK beyond the highest offset turns the uncaptured bytes up to it into a hole.
  - An ACK never moves the ACKed offset past the FIN offset and never adds holes after it.
  - An ACK that a stream can't apply yet, because it has no start, or because the ACK lies at or before offset 0 while bytes can still be prepended (A5), is kept and applied after every packet until it counts, if it lies at most as far before offset 0 as bytes can be put in front (k times the last window, as in A5, which is the fallback window on a pickup; a forged ACK further before would widen F4; council review, 2026-11-07). The last such ACK is kept, as ACKs before a start can't be ordered, and a forged one is then replaced by the next real one (user decision, 2026-10-11). A later ACK that counts drops the kept one, and none is kept once an ACK counted, so an outdated ACK can't lower the bound of F4. The kept ACK counts with the number of the packet that carried it, so a hole that a prepend puts before it is overdue `ack_reorder_tolerance` packets after that packet (K4(b)), not after the prepend (council review, 2026-11-07). The segment that starts the stream against the kept ACK drops it (A4), so it neither counts as the seen ACK nor as resync evidence, and no longer bounds F4 (council review, 2026-11-07). A kept ACK also counts as soon as a kept SYN (S5) gives the stream its start, before the bytes of the segment that confirmed the SYN are compared, so a retransmission of ACKed bytes conflicts with nothing (D2; council review, 2026-11-08).
- **K2** The implied ACK is `highest offset − k × window`, saturating at 0. It applies only while `hole_give_up_window_factor` is `Some(k)`, with k at least 1 as in S4. It is updated after every packet of the connection, and the checks inside a packet use its value from before that packet. The distance `k × window` is at most half of `max_stream_buffer`, but never less than the largest window the receiver advertised: with the defaults, `k × fallback_window` equalled the buffer, so a reader of the ACKed bytes in a one-direction capture sat at the buffer's end, every further segment was rejected, and half the stream was lost; a distance below a known window would be unsound, as the sender can have sent that far past the ACK. So a reader of ACKed bytes without captured ACKs keeps up only if `max_stream_buffer` is clearly larger than the receiver's largest window; otherwise the bytes that don't fit are rejected and counted (council review, 2026-11-07).
  - The window is the largest window the receiver has advertised, as the sender can have sent bytes into a larger window before the window shrank, e.g. to 0 when the receiver's buffer is full. The fallback window applies only while no window is known (S3). With the last window, an ACK that advertises window 0 would make the hole it adds overdue at once, without waiting for `ack_reorder_tolerance` (user decision, 2026-10-11).
  - The implied ACK never moves back, e.g. when the window grows: bytes sent earlier still prove what the receiver had ACKed then (user decision, 2026-10-11).
- **K3** The ACKed offset is `max(seen ACK, implied ACK)`. `read_acked()` returns contiguous bytes up to it.
- **K4** A hole is **overdue** once its end lies at or before either:
  - (a) the implied ACK, or
  - (b) the seen ACK as it was `ack_reorder_tolerance` packets ago (default 256: a capture merged from two taps shows the ACKs of one direction ahead of the data by the skew between the taps, which at 1 Gbit/s is hundreds of packets per millisecond; 16 gave captured bytes up as gaps from about 200 Mbit/s on; council review, 2026-11-08). Every packet applied to the connection counts, in either direction, as for `last_seen` (P7). The packet whose ACK covers the hole doesn't count, so the hole is overdue after the N-th packet after it. The bytes of a packet are stored before the packet's overdue check, so the N-th packet still fills the hole (user decision, 2026-10-11), or
  - (c) the end of the furthest bytes the stream rejected (D4). Rejected bytes at the end of a stream join one hole that each rejected segment extends to the highest offset, so (a) never passes it, and in a continuous flow the reader would stall there. Once a stream overflows, waiting for late segments is futile, so capture-loss holes before the rejected bytes are overdue too (user decision, 2026-10-12).
    - Known limit: bytes of a segment that lies partly inside the buffer and that the limits reject stay rejected until a retransmission brings them; nothing asks for them again, and `rejected_bytes` counts them (council review, 2026-11-07).

  A hole is overdue as a whole, never in parts: a hole that is only partly before these offsets is not overdue. One lost range thus gives one gap (user decision, 2026-10-11).

  K4(b) also holds for a hole that a prepend (A5) adds before an ACK seen earlier, so a pickup that can still prepend keeps the ACKs of the last `ack_reorder_tolerance` packets even without holes (user decision, 2026-10-11).

  Gaps are lazy (user decision, 2026-10-11):
  - an overdue hole stays a hole, and late segments still fill it, so the reassembler never drops bytes the reader hasn't reached;
  - the overdue hole at the read position becomes a gap as soon as it is overdue. This is checked after every packet and after every move of the read position, so reads, `holes()`, `status()` and `consume_gap()` always agree, whether or not the user has called `read_*()`. The gap is read as `Gap` and counted;
  - when a connection ends, its remaining holes become gaps (F5);
  - at eviction (P6), no more packets come, so every hole that the seen ACK covers counts as overdue.

**Resync (R)**
- **R1** Out-of-window data records the latest candidate: data after the window (S4) or at a distance that can't be mapped (S2). Bytes before offset 0 (A5) or after the FIN (D5) are no candidates. So a jump to a new ISN that maps behind the stream, half of all ISN changes, is not detected; `force_resync()` recovers such a stream (user decision, 2026-10-11).
  - Any other data segment (in the window, a retransmission, before offset 0) shows that the stream didn't jump and clears the candidate. So does anything that moves the highest offset forward (bytes, an ACK, a FIN), and a resync (user decision, 2026-10-11).
  - SYNs are never candidates or new starts and clear nothing: reconnects are C2's. Once the FIN is known, no resync happens, also not for a candidate recorded before the FIN, so `End(Fin)` stays final (user decisions, 2026-10-11).
- **R2** An ACK from the other direction within one window of the candidate triggers a resync. "Within one window" means at most the receiver's last window (not the largest one that S4 uses) before the candidate's first byte or after its last byte; the largest window was considered and rejected, as its range never shrinks again (user decision, 2026-10-11). The stream continues right after the candidate's bytes, mapped to the highest offset, behind a `Gap { len: None }`. The candidate's bytes are not stored (S4) and are part of that gap, so reading doesn't stall and no extra memory is needed. So is all out-of-window data before the confirming ACK, up to about one window (user decisions, 2026-10-11). A FIN in the candidate's segment, or a FIN without bytes right after it, ends the stream at the resync point. Other FINs without bytes after the window are only counted, so a stream whose jump has no bytes before its FIN doesn't finish (user decision, 2026-10-11). `resyncs` is incremented. Resyncs (R2–R4) wait while the stream has more than `max_holes_per_stream` gaps the reader hasn't stepped over (D4). Known limit: a blind data segment with a FIN after the window and a blind ACK of it from the other side end the stream at that FIN for good, as `force_resync()` does nothing after a FIN; the stream shows the resync (council review, 2026-11-07).
  - An ACK beyond the window that arrives before the data counts too. The last such ACK is kept until a resync or until the stream moves forward; only another ACK beyond the window replaces it, older ACKs don't. Out-of-window data within one window of it triggers the resync at once and becomes the new start, with its bytes stored, and the kept ACK then counts like the confirming ACK below (user decisions, 2026-10-11).
  - The ACK that confirms a jump counts after the resync, and it ACKs at least all bytes before the resync point: the receiver ACKed bytes after the jump, so it has the ones before it, or they belong to a connection that is over (user decision, 2026-10-11).
  - At a resync, all holes before the resync point become gaps and are counted (Q4), as their sequence numbers now map elsewhere. Bytes, FINs and ACKs that map before the resync point are ignored without counting and are not compared for conflicts. The segment that becomes the new start doesn't count as out-of-window, as its bytes are stored (user decisions, 2026-10-11).
  - The resync's gap counts only in `resyncs`, not in `gaps` or `gap_bytes`. Resyncs without bytes between them leave one `Gap { len: None }` but count each, unless the reader stepped over the first gap (user decisions, 2026-10-11).
- **R3** With `resync_after_segments = Some(n)`, n consecutive out-of-window segments that each lie within one window of the previous one also trigger a resync. The n-th becomes the new start, with its bytes stored. Other data segments, the stream moving forward and a resync restart the count; `Some(0)` works like `Some(1)` (user decisions, 2026-10-11).
- **R4** `force_resync()` makes the next segment with bytes, apart from a SYN, the new start, wherever it lies (in the window, a retransmission, a keep-alive), the same as R2. It does nothing before the stream started or after its FIN, and while it is pending, bytes can't be prepended (A5) (user decision, 2026-10-11).

**FIN, RST and ends (F)**
- **F1** The first FIN within the window sets the FIN offset. Later FINs at other offsets are ignored. A FIN that lies before bytes already received is ignored.
  - An ACK never blocks a FIN. A FIN inside a hole that an ACK created is accepted, cuts the hole, and moves the highest offset back to the FIN offset. It counts as ACKed if the seen ACK lies after it. Otherwise one forged ACK within the window could keep the stream from ever finishing (user decision, 2026-10-11).
  - "Received" means stored: bytes that arrive after they were consumed or given up are ignored and don't count. Bytes that a limit rejected (D4) count as received too, so a FIN before the end of the furthest rejected bytes is ignored, and a forged FIN inside them can't cut a full stream short; the real FIN after them counts (user decision after the review, 2026-10-12). A FIN that lies before the read position, because the user gave up or discarded bytes up to an ACK after it, is accepted and moves the read position back to it. Example: the ACK of a FIN arrives before the FIN, and the user gives up the FIN's position (user decision, 2026-10-11).
- **F2** A finished stream has its FIN seen and no holes before the FIN offset. Overdue holes count as holes, because late segments can still fill them, and because otherwise `is_complete()` would turn from true to false once the reader reaches such a hole (user decision, 2026-10-11).
- **F3** A finished connection has both FINs seen and ACKed. It ends as `Finished`, and its remaining holes become gaps (F5), so both streams are then finished (user decision, 2026-10-11). The holes an ACKed FIN covers need not be overdue (K4(b)): the FIN was captured after the bytes of its direction, so they are capture loss, not an ACK that leads its bytes, and no packet would come after a clean close to make them overdue (with `ack_reorder_tolerance` 256, most lossy connections would otherwise stay open until eviction). Known limit: bytes of a direction that a capture shows after the ACK of that direction's FIN are lost as a gap, and their late retransmission is ignored after the end. In a single-tap capture that can't happen (the ACK of the FIN follows the bytes the receiver needed); in a capture merged from two taps it happens to a segment lost before the tap and retransmitted after the FIN when the skew between the taps exceeds the time from the tap to the receiver and back, the capture that K4(b) tolerates. Lossy connections would otherwise stay open until eviction (council review, 2026-11-08).
- **F4** An RST is accepted if its sequence number lies from the seen ACK of the sender's stream up to one window after the bytes the sender is known to have sent (the highest offset, plus 1 once the FIN is known). These are the RSTs the receiver can accept: RFC 9293 accepts an RST from RCV.NXT up to RCV.NXT + RCV.WND, RCV.NXT lies between the ACK the receiver sent and the bytes sent, and a window of 0 still accepts an RST at RCV.NXT. The window is the receiver's last window (S3). An accepted RST ends the connection as `Reset { by }`. Other RSTs are ignored and counted in `out_of_window_segments`, so injected RSTs stay visible (user decisions, 2026-10-11).
  - A stream without a start is checked against the last ACK the other side sent for it (A4/K1 keep it): from that ACK up to one window after it. Only a stream with neither a start nor such an ACK accepts an RST with any sequence number, e.g. the RST/ACK that answers a SYN on a closed port; a receiver in SYN-SENT accepts only an RST that ACKs its SYN, one in SYN-RECEIVED checks the sequence number as usual (S5) (user decision, 2026-10-11; council review, 2026-11-07).
  - No ACK moves the lower bound past the end of the received bytes, so an ACK never blocks an RST at or after them. Otherwise one forged ACK within the window would keep every real RST from ending the connection, as F1 prevents for FINs. An ACK that a pickup keeps before offset 0 (K1) is the receiver's ACK too and lowers the bound to it. After a resync, RSTs that map before the resync point are ignored and counted, as R2 ignores bytes, FINs and ACKs there (user decisions after the review, 2026-10-11).
  - An RST carries no bytes of the stream: its bytes are diagnostic (RFC 9293 3.5.3, RFC 1122 4.2.2.12), and its SYN and FIN flags are ignored, so the stream ends with `End(Reset)`. The ACK of an accepted RST counts. An ignored RST is dropped with its ACK and window, but counts as a packet (P7, K4(b)). An RST whose ACK ACKs the last FIN ends the connection as `Reset`, not `Finished` (user decisions, 2026-10-11).
- **F5** When a connection ends, for any reason, all its holes become gaps and are counted, so its status is final when it is handed over. Late segments go to the tombstone (P3) and can't fill them anymore (user decision, 2026-10-11).
- **F6** `read_*()` returns `End(..)` once everything readable has been read and no more bytes can come. On an ended connection, `read_acked()` returns `End` even if un-ACKed bytes remain; `read_received()` still returns them. The end is `End(Fin)` when the read position is at the FIN, and the connection's end otherwise. So a stream whose FIN was seen before a reset ends with `End(Fin)` for `read_received()`, but with `End(Reset)` for a `read_acked()` that stops before un-ACKed bytes (user decision, 2026-10-11).

**Reconnect (C)**
- **C1** A SYN or SYN-ACK on a tombstone creates a new connection right away, unless it belongs to the handshake of the ended connection: its ISN equals the ISN of its sender's stream, or it is a SYN-ACK that ACKs the SYN of the other stream. Such a late retransmission stays `AfterEnd`, so late duplicates of the old handshake create no ghost connections. Tombstones of pickups know no ISN, so a SYN or SYN-ACK creates a new connection there, unless it lies right at a pickup stream's first byte: its ISN + 1 is that byte, or it is a SYN-ACK that ACKs it (the ended pickup's own late handshake, as in C4). The exact evidence comes first, here and in C4: the sender's observed ISN, then, for a SYN-ACK, the other stream's observed SYN, which it ACKs or not; a pickup's first byte decides only where no observed SYN speaks, as the first byte the capture showed can coincide with a reconnect's ISN + 1. A connection that replaced another (C2) or started on its tombstone remembers the replaced one's handshake the same way and absorbs its late duplicates, which would otherwise start a further reconnect, and its tombstone remembers it too; the handshake of the connection two reconnects back is forgotten, so its late duplicate starts a new connection (a known limit) (user decisions, 2026-10-11; council review, 2026-11-08).
  - Late segments of the replaced connection, one rule: on one path, an endpoint's segments of the replaced connection can't arrive after its first segment of the new one, so while the sender has sent nothing the new connection took (didn't drop), a segment without SYN is the replaced connection's if its sequence numbers say so, and is absorbed with `AfterEnd`: it lies within the numbers its sender's stream covered there (from its first byte to the number it reached, after its highest byte or after its FIN), widened by k windows on both sides for bytes the capture may have missed, but not before an observed SYN or after a seen FIN, before and after which the sender sent nothing (a mid-stream pickup's first byte is only where the capture started, so the other side's ACKs can lie before it), and its ACK number, if it has one, within the other stream's the same way, or the other stream is unknown. A stream the capture never saw has no first byte, only the number its peer's ACKs showed it reached (K1), so its span runs up to there. The ACK number of an absorbed ACK moves the number the other stream reached forward, as the capture may have missed that stream's FIN.
  - The new connection's own segments come first, as the new ISNs can lie within the old spans after a reset, which has no TIME-WAIT to keep them apart: where the new connection knows where the sender's stream begins (its SYN, or the ACK number of the other side's SYN-ACK, A2), a segment within what that stream is known to have sent (up to the position it expects next) is the new connection's; where it doesn't, a segment that ACKs what the other stream sent in the new connection is.
  - One exception: an RST without ACK from a side in SYN-SENT (its SYN seen, and nothing of the other side ACKed yet) answers an ACK of the replaced connection (RFC 9293 3.10.7.3) and is absorbed wherever it lies, whether that ACK was captured, before or after it, or not. Past SYN-SENT, only a side that crashed sends an RST without ACK (from CLOSED, RFC 9293 3.10.7.1), which resets the new connection.
  - This covers a near reuse of the four-tuple whose new ISN lies below the old stream's end, and a reuse right after an abort:
    - the ACK with which a server in TIME-WAIT answers such a SYN (which S5 would otherwise take as the answer to the SYN, with a fake hole of the distance);
    - the client's RST to that ACK (which would otherwise reset the new connection, whose tombstone would then swallow the real handshake, F4);
    - the old close's last ACK or a FIN retransmission captured after the new SYN, and bytes of the old connection still in flight;
    - the RST of a client that aborted and reconnected at once, captured after the new SYN-ACK because the client's tap lags;
    - the server's segment in flight when a client aborted after bytes the capture lost, which ACKs them (the slack covers them, also when the new ISN lies within them);
    - the late RST of a client that ACKs bytes before the first byte of a server stream the capture picked up mid-stream.

    A captured FIN ends the old stream exactly, so the response of a reuse 1 ms after a close, captured before the request it ACKs (the SYN-ACK lost, the client's tap behind), lies past the old FINs and is the new connection's.
  - Known limits, named as in the simulator's `known_limit` (council review, 2026-11-08):
    - once the sender sent a segment the new connection took, its late old segments go through the new connection's rules (S5, S2); a single path never shows this, so the simulator doesn't produce it;
    - segments before the handshake: segments of a new connection that the capture shows before either half of its handshake (it lost one half and shows the other after them, as a tap lags) go to the connection before: its tombstone absorbs them as late segments (P3), and an open one can't start a new connection from bytes and takes the ACK numbers for its own, which can make it refuse its own later segments (a receiver drops a segment whose sequence number lies outside its window together with its ACK, RFC 9293 3.10.7.4; the pool applies the ACK first);
    - unseen connection: late segments of a connection the pool never saw (the capture starts at its close) can't be told from the new connection's, so the ACK of a server that still held it answers the new SYN (S5) and the client's RST to that ACK resets the new connection (F4);
    - new taken for old: where both new streams begin within the old spans, or within k windows past the end of an old stream whose FIN the capture didn't show (a quick reuse after an abort or a crash), and the capture lost a half of the new handshake, the first segments of the lost half's stream are the old connection's by their numbers as long as they ACK bytes the capture doesn't show yet (lost, or late as a tap lags);
    - old taken for new: where the new ISNs lie within the old spans, a late segment whose numbers fall within what the new streams sent is the new connection's by the precedence above;
    - late pickup handshake: a handshake half of a pickup, captured after the connection ended or the next one started, that no observed SYN tells apart and that doesn't lie right at a stream's first byte (the capture lost the first bytes too) starts a new connection;
    - coinciding end: an old end that coincides with the new ISN + 1 of the same endpoint can't be told from it.
  - Late segments of a replaced connection, in the order the rules apply (R: the new connection, X: the segment's sender):

    | late segment of the replaced connection | X sent nothing R took yet | X sent a segment R took |
    |---|---|---|
    | its SYN or SYN-ACK (same ISN, or a SYN-ACK ACKing its SYN) | `AfterEnd` (also on R's tombstone, one reconnect back) | `AfterEnd` |
    | a SYN or SYN-ACK with another new ISN | starts a further reconnect (C2) | starts a further reconnect (C2) |
    | an RST without ACK while X is in SYN-SENT (X's SYN seen, nothing of the other side ACKed yet) | — (R took X's SYN) | `AfterEnd` |
    | R's own: within what X is known to have sent in R where R knows X's begin, else ACKing what the other stream sent in R | R's rules (S5, S2 to S4) | R's rules |
    | no SYN, within X's old span (widened by k windows, but not before an observed SYN or past a seen FIN) and its ACK within the other stream's old span the same way, or that stream unknown | `AfterEnd` | R's rules: S5 while R's SYN is unanswered, else S2 to S4 (counted) |
    | others (numbers outside the spans) | R's rules (a known limit: within k windows after R's SYN, S5 takes an ACK as its answer) | R's rules |
- **C2** A SYN or SYN-ACK with a new ISN from an endpoint of an open connection is a reconnect and replaces the connection right away, in either order of the handshake's capture (a capture merged from two taps can show the SYN-ACK first): the old connection comes back in `ended` as `Reconnect` (or as `Finished` if both its FINs were ACKed, as at eviction (P6)), and the new one, which starts at that segment like a connection on a tombstone (C1), is `active`. Its id is assigned then, and its `first_seen` is the segment's timestamp. The reconnect's other segments, captured between the halves of its handshake or after them, are its own, so its bytes, holes, windows, ACKs and FINs count there, and the old connection gets no fake hole from them when the ISNs lie near (a quick reuse of the four-tuple, RFC 6528). A SYN-ACK that ACKs neither the receiver's observed SYN nor a kept one answers another SYN, which the capture missed, and starts the reconnect too, also while that observed SYN waits for its answer (S5): a failed attempt whose answer was never captured doesn't block the next one. Late segments of the replaced connection that C1 doesn't absorb count as out-of-window in the new one: all of them while the new SYN is unanswered (S5), afterwards those with bytes (a late FIN without bytes before the first byte is ignored without counting) (user decisions, 2026-10-11; council review, 2026-11-07 and 2026-11-08).
  - Benign traffic has no other SYN or SYN-ACK with a new ISN from an endpoint of a live connection: a retransmission repeats the ISN (C3), and a new attempt after a failed one is a new connection. Until 2026-11-08 the SYN was kept until a SYN-ACK of the other endpoint confirmed it, so that a spoofed SYN couldn't end a connection (user decision, 2026-10-11); the confirmation and the segments kept with it grew into a mechanism of their own (kept SYN-ACKs, retained segments, their exits and budgets) that four review rounds kept finding gaps in, and the owner's focus on captures without an attacker made it dispensable (council review, 2026-11-08).
  - Known limits: a spoofed SYN or SYN-ACK with a new ISN replaces a live connection, whose end `Reconnect` and the out-of-window counts of the new connection show it; a reconnect's SYN or SYN-ACK that lies in the A5 range of a mid-stream pickup before a FIN of the connection was seen is taken for the pickup's own late SYN (C4: through A5 if the pickup can take it, counted as out-of-window otherwise), and the reconnect starts at the other half of its handshake instead, or not at all: if A5 took it, the pickup's stream has the new ISN, and once the old connection ended, its tombstone takes the other half for a late duplicate of its handshake (C1) (council review, 2026-11-08).
- **C3** A SYN with the same ISN is a retransmission and starts no reconnect; its bytes go through D1 and D2 like any retransmission (a changed TCP Fast Open payload is a conflicting retransmission), and a late one still gives the window scale (A3). (user decision, 2026-10-11).
- **C4** The exact evidence decides first whose a SYN or SYN-ACK is: the ISN of its sender's observed SYN (C3), else, for a SYN-ACK, the other stream's observed SYN, which it ACKs (its stream's own late SYN-ACK, also on a pickup and after a FIN: within one direction the network can reorder it behind its sender's next segments) or not (it answers another SYN, C2). Where no observed SYN speaks, a SYN on a mid-stream pickup (a stream that started from its sender's bytes or FIN) is the pickup's own late SYN if its ISN + 1 lies at or before offset 0 and at most k windows before it (the A5 range) and no FIN of the connection was seen yet, or if its ISN + 1 is the stream's first byte: a late own SYN arrives among the stream's first segments, which a capture can reorder, while a reconnect's SYN arrives after the old connection began to close (after a FIN, a SYN elsewhere in the range starts a reconnect, C2): it goes through A5 if A5 can still take it (the pickup was not read from, didn't start at a FIN and didn't resync, and the bytes in front fit the limits, D4), and is counted as out-of-window and ignored otherwise, with its window and ACK number (the ACK number of a refused late SYN-ACK would otherwise move the other stream, A2), as its bytes can't be placed anymore; the budget its bytes in front were checked against is reserved for them, so the ACK number of a late SYN-ACK can't spend it on the other stream's start first (A2, D4); a SYN or SYN-ACK in the A5 range starts no reconnect (a reconnect's SYN lies there by chance only, a known limit of C2). Any other SYN goes through C2. On a stream without a start, a SYN is the stream's own if the other side's kept ACK of the stream (K1) lies at or after ISN + 1 and at most k windows after it, or if no such ACK was seen, also after a FIN: a capture merged from two taps can show the late SYN or SYN-ACK of a connection whose other half it lost after the other side's FIN; while the other side's SYN is unanswered, a SYN without ACK is only kept (S5). Known limit: a pickup's own late SYN, or its late SYN-ACK where the other stream has no observed SYN, that the network reordered behind its sender's next segments and that arrives after a FIN of the connection, starts a reconnect (the simulator's `C4 late own half`) (user decisions, 2026-10-11; council review, 2026-11-07 and 2026-11-08).

**Pool (P)**
- **P1** The key comes from the packet's VLAN IDs, IP addresses and ports, plus the channel id. The endpoints are sorted.
- **P2** Non-TCP packets and IP-fragmented TCP are ignored with `NotTcp`.
- **P3** A connection that ends other than by eviction leaves a tombstone with its key, its last-seen time, and the observed SYNs of its streams with the bytes they carried (C1); tombstones live in their own table, so they cost a fraction of a connection (council review, 2026-11-07). Late segments are ignored with `AfterEnd` and update the tombstone's last-seen time (P7), so eviction removes a tombstone only once no late segment came since the cutoff, and late segments that keep coming never start a ghost pickup (user decision, 2026-10-12). A SYN (C1) or eviction removes the tombstone. Tombstones count towards `max_connections`.
- **P4** Connection ids start at 0 and increase by one for each new connection.
- **P5** The free list keeps at most `max_pooled_buffers` buffers per kind. Recycled buffers are shrunk to `max_pooled_buffer_capacity`. The kinds are buffers for bytes (streams and kept SYNs), holes, gaps and kept ACKs, and buffers without capacity are not kept, as they would take the place of ones that save an allocation (implementation decisions, 2026-10-12). A stream gives the room of consumed bytes back once they make up half of its buffer: it keeps at most twice the room its bytes need, but at least `max_pooled_buffer_capacity`. Until half is consumed again, the room can be four times the bytes left, so the memory of all streams stays within about four times `max_total_buffered` plus that capacity per stream (council review, 2026-11-07). That capacity is the idle cost of a stream whose buffer once grew, e.g. by a hole that waited for K4(b), even after every byte was read: with the default of 64 KiB, 100,000 idle connections with one such stream each hold about 6.5 GB, which `max_total_buffered` doesn't bound; a monitor with many concurrent connections lowers `max_pooled_buffer_capacity` (council review, 2026-11-08).
- **P6** `evict_older_than` ends connections with `last_seen < cutoff` as `Evicted` (F5). A connection that is already finished (F3), e.g. because the user gave up its last hole after both FINs were ACKed, ends as `Finished` instead; `evict_all` does the same (user decision, 2026-10-11). A connection that closed cleanly is finished by F3 whatever holes its ACKed FINs cover (user decision, 2026-10-11; council review, 2026-11-08). It calls the callback in the order of the connection ids, so the output is the same in every run (user decision, 2026-10-12), and then recycles their buffers. It also removes tombstones older than the cutoff. The return value counts the connections passed to the callback, also those that end as `Finished`, but not tombstones.
- **P7** Every processed packet of a connection updates `last_seen`, also a late one that its tombstone absorbs (P3). `first_seen` is the timestamp of its first packet.

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
