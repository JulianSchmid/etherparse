# 13: Packet inputs

Parent: ../spec.md

**What to build:**
- Users feed `SlicedPacket`s and `LaxSlicedPacket`s directly. The connection key is built from the VLAN IDs, the IPv4 or IPv6 addresses and ports, and the channel id.
- Non-TCP packets and IP-fragmented TCP are ignored with `NotTcp`.
- With lax input and a truncated payload, only the captured bytes are added; the rest stays a hole, and the FIN of a truncated segment is ignored.
- TCP that `IpDefragPool` put back together can be fed through `process_segment`.

Rules: P1, P2, D6.

**Blocked by:** 02, 03

**Status:** ready-for-agent

- [ ] IPv4 and IPv6, with zero to three VLAN tags; differing VLAN IDs or channel ids keep otherwise identical connections apart
- [ ] Non-TCP and IP-fragmented packets are ignored with `NotTcp`
- [ ] Lax input with a truncated payload: the captured bytes plus a hole; the FIN on a truncated segment is ignored
- [ ] A TCP segment reassembled by `IpDefragPool` and fed through `process_segment` is reassembled correctly
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-11 — carry-over from ticket 07:** the start rules of a pickup look at `tcp.payload()`. With truncated payload (D6), a segment with 1 captured byte can look like a keep-alive, and the ignored FIN of a truncated segment must not start a stream at its FIN either.

**2026-10-11 — carry-over from ticket 08:** with truncated payload (D6), a resync candidate's end is computed from the captured bytes (`ResyncCandidate::new(seq, data.len(), tcp.fin())` in `TcpStream::add_segment`). An ACK-confirmed resync would then continue in the middle of the truncated segment, and its FIN would count. Use the segment's real length for the candidate when it is known, and ignore the FIN of a truncated candidate as D6 does.

**2026-10-11 — carry-over from ticket 10:** a kept SYN is replayed from a copy of its raw bytes (`ReconnectSyn::tcp` parses them with `TcpSlice::from_slice`). If lax input marks truncated segments (D6), a kept SYN has to keep that mark, or its replay applies a FIN that D6 would ignore.

**2026-10-12 — carry-over from ticket 12:** `stats().ignored_packets` counts every packet with `TcpProcessed::ignored` set (user decision 4 of ticket 12). Packets that `process_sliced_packet` / `process_lax_sliced_packet` ignore with `NotTcp` must count too. Return them through the pool's helper `ignore(reason, &mut self.ignored_packets)` in `tcp_reassembly_pool.rs`, and extend the `stats` test.
