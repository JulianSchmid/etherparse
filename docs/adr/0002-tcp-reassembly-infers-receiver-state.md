# TCP reassembly infers the receiver's state to give up holes and resync

A passive capture misses packets, and a missing segment that the receiver got will never be retransmitted. So the reassembler gives up holes, and treats bytes as ACKed, based on inferred receiver state instead of waiting for a retransmission or an ACK it may never see. There are two inference rules:

- **Implied ACK.** A sender can only send up to ack + window. Bytes seen at offset X therefore prove the receiver ACKed X − window. Holes before X − k×window become gaps. k defaults to 2 to tolerate window changes. If the window is unknown (mid-stream pickup or one-direction capture), a configurable fallback window of 4 MiB is used.
- **Resync.** When a stream jumps far outside any plausible window without a SYN, it continues at the new position once the other direction's ACKs confirm the jump. Resyncing after N consecutive agreeing segments is opt-in, for one-direction captures.

Without these rules, a stream stalls forever after capture loss or a missed reconnect, and reading only ACKed bytes stalls on one-direction captures. An earlier implementation hit exactly these stalls on real captures.

## Consequences

If the fallback window is set too small, holes are given up whose retransmission would still have arrived. Spoofed ACKs can force a resync, which a passive observer cannot fully prevent. Both effects are visible in the stream status, so the stream is no longer clean.
