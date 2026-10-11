# TCP reassembly infers the receiver's state to give up holes and resync

A passive capture misses packets, and a missing segment that the receiver got will never be retransmitted. So the reassembler gives up holes, and treats bytes as ACKed, based on inferred receiver state instead of waiting for a retransmission or an ACK it may never see. There are two inference rules:

- **Implied ACK.** A sender can only send up to ack + window. Bytes seen at offset X therefore prove the receiver ACKed X − window. Holes before X − k×window become overdue. k defaults to 2 to tolerate window changes. If the window is unknown (mid-stream pickup or one-direction capture), a configurable fallback window of 4 MiB is used.
- **Resync.** When a stream jumps far outside any plausible window without a SYN, it continues at the new position once the other direction's ACKs confirm the jump. Resyncing after N consecutive agreeing segments is opt-in, for one-direction captures.

Without these rules, a stream stalls forever after capture loss or a missed reconnect, and reading only ACKed bytes stalls on one-direction captures. An earlier implementation hit exactly these stalls on real captures.

Giving up is lazy. An overdue hole (by the implied ACK, or covered by a seen ACK for a configurable number of packets) stays a hole that late segments still fill. It becomes a gap only once the reader reaches it or the connection ends. A rule firing only means the bytes are unlikely to come; giving the hole up right away would drop segments that merely arrive late, e.g. in merged captures, before the reader needs them.

## Considered Options

- **Eager gaps**: giving a hole up as soon as a rule fires is simpler and counts gaps earlier, but drops late bytes the reader hasn't reached yet, and leaves gaps anywhere in the buffer instead of only at the read position.

## Consequences

If the fallback window is set too small, holes are given up whose retransmission would still have arrived. Spoofed ACKs can force a resync, which a passive observer cannot fully prevent. Both effects are visible in the stream status, so the stream is no longer clean.

Overdue holes keep counting towards the per-stream hole limit until the reader reaches them. A keep-alive's filler byte, sent at the last ACKed byte, could land in an overdue hole the reader hasn't reached, so a 1-byte segment ending at the seen ACK is ignored there.
