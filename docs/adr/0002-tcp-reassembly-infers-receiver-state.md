# TCP reassembly infers the receiver's state to give up holes and resync

A passive capture misses packets, and a missing segment that the receiver got will never be retransmitted. So the reassembler gives up holes, and treats bytes as ACKed, based on inferred receiver state instead of waiting for a retransmission or an ACK it may never see. There are two inference rules:

- **Implied ACK.** A sender can only send up to ack + window. Bytes seen at offset X therefore prove the receiver ACKed X − window. Holes before X − k×window become overdue. k defaults to 2 to tolerate window changes, and the window is the largest one the receiver advertised, so a window that shrinks (e.g. to 0 when its buffer is full) doesn't make holes overdue early. If the window is unknown (mid-stream pickup or one-direction capture), a configurable fallback window of 4 MiB is used. The distance is capped at half of the stream's buffer, so that a reader of ACKed bytes keeps up before the buffer is full, but never below a known window, as that would be unsound. So without captured ACKs, such a reader keeps up only if the buffer is clearly larger than the receiver's window; otherwise bytes are rejected and counted.
- **Resync.** When a stream jumps far outside any plausible window without a SYN, it continues at the new position once the other direction's ACKs confirm the jump. Resyncing after N consecutive agreeing segments is opt-in, for one-direction captures.

Without these rules, a stream stalls forever after capture loss or a missed reconnect, and reading only ACKed bytes stalls on one-direction captures. An earlier implementation hit exactly these stalls on real captures.

Giving up is lazy. An overdue hole (by the implied ACK, or covered by a seen ACK for a configurable number of packets, but not past half of the buffer) stays a hole that late segments still fill. It becomes a gap only once the reader reaches it or the connection ends. A rule firing only means the bytes are unlikely to come; giving the hole up right away would drop segments that merely arrive late, e.g. in merged captures, before the reader needs them.

## Why the rules look as they do

The spec states the rules (S3, S4, K2, K4); this is why, and what they replaced.

- **The largest window counts (S4, K2).** The sender can have sent into a larger window before the receiver's window shrank, e.g. to 0 when its buffer is full. With the last window, a lost segment among those in flight made the rest out-of-window and let their ACK resync the stream, and an ACK advertising window 0 made the hole it added overdue at once (user decision, 2026-10-11; council review, 2026-11-07).
- **A SYN's window is unknown under a scale (S3).** A SYN's window is never scaled, so under a scale above 0 it is only a lower bound of the window after it. A capture merged from two taps can show the receiver's first scaled window late. Until then, K2 went by the SYN's window, and a segment reordered behind six later ones became a gap. Round 36 delayed the implied ACK by `ack_reorder_tolerance` packets instead, but that wait counts packets, not bytes: with large segments, one lost segment then overflowed the buffer (council review, 2026-11-08, rounds 36 and 37).
- **The implied ACK goes by what the capture showed of the sender (K2).** With the highest offset, which ACKs move, ACKs that a merged capture showed before the bytes made holes that ordinary reordering opened overdue at once (council review, 2026-11-08).
- **The implied ACK's distance (K2)** is at most half of the buffer: with the defaults, k times the fallback window equalled the buffer, so a reader of the ACKed bytes in a one-direction capture sat at the buffer's end, every further segment was rejected, and half the stream was lost. It is never less than a known window, as the sender can have sent that far past the ACK (council review, 2026-11-07).
- **K4(b) waits 256 packets by default.** A merged capture shows the ACKs of one direction ahead of the data by the skew between the taps, hundreds of packets per millisecond at 1 Gbit/s; 16 gave captured bytes up as gaps from about 200 Mbit/s on (council review, 2026-11-08).
- **K4(c) gives holes up before rejected bytes.** Rejected bytes at the end of a stream join one hole that each rejected segment extends, so the implied ACK never passes it, and in a continuous flow the reader would stall there (user decision, 2026-10-12).
- **K4(d) bounds K4(b) by the buffer.** Where a known window keeps the implied ACK further back than half the buffer, nothing else bounded the stall: with jumbo frames and a 1 MiB buffer, 256 packets didn't fit, and the bytes after a lost segment were rejected as a second gap (council review, 2026-11-08, round 37).
- **The leading data (S4)** mirrors the leading ACK (K1). A receiver's tap that lags past k windows shows the ACKs that would let the window reach the bytes after a burst of capture loss too late. Every later segment lay after the window, and the rest of the stream and its FIN were lost. The bound by the buffer keeps a jump, which lies there by chance only, a resync candidate (council review, 2026-11-08, round 36).

## Considered Options

- **Eager gaps**: giving a hole up as soon as a rule fires is simpler and counts gaps earlier, but drops late bytes the reader hasn't reached yet, and leaves gaps anywhere in the buffer instead of only at the read position.

## Consequences

If the fallback window is set too small, holes are given up whose retransmission would still have arrived. Spoofed ACKs can force a resync, which a passive observer cannot fully prevent, and a spoofed data segment with a FIN after the window plus a spoofed ACK of it end the stream at that FIN, which `force_resync()` doesn't undo. A spoofed SYN or SYN-ACK with a new ISN replaces a live connection as a reconnect (C2), as the reassembler is built for captures without an attacker. All of these are visible in the stream status or the connection's end, so the stream is no longer clean.

Overdue holes keep counting towards the per-stream hole limit until the reader reaches them. A keep-alive's filler byte, sent at the last ACKed byte, could land in an overdue hole the reader hasn't reached, so a 1-byte segment ending at the seen ACK is ignored there.
