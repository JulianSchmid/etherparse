# TCP reassembly takes a reconnect at once and tells late segments by their numbers

Clients reuse a four-tuple when they reconnect after a close, an abort or a crash. A capture merged from two taps can show the halves of the new handshake, and the late segments of the connection before, in almost any order. The reassembler decides whose a segment is by its sequence numbers. The exact evidence comes first, and a SYN or SYN-ACK with a new ISN replaces the connection at once (spec rules C1, C2, C4). Until a SYN is answered, the pool drops segments like the endpoints do (S5).

## A reconnect replaces the connection at once (C2)

Benign traffic has no other SYN or SYN-ACK with a new ISN from an endpoint of a live connection: a retransmission repeats the ISN (C3), and a new attempt after a failed one is a new connection. So a new ISN is a reconnect, in either order of the handshake's capture, as a merged capture can show the SYN-ACK first. The reconnect's other segments are its own, so its bytes, holes, windows, ACKs and FINs count there. The old connection gets no fake hole from them when the ISNs lie near (a quick reuse, RFC 6528). A SYN-ACK that ACKs no SYN the pool knows answers one the capture missed. So a failed attempt whose answer was never captured doesn't block the next one.

Until 2026-11-08, the SYN was kept until a SYN-ACK of the other endpoint confirmed it, so that a spoofed SYN couldn't end a connection (user decision, 2026-10-11). The confirmation and the segments kept with it grew into a mechanism of their own: kept SYN-ACKs, retained segments, their exits and budgets. Four review rounds kept finding gaps in it, and the owner's focus on captures without an attacker made it dispensable (council review, 2026-11-08).

## The exact evidence comes first (C4, C1)

Whose a SYN or SYN-ACK is, is decided in this order: the sender's observed ISN, then, for a SYN-ACK, the other stream's observed SYN, and only then the heuristics of pickups and streams without a start. The other order failed twice (council round 34):

- A pickup's first captured byte is only where the capture started, so a reconnect's ISN + 1 can lie right there without repeating an ISN. With the first byte first, the reconnect's SYN-ACK and its response were absorbed as the old connection's.
- A SYN-ACK that ACKs the client's observed SYN is its stream's own late SYN-ACK, also after a FIN: within one direction, the network can reorder it behind its sender's next segments. With C4's FIN rule first, it started a ghost reconnect.

The heuristics: a pickup's own late SYN arrives among the stream's first segments, which a capture can reorder, while a reconnect's SYN arrives after the old connection began to close. So the A5 range counts only before a FIN, and the first byte always. On a stream without a start, a merged capture can show the late SYN or SYN-ACK of a connection whose other half it lost after the other side's FIN, so there the other side's kept ACK (K1) decides. A late SYN-ACK that a pickup refuses changes nothing, its ACK number included, which would otherwise move the other stream's start (A2).

## Late segments of a replaced connection go by their numbers (C1)

On one path, an endpoint's segments of the replaced connection can't arrive after its first segment of the new one. So while the sender sent nothing the new connection took, a segment without SYN is the replaced connection's if its numbers lie within the old spans. The spans are widened by k windows for bytes the capture may have missed. They are exact at an observed SYN and a seen FIN, as the sender sent nothing before and after them. A pickup's first byte is only where the capture started, so the other side's ACKs can lie before it. A captured FIN thus ends the old stream exactly. The response of a reuse 1 ms after a close, captured before the request it ACKs (the SYN-ACK lost, the client's tap behind), lies past the old FINs and is the new connection's. The ACK number of an absorbed ACK moves the other stream's end forward, as the capture may have missed that stream's FIN, and the RST that answers the ACK lies at the ACK number (RFC 9293 3.10.7.3).

The new connection's own segments come first, as after a reset, which has no TIME-WAIT to keep them apart, the new ISNs can lie within the old spans. One exception: an RST without ACK from a side in SYN-SENT answers an ACK of the replaced connection (RFC 9293 3.10.7.3), wherever it lies and whether that ACK was captured or not. Past SYN-SENT, only a side that crashed sends an RST without ACK (from CLOSED, RFC 9293 3.10.7.1), which resets the new connection.

This covers a near reuse of the four-tuple whose new ISN lies below the old stream's end, and a reuse right after an abort:

- the ACK with which a server in TIME-WAIT answers such a SYN, which S5 would otherwise take as the answer to the SYN, with a fake hole of the distance;
- the client's RST to that ACK, which would otherwise reset the new connection, whose tombstone would then swallow the real handshake (F4);
- the old close's last ACK or a FIN retransmission captured after the new SYN, and bytes of the old connection still in flight;
- the RST of a client that aborted and reconnected at once, captured after the new SYN-ACK because the client's tap lags;
- the server's segment in flight when a client aborted after bytes the capture lost, which ACKs them (the slack covers them, also when the new ISN lies within them);
- the late RST of a client that ACKs bytes before the first byte of a server stream the capture picked up mid-stream.

A connection keeps the numbers of only the connection it replaced, not of the one before: the late duplicate of a handshake two reconnects back starts a new connection.

## Until a SYN is answered, the pool drops like the endpoints do (S5)

An endpoint in SYN-SENT or SYN-RECEIVED drops most segments of the other side (RFC 9293 3.10.7.3 and 3.10.7.4). The pool does the same before anything else looks at the segment, as the endpoint never took a dropped segment. What passes, and why:

- An ACK up to k windows after the SYN: the capture may have lost the SYN-ACK or the ACK of the SYN-ACK. An RST there comes from a side that got past SYN-SENT, so it resets like the bytes that side sent (council review, 2026-11-08; until then only the exact ACK of the SYN counted, against blind RSTs).
- A SYN-ACK without RST and FIN, always: it answers the SYN, or it answers another SYN and starts a reconnect (C2). With an RST, it would be an RST that F4 accepts blindly; with a FIN, it would end the stream.
- An ACK within one window of the resync candidate: the bytes jumped and the other side ACKs them (R2). An RST or FIN doesn't pass this way, as a blind pair of segments could land one there, or a FIN with the jump.
- A SYN without ACK, FIN and RST: a simultaneous open. One with a FIN is dropped like a blind one, as nothing could recover a stream that a blind FIN ended.
- An RST in SYN-RECEIVED: F4 checks it by its sequence number.

The wait also ends with a segment of the SYN's sender that its stream accepts, as the sender got an answer the capture missed. After any exit, an RST or FIN of a side with neither a start nor a kept ACK still has to ACK the SYN, as F4 and A4 would take any RST or FIN of such a side.

A SYN without ACK of a side without a start, while the other side's SYN is unanswered, may be blind. As the stream's start, it would wait for an ACK that never comes and drop every segment of the other side, so it is kept until a SYN-ACK confirms it. A SYN-ACK or RST that ACKs the observed SYN overrules an ACK kept for its sender's stream, which can come from a blind segment with the SYN sender's address. A SYN-ACK keeps a kept ACK that allows it, as the kept ACK of a reordered capture ACKs its bytes. A kept SYN's bytes retransmitted differently are no concern of benign traffic (owner decision, 2026-11-08).

## Considered Options

- **Keep a SYN with a new ISN until a SYN-ACK confirms it** (until 2026-11-08): it guarded live connections against a spoofed SYN, at the cost of the mechanism described above.
- **Any SYN on a pickup's tombstone creates a new connection** (user decision, 2026-10-11): the ended pickup's own late handshake then started a ghost connection, so a SYN right at a pickup stream's first byte is its own.
- **The pickup's first byte before an observed SYN** (council round 33): replaced by the exact evidence first (round 34), see above.
- **Clip the old spans by ACKs**: it broke cases where the new numbers lie inside the old spans, so the spans end exactly only at an observed SYN and a seen FIN, and have slack elsewhere.
- **Apply the ACK of a segment only if its receiver accepts the segment** (RFC 9293 3.10.7.4): it would let an open connection refuse fewer of its own segments after a new connection's segments came before its handshake, but it touches the S and R rules, so it is left to the owner.

## Consequences

The known limits that C1, C2, C4 and S5 list come from these choices. The simulator names them (`known_limit`) and keeps them rare: below 5% of its random histories. A spoofed SYN or SYN-ACK with a new ISN replaces a live connection, which the end `Reconnect` shows.
