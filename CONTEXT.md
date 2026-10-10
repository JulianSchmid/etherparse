# etherparse

A zero-allocation library for parsing and writing network packets, plus helpers that rebuild data spread over several packets (IP defragmentation, TCP reassembly).

## Language

### Packet identification

**Channel id**:
A user-defined value that separates packets the protocol headers alone cannot tell apart (e.g. the capture interface or a tunnel).
_Avoid_: custom id, source id

### TCP reassembly

**Connection**:
Both directions of one TCP connection, identified by its connection key. A reconnect on the same addresses and ports is a new connection.
_Avoid_: flow, session, stream (for both directions)

**Connection key**:
The VLAN ids, IP addresses, ports and channel id that identify a connection, the same for both directions.
_Avoid_: stream id, 4-tuple, 5-tuple

**Connection id**:
A number, unique within a pool, that the pool assigns to each connection; a reconnect gets a different id than the connection it replaces.
_Avoid_: connection key (the header fields), generation

**Reconnect**:
A new connection, started with a SYN, that reuses the connection key of an earlier connection.
_Avoid_: port reuse, restart

**Ended connection**:
A connection that was reset, finished, replaced by a reconnect or evicted, and has been handed over to the user.
_Avoid_: closed connection, dead connection

**Initiator**:
The endpoint of a connection that sent the SYN.
_Avoid_: client, originator, A

**Responder**:
The endpoint of a connection that answered the SYN.
_Avoid_: server, B

**Guessed roles**:
Initiator and responder assigned from the port numbers (the lower port is the responder) because the handshake was not seen.
_Avoid_: unknown roles, heuristic direction

**Stream**:
The bytes sent in one direction of a connection; every connection has two streams.
_Avoid_: half-connection, flow, direction (for the data itself)

**Observed start**:
A stream whose first byte is known from the handshake.
_Avoid_: handshake seen, complete start

**Mid-stream pickup**:
A stream whose first seen segment was not its SYN, so the bytes before it are unknown.
_Avoid_: partial stream, lazy anchor

**Retransmission**:
A segment carrying bytes of a stream that were already received.
_Avoid_: resend, duplicate

**Conflicting retransmission**:
A retransmission of not yet ACKed bytes whose content differs from the bytes first received for the same positions; the first received bytes are kept. Retransmissions of ACKed bytes never conflict, as the receiver ignores them too.
_Avoid_: overlap conflict, corrupted retransmit

**Hole**:
Missing bytes of a stream with later bytes already received behind them; a retransmission can still fill it.
_Avoid_: gap (while the bytes may still arrive), missing segment

**Gap**:
A hole that was given up, by the user or by a policy; a permanent break in the delivered bytes.
_Avoid_: hole (once given up), loss, skip

**Implied ACK**:
The position up to which the receiver must have acknowledged a stream, inferred from how far the sender has sent and the receiver's window, without that ACK being seen.
_Avoid_: virtual ack, assumed ack

**Resync**:
Continuing a stream at a new sequence position after a large jump without a SYN, leaving a gap of unknown length.
_Avoid_: rebase, re-anchor, jump

**Rejected bytes**:
Received bytes of a stream that were not stored because a memory limit was reached.
_Avoid_: dropped bytes, lost bytes

**Finished stream**:
A stream whose FIN was seen and that has no holes before the FIN.
_Avoid_: closed stream, complete stream

**Finished connection**:
A connection whose two streams are finished and whose two FINs were both ACKed.
_Avoid_: closed connection, completed connection

**Clean**:
A stream that so far has no gaps, resyncs, conflicting retransmissions or rejected bytes; a mid-stream pickup can be clean.
_Avoid_: valid, intact, healthy

**Complete**:
A clean stream with an observed start that is finished: every byte the sender sent, exactly once and unambiguously.
_Avoid_: full, whole, clean (for this stronger property)
