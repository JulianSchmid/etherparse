# TCP reassembly keeps each stream in one contiguous buffer that the user pulls from

The TCP reassembly pool stores the bytes of each stream in a single contiguous buffer, recycled through the pool's free list as `IpDefragPool` does. Users read the readable bytes as one `&[u8]` and call `consume`. We chose this because protocol parsers built on top want one contiguous slice, and pull reads let the user decide when bytes are dropped and whether to read only ACKed bytes.

## Considered Options

- **Fixed-size pages from a central page pool** (gopacket, Suricata): pages give a natural global memory cap and avoid compaction, but every reader would get an iterator of slices and most would end up copying to get contiguous bytes.
- **Push callbacks** when bytes become readable: these keep no data after the call, which rules out user-controlled dropping and reading only ACKed bytes later.

## Consequences

Compacting a buffer costs a memmove, and a single stream can grow up to its per-stream limit, so memory is bounded by limits rather than by page accounting.

Missing bytes take placeholders, so a few bytes far apart cost as much memory as the bytes between them. A stream gives the room of consumed bytes back once they make up half of its buffer, so the memory of all streams follows the bytes they hold (about four times `max_total_buffered`, as the room shrinks to twice the bytes left and half of it can be consumed before it shrinks again, plus the pooled buffer capacity per stream). The price is that a stream whose reader keeps up takes the room for a burst again at the next one: tiny segments far apart with an eager reader cost a buffer's worth of fresh pages each, far more than a normal segment.
