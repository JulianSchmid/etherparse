# TCP reassembly keeps each stream in one contiguous buffer that the user pulls from

The TCP reassembly pool stores the bytes of each stream in a single contiguous buffer, recycled through the pool's free list as `IpDefragPool` does. Users read the readable bytes as one `&[u8]` and call `consume`. We chose this because protocol parsers built on top want one contiguous slice, and pull reads let the user decide when bytes are dropped and whether to read only ACKed bytes.

## Considered Options

- **Fixed-size pages from a central page pool** (gopacket, Suricata): pages give a natural global memory cap and avoid compaction, but every reader would get an iterator of slices and most would end up copying to get contiguous bytes.
- **Push callbacks** when bytes become readable: these keep no data after the call, which rules out user-controlled dropping and reading only ACKed bytes later.

## Consequences

Compacting a buffer costs a memmove, and a single stream can grow up to its per-stream limit, so memory is bounded by limits rather than by page accounting.
