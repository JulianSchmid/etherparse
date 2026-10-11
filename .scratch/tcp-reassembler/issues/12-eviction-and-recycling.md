# 12: Eviction and buffer recycling

Parent: ../spec.md

**What to build:** Users control timeouts and buffer reuse:
- `evict_older_than(cutoff, callback)` ends connections whose last-seen time is strictly older than the cutoff. Each gets the end `Evicted` and its holes become gaps. The callback drains it before the pool recycles the buffers.
- Tombstones older than the cutoff are removed. The return value counts evicted connections, not tombstones.
- `evict_all(callback)` does the same for every connection, for flushing at the end of a capture.
- The free list keeps at most `max_pooled_buffers` buffers and shrinks them to `max_pooled_buffer_capacity`.
- `stats()`, `get_mut()` and `iter_mut()` are available.

Rules: P5, P6, F5, F6 (`End(Evicted)`).

**Blocked by:** 02, 05

**Status:** ready-for-agent

- [ ] `evict_older_than`: strict `<`; the callback sees `End(Evicted)` and the gaps; the count excludes tombstones; old tombstones are removed
- [ ] `evict_all` flushes every connection
- [ ] A counting-allocator test: after warm-up, steady-state processing with `recycle` allocates no new buffers; the free-list count and capacity limits hold
- [ ] `stats()` reports connections, tombstones, buffered bytes, rejected connections and ignored packets exactly
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 02:**
- The free list (`TcpReassemblyPool::free_buffers`) exists, but it is unbounded and its buffers aren't shrunk.
- Decide whether late segments refresh a tombstone's `last_seen`. They don't today. P7 says every packet updates `last_seen`, but P6 removes old tombstones.
- Tombstones are `TcpConnection`s with `end().is_some()` in the same map. `get_mut`, `iter_mut` and `stats()` must tell them apart.

**2026-10-10 — carry-over from ticket 03:** each stream now also owns a `holes: Vec<Range<u64>>`. `TcpStream::into_buffer` drops it instead of recycling it, so the steady-state allocation test needs it in the free list too ("buffers kept per kind").

**2026-10-11 — carry-over from ticket 05:** giving up the last hole can finish a stream, and with both FINs ACKed the connection too (F3). But `TcpConnection::end` is only set in `add_segment`, so the pool hands the connection over only with its next segment. In real captures that segment often never comes, and eviction then ends a connection that is in fact finished as `Evicted`.
**User decision (2026-10-11):** `evict_older_than` and `evict_all` check F3 first. A connection that is already finished ends as `Finished`, not `Evicted` (P6 in spec.md). No new pool method.

F5 for `Evicted` uses `TcpStream::give_up_holes_before(highest_offset)` (see ticket 09).
