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

- [x] `evict_older_than`: strict `<`; the callback sees `End(Evicted)` and the gaps; the count excludes tombstones; old tombstones are removed
- [x] `evict_all` flushes every connection
- [x] A counting-allocator test: after warm-up, steady-state processing with `recycle` allocates no new buffers; the free-list count and capacity limits hold
- [x] `stats()` reports connections, tombstones, buffered bytes, rejected connections and ignored packets exactly
- [x] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Comments

**2026-10-10 — carry-over from ticket 02:**
- The free list (`TcpReassemblyPool::free_buffers`) exists, but it is unbounded and its buffers aren't shrunk.
- Decide whether late segments refresh a tombstone's `last_seen`. They don't today. P7 says every packet updates `last_seen`, but P6 removes old tombstones.
- Tombstones are `TcpConnection`s with `end().is_some()` in the same map. `get_mut`, `iter_mut` and `stats()` must tell them apart.

**2026-10-10 — carry-over from ticket 03:** each stream now also owns a `holes: Vec<Range<u64>>`. `TcpStream::into_buffer` drops it instead of recycling it, so the steady-state allocation test needs it in the free list too ("buffers kept per kind").

**2026-10-11 — carry-over from ticket 05:** giving up the last hole can finish a stream, and with both FINs ACKed the connection too (F3). But `TcpConnection::end` is only set in `add_segment`, so the pool hands the connection over only with its next segment. In real captures that segment often never comes, and eviction then ends a connection that is in fact finished as `Evicted`.
**User decision (2026-10-11):** `evict_older_than` and `evict_all` check F3 first. A connection that is already finished ends as `Finished`, not `Evicted` (P6 in spec.md). No new pool method.

F5 for `Evicted` uses `TcpStream::give_up_holes_before(highest_offset)` (see ticket 09).

**2026-10-11 — carry-over from the ticket-06 grilling (lazy gaps):** when P6 checks F3 at eviction (`evict_older_than` and `evict_all`), every hole that the seen ACK covers counts as overdue, because no more packets come. Example: a connection that closed cleanly, whose last hole was covered by the ACK of a FIN with fewer than `ack_reorder_tolerance` packets after it, ends as `Finished`, not `Evicted`. As at every end, its holes become counted gaps (F5), and reads end in `End(Fin)`. Add a test for exactly this case.

**2026-10-11 — carry-over from ticket 06:** `TcpStream::can_finish()` checks F3 for a stream: the FIN is ACKed and every hole left is overdue. Eviction needs a variant that treats every hole the seen ACK covers as overdue (the tolerance counts as elapsed). `give_up_all_holes()` then turns them into counted gaps.

**2026-10-11 — carry-over from ticket 08:** a stream's FIN can sit at a resync point (the candidate's FIN, R2), with the resync's gap in front of it, so `can_finish()` and eviction see a finished stream behind a `Gap { len: None }`. F5 at eviction keeps that gap (it is an empty range in `TcpStream::gaps`, which `give_up_holes_before` leaves alone).

**2026-10-11 — carry-over from ticket 09:**
- F5 at eviction is `TcpStream::connection_ended(TcpStreamEnd::Evicted)`, which replaced `give_up_all_holes()`. It also makes reads return `End(Evicted)` away from the FIN. `Evicted` needs an arm in the `TcpConnectionEnd → TcpStreamEnd` match in `TcpConnection::add_segment`, or a shared mapping.
- Ignored RSTs update `last_seen` (user decision), so injected RSTs keep a connection from being evicted, like any other packet of it.

**2026-10-11 — carry-over from ticket 10:**
- `TcpStream::is_fin_acked()` is the variant of F3 that P6 needs: all holes lie before the FIN, so an ACKed FIN covers them all. `TcpConnection::end_replaced` already ends a connection replaced by a reconnect as `Finished` when both FINs are ACKed (user decision 8 of ticket 10, the same rule as P6).
- Tombstones now keep the ISNs of their streams (`TcpStream::tombstone`) and the kept SYN of a reconnect (`ReconnectSyn`). Evicting a connection or a tombstone should return that SYN's buffer to the free list, as the pool does when a reconnect starts.
- The kept SYN's buffer goes to the unbounded free list; a mutant that drops this push survives until the counting-allocator test exists.

**2026-10-12 — carry-over from ticket 11:**
- The pool keeps the bytes all streams buffer as `TcpReassemblyPool::buffered`, accounted for per connection (`TcpConnection::account_buffered` / `release_buffered`), and the key of the connection the last call handed out (`handed_out`), which it accounts for again at the next call. Both are kept only while `max_total_buffered` is set.
  - `get_mut` and `iter_mut` hand out connections whose streams the user can read, so they must account for them too (set `handed_out`, or account for all connections after `iter_mut`).
  - Eviction must release every evicted connection, or the budget stays used.
  - `stats()` needs the accounting without a limit too, or a sum over the connections.
- `TooManyConnections` is returned in the `Entry::Vacant` branch of `process_segment`; the rejected-connections counter of `stats()` belongs there.
- Tombstones count towards `max_connections`, so without eviction a pool full of tombstones rejects every new connection.
- A stream's buffer can take up to about twice `max_stream_buffer`, as consumed bytes are drained once they make up half of it. The allocation test and `max_pooled_buffer_capacity` should allow for that.

**2026-10-12 — user decisions (asked before implementing):**
1. **Late segments refresh a tombstone's `last_seen`** (P7 holds for tombstones too): eviction removes a tombstone only once no late segment came since the cutoff, so late packets that keep coming never start a ghost pickup. Rejected: keeping the last-seen time of the connection's last packet, under which a tombstone goes one timeout after the end, and a late segment with bytes after that starts a ghost mid-stream pickup.
2. **The callback is called in the order of the connection ids** (creation order), so output at `evict_all` is the same in every run. The pool keeps a reusable list of the keys to evict and sorts it. Rejected: the hash map's order, which changes from run to run.
3. **`stats()` walks the connection table** at each call: O(connections), always exact, no cost per packet. Rejected: counters, under which the buffered-byte accounting of `max_total_buffered` would run for every packet also without the limit.
4. **`ignored_packets` counts every packet with `TcpProcessed::ignored` set**, and `rejected_connections` the `TooManyConnections` ones among them. Rejected: disjoint counters.

spec.md P3, P6 and the `stats()` API are updated.

**2026-10-12 — implemented:**
- `fc44419` (refactor): the free list moves into `FreeBuffers`, one `FreeList` per kind. Streams, connections and kept SYNs (`ReconnectSyn::recycle`) take their buffers from it and put them back.
- `3babf47` (test groundwork): a counting allocator for the unit-test binary counts the allocations of the current thread (`count_allocations`), and `TestSegment::to_bytes` / `feed_bytes` feed pre-serialized segments without allocating.
- `1306081`: holes, gaps and kept ACKs get free lists of their own kinds, and a kept SYN takes its buffer from the list for bytes. The `recycle` test runs rounds of a steady state with every kind of buffer and end, including both kinds of reconnect, and every round after the first allocates nothing.
- `bfb1fa1`: P5. Each list keeps at most `max_pooled_buffers` buffers, shrunk to `max_pooled_buffer_capacity` bytes. It takes both limits from the configuration when the pool is created.
- `3ec2b42` (refactor): `TcpConnection::end_unless_finished(end)` replaces `end_replaced()`, also in the model.
- `c09e24b`: `TcpConnectionEnd::Evicted`, `TcpStreamEnd::Evicted`, `evict_older_than` and `evict_all` (P6, F5, F6):
  - callbacks come in id order, from a reused key list (`evicted_keys`);
  - the buffers of evicted connections and kept SYNs are recycled, also a tombstone's;
  - evicted connections leave `max_total_buffered`;
  - old tombstones are forgotten without being counted.
- `987f095`: late segments refresh a tombstone's `last_seen` (decision 1).
- `9126a37`: `get_mut` and `iter_mut` return open connections only. The next call accounts for what they handed out: `HandedOut::Connection(key)`, or `HandedOut::All` after `iter_mut`. `get_mut` first accounts for the connection handed out before it.
- `539f7cc`: `TcpPoolStats` and `stats()` (decisions 3 and 4). The pool counts ignored packets in one helper, `ignore()`.
- `802f79b`: `ReferenceModel::evict`, `check_to_end`, the harness parameter `evictions` with `evict_and_check`, and the proptest `evictions`. That proptest evicts at random points of connections with capture loss, an RST and a budget, and is green at 3000 cases. A seed from a mutant run is committed.

Implementation decisions (not asked):
- Free-list kinds are by purpose: bytes (stream buffers and kept SYNs), holes, gaps and kept ACKs. A first version shared one kind for holes and gaps, and a stream's unused gaps slot then took the buffer its holes needed.
- Buffers without capacity are not kept, as they would take the place of buffers that save an allocation.
- Every stream that stores bytes uses its holes buffer, because `extend_to` pushes a hole that `remove_from_holes` takes out again. So even in-order streams need one; it is recycled.
- `evict_older_than` takes the cutoff by value, like `process_segment` takes its timestamp. The callback is `FnMut(&mut TcpConnection)`.
- The return value of both evictions counts every connection passed to the callback, also those that end as `Finished` (spec P6 now says so).
- `iter_mut` hands out connections in hash-map order. Users who need an order can collect the references and sort them by id. Only the eviction callbacks are sorted (decision 2).

Review (standards and spec, both axes):
- The spec review traced finishing at eviction, kept SYNs in connections and tombstones, budget accounting through `get_mut`/`iter_mut`/eviction, tombstone refresh and late segments after forgetting, and found no bug. Its findings are fixed:
  - P6 now states what the return value counts;
  - the `stats()` doc mentions tombstones;
  - the `evict_all` test covers `Finished` with a gap;
  - the seed is committed;
  - ticket 13 has a carry-over for `NotTcp`.
- The standards review's findings are fixed:
  - the free list is `FreeList` from the first commit, the test groundwork is its own commit, and the model's rename sits in the refactor commit;
  - `ReconnectSyn::recycle` replaces four copies of `put(syn.into_buffer())`;
  - the free list keeps its limits itself, so `config` no longer travels with `free`;
  - the field is now `evicted_keys`;
  - the test helpers `with_port`, `late_bytes`, `budget_scripts` and `key_of` replace duplicated scripts;
  - the counting allocator has its own test.
- Judgement calls left as they are:
  - `feed_and_check` takes a sixth slice (`evictions`) rather than a schedule type (ticket 14 may restructure it);
  - the model keeps its own `TcpConnectionEnd` → `TcpStreamEnd` match (an independent oracle);
  - `free_buffers.rs` has no tests of its own, as the free list is tested through the pool (the spec's single seam);
  - the eviction docs say the callback comes before the buffers are re-used, as users need to know that the connection is gone afterwards.

The library code of the module is fully covered (merged view of `cargo cov`). Manual mutants of every new condition are killed, apart from these equivalent ones: `if self.config.max_total_buffered.is_some()` → `if true` in `get_mut` and `iter_mut` (it only skips the accounting without a budget). The `set_last_seen` mutant survives the model proptest, which uses `evict_all`, but the `evict_older_than` unit test kills it.

