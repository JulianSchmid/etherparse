# 15: Fuzzing and mutation testing

Parent: ../spec.md

**What to build:**
- A `cargo-fuzz` crate outside the workspace and outside CI. It feeds arbitrary packet sequences and config values to the pool and asserts that nothing panics and that the limits hold.
- A `cargo mutants` run on the module. Every surviving mutant is killed with a test or listed below as equivalent, with the reason.

**Blocked by:** 14

**Status:** ready-for-agent

- [ ] The fuzz target runs for at least 30 minutes without findings; every crash found along the way is fixed with a regression test
- [ ] No mutant survives without an explanation below
- [ ] All new behaviour is tested through the pool's public API (value types directly), with every branch covered; `cargo test`, `cargo test --no-default-features` and the bare-metal no_std build pass

## Equivalent mutants

(to be filled in)

**2026-10-12 — carry-over from ticket 11:**
- Equivalent mutants: in the fill loop of `TcpStream::add_data`, `.min(stored_end)` → `.min(end)` (a rejected segment then writes into placeholders whose hole stays, which nothing can observe); `if self.config.max_total_buffered.is_some()` → `if true` before `handed_out` in `TcpReassemblyPool::process_segment` (it only skips a lookup without a budget).
- The fuzzer can assert that `holes()` lists at most `max_holes_per_stream` + 1 holes, and that a stream never has more than about 2 × `max_holes_per_stream` + 2 unread gaps while open.

## Comments

**2026-10-12 — carry-over from ticket 12:**
- Equivalent mutants: `if self.config.max_total_buffered.is_some()` → `if true` in `get_mut` and `iter_mut`, as in `process_segment` (it only skips the accounting of handed-out connections without a budget).
- The fuzzer should also call `evict_older_than`, `evict_all`, `get_mut`, `iter_mut` and `recycle` at random points, and check `stats()`: `connections + tombstones` within `max_connections`.
