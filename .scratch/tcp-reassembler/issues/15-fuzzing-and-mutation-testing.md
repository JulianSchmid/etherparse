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
