# etherparse

Zero-allocation `no_std` library for parsing and writing packet-based protocols (Ethernet II, VLAN, MACsec, Linux SLL, ARP, IPv4/IPv6 + extension headers, UDP, TCP, ICMPv4/v6, IGMP). Only IP defragmentation (`defrag`) and TCP reassembly (`tcp_reassembly`) allocate.

## Commands

Run from the workspace root.

```sh
cargo build
cargo test                                  # all tests (unit tests live inside src/)
cargo test --no-default-features            # no_std / no-alloc build must also pass
cargo test -p etherparse udp_slice          # tests whose path matches a filter
cargo test -p etherparse --lib transport::udp_slice::test::from_slice -- --exact
PROPTEST_CASES=16 cargo test                # fewer proptest iterations for a faster run
```

CI (`.github/workflows/main.yml`) additionally checks:

- **Big-endian / 32-bit**: `cross test --target powerpc64-unknown-linux-gnu` and `i686-unknown-linux-gnu` (`Cross.toml` passes `PROPTEST_CASES` through). Catches endianness bugs, e.g. in checksums.
- **Bare-metal no_std**: `cd etherparse/ensure_no_std && cargo build --target x86_64-unknown-none`.
- **MSRV**: `cargo check --package etherparse --all-features` on the `rust-version` from `etherparse/Cargo.toml` (currently 1.83.0). Stay within it; when a newer language/std feature is worth it, raising `rust-version` (in both crates) to a release that is at least a year old is fine.

Coverage: `coverage/coverage.bash` (needs `llvm-tools-preview`, `cargo-binutils`, `rustfilt`, `jq`); reports land in `target/coverage/`.

## Architecture

The crate root (`etherparse/src/lib.rs`) is `#![no_std]`; `alloc`/`std` are opt-in features (`std` is default). `std`-only modules (`defrag`, `tcp_reassembly`, `io`, writer/`read` APIs) are gated with `#[cfg(feature = "std")]` plus `#[cfg_attr(docsrs, doc(cfg(feature = "std")))]`.

Protocols are grouped by layer: `link/`, `net/`, `transport/`. Each layer module re-exports everything flat (`pub use link::*`), so the public API is flat at the crate root. Errors live in a parallel tree under `err/` (`err::ipv4::HeaderError`, `err::tcp::HeaderSliceError`, ...), with shared types like `LenError`, `Layer` and `LenSource`.

Every protocol comes as a family of types, one per file:

- `FooHeader`: owned, decoded struct; can be built, modified and written (`write`, `to_bytes`).
- `FooHeaderSlice<'a>`: zero-copy view over just the header bytes, fields decoded on access.
- `FooSlice<'a>`: zero-copy view over header + payload, validating length fields.
- `LaxFooSlice<'a>`: like `FooSlice` but tolerates truncated packets/inconsistent lengths (e.g. packets embedded in ICMP errors) and reports where the length came from via `LenSource`.

These compose into the whole-packet entry points, which exist in strict/lax pairs and all need updating when a protocol is added or extended:

- `SlicedPacket` / `LaxSlicedPacket`: zero-copy, layer-by-layer (`link`, `link_exts`, `net`, `transport`), driven by `sliced_packet_cursor.rs` / `lax_sliced_packet_cursor.rs`.
- `PacketHeaders` / `LaxPacketHeaders`: decode every header into owned structs.
- `PacketBuilder`: typestate builder for writing packets with correct lengths and checksums.
- Layer enums such as `LinkSlice`, `NetSlice`, `TransportSlice`, `TransportHeader`, `PayloadSlice` / `LaxPayloadSlice`.

Value newtypes (`EtherType`, `IpNumber`, `VlanId`, `IpDscp`, ...) wrap the raw integer; well-known values are module constants (`ether_type::IPV4`, `ip_number::TCP`). Bounded newtypes are created with `try_new`.

## Testing

- Unit tests sit at the bottom of each source file in `#[cfg(test)] mod test { ... }` and are mostly `proptest!` property tests. Cover every error branch: coverage is tracked.
- Proptest strategies for crate-internal tests are in `etherparse/src/test_gens/mod.rs`; `etherparse_proptest_generators` is a separate published crate with strategies for downstream users. Add new strategies to `test_gens`.
- Cross-protocol tests: `etherparse/src/compositions_tests.rs`. Integration tests: `etherparse/tests/`.
- Proptest failure seeds are committed under `etherparse/proptest-regressions/`.

## Conventions

Follow `docs/coding-style.md` (naming across type families, `unsafe`/`SAFETY` rules, error types, docs and test structure). In short:

- No allocations or syscalls outside `defrag` and `tcp_reassembly` (and `std`-gated reading/writing).
- Keep etherparse's `[dependencies]` minimal: implement what you need inside the crate; a new dependency is a last resort. Dev-dependencies for examples and test frameworks are fine.
- No `unwrap`/`expect`/panics on input-derived data in library code (hard rule).
- `false == value`, never `!value` (`clippy::bool_comparison` is allowed on purpose).
- Doc comments are short and written for users: description, then example, then only the details users need.
- Structure commits so a human can review a branch commit by commit: one logical change each, refactors separate from behaviour changes. Intermediate commits needn't compile; only the branch end must build and pass all tests. See "Commits" in `docs/coding-style.md`.
- Record user-facing changes under `## Unreleased` in `changelog.md`.
- `README.md` is produced from the crate-level docs in `lib.rs` via the `README.tpl` template (cargo-readme). Change both together and keep the docs.rs links on the current version.

## Agent skills

### Issue tracker

Issues and specs are tracked as local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as a `Status:` line in each issue file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
