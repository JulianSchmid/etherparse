# Coding style

How code is written in etherparse. These rules describe the existing code; when in doubt, copy the shape of a neighbouring type (`UdpHeader`/`UdpSlice`, `Ipv4Header`/`Ipv4HeaderSlice`, `VlanId`).

Formatting is plain `cargo fmt` (no `rustfmt.toml`); the tree is fmt-clean, keep it that way.

## Files & modules

- One public type per file, file named after the type in snake case (`ipv4_header_slice.rs` → `Ipv4HeaderSlice`).
- Layer `mod.rs` files declare each file as a private `mod` followed by `pub use <file>::*;`. Only protocol namespaces that group many constants or sub-types are public modules (`pub mod icmpv4;`, `pub mod igmp;`, `pub mod err;`).
- Import with `use crate::*;` (plus `err::*` or a protocol namespace as needed) rather than long explicit paths.
- Use `core::` / `alloc::` paths; `std::` only inside `#[cfg(feature = "std")]` code and tests.

## Type families

Each protocol provides the family described in `AGENTS.md` (`FooHeader`, `FooHeaderSlice`, `FooSlice`, `LaxFooSlice`). Keep method names consistent across the family:

| Purpose | Name |
| --- | --- |
| Constructor from bytes (checked) | `from_slice` (headers return `(Header, &rest)`) |
| Constructor that skips checks | `pub(crate) unsafe fn from_slice_unchecked` |
| Lax constructor on a strict type | `from_slice_lax` |
| Read from `std::io::Read` | `read` (std-gated) |
| Serialize | `write` (std-gated), `to_bytes` (fixed array or `ArrayVec`, no alloc) |
| Lengths | `header_len`, `header_len_u16`; constants `LEN` / `MIN_LEN` / `MAX_LEN` (+ `_U16` variants) |
| Slice accessors | `slice`, `header_slice`, `payload`, `payload_len_source` |
| Slice → owned | `to_header` |
| Checksums | `calc_checksum_*`, `with_*_checksum`, `is_checksum_valid` |

Header-slice field getters are named after the protocol field and decode on access, e.g. `source_port()`, `ihl()`.

Method names that are kept only for compatibility stay, but get `#[deprecated(since = "x.y.z", note = "Use `...` instead")]`.

## Derives

- Owned headers: `Clone, Debug, Eq, PartialEq, Hash` (plus `Default`, `Ord`/`PartialOrd` where meaningful).
- Slices: `Clone, Debug, Eq, PartialEq`.
- Types up to 64 bits (newtypes, small fixed-size structs/enums) derive `Copy`; deriving it is also fine up to 128 bits. Larger types don't.
- Value newtypes derive `Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash`.

## Value newtypes

Raw protocol values are wrapped in a newtype over the integer (`VlanId(u16)`, `EtherType(u16)`, `IpNumber(u8)`).

- Open value sets (any integer valid, e.g. `EtherType`) have a `pub` field and well-known values as constants in a lowercase module (`ether_type::IPV4`, `ip_number::TCP`).
- Bit-limited values keep the field private and provide:
  - `pub const MAX_U<n>` and `ZERO` constants,
  - `pub const fn try_new(value) -> Result<Self, ValueTooBigError<_>>`,
  - `pub const unsafe fn new_unchecked(value)` with a `# Safety` section and a `debug_assert!` of the invariant,
  - `pub const fn value(self)`,
  - `Display`, `From<Newtype> for uN` and `TryFrom<uN>`.
- Prefer `const fn` wherever the body allows it.

## Zero-copy & `unsafe`

The crate uses `unsafe` for unchecked reads once a constructor has validated the length. Rules:

- Validate lengths once, in the constructor; accessors then use `get_unchecked`, `core::slice::from_raw_parts`, and the crate helpers `get_unchecked_be_u16` / `get_unchecked_be_u32`.
- Every `unsafe` block gets a `// SAFETY:` comment naming the check that makes it sound, e.g. "Safe as the constructor checks that the slice has at least the length of UdpHeader::LEN (8)."
- Every `unsafe fn` gets a `# Safety` doc section stating the *complete* precondition (all length requirements, including variable-length parts derived from header fields), and asserts it with `debug_assert!` where practical.
- Unchecked constructors stay `pub(crate)` unless there is a reason to expose them.
- Multi-byte fields are big endian (network byte order): use `to_be_bytes` / `from_be_bytes` or the `be` helpers, never native-endian conversions. CI runs on big-endian ppc64 to catch this.

## Errors

- Error types live in `err/<protocol>/` with a fixed vocabulary:
  - `HeaderError`: problems with header contents (field-shaped enum variants carrying the offending values, e.g. `UnexpectedVersion { version_number }`).
  - `HeaderSliceError { Len(LenError), Content(HeaderError) }`: decoding from a slice.
  - `HeaderReadError { Io(std::io::Error), Content(HeaderError) }`: decoding from `std::io::Read` (std-gated).
  - Shared: `LenError`, `ValueTooBigError<T>` (with an `err::ValueType`), `Layer`, `LenSource`.
- Length errors fill in all `LenError` fields: `required_len`, `len`, `len_source`, `layer`, `layer_start_offset`. Errors from nested layers are shifted with `add_offset` / `add_slice_offset`.
- Every error implements `Display` and `core::error::Error`. Display messages start with the protocol context and quote values: `"IPv4 Header Error: Encountered '{version_number}' as IP version number in the IPv4 header (must be '4' in an IPv4 header)."`.
- Errors derive `Clone, Debug, Eq, PartialEq, Hash` (except ones holding `std::io::Error`, which only derive `Debug`).
- **Hard rule:** no `unwrap`, `expect`, or other panics on input-derived data in library code; return an error instead. (Tests may unwrap freely.)

## Control-flow style

- Comparisons put the constant first and negate explicitly: `if 4 != version_number`, `if false == fragmented` (never `!fragmented`; `clippy::bool_comparison` is allowed for this).
- Validate and return early (`return Err(...)`) at the top of constructors, then build the value once all checks pass.
- Short `// lowercase` comments mark the steps of a parser (`// check length`, `// check version`).

## Documentation

Keep doc comments short and sweet. Write for users of the crate, and leave out anything a user doesn't need to know (implementation details, history, internal reasoning). Comments in the code are the place for those.

- Simple items (getters, constants, trivial constructors) get a one-line summary.
- Complicated items follow this order:
  1. a short description of what it does,
  2. an example showing how to use it (doc-test),
  3. only the details a user needs: errors returned, edge cases or fallbacks that change the result, `# Safety` for `unsafe fn`.
- Every public item has a doc comment. Field getters say which header field they read, quoted: `/// Reads the "length" field in the UDP header.`
- Protocol types with a fixed layout include an RFC-style bit diagram in a ```` ```text ```` block. Check that the type values in the diagram match the code.
- Link related items with intra-doc links (``[`crate::Ipv4Slice::from_slice`]``), and point to the strict/lax alternatives where they exist.
- Fallible or non-obvious constructors include a doc-test example; `assert_eq!` on the exact `Err(...)` value is common.
- Reference the defining standard (RFC or IEEE) on the type. Whenever an RFC/standard is implemented, or used as a reference in an implementation, add it to the reference list in both the `lib.rs` crate docs and `README.md`.

## Tests

- Tests live at the bottom of the file in `#[cfg(test)] mod test { use super::*; ... }`, importing `crate::test_gens::*`, `proptest::prelude::*` and `alloc::{format, vec::Vec}` as needed.
- Prefer `proptest!` tests driven by the generators in `src/test_gens/mod.rs` (`udp_any()`, `ipv4_any()`, ...); add a generator there for every new type.
- **Coverage should be as high as possible.** Every branch, especially every error path, needs a test; `coverage/coverage.bash` shows what's missing.
- Usually **one test function per method/function**, named after it (`fn from_slice`, `fn to_bytes`), which tests *all* of that method's branches. Separate cases go in `{ ... }` blocks inside that one function, each with a comment (`// normal case`, `// length too large`), and errors are checked with an exact `assert_eq!` on the expected error value. Exceptions are fine where splitting genuinely reads better. Derived traits get a `debug_clone_eq` / `derived_traits` test.
- **Composition tests** check that the whole-packet parsers and slicers handle every combination of layers. `src/compositions_tests.rs` builds packets from generated headers (link → link exts → net → transport → payload), serializes them, and checks that `SlicedPacket` and `PacketHeaders` give the same headers back. The per-parser tests in `sliced_packet.rs`, `packet_headers.rs` and their `lax_*` versions do the same through the shared `src/test_packet.rs` (`TestPacket`) helper. When you add a protocol or packet variant, add it to these composition tests as well as unit-testing its own types.
- Error types get `debug`, `clone_eq_hash`, `fmt` and `source` tests that pin the exact message strings.
- Gate tests that need `std` (`std::io::Cursor`, `Error::source`) with `#[cfg(feature = "std")]`, so `cargo test --no-default-features` still builds.

## Commits

Commits are made for a human reviewer who reads a branch commit by commit. Each commit should be easy to review and understand on its own.

- **One logical change per commit.** Keep refactors, renames, moves and formatting in separate commits from behaviour changes, so the behaviour diff isn't buried. If a feature needs groundwork (a new error type, a generator, a refactor of an existing parser), commit that first.
- **Build up in an order that reads well**, e.g. value types and errors → header/slice types with their unit tests → integration into the whole-packet types (`SlicedPacket`, `PacketHeaders`, `PacketBuilder`, ...) and composition tests → changelog/README.
- **Reviewability comes before a green build at every commit.** An intermediate commit may fail to compile or fail tests if that makes the series easier for a human to review. Only the final state of the branch must build and pass everything (`cargo test` and `cargo test --no-default-features`).
- **Tests go in the same commit as the code they test.**
- **Messages:** a short imperative subject (`Add IGMP slice implementation`, `Fix bug in udp header checksum tests`), optionally prefixed with the protocol (`IGMP: ...`). Add a body when the reason isn't obvious from the diff: what was wrong or missing and why this approach was chosen.
- Before opening a PR, clean up the history (squash fixups, reorder) so it tells this story, not the order the work happened in.
