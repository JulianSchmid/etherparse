# Changelog:

## 0.14.1

Corrected example in README.md (replaced `ip` with `net`).

## 0.14.0

### Highlights

* `SlicedPacket` & `PacketHeaders` now use the length fields in the headers to determine the payload length.
* The payload(s) in `SlicedPacket` now can be accessed via the layer slices (e.g. `link.unwrap().payload()`).
* Added `LaxSlicedPacket` & `LaxPacketHeaders` to allow for parsing of packets without length checks & other inconsistency checks present in `SlicedPacket` & `PacketHeaders`.
* `SlicedPacket.ip` & `PacketHeaders.ip` have been renamed to `SlicedPacket.net` & `PacketHeaders.net`
* Added `no_std` support.
* Errors are now more fine granular (in case you want a general error type you can convert all errors via `into` & `from` into `err::FromSliceError` or `err::ReadError`).
* Added `to_bytes()` methods to most header types.
* Added slice types which contain both the header(s) and payload (e.g. `IpSlice`, `UdpSlice`).
* Added payload types (e.g. `IpPayloadSlice`, `EtherPayloadSlice`) which contain the slice & information about the payload type (e.g. the IpNumber in case of an `IpPayloadSlice`).

### What happened?

This version took more then a year to complete. Which for sure was not my plan when starting out.

I started out trying to implement correct handing of "payload lengths" (aka actually using the length fields in headers to determine the payload). This was needed, as without it, incorrect data would sometimes creep into the payload of and IP packet (see https://github.com/JulianSchmid/etherparse/issues/35 ). But this "simple" feature triggered a chain reaction of changes that required me to re-architect big parts of the crate. Specifically the error types were an major issue, which I did not forsee costing so much time and at some time.

But no matter, now it is done. Sadly there are quiet some breaking changes, but I think the crate is now in a better position for future changes & behaves correcter then in the past. There are also quiet a lot of quality of life changes.

### New

* Added non-allocating `to_bytes()` methods that return `arrayvec::ArrayVec<u8, Header::MAX_LEN>` to the following headers:
  * `Ipv4Header`
* Added `LaxSlicedPacket` & `LaxPacketHeaders` to allow for parsing of packets without length checks & other inconsistency checks present in `SlicedPacket` & `PacketHeaders`.
* `no_std` Support was added. To enable use etherparse without default features: `etherparse = { version = "0.14", default-features = false }`
* Added `LEN` or `MIN_LEN` & `MAX_LEN` constants to all headers & packets.
* Added `InternetSlice::source_addr` & `InternetSlice::destination_addr` to get the source & destination as `std::net::IpAddr` (thanks to @nagy)

### Changes in Behavior

* `SlicedPacket` & `PacketHeaders` now also verify the total_length and payload length fields present in the IPv4 & IPv6 header. This means the `*from_slice*` methods newly throw an error not enough data is present and also newly limit the resulting payload size.
* The payload(s) in `SlicedPacket` now can be accessed via the layer fields (e.g. `link.unwrap().payload()`).
* The payload in `PacketHeaders` now is an enum that indicates from which layer the payload came.
* Removed `ReadError::Ipv6TooManyHeaderExtensions` error when calling `Ipv6Header::skip_all_header_extensions` and `Ipv6Header::skip_all_header_extensions_in_slice`.
* The slice returned by `IpHeader::from_slice`is now the payload of the IP packet (determined by the length specified in the IP header). Previously whatever was left over from the input slice after parsing the IP header and extensions was returned. Now the slice length is limited based on the "payload length" field (IPv6) or "total length" field IPv4.
* `Ipv4Header::from_slice` no longer verifies that the `total_len` has enough data to contain the header itself. This check is done when the complete packet is parsed. The check was removed as the `total_len` is sometimes set at a later stage (e.g. in the kernel) in some systems and I would still like to enable people to at least decode the header even if the total length was not yet set.

### Breaking Changes:

* `ip` as been renamed to `net` in `SlicedPacket` and `PacketHeaders`
* `packet_filter` has been removed
* Refactored error types so functions & methods (mostly) only return error types that they can cause.
* Removed `SerializedSize` trait and deprecated `SERIALIZED_SIZE`. Newly added constants `Header::LEN`, `Header::MIN_LEN` & `Header::MAX_LEN` to the headers as an replacement.
* `Ipv4Header.fragments_offset` renamed to `Ipv4Header.fragment_offset`.
* Removed `IPV6_MAX_NUM_HEADER_EXTENSIONS` as it is no longer used by the skip functions.
* Type of `fragment_offset` in `Ipv4Header` & `Ipv6FragmentHeader` changed from `u16` to `IpFragOffset`.
* `Ipv4Header.differentiated_services_code_point` renamed to `Ipv4Header.dscp`.
* `Ipv4Header.explicit_congestion_notification` renamed to `Ipv4Header.ecn`.
* `Ipv4Header.fragments_offset` renamed to `Ipv4Header.fragment_offset`.
* `SingleVlanHeader.vlan_identifier` renamed to `SingleVlanHeader.vlan_id`.
* Type of `vlan_id` in `SingleVlanHeader` changed from `u16` to `VlanId`.
* Moved options of `Ipv4Header` and `TcpHeader` into separate structs and made all fields in `Ipv4Header` & `TcpHeader` public for easier default initialization.

### Bugfixes

* `PacketHeaders::from_ip_slice` now only tries to decode the transport layer if the packet is not fragmented. Previously it would also try to decode the transport layer even if the packet contained only a fragment.
* The IPv6 extension header skipping functions were previously checking that the slice length is at least 2 before checking if an extension header is even present. If less then two bytes were present an error was returned. This was wrong behavior, as there are no guarantees for other protocols that there are 2 bytes of data present. A check has been added, that validates the header type before checking the slice length. The following functions were corrected:
  * `Ipv6Header::skip_header_extension_in_slice`
  * `Ipv6Header::skip_all_header_extensions_in_slice`

* Previously the manual `core::fmt::Debug` implementations for some types were not correctly inserting newlines & indentation when `{:#?}` was used for debug printing. This has been corrected for the following types:
  * `Ipv4Header`
  * `IpAuthHeader`
  * `Ipv6RawExtHeader`

### Deprecations / Renames:

* The following types have been renamed (alias with the old name exist for backwards compatibility but will trigger a deprecation warning):
  * `InternetSlice` to `NetSlice` & `IpSlice`
  * `IpAuthenticationHeader` to `IpAuthHeader`
  * `IpAuthenticationHeaderSlice` to `IpAuthHeaderSlice`
  * `Ipv6RawExtensionHeader` to `Ipv6RawExtHeader`
  * `Ipv6RawExtensionHeaderSlice` to `Ipv6RawExtHeaderSlice`

### Internal Changes:

* Separated proptest generators into separate library `etherparse_proptest_generators`
* Split modules up into one file per struct/enum and moved tests there
* Applied rust fmt

## 0.13.0

* Switched license to MIT OR Apache-2.0

## 0.12.0

* Add `payload_ether_type` method to `SlicedPacket` & `PacketHeaders`

## 0.11.0

### New Features:

* Added partial ICMP and ICMPv6 support (thanks to @robs-zeynet for the PR with the initial implementation).
* Added `PacketBuilder::<IpHeader>::write` that allows writing without specifying a transport protocol (thanks to @karpawich for the PR)
* Added functions [SlicedPacket::from_ether_type](https://docs.rs/etherparse/0.11.0/etherparse/struct.SlicedPacket.html#method.from_ether_type) & [PacketHeaders::from_ether_type](https://docs.rs/etherparse/0.11.0/etherparse/struct.PacketHeaders.html#method.from_ether_type) to slice & decode messages based on the starting `ether type`
* `IpHeader::set_payload_len` added to set the length fields in the ip header (thanks to @agrover for the PR).
* `InternetSlice::is_fragmenting_payload` added to check for fragmentation (thanks to @agrover for the PR).

### Breaking Changes:

* `Ipv4Header::new` changed `protocol` argument type from `IpNumber` to `u8`.
* `TransportHeader::Icmpv4` & `TransportHeader::Icmpv6` enum values added
* `TransportSlice::Icmpv4`& `TransportSlice::Icmpv6` enum values added

## 0.10.1: Corrected Fragmentation Handling, Additional IP Extension Headers Support & Qualitiy of Life Improvements

With this version the support for IPv6 gets extended and bugs in the parsing of fragmented packets as well as authentication headers are fixed. Additionally a bunch of performance improvements are included and new methods have been added (e.g. the method `to_bytes` for headers with static sizes).

It has been almost two years since the last update and I think it is fair to say that I underestimated the effort it would take to introduce partial support for IPv6 extension headers. As it was so long sice the last update a bunch of changes have piled on. This also means there are some breaking changes in this version.

The next versions will hopefully be smaller and contain some qualitiy of life improvements.

Special thanks to @Bren2010 for reporting the errors with fragmented packets.

### Extension headers added to `IpHeader` & `InternetSlice`

With the added support for authentication headers (for both IPV4 and IPV6) and additional IPV6 extension headers support a place to store the results when parsing headers or slicing them had be chosen. After some though I decided to put the results into the enum values as a second argument. 

So the signature of `IpHeader` has changed from

```rust
pub enum IpHeader {
    Version4(Ipv4Header),
    Version6(Ipv6Header)
}
```

to

```rust
pub enum IpHeader {
    Version4(Ipv4Header, Ipv4Extensions),
    Version6(Ipv6Header, Ipv6Extensions)
}
```

and the signature of `InternetSlice` has changed from

```rust
pub enum InternetSlice<'a> {
    Ipv4(Ipv4HeaderSlice<'a>),
    Ipv6(Ipv6HeaderSlice<'a>, [Option<(u8, Ipv6ExtensionHeaderSlice<'a>)>; IPV6_MAX_NUM_HEADER_EXTENSIONS]),
}
```

to

```rust
pub enum InternetSlice<'a> {
    Ipv4(Ipv4HeaderSlice<'a>, Ipv4ExtensionsSlice<'a>),
    Ipv6(Ipv6HeaderSlice<'a>, Ipv6ExtensionsSlice<'a>),
}
```

### `source()` & `destination()` return static arrays:

Previously when slicing packets the the methods for accessing the `source` & `destination` returned a slice reference:

```rust

pub fn source(&self) -> &'a [u8] {
    ...
}

```

which becomes a problem if you want to copy it to an actual header as the header structs expect an fixed-sized array. E.g. `[u8;4]` for IPv4:

```rust
Ipv4Header::new(
    ...
    // expects [u8;4], so we have to convert the slice into an fixed-sized array
    [
        slice.source()[0],
        slice.source()[1],
        slice.source()[2],
        slice.source()[3],
    ],
    ...
)
```

To get around this problem the return types of the `source` & `destination` methods have been changed to return fixed-sized arrays for `Ipv4HeaderSlice`, `Ipv6HeaderSlice` & `Ethernet2HeaderSlice`. E.g. for IPv4 the signature is now

```rust

pub fn source(&self) -> [u8;4] {
    ...
}

```

which enables you to simply pass address values to `Ipv4Header::new`:

```rust
Ipv4Header::new(
    ...
    // much better
    slice.source(),
    ...
)
```

Not only makes this change it easier to copy address values from a slice to a header, but it also should bring a minor performance improvements (together with other changes). Fixed-sized arrays don't require slice range checks when acessed and the arrays are small enough that they fit in one or two registers on 64bit systems.

### `UdpHeader::calc_checksum_ipv4*` & `UdpHeader::calc_checksum*` now use a constant for the `protocol` field in the pseudo header

Previously checksum calculation functions for udp used a protocol value either given as an argument or taken from the ipv4 headers protocol field in it's checksum calculation. After having a closer look at [RFC 768](https://tools.ietf.org/html/rfc768) and what Wireshark does, this seems to have been a mistake. Specifically when an authentifiction header is present between the ip header and the udp header. In this case `ip_number::UDP` (17) should be used and not the value of the ipv4 header `protocol` field (which will be `ip_number::AUTH` (51)).

To resolve this I changed the checksum calculation to always use `ip_number::UDP` and remove all arguments that allow the user to pass in the protocol number from the outside.

Which means 

```rust
impl UdpHeader {
    pub fn calc_checksum_ipv4_raw(&self, source: [u8;4], destination: [u8;4], protocol: u8, payload: &[u8]) -> Result<u16, ValueError> {
        // ...
    }
```

looses the `protocol` argument

```rust
impl UdpHeader {

    pub fn calc_checksum_ipv4_raw(&self, source: [u8;4], destination: [u8;4], payload: &[u8]) -> Result<u16, ValueError> {
```

and 

```rust
impl UdpHeader {
    pub fn with_ipv4_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv4Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {
        // ...
    }

    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        // ....
    }

```

will no longer use `ip_header.protocol` in their checksum calculations.

### General:

* Corrected decoding & handling of authentication headers & encapsulating security payload for IPv6 packets.
* Added support for authentifaction headers in IPv4 packets.
* Corrected handling of fragmented packets. `InternetSlice::from_*` & `PacketHeaders::from_*` no longer try to decode packets that have been flaged as fragmented (IPv4 & IPv6). Thanks to @Bren2010 for making a PR & noticing the issue.
* Added support for parsing "IPv6 Fragment Headers" & "Authentication Headers"

### Fixed bugs:

* The length field in authentication fields was assumed to be in 8 octet units (same as hop-by-hop options header & the routing header). This was incorrect, the length field is in 4 octet units and the code has been corrected to support this.
* For the "Encapsulating Security Payload header" it was incorrectly assumed, that the basic build up is the same as for the other header extensions (with a next_header & header length field at the start of the header). Parsing of packets will now stop as soon as a "Encapsulating Security Payload header" is encountered.

### Breaking API changes:

* Renamed `TcpOptionElement::Nop` to `TcpOptionElement::Noop`
* Renamed `Ipv6ExtensionHeader` to `Ipv6RawExtensionHeader`
* Renamed `Ipv6ExtensionHeaderSlice` to `Ipv6RawExtensionHeaderSlice`
* Reduced the list of supported headers as `Ipv6RawExtensionHeader` & `Ipv6RawExtensionHeaderSlice` to:
    * Hop-by-Hop Options Header
    * Routing Header
    * Destination Options Header
    * Mobility Header
    * Host Identity Protocol
    * Shim6 Header
* Renamed `IpTrafficClass::IPv6AuthenticationHeader` to `IpNumber::AuthenticationHeader`.
* Renamed `IpTrafficClass::IPv6EncapSecurityPayload` to `IpNumber::EncapsulatingSecurityPayload`
* Renamed `ReadError::VlanDoubleTaggingUnexpectedOuterTpid` to `ReadError::DoubleVlanOuterNonVlanEtherType`
* Moved the extensions out of the Ipv6Header[Slice] and into the PacketHeaders & SlicedPacket struct.
* `TcpOptionReadError::UnexpectedEndOfSlice` changed from a single value 

This change had been a long time coming. Originally I coupled the IPv6 header extensions to the ipv6 header under the assumption that they only exist in IPv6. But this was not correct, the authentication header and encapsulating security payload are present in IPv6 as well as IPv4. So seperating this form IPv6 made sense.

* Ipv6ExtensionHeader was extended with a slice pointing to the data of the header
* Moved `TCP_OPTION_ID_*` contants into a new module `tcp_options::KIND_*` (the old constants still present but marked as deprecated).
* Return type of `Ethernet2HeaderSlice::{destination, source}`  changed to `[u8;6]` (previously `&'a [u8]`)

### API changes with deprecation warning:

The following changes will cause a deprecation warning:

* Renamed `IpTrafficClass` to `IpNumber`. Traffic class was just the wrong name and confusing as there is a traffic class field in IPv6 headers.
* Renamed `read_from_slice` methods to `from_slice`.
