# Changelog:

## 0.10.0: Corrected Fragmentation Handling, Additional IP Extension Headers Support & Qualitiy of Life Improvements

It has been 1.5 years since the last update, I think it is fair to say I underestimated the effort it would take to introduce partial support for IPv6 extension headers. As it was so long sice the last update a bunch of changes has piled on. Sadly this also means there are some breaking changes in this version.

But I hope the changes overall improve the library and will be worth it in the long run.


### Extension headers added to `IpHeader` & `InternetSlice`

With the added support for authentification headers (for both IPV4 and IPV6) and additional IPV6 extension headers a place to store the results when parsing headers or slicing them had be chosen. After some though I decided to put the results into the enum values as a second argument. 

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

Previously when slicing packets the the methods for accessing the `source` & `destionation` returned a slice reference:

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

* Corrected decoding & handling of authentification headers & encapsulating security payload for IPv6 packets.
* Added support for authentifaction headers in IPv4 packets.
* Corrected handling of fragmented packets. `InternetSlice::from_*` & `PacketHeaders::from_*` no longer try to decode packets that have been flaged as fragmented (IPv4 & IPv6). Thanks to @Bren2010 for making a PR & noticing the issue.
* Added support for parsing "IPv6 Fragment Headers" & "Authentification Headers"
* `packet_filter` was marked as deprecated and will be removed in a future release. `packet_filter` was never especially well thought out, so I made the decision to remove it. If you still want to use it feel free to copy the source into your project https://github.com/JulianSchmid/etherparse/blob/0.9.0/src/packet_filter.rs directly.

### Fixed bugs:

* The length field in authentification fields was assumed to be in 8 octet units (same as hop-by-hop options header & the routing header). This was incorrect, the length field is in 4 octet units and the code has been corrected to support this.
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

