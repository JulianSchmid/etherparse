# Changelog:

## 0.10.0: Corrected Fragmentation Handling & Additional IP Extension Headers Support

### General:

* Corrected decoding & handling of authentification headers & encapsulating security payload for IPv6 packets.
* Added support for authentifaction headers in IPv4 packets.
* Corrected handling of fragmented packets. `InternetSlice::from_*` & `PacketHeaders::from_*` no longer try to decode packets that have been flaged as fragmented (IPv4 & IPv6).
* Added support for parsing "IPv6 Fragment Headers" & "Authentification Headers"
* `packet_filter` was marked as deprecated and will be removed in a future release. `packet_filter` was never especially well thought out, so I made the decision to remove it. If you still want to use it feel free to copy the source into your project https://github.com/JulianSchmid/etherparse/blob/0.9.0/src/packet_filter.rs directly.

### Fixed bugs:

* The length field in authentification fields was assumed to be in 8 octet units (same as hop-by-hop options header & the routing header). This was incorrect, the length field is in 4 octet units and the code has been corrected to support this.
* For the "Encapsulating Security Payload header" it was incorrectly assumed, that the basic build up is the same as for the other header extensions (with a next_header & header length field at the start of the header). Parsing of packets will now stop as soon as a "Encapsulating Security Payload header" is encountered.

### Breaking API changes:

* Renamed `Ipv6ExtensionHeader` to `Ipv6OptionsHeader`
    * Reduced the list of supported headers as `Ipv6OptionsHeader` to:
        * Hop-by-Hop Options Header
        * Routing Header
        * Destination Options Header
        * Mobility Header
        * Host Identity Protocol
        * Shim6 Header
* Renamed `Ipv6ExtensionHeaderSlice` to `Ipv6OptionsHeaderSlice`
* Renamed `IPv6AuthenticationHeader` to `AuthenticationHeader`
* Renamed `IPv6EncapSecurityPayload` to `EncapsulatingSecurityPayload`
* Renamed `ReadError` values:
  * Renamed `VlanDoubleTaggingUnexpectedOuterTpid` to `DoubleVlanOuterNonVlanEtherType`
* Moved the extensions out of the Ipv6Header[Slice] and into the PacketHeaders & SlicedPacket struct.

This change had been a long time coming. Originally I coupled the IPv6 header extensions to the ipv6 header under the assumption that they only exist in IPv6. But this was not correct, the authentication header and encapsulating security payload are present in IPv6 as well as IPv4. So seperating this form IPv6 made sense.

* Ipv6ExtensionHeader was extended with a slice pointing to the data of the header
* Moved `TCP_OPTION_ID_*` contants into a new module `tcp_options::KIND_*` (the old constants still present but marked as deprecated).
* Renamed `TcpOptionElement::Nop` to `TcpOptionElement::Noop`
