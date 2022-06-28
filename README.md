[![Crates.io](https://img.shields.io/crates/v/etherparse.svg)](https://crates.io/crates/etherparse)
[![docs.rs](https://docs.rs/etherparse/badge.svg)](https://docs.rs/etherparse)
[![Build Status Github](https://github.com/JulianSchmid/etherparse/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/JulianSchmid/etherparse/actions/workflows/main.yml)
[![Build Status Appveyor](https://ci.appveyor.com/api/projects/status/kbr91rpaim1mvcca?svg=true)](https://ci.appveyor.com/project/JulianSchmid/etherparse)
[![Build Status Gitlab](https://gitlab.com/julian.schmid/etherparse/badges/master/pipeline.svg)](https://gitlab.com/julian.schmid/etherparse/-/commits/master)
[![Codecov](https://codecov.io/gh/JulianSchmid/etherparse/branch/master/graph/badge.svg?token=yjfRLgScR6)](https://codecov.io/gh/JulianSchmid/etherparse)

# etherparse

A zero allocation library for parsing & writing a bunch of packet based protocols (EthernetII, IPv4, IPv6, UDP, TCP ...).

Currently supported are:
* Ethernet II
* IEEE 802.1Q VLAN Tagging Header
* IPv4
* IPv6 (supporting the most common extension headers, but not all)
* UDP
* TCP
* ICMP & ICMPv6 (not all message types are supported)

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
etherparse = "0.10.1"
```

## What is etherparse?
Etherparse is intended to provide the basic network parsing functions that allow for easy analysis, transformation or generation of recorded network data.

Some key points are:

* It is completly written in Rust and thoroughly tested.
* Special attention has been paid to not use allocations or syscalls.
* The package is still in development and can & will still change.
* The current focus of development is on the most popular protocols in the internet & transport layer.

## How to parse network packages?
Etherparse gives you two options for parsing network packages automatically:

### Slicing the packet
Here the different components in a packet are seperated without parsing all their fields. For each header a slice is generated that allows access to the fields of a header.
```rust
match SlicedPacket::from_ethernet(&packet) {
    Err(value) => println!("Err {:?}", value),
    Ok(value) => {
        println!("link: {:?}", value.link);
        println!("vlan: {:?}", value.vlan);
        println!("ip: {:?}", value.ip);
        println!("transport: {:?}", value.transport);
    }
}
```
This is the faster option if your code is not interested in all fields of all the headers. It is a good choice if you just want filter or find packages based on a subset of the headers and/or their fields.

Depending from which point downward you want to slice a package check out the functions:

* [`SlicedPacket::from_ethernet`](https://docs.rs/etherparse/~0/etherparse/struct.SlicedPacket.html#method.from_ethernet) for parsing from an Ethernet II header downwards
* [`SlicedPacket::from_ether_type`](https://docs.rs/etherparse/~0/etherparse/struct.SlicedPacket.html#method.from_ether_type) for parsing a slice starting after an Ethernet II header
* [`SlicedPacket::from_ip`](https://docs.rs/etherparse/~0/etherparse/struct.SlicedPacket.html#method.from_ip) for parsing from an IPv4 or IPv6 downwards

### Deserializing all headers into structs
This option deserializes all known headers and transferes their contents to header structs.
```rust
match PacketHeaders::from_ethernet_slice(&packet) {
    Err(value) => println!("Err {:?}", value),
    Ok(value) => {
        println!("link: {:?}", value.link);
        println!("vlan: {:?}", value.vlan);
        println!("ip: {:?}", value.ip);
        println!("transport: {:?}", value.transport);
    }
}
```
This option is slower then slicing when only few fields are accessed. But it can be the faster option or useful if you are interested in most fields anyways or if you want to re-serialize the headers with modified values.

Depending from which point downward you want to unpack a package check out the functions

* [`PacketHeaders::from_ethernet_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketHeaders.html#method.from_ethernet_slice) for parsing from an Ethernet II header downwards
* [`PacketHeaders::from_ether_type`](https://docs.rs/etherparse/~0/etherparse/struct.PacketHeaders.html#method.from_ether_type) for parsing a slice starting after an Ethernet II header
* [`PacketHeaders::from_ip_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketHeaders.html#method.from_ip_slice) for parsing from an IPv4 or IPv6 downwards

### Manually slicing & parsing packets
It is also possible to manually slice & parse a packet. For each header type there is are metods that create a slice or struct from a memory slice.

Have a look at the documentation for the <NAME>Slice.from_slice methods, if you want to create your own slices:

* [`Ethernet2HeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ethernet2HeaderSlice.html#method.from_slice)
* [`SingleVlanHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.SingleVlanHeaderSlice.html#method.from_slice)
* [`DoubleVlanHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.DoubleVlanHeaderSlice.html#method.from_slice)
* [`Ipv4HeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4HeaderSlice.html#method.from_slice)
* [`Ipv4ExtensionsSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4ExtensionsSlice.html#method.from_slice)
* [`Ipv6HeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6HeaderSlice.html#method.from_slice)
* [`Ipv6ExtensionsSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6ExtensionsSlice.html#method.from_slice)
* [`Ipv6RawExtensionHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6RawExtensionHeaderSlice.html#method.from_slice)
* [`IpAuthenticationHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.IpAuthenticationHeaderSlice.html#method.from_slice)
* [`Ipv6FragmentHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6FragmentHeaderSlice.html#method.from_slice)
* [`UdpHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.UdpHeaderSlice.html#method.from_slice)
* [`TcpHeaderSlice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.TcpHeaderSlice.html#method.from_slice)
* [`Icmpv4Slice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv4Slice.html#method.from_slice)
* [`Icmpv6Slice::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv6Slice.html#method.from_slice)

And for deserialization into the corresponding header structs have a look at:

* [`Ethernet2Header::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ethernet2Header.html#method.read) & [`Ethernet2Header::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ethernet2Header.html#method.from_slice)
* [`SingleVlanHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.SingleVlanHeader.html#method.read) & [`SingleVlanHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.SingleVlanHeader.html#method.from_slice)
* [`DoubleVlanHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.DoubleVlanHeader.html#method.read) & [`DoubleVlanHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.DoubleVlanHeader.html#method.from_slice)
* [`IpHeader::read`](https://docs.rs/etherparse/~0/etherparse/enum.IpHeader.html#method.read) & [`IpHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/enum.IpHeader.html#method.from_slice)
* [`Ipv4Header::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.read) & [`Ipv4Header::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.from_slice)
* [`Ipv4Extensions::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Extensions.html#method.read) & [`Ipv4Extensions::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Extensions.html#method.from_slice)
* [`Ipv6Header::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Header.html#method.read) & [`Ipv6Header::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Header.html#method.from_slice)
* [`Ipv6Extensions::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Extensions.html#method.read) & [`Ipv6Extensions::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Extensions.html#method.from_slice)
* [`Ipv6RawExtensionHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6RawExtensionHeader.html#method.read) & [`Ipv6RawExtensionHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6RawExtensionHeader.html#method.from_slice)
* [`IpAuthenticationHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.IpAuthenticationHeader.html#method.read) & [`IpAuthenticationHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.IpAuthenticationHeader.html#method.from_slice)
* [`Ipv6FragmentHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6FragmentHeader.html#method.read) & [`Ipv6FragmentHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6FragmentHeader.html#method.from_slice)
* [`UdpHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.UdpHeader.html#method.read) & [`UdpHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.UdpHeader.html#method.from_slice)
* [`TcpHeader::read`](https://docs.rs/etherparse/~0/etherparse/struct.TcpHeader.html#method.read) & [`TcpHeader::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.TcpHeader.html#method.from_slice)
* [`Icmpv4Header::read`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv4Header.html#method.read) & [`Icmpv4Header::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv4Header.html#method.from_slice)
* [`Icmpv6Header::read`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv6Header.html#method.read) & [`Icmpv6Header::from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv6Header.html#method.from_slice)

## How to generate fake packet data?
### Packet Builder
The PacketBuilder struct provides a high level interface for quickly creating network packets. The PacketBuilder will automatically set fields which can be deduced from the content and compositions of the packet itself (e.g. checksums, lengths, ethertype, ip protocol number).

[Example:](examples/write_udp.rs)
```rust
use etherparse::PacketBuilder;

let builder = PacketBuilder::
    ethernet2([1,2,3,4,5,6],     //source mac
               [7,8,9,10,11,12]) //destination mac
    .ipv4([192,168,1,1], //source ip
          [192,168,1,2], //desitination ip
          20)            //time to life
    .udp(21,    //source port
         1234); //desitnation port

//payload of the udp packet
let payload = [1,2,3,4,5,6,7,8];

//get some memory to store the result
let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

//serialize
//this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
//before writing the packet out to "result"
builder.write(&mut result, &payload).unwrap();
```

There is also an [example for TCP packets](examples/write_tcp.rs) available.

Check out the [PacketBuilder documentation](https://docs.rs/etherparse/~0/etherparse/struct.PacketBuilder.html) for more informations.

### Manually serialising each header
Alternativly it is possible to manually build a packet ([example](examples/write_ipv4_udp.rs)). Generally each struct representing a header has a "write" method that allows it to be serialized. These write methods sometimes automatically calculate checksums and fill them in. In case this is unwanted behavior (e.g. if you want to generate a packet with an invalid checksum), it is also possible to call a "write_raw" method that will simply serialize the data without doing checksum calculations.

Read the documentations of the different methods for a more details:

* [`Ethernet2Header::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ethernet2Header.html#method.write)
* [`SingleVlanHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.SingleVlanHeader.html#method.write)
* [`DoubleVlanHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.DoubleVlanHeader.html#method.write)
* [`Ipv4Header::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.write)
* [`Ipv4Header::write_raw`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.write_raw)
* [`Ipv4Extensions::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Extensions.html#method.write)
* [`Ipv6Header::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Header.html#method.write)
* [`Ipv6Extensions::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Extensions.html#method.write)
* [`Ipv6RawExtensionHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6RawExtensionHeader.html#method.write)
* [`IpAuthenticationHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.IpAuthenticationHeader.html#method.write)
* [`Ipv6FragmentHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6FragmentHeader.html#method.write)
* [`UdpHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.UdpHeader.html#method.write)
* [`TcpHeader::write`](https://docs.rs/etherparse/~0/etherparse/struct.TcpHeader.html#method.write)
* [`Icmpv4Header::write`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv4Header.html#method.write)
* [`Icmpv6Header::write`](https://docs.rs/etherparse/~0/etherparse/struct.Icmpv6Header.html#method.write)

## Roadmap
* MutPacketSlice -> modifaction of fields in slices directly?
* Reserializing SlicedPacket & MutSlicedPacket with corrected checksums & id's
* IEEE 802.3

## References
* Darpa Internet Program Protocol Specification [RFC 791](https://tools.ietf.org/html/rfc791)
* Internet Protocol, Version 6 (IPv6) Specification [RFC 8200](https://tools.ietf.org/html/rfc8200)
* [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
* [Internet Protocol Version 6 (IPv6) Parameters](https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml)
* [Wikipedia IEEE_802.1Q](https://en.wikipedia.org/w/index.php?title=IEEE_802.1Q&oldid=820983900)
* User Datagram Protocol (UDP) [RFC 768](https://tools.ietf.org/html/rfc768)
* Transmission Control Protocol [RFC 793](https://tools.ietf.org/html/rfc793)
* TCP Extensions for High Performance [RFC 7323](https://tools.ietf.org/html/rfc7323)
* The Addition of Explicit Congestion Notification (ECN) to IP [RFC 3168](https://tools.ietf.org/html/rfc3168)
* Robust Explicit Congestion Notification (ECN) Signaling with Nonces [RFC 3540](https://tools.ietf.org/html/rfc3540)
* IP Authentication Header [RFC 4302](https://tools.ietf.org/html/rfc4302)
* Mobility Support in IPv6 [RFC 6275](https://tools.ietf.org/html/rfc6275)
* Host Identity Protocol Version 2 (HIPv2) [RFC 7401](https://tools.ietf.org/html/rfc7401)
* Shim6: Level 3 Multihoming Shim Protocol for IPv6 [RFC 5533](https://tools.ietf.org/html/rfc5533)
* Computing the Internet Checksum [RFC 1071](https://datatracker.ietf.org/doc/html/rfc1071)
* Internet Control Message Protocol [RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
* [IANA Internet Control Message Protocol (ICMP) Parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
* Requirements for Internet Hosts -- Communication Layers [RFC 1122](https://datatracker.ietf.org/doc/html/rfc1122)
* Requirements for IP Version 4 Routers [RFC 1812](https://datatracker.ietf.org/doc/html/rfc1812)
* Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification [RFC 4443](https://datatracker.ietf.org/doc/html/rfc4443)
* ICMP Router Discovery Messages [RFC 1256](https://datatracker.ietf.org/doc/html/rfc1256)
* [Internet Control Message Protocol version 6 (ICMPv6) Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
* Multicast Listener Discovery (MLD) for IPv6 [RFC 2710](https://datatracker.ietf.org/doc/html/rfc2710)
* Neighbor Discovery for IP version 6 (IPv6) [RFC 4861](https://datatracker.ietf.org/doc/html/rfc4861)

## License
Licensed under the BSD 3-Clause license. Please see the LICENSE file for more information.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be licensed as above, without any additional terms or conditions.
