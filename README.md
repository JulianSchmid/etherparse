# etherparse
[![Build Status][build_badge]][build_status]
[![Code Coverage][coverage_badge]][coverage_report]

A library for parsing & writing a bunch of packet based protocols (EthernetII, IPv4, IPv6, UDP ...).

Currently supported are:
* Ethernet II
* IEEE 802.1Q VLAN Tagging Header
* IPv4
* IPv6 (missing extension headers, but supporting skipping them)
* UDP

## Usage

First, add the following to your `Cargo.toml`:

```toml
[dependencies]
etherparse = "0.3.1"
```

Next, add this to your crate root:

```rust
extern crate etherparse;
```

## What is etherparse?
Etherparse is intended to provide the basic network parsing functions that allow for easy analysis, transformation or generation of recorded network data. 

Some key points are:

* It is completly written in Rust and thoroughly tested.
* Special attention has been paid to avoid allocations or other syscalls whenever possible.
* The package is still in development and can & will still change. 
* The current focus of development is on the most popular protocols in the internet & transport layer.

## How to generate fake packet data?
### Packet Builder
There is the option to use the PacketBuilder, which provides a high level interface to create UDP network packets. The PacketBuilder will take care of setting all the fields which can be deduced from the content and compositions of the packet (checksums, lengths, ethertype, ip protocol number).

[Example:](examples/write_udp.rs)
```rust
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

//serialize
//this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
//before writing the packet out to "result"
builder.write(&mut result, &payload).unwrap();
```

Check out the [PacketBuilder documentation](https://docs.rs/etherparse/~0/etherparse/struct.PacketBuilder.html) for more informations.

### Manually serialising each header
Alternativly it is possible to manually build a packet ([example](examples/write_ipv4_udp.rs)). Generally each struct representing a header has a "write" method that allows it to be serialized. These write methods sometimes automatically calculate checksums and fill them in. In case this is unwanted behavior (e.g. if you want to generate a packet with an invalid checksum), it is also possible to call a "write_raw" method that will simply serialize the data without doing checksum calculations.

Read the documentations of the different methods for a more details:

* [Ethernet2Header.write](https://docs.rs/etherparse/~0/etherparse/struct.Ethernet2Header.html#method.write)
* [SingleVlanHeader.write](https://docs.rs/etherparse/~0/etherparse/struct.SingleVlanHeader.html#method.write)
* [DoubleVlanHeader.write](https://docs.rs/etherparse/~0/etherparse/struct.DoubleVlanHeader.html#method.write)
* [Ipv4Header.write](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.write)
* [Ipv4Header.write_raw](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.write_raw)
* [Ipv6Header.write](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Header.html#method.write)
* [UdpHeader.write](https://docs.rs/etherparse/~0/etherparse/struct.UdpHeader.html#method.write)

## Roadmap
* Generic packet parser (automaticly parsing of a packet based on its content)
* TCP
* Lazy header parsers (holds slice, only parse fields if requested)
* IEEE 802.3

## References
* Darpa Internet Program Protocol Specification [RFC 791](https://tools.ietf.org/html/rfc791)
* Internet Protocol, Version 6 (IPv6) Specification [RFC 8200](https://tools.ietf.org/html/rfc8200)
* [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
* [Wikipedia IEEE_802.1Q](https://en.wikipedia.org/w/index.php?title=IEEE_802.1Q&oldid=820983900)
* User Datagram Protocol (UDP) [RFC 768](https://tools.ietf.org/html/rfc768)

[build_badge]: https://travis-ci.org/JulianSchmid/etherparse.svg?branch=master
[build_status]: https://travis-ci.org/JulianSchmid/etherparse
[coverage_badge]: https://codecov.io/gh/JulianSchmid/etherparse/branch/master/graph/badge.svg
[coverage_report]: https://codecov.io/gh/JulianSchmid/etherparse/branch/master
