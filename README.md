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
etherparse = "0.4.0"
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

### Manually slicing & parsing packets
It is also possible to manually slice & parse a packet. For each header type there is are metods that create a slice or struct from a memory slice. 

Have a look at the documentation for the PacketSlice<T>.from_slice methods, if you want to create your own slices:

* [`PacketSlice<Ethernet2Header>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice)
* [`PacketSlice<SingleVlanHeader>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice-1)
* [`PacketSlice<DoubleVlanHeader>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice-2)
* [`PacketSlice<Ipv4Header>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice-3)
* [`PacketSlice<Ipv6Header>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice-4)
* [`PacketSlice<Ipv6ExtensionHeader>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice-5)
* [`PacketSlice<UdpHeader>.from_slice`](https://docs.rs/etherparse/~0/etherparse/struct.PacketSlice.html#method.from_slice-6)

And for deserialization into the corresponding header structs have a look at:

* [Ethernet2Header.read](https://docs.rs/etherparse/~0/etherparse/struct.Ethernet2Header.html#method.read)
* [SingleVlanHeader.read](https://docs.rs/etherparse/~0/etherparse/struct.SingleVlanHeader.html#method.read)
* [DoubleVlanHeader.read](https://docs.rs/etherparse/~0/etherparse/struct.DoubleVlanHeader.html#method.read)
* [IpHeader.read](https://docs.rs/etherparse/~0/etherparse/enum.IpHeader.html#method.read)
* [Ipv4Header.read](https://docs.rs/etherparse/~0/etherparse/struct.Ipv4Header.html#method.read)
* [Ipv6Header.read](https://docs.rs/etherparse/~0/etherparse/struct.Ipv6Header.html#method.read)
* [UdpHeader.read](https://docs.rs/etherparse/~0/etherparse/struct.UdpHeader.html#method.read)

## How to generate fake packet data?
### Packet Builder
The PacketBuilder struct provides a high level interface for quickly creating network packets. The PacketBuilder will automatically set fields which can be deduced from the content and compositions of the packet itself (e.g. checksums, lengths, ethertype, ip protocol number).

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
* Documentation
  * Packet Builder
* TCP
* MutPacketSlice -> modifaction of fields in slices directly?
* Reserializing SlicedPacket & MutSlicedPacket with corrected checksums & id's
* Slicing & reading packet from different layers then ethernet onward (e.g. ip, vlan...)
* IEEE 802.3

## References
* Darpa Internet Program Protocol Specification [RFC 791](https://tools.ietf.org/html/rfc791)
* Internet Protocol, Version 6 (IPv6) Specification [RFC 8200](https://tools.ietf.org/html/rfc8200)
* [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
* [Wikipedia IEEE_802.1Q](https://en.wikipedia.org/w/index.php?title=IEEE_802.1Q&oldid=820983900)
* User Datagram Protocol (UDP) [RFC 768](https://tools.ietf.org/html/rfc768)
* Transmission Control Protocol [RFC 793](https://tools.ietf.org/html/rfc793)
* The Addition of Explicit Congestion Notification (ECN) to IP [RFC 3168](https://tools.ietf.org/html/rfc3168)
* Robust Explicit Congestion Notification (ECN) Signaling with Nonces [RFC 3540](https://tools.ietf.org/html/rfc3540)

[build_badge]: https://travis-ci.org/JulianSchmid/etherparse.svg?branch=master
[build_status]: https://travis-ci.org/JulianSchmid/etherparse
[coverage_badge]: https://codecov.io/gh/JulianSchmid/etherparse/branch/master/graph/badge.svg
[coverage_report]: https://codecov.io/gh/JulianSchmid/etherparse/branch/master
