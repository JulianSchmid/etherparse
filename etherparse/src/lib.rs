//! A zero allocation library for parsing & writing a bunch of packet based protocols (EthernetII, IPv4, IPv6, UDP, TCP ...).
//!
//! Currently supported are:
//! * Ethernet II
//! * IEEE 802.1Q VLAN Tagging Header
//! * IPv4
//! * IPv6 (supporting the most common extension headers, but not all)
//! * UDP
//! * TCP
//! * ICMP & ICMPv6 (not all message types are supported)
//!
//! # Usage
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! etherparse = "0.13"
//! ```
//!
//! # What is etherparse?
//! Etherparse is intended to provide the basic network parsing functions that allow for easy analysis, transformation or generation of recorded network data.
//!
//! Some key points are:
//!
//! * It is completly written in Rust and thoroughly tested.
//! * Special attention has been paid to not use allocations or syscalls.
//! * The package is still in development and can & will still change.
//! * The current focus of development is on the most popular protocols in the internet & transport layer.
//!
//! # How to parse network packages?
//! Etherparse gives you two options for parsing network packages automatically:
//!
//! ## Slicing the packet
//! Here the different components in a packet are seperated without parsing all their fields. For each header a slice is generated that allows access to the fields of a header.
//! ```
//! # use etherparse::{SlicedPacket, PacketBuilder};
//! # let builder = PacketBuilder::
//! #    ethernet2([1,2,3,4,5,6],     //source mac
//! #               [7,8,9,10,11,12]) //destination mac
//! #    .ipv4([192,168,1,1], //source ip
//! #          [192,168,1,2], //destination ip
//! #          20)            //time to life
//! #    .udp(21,    //source port
//! #         1234); //desitnation port
//! #    //payload of the udp packet
//! #    let payload = [1,2,3,4,5,6,7,8];
//! #    //get some memory to store the serialized data
//! #    let mut packet = Vec::<u8>::with_capacity(
//! #                            builder.size(payload.len()));
//! #    builder.write(&mut packet, &payload).unwrap();
//! match SlicedPacket::from_ethernet(&packet) {
//!     Err(value) => println!("Err {:?}", value),
//!     Ok(value) => {
//!         println!("link: {:?}", value.link);
//!         println!("vlan: {:?}", value.vlan);
//!         println!("ip: {:?}", value.ip);
//!         println!("transport: {:?}", value.transport);
//!     }
//! }
//! ```
//! This is the faster option if your code is not interested in all fields of all the headers. It is a good choice if you just want filter or find packages based on a subset of the headers and/or their fields.
//!
//! Depending from which point downward you want to slice a package check out the functions:
//!
//! * [`SlicedPacket::from_ethernet`] for parsing from an Ethernet II header downwards
//! * [`SlicedPacket::from_ether_type`] for parsing a slice starting after an Ethernet II header
//! * [`SlicedPacket::from_ip`] for parsing from an IPv4 or IPv6 downwards
//!
//! ## Deserializing all headers into structs
//! This option deserializes all known headers and transferes their contents to header structs.
//! ```rust
//! # use etherparse::{PacketHeaders, PacketBuilder};
//! # let builder = PacketBuilder::
//! #    ethernet2([1,2,3,4,5,6],     //source mac
//! #               [7,8,9,10,11,12]) //destination mac
//! #    .ipv4([192,168,1,1], //source ip
//! #          [192,168,1,2], //destination ip
//! #          20)            //time to life
//! #    .udp(21,    //source port
//! #         1234); //desitnation port
//! #    //payload of the udp packet
//! #    let payload = [1,2,3,4,5,6,7,8];
//! #    //get some memory to store the serialized data
//! #    let mut packet = Vec::<u8>::with_capacity(
//! #                            builder.size(payload.len()));
//! #    builder.write(&mut packet, &payload).unwrap();
//! match PacketHeaders::from_ethernet_slice(&packet) {
//!     Err(value) => println!("Err {:?}", value),
//!     Ok(value) => {
//!         println!("link: {:?}", value.link);
//!         println!("vlan: {:?}", value.vlan);
//!         println!("ip: {:?}", value.ip);
//!         println!("transport: {:?}", value.transport);
//!     }
//! }
//! ```
//! This option is slower then slicing when only few fields are accessed. But it can be the faster option or useful if you are interested in most fields anyways or if you want to re-serialize the headers with modified values.
//!
//! Depending from which point downward you want to unpack a package check out the functions
//!
//! * [`PacketHeaders::from_ethernet_slice`] for parsing from an Ethernet II header downwards
//! * [`PacketHeaders::from_ether_type`] for parsing a slice starting after an Ethernet II header
//! * [`PacketHeaders::from_ip_slice`] for parsing from an IPv4 or IPv6 downwards
//!
//! ## Manually slicing & parsing packets
//! It is also possible to manually slice & parse a packet. For each header type there is are metods that create a slice or struct from a memory slice.
//!
//! Have a look at the documentation for the \[NAME\]Slice.from_slice methods, if you want to create your own slices:
//!
//! * [`Ethernet2HeaderSlice::from_slice`]
//! * [`SingleVlanHeaderSlice::from_slice`]
//! * [`DoubleVlanHeaderSlice::from_slice`]
//! * [`Ipv4HeaderSlice::from_slice`]
//! * [`Ipv4ExtensionsSlice::from_slice`]
//! * [`Ipv6HeaderSlice::from_slice`]
//! * [`Ipv6ExtensionsSlice::from_slice`]
//! * [`Ipv6RawExtHeaderSlice::from_slice`]
//! * [`IpAuthHeaderSlice::from_slice`]
//! * [`Ipv6FragmentHeaderSlice::from_slice`]
//! * [`UdpHeaderSlice::from_slice`]
//! * [`TcpHeaderSlice::from_slice`]
//! * [`Icmpv4Slice::from_slice`]
//! * [`Icmpv6Slice::from_slice`]
//!
//! And for deserialization into the corresponding header structs have a look at:
//!
//! * [`Ethernet2Header::read`] & [`Ethernet2Header::from_slice`]
//! * [`SingleVlanHeader::read`] & [`SingleVlanHeader::from_slice`]
//! * [`DoubleVlanHeader::read`] & [`DoubleVlanHeader::from_slice`]
//! * [`IpHeaders::read`] & [`IpHeaders::from_slice`]
//! * [`Ipv4Header::read`] & [`Ipv4Header::from_slice`]
//! * [`Ipv4Extensions::read`] & [`Ipv4Extensions::from_slice`]
//! * [`Ipv6Header::read`] & [`Ipv6Header::from_slice`]
//! * [`Ipv6Extensions::read`] & [`Ipv6Extensions::from_slice`]
//! * [`Ipv6RawExtHeader::read`] & [`Ipv6RawExtHeader::from_slice`]
//! * [`IpAuthHeader::read`] & [`IpAuthHeader::from_slice`]
//! * [`Ipv6FragmentHeader::read`] & [`Ipv6FragmentHeader::from_slice`]
//! * [`UdpHeader::read`] & [`UdpHeader::from_slice`]
//! * [`TcpHeader::read`] & [`TcpHeader::from_slice`]
//! * [`Icmpv4Header::read`] & [`Icmpv4Header::from_slice`]
//! * [`Icmpv6Header::read`] & [`Icmpv6Header::from_slice`]
//!
//! # How to generate fake packet data?
//! ## Packet Builder
//! The PacketBuilder struct provides a high level interface for quickly creating network packets. The PacketBuilder will automatically set fields which can be deduced from the content and compositions of the packet itself (e.g. checksums, lengths, ethertype, ip protocol number).
//!
//! [Example:](https://github.com/JulianSchmid/etherparse/blob/0.10.1/examples/write_udp.rs)
//! ```rust
//! use etherparse::PacketBuilder;
//!
//! let builder = PacketBuilder::
//!     ethernet2([1,2,3,4,5,6],     //source mac
//!                [7,8,9,10,11,12]) //destination mac
//!     .ipv4([192,168,1,1], //source ip
//!           [192,168,1,2], //desitination ip
//!           20)            //time to life
//!     .udp(21,    //source port
//!          1234); //desitnation port
//!
//! //payload of the udp packet
//! let payload = [1,2,3,4,5,6,7,8];
//!
//! //get some memory to store the result
//! let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
//!
//! //serialize
//! //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
//! //before writing the packet out to "result"
//! builder.write(&mut result, &payload).unwrap();
//! ```
//!
//! There is also an [example for TCP packets](https://github.com/JulianSchmid/etherparse/blob/0.10.1/examples/write_tcp.rs) available.
//!
//! Check out the [PacketBuilder documentation](struct.PacketBuilder.html) for more informations.
//!
//! ## Manually serialising each header
//! Alternativly it is possible to manually build a packet ([example](https://github.com/JulianSchmid/etherparse/blob/0.10.1/examples/write_ipv4_udp.rs)). Generally each struct representing a header has a "write" method that allows it to be serialized. These write methods sometimes automatically calculate checksums and fill them in. In case this is unwanted behavior (e.g. if you want to generate a packet with an invalid checksum), it is also possible to call a "write_raw" method that will simply serialize the data without doing checksum calculations.
//!
//! Read the documentations of the different methods for a more details:
//!
//! * [`Ethernet2Header::write`]
//! * [`SingleVlanHeader::write`]
//! * [`DoubleVlanHeader::write`]
//! * [`Ipv4Header::write`]
//! * [`Ipv4Header::write_raw`]
//! * [`Ipv4Extensions::write`]
//! * [`Ipv6Header::write`]
//! * [`Ipv6Extensions::write`]
//! * [`Ipv6RawExtHeader::write`]
//! * [`IpAuthHeader::write`]
//! * [`Ipv6FragmentHeader::write`]
//! * [`UdpHeader::write`]
//! * [`TcpHeader::write`]
//! * [`Icmpv4Header::write`]
//! * [`Icmpv6Header::write`]
//!
//! # References
//! * Darpa Internet Program Protocol Specification [RFC 791](https://tools.ietf.org/html/rfc791)
//! * Internet Protocol, Version 6 (IPv6) Specification [RFC 8200](https://tools.ietf.org/html/rfc8200)
//! * [IANA 802 EtherTypes](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
//! * [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
//! * [Internet Protocol Version 6 (IPv6) Parameters](https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml)
//! * [Wikipedia IEEE_802.1Q](https://en.wikipedia.org/w/index.php?title=IEEE_802.1Q&oldid=820983900)
//! * User Datagram Protocol (UDP) [RFC 768](https://tools.ietf.org/html/rfc768)
//! * Transmission Control Protocol [RFC 793](https://tools.ietf.org/html/rfc793)
//! * TCP Extensions for High Performance [RFC 7323](https://tools.ietf.org/html/rfc7323)
//! * The Addition of Explicit Congestion Notification (ECN) to IP [RFC 3168](https://tools.ietf.org/html/rfc3168)
//! * Robust Explicit Congestion Notification (ECN) Signaling with Nonces [RFC 3540](https://tools.ietf.org/html/rfc3540)
//! * IP Authentication Header [RFC 4302](https://tools.ietf.org/html/rfc4302)
//! * Mobility Support in IPv6 [RFC 6275](https://tools.ietf.org/html/rfc6275)
//! * Host Identity Protocol Version 2 (HIPv2) [RFC 7401](https://tools.ietf.org/html/rfc7401)
//! * Shim6: Level 3 Multihoming Shim Protocol for IPv6 [RFC 5533](https://tools.ietf.org/html/rfc5533)
//! * Computing the Internet Checksum [RFC 1071](https://datatracker.ietf.org/doc/html/rfc1071)
//! * Internet Control Message Protocol [RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
//! * [IANA Internet Control Message Protocol (ICMP) Parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
//! * Requirements for Internet Hosts -- Communication Layers [RFC 1122](https://datatracker.ietf.org/doc/html/rfc1122)
//! * Requirements for IP Version 4 Routers [RFC 1812](https://datatracker.ietf.org/doc/html/rfc1812)
//! * Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification [RFC 4443](https://datatracker.ietf.org/doc/html/rfc4443)
//! * ICMP Router Discovery Messages [RFC 1256](https://datatracker.ietf.org/doc/html/rfc1256)
//! * [Internet Control Message Protocol version 6 (ICMPv6) Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
//! * Multicast Listener Discovery (MLD) for IPv6 [RFC 2710](https://datatracker.ietf.org/doc/html/rfc2710)
//! * Neighbor Discovery for IP version 6 (IPv6) [RFC 4861](https://datatracker.ietf.org/doc/html/rfc4861)

// # Reason for 'bool_comparison' disable:
//
// Clippy triggers triggers errors like the following if the warning stays enabled:
//
//   warning: equality checks against false can be replaced by a negation
//     --> src/packet_decoder.rs:131:20
//      |
//  131 |                 if false == fragmented {
//      |                    ^^^^^^^^^^^^^^^^^^^ help: try simplifying it as shown: `!fragmented`
//
//
// I prefer to write `false == value` instead of `!value` as it
// is more visually striking and is not as easy to overlook as the single
// character '!'.
#![allow(clippy::bool_comparison)]
// Removes all std and alloc default imports & enables "non std" support.
#![no_std]

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate proptest;
#[cfg(any(feature = "std", test))]
extern crate std;

/// Module containing error types that can be triggered.
pub mod err;

mod link;
pub use crate::link::double_vlan_header::*;
pub use crate::link::double_vlan_header_slice::*;
pub use crate::link::ether_type_impl::*;
pub use crate::link::ethernet2_header::*;
pub use crate::link::ethernet2_header_slice::*;
pub use crate::link::link_slice::*;
pub use crate::link::single_vlan_header::*;
pub use crate::link::single_vlan_header_slice::*;
pub use crate::link::vlan_header::*;
pub use crate::link::vlan_id::*;
pub use crate::link::vlan_pcp::*;
pub use crate::link::vlan_slice::*;

#[cfg(test)]
pub(crate) mod test_gens;

mod internet;
pub use crate::internet::ip_auth_header::*;
pub use crate::internet::ip_auth_header_slice::*;
pub use crate::internet::ip_frag_offset::*;
pub use crate::internet::ip_header::*;
pub use crate::internet::ip_number_impl::*;
pub use crate::internet::ip_payload::*;
pub use crate::internet::ip_slice::*;
pub use crate::internet::ipv4_dscp::*;
pub use crate::internet::ipv4_ecn::*;
pub use crate::internet::ipv4_exts::*;
pub use crate::internet::ipv4_exts_slice::*;
pub use crate::internet::ipv4_header::*;
pub use crate::internet::ipv4_header_slice::*;
pub use crate::internet::ipv4_options::*;
pub use crate::internet::ipv4_slice::*;
pub use crate::internet::ipv6_ext_slice::*;
pub use crate::internet::ipv6_ext_slice_iter::*;
pub use crate::internet::ipv6_exts::*;
pub use crate::internet::ipv6_exts_slice::*;
pub use crate::internet::ipv6_flow_label::*;
pub use crate::internet::ipv6_fragment_header::*;
pub use crate::internet::ipv6_fragment_header_slice::*;
pub use crate::internet::ipv6_header::*;
pub use crate::internet::ipv6_header_slice::*;
pub use crate::internet::ipv6_raw_ext_header::*;
pub use crate::internet::ipv6_raw_ext_header_slice::*;
pub use crate::internet::ipv6_routing_exts::*;
pub use crate::internet::ipv6_slice::*;

#[cfg(feature = "std")]
pub mod io;

mod transport;
pub use crate::transport::icmp_echo_header::*;
pub use crate::transport::icmpv4;
pub use crate::transport::icmpv4_header::*;
pub use crate::transport::icmpv4_slice::*;
pub use crate::transport::icmpv4_type::*;
pub use crate::transport::icmpv6;
pub use crate::transport::icmpv6_header::*;
pub use crate::transport::icmpv6_slice::*;
pub use crate::transport::icmpv6_type::*;
pub use crate::transport::tcp_header::*;
pub use crate::transport::tcp_header_slice::*;
pub use crate::transport::tcp_option_element::*;
pub use crate::transport::tcp_option_impl::*;
pub use crate::transport::tcp_option_read_error::*;
pub use crate::transport::tcp_option_write_error::*;
pub use crate::transport::tcp_options::*;
pub use crate::transport::tcp_options_iterator::*;
pub use crate::transport::transport_header::*;
pub use crate::transport::transport_slice::*;
pub use crate::transport::udp_header::*;
pub use crate::transport::udp_header_slice::*;
pub use crate::transport::udp_slice::*;

/// Helpers for calculating checksums.
pub mod checksum;

#[cfg(test)]
mod compositions_tests;

mod helpers;

#[cfg(feature = "std")]
mod packet_builder;
#[cfg(feature = "std")]
pub use crate::packet_builder::*;

mod packet_headers;
pub use crate::packet_headers::*;

mod sliced_packet;
pub use crate::sliced_packet::*;

pub mod packet_filter;

#[cfg(test)]
pub(crate) mod test_packet;

/// Deprecated use [err::ReadError] instead or use the specific error type returned by operation you are using.
#[cfg(feature = "std")]
#[deprecated(
    since = "0.14.0",
    note = "Please use the type err::ReadError instead or use the specific error type returned by operation you are using."
)]
pub type ReadError = err::ReadError;

/// Deprecated use [err::ReadError] instead or use the specific error type returned by operation you are using.
#[cfg(feature = "std")]
#[deprecated(since = "0.14.0", note = "Please use the type err::Field instead.")]
pub type ErrorField = err::ValueType;

/// Helper function for reading big endian u16 values from a ptr unchecked.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 2
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_be_u16(ptr: *const u8) -> u16 {
    u16::from_be_bytes([*ptr, *ptr.add(1)])
}

/// Helper function for reading big endian u32 values from a ptr unchecked.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 4
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_be_u32(ptr: *const u8) -> u32 {
    u32::from_be_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)])
}

/// Helper function for reading a 4 byte fixed-size array.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 4
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_4_byte_array(ptr: *const u8) -> [u8; 4] {
    [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]
}

/// Helper function for reading a 6 byte fixed-size array.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 6
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_6_byte_array(ptr: *const u8) -> [u8; 6] {
    [
        *ptr,
        *ptr.add(1),
        *ptr.add(2),
        *ptr.add(3),
        *ptr.add(4),
        *ptr.add(5),
    ]
}

/// Helper function for reading a 16 byte fixed-size array.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 16
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_16_byte_array(ptr: *const u8) -> [u8; 16] {
    [
        *ptr,
        *ptr.add(1),
        *ptr.add(2),
        *ptr.add(3),
        *ptr.add(4),
        *ptr.add(5),
        *ptr.add(6),
        *ptr.add(7),
        *ptr.add(8),
        *ptr.add(9),
        *ptr.add(10),
        *ptr.add(11),
        *ptr.add(12),
        *ptr.add(13),
        *ptr.add(14),
        *ptr.add(15),
    ]
}
