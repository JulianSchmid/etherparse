//! A zero allocation library for parsing & writing a bunch of packet based protocols (EthernetII, IPv4, IPv6, UDP, TCP ...).
//! 
//! Currently supported are:
//! * Ethernet II
//! * IEEE 802.1Q VLAN Tagging Header
//! * IPv4
//! * IPv6 (supporting the most common extension headers, but not all)
//! * UDP
//! * TCP
//! 
//! # Usage
//! 
//! Add the following to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! etherparse = "0.10.1"
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
//! #               [7,8,9,10,11,12]) //destionation mac
//! #    .ipv4([192,168,1,1], //source ip
//! #          [192,168,1,2], //desitionation ip
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
//! #               [7,8,9,10,11,12]) //destionation mac
//! #    .ipv4([192,168,1,1], //source ip
//! #          [192,168,1,2], //desitionation ip
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
//! Have a look at the documentation for the <NAME>Slice.from_slice methods, if you want to create your own slices:
//! 
//! * [`Ethernet2HeaderSlice::from_slice`]
//! * [`SingleVlanHeaderSlice::from_slice`]
//! * [`DoubleVlanHeaderSlice::from_slice`]
//! * [`Ipv4HeaderSlice::from_slice`]
//! * [`Ipv4ExtensionsSlice::from_slice`]
//! * [`Ipv6HeaderSlice::from_slice`]
//! * [`Ipv6ExtensionsSlice::from_slice`]
//! * [`Ipv6RawExtensionHeaderSlice::from_slice`]
//! * [`IpAuthenticationHeaderSlice::from_slice`]
//! * [`Ipv6FragmentHeaderSlice::from_slice`]
//! * [`UdpHeaderSlice::from_slice`]
//! * [`TcpHeaderSlice::from_slice`]
//!
//! And for deserialization into the corresponding header structs have a look at:
//!
//! * [`Ethernet2Header::read`] & [`Ethernet2Header::from_slice`]
//! * [`SingleVlanHeader::read`] & [`SingleVlanHeader::from_slice`]
//! * [`DoubleVlanHeader::read`] & [`DoubleVlanHeader::from_slice`]
//! * [`IpHeader::read`] & [`IpHeader::from_slice`]
//! * [`Ipv4Header::read`] & [`Ipv4Header::from_slice`]
//! * [`Ipv4Extensions::read`] & [`Ipv4Extensions::from_slice`]
//! * [`Ipv6Header::read`] & [`Ipv6Header::from_slice`]
//! * [`Ipv6Extensions::read`] & [`Ipv6Extensions::from_slice`]
//! * [`Ipv6RawExtensionHeader::read`] & [`Ipv6RawExtensionHeader::from_slice`]
//! * [`IpAuthenticationHeader::read`] & [`IpAuthenticationHeader::from_slice`]
//! * [`Ipv6FragmentHeader::read`] & [`Ipv6FragmentHeader::from_slice`]
//! * [`UdpHeader::read`] & [`UdpHeader::from_slice`]
//! * [`TcpHeader::read`] & [`TcpHeader::from_slice`]
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
//! * [`Ipv6RawExtensionHeader::write`]
//! * [`IpAuthenticationHeader::write`]
//! * [`Ipv6FragmentHeader::write`]
//! * [`UdpHeader::write`]
//! * [`TcpHeader::write`]
//!
//! # Roadmap
//! * Documentation
//!   * Packet Builder
//! * MutPacketSlice -> modifaction of fields in slices directly?
//! * Reserializing SlicedPacket & MutSlicedPacket with corrected checksums & id's
//! * Slicing & reading packet from different layers then ethernet onward (e.g. ip, vlan...)
//! * IEEE 802.3
//! 
//! # References
//! * Darpa Internet Program Protocol Specification [RFC 791](https://tools.ietf.org/html/rfc791)
//! * Internet Protocol, Version 6 (IPv6) Specification [RFC 8200](https://tools.ietf.org/html/rfc8200)
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

use std::io;

mod errors;
pub use crate::errors::*;

/// Contains the error types
pub mod error;

mod link;
pub use crate::link::LinkSlice;
pub use crate::link::ethernet::*;
pub use crate::link::vlan_tagging::*;

mod internet;
pub use crate::internet::ip::*;
pub use crate::internet::ip_authentication::*;
pub use crate::internet::ipv4::*;
pub use crate::internet::ipv4_extensions::*;
pub use crate::internet::ipv6::*;
pub use crate::internet::ipv6_extensions::*;
pub use crate::internet::ipv6_raw_extension::*;
pub use crate::internet::ipv6_fragment::*;

mod transport;
pub use crate::transport::tcp::*;
pub use crate::transport::udp::*;
pub use crate::transport::TransportHeader;

/// Helpers for calculating checksums.
pub mod checksum;

mod packet_builder;
pub use crate::packet_builder::*;

mod packet_decoder;
pub use crate::packet_decoder::*;

mod packet_slicing;
pub use crate::packet_slicing::*;

pub mod packet_filter;

///Contains the size when serialized.
pub trait SerializedSize {
    const SERIALIZED_SIZE: usize;
}

fn max_check_u8(value: u8, max: u8, field: ErrorField) -> Result<(), ValueError> {
    use crate::ValueError::U8TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U8TooLarge { 
            value, 
            max,
            field
        })
    }
}

fn max_check_u16(value: u16, max: u16, field: ErrorField) -> Result<(), ValueError> {
    use crate::ValueError::U16TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U16TooLarge{ 
            value, 
            max, 
            field
        })
    }
}

/// Helper function for reading big endian u16 values from a ptr unchecked.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 2
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_be_u16(ptr: *const u8) -> u16 {
    u16::from_be_bytes(
        [
            *ptr,
            *ptr.add(1),
        ]
    )
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
    u32::from_be_bytes(
        [
            *ptr,
            *ptr.add(1),
            *ptr.add(2),
            *ptr.add(3)
        ]
    )
}

/// Helper function for reading a 4 byte fixed-size array.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 4
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_4_byte_array(ptr: *const u8) -> [u8;4] {
    [
        *ptr,
        *ptr.add(1),
        *ptr.add(2),
        *ptr.add(3)
    ]
}

/// Helper function for reading a 6 byte fixed-size array.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 6
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
unsafe fn get_unchecked_6_byte_array(ptr: *const u8) -> [u8;6] {
    [
        *ptr,
        *ptr.add(1),
        *ptr.add(2),
        *ptr.add(3),
        *ptr.add(4),
        *ptr.add(5)
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
unsafe fn get_unchecked_16_byte_array(ptr: *const u8) -> [u8;16] {
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
