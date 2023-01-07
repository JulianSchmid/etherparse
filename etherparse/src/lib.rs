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
//! * [`IpHeader::read`] & [`IpHeader::from_slice`]
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

use std::io;

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
pub use crate::link::vlan_slice::*;

#[cfg(test)]
pub(crate) mod test_gens;

mod internet;
pub use crate::internet::ip_header::*;
pub use crate::internet::ip_auth_header::*;
pub use crate::internet::ip_auth_header_slice::*;
pub use crate::internet::ip_number_impl::*;
pub use crate::internet::ipv4_exts::*;
pub use crate::internet::ipv4_exts_slice::*;
pub use crate::internet::ipv4_header::*;
pub use crate::internet::ipv4_header_slice::*;
pub use crate::internet::ipv6_ext_slice::*;
pub use crate::internet::ipv6_ext_slice_iter::*;
pub use crate::internet::ipv6_exts::*;
pub use crate::internet::ipv6_exts_slice::*;
pub use crate::internet::ipv6_fragment_header::*;
pub use crate::internet::ipv6_fragment_header_slice::*;
pub use crate::internet::ipv6_header::*;
pub use crate::internet::ipv6_header_slice::*;
pub use crate::internet::ipv6_raw_ext_header::*;
pub use crate::internet::ipv6_raw_ext_header_slice::*;
pub use crate::internet::ipv6_routing_exts::*;

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
pub use crate::transport::tcp_options_iterator::*;
pub use crate::transport::transport_header::*;
pub use crate::transport::udp_header::*;
pub use crate::transport::udp_header_slice::*;

/// Helpers for calculating checksums.
pub mod checksum;

mod packet_builder;
pub use crate::packet_builder::*;

mod packet_decoder;
pub use crate::packet_decoder::*;

mod packet_slicing;
pub use crate::packet_slicing::*;

pub mod packet_filter;

/// Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    /// Whenever an std::io::Error gets triggerd during a write it gets forwarded via this enum value.
    IoError(std::io::Error),
    /// Error when an unexpected end of a slice was reached even though more data was expected to be present.
    SliceLen(err::LenError),
    /// Error when a slice has a different size then expected.
    UnexpectedLenOfSlice { expected: usize, actual: usize },
    /// Error when decoding an IP header.
    IpHeader(err::ip::HeaderError),
    /// Error when decoding an IPv4 header.
    Ipv4Header(err::ipv4::HeaderError),
    /// Error when decoding an IPv6 header.
    Ipv6Header(err::ipv6::HeaderError),
    /// Error when decoding a IPv6 extension headers.
    Ipv6ExtsHeader(err::ipv6_exts::HeaderError),
    /// Error when decoding an IP authentification header.
    IpAuthHeader(err::ip_auth::HeaderError),
    /// Error when decoding a TCP header.
    TcpHeader(err::tcp::HeaderError),
    /// Error when the packet size is too big (e.g larger then can be represendted in a length field).
    ///
    /// This error can be triggered by
    /// * `Icmpv6Slice::from_slice`
    Icmpv6PacketTooBig(usize),
}

impl ReadError {
    /// Adds an offset value to the UnexpectedEndOfSlice error.
    pub fn add_slice_offset(self, offset: usize) -> ReadError {
        use crate::ReadError::*;
        match self {
            SliceLen(value) => SliceLen(err::LenError {
                required_len: value.required_len,
                actual_len: value.actual_len,
                actual_len_source: value.actual_len_source,
                layer: value.layer,
                layer_start_offset: value.layer_start_offset + offset,
            }),
            UnexpectedLenOfSlice { expected, actual } => UnexpectedLenOfSlice {
                expected: expected + offset,
                actual: actual + offset,
            },
            value => value,
        }
    }

    /// Returns the `std::io::Error` value if the `ReadError` is an `IoError`.
    /// Otherwise `None is returned.
    pub fn io_error(self) -> Option<std::io::Error> {
        match self {
            ReadError::IoError(value) => Some(value),
            _ => None,
        }
    }
    /// Returns the `err::UnexpectedEndOfSliceError` value if the `ReadError` is an `UnexpectedEndOfSlice`.
    pub fn slice_len(self) -> Option<err::LenError> {
        match self {
            ReadError::SliceLen(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the `err::ipv4::HeaderError` value if the `ReadError` is an `Ipv4Header`.
    pub fn ipv4_header(self) -> Option<err::ipv4::HeaderError> {
        match self {
            ReadError::Ipv4Header(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the `err::ip_auth::HeaderError` value if the `ReadError` is an `IpAuthHeader`.
    pub fn ip_auth_header(self) -> Option<err::ip_auth::HeaderError> {
        match self {
            ReadError::IpAuthHeader(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the `err::tcp::HeaderError` value if the `ReadError` is a `TcpHeader`.
    pub fn tcp_header(self) -> Option<err::tcp::HeaderError> {
        match self {
            ReadError::TcpHeader(value) => Some(value),
            _ => None,
        }
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ReadError::*;

        match self {
            IoError(err) => err.fmt(f),
            SliceLen(err) => err.fmt(f),
            UnexpectedLenOfSlice { expected, actual } => {
                write!(f, "ReadError: Unexpected length of slice. The given slice contained {} bytes but {} bytes were required.", actual, expected)
            }
            IpHeader(err) => err.fmt(f),
            Ipv4Header(err) => err.fmt(f),
            Ipv6Header(err) => err.fmt(f),
            Ipv6ExtsHeader(err) => err.fmt(f),
            IpAuthHeader(err) => err.fmt(f),
            TcpHeader(err) => err.fmt(f),
            Icmpv6PacketTooBig(size) => {
                write!(f, "ReadError: ICMPv6 packet length {} is bigger then can be represented in an u32.", size)
            }
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadError::IoError(err) => Some(err),
            ReadError::SliceLen(err) => Some(err),
            ReadError::IpHeader(err) => Some(err),
            ReadError::Ipv4Header(err) => Some(err),
            ReadError::Ipv6Header(err) => Some(err),
            ReadError::Ipv6ExtsHeader(err) => Some(err),
            ReadError::TcpHeader(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> ReadError {
        ReadError::IoError(err)
    }
}

///Errors that can occur when writing.
#[derive(Debug)]
pub enum WriteError {
    IoError(std::io::Error),
    ///Error in the data that was given to write
    ValueError(ValueError),
    ///Error when a given slice is not big enough to serialize the data.
    SliceTooSmall(usize),
}

impl WriteError {
    /// Returns the `std::io::Error` value if the `WriteError` is an `IoError`.
    /// Otherwise `None is returned.
    pub fn io_error(self) -> Option<std::io::Error> {
        match self {
            WriteError::IoError(value) => Some(value),
            _ => None,
        }
    }
    /// Returns the `std::io::Error` value if the `WriteError` is an `ValueError`.
    /// Otherwise `None` is returned.
    pub fn value_error(self) -> Option<ValueError> {
        match self {
            WriteError::ValueError(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the expected minimum size if the error is an `SliceTooSmall`.
    pub fn slice_too_small_size(self) -> Option<usize> {
        match self {
            WriteError::SliceTooSmall(value) => Some(value),
            _ => None,
        }
    }
}

impl From<ValueError> for WriteError {
    fn from(err: ValueError) -> WriteError {
        WriteError::ValueError(err)
    }
}

impl From<std::io::Error> for WriteError {
    fn from(err: std::io::Error) -> WriteError {
        WriteError::IoError(err)
    }
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use WriteError::*;
        match self {
            IoError(err) => err.fmt(f),
            ValueError(err) => {
                write!(f, "ValueError: {}", err)
            }
            SliceTooSmall(size) => {
                write!(f, "SliceTooSmall: The slice given to write to is too small (required to be at least {} bytes large)", size)
            }
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use WriteError::*;
        match self {
            IoError(ref err) => Some(err),
            ValueError(ref err) => Some(err),
            SliceTooSmall(_) => None,
        }
    }
}

/// Errors in the given data
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValueError {
    /// Error when the ipv4 options length is too big or not aligned (cannot be bigger then 40 bytes and must be a multiple of 4 bytes).
    Ipv4OptionsLengthBad(usize),
    /// Error when a given payload & ipv4 header is bigger then what fits inside an ipv4 total_length field.
    Ipv4PayloadLengthTooLarge(usize),
    /// Error when a given payload & ipv6 header block is bigger then what fits inside an ipv6 payload_length field.
    Ipv6PayloadLengthTooLarge(usize),
    /// Error when a given payload size is smaller then 6 octets which is the minimum ipv6 extended header size ([Ipv6RawExtHeader::MAX_PAYLOAD_LEN]).
    Ipv6ExtensionPayloadTooSmall(usize),
    /// Error when a given payload size is bigger then what fits inside an ipv6 extended header size ([Ipv6RawExtHeader::MAX_PAYLOAD_LEN]).
    Ipv6ExtensionPayloadTooLarge(usize),
    /// Error when a given payload length is not aligned to be a multiple of 8 octets when 6 is substracted and can not be represented by the header length field.
    Ipv6ExtensionPayloadLengthUnaligned(usize),
    /// Error when a given authentication header icv size is not a multiple of 4 bytes or bigger then 1016 bytes and therefor can not be represented in the header length field.
    IpAuthenticationHeaderBadIcvLength(usize),
    /// Error when a header in `Ipv4Extensions` is never written as it is never referenced by any of the other `next_header` fields or the initial `protocol`.
    Ipv4ExtensionNotReferenced(IpNumber),
    /// Error when a hop-by-hop header is not referenced as the first header after the ipv6 header but as a later extension header.
    Ipv6ExtensionHopByHopNotAtStart,
    /// Error when a header in `Ipv6Extensions` is never written as it is never referenced by any of the other `next_header` fields or the initial ip number.
    Ipv6ExtensionNotReferenced(IpNumber),
    /// Error when a header in `Ipv6Extensions` is referenced multiple times or is referenced and not defined.
    Ipv6ExtensionNotDefinedReference(IpNumber),
    /// Error when a given payload is bigger then what fits inside an udp packet
    /// Note that a the maximum payload size, as far as udp is conceirned, is max_value(u16) - 8. The 8 is for the size of the udp header itself.
    UdpPayloadLengthTooLarge(usize),
    /// Error when a given payload + tcp header options is bigger then what fits inside an tcp packet
    /// Note that a the maximum size, as far as tcp is conceirned, is max_value(u16) - tcp_header.data_offset()*4. The data_offset is for the size of the udp header itself.
    TcpLengthTooLarge(usize),
    /// Error when a u8 field in a header has a larger value then supported.
    U8TooLarge {
        value: u8,
        max: u8,
        field: ErrorField,
    },
    /// Error when a u16 field in a header has a larger value then supported.
    U16TooLarge {
        value: u16,
        max: u16,
        field: ErrorField,
    },
    /// Error when a u32 field in a header has a larger value then supported.
    U32TooLarge {
        value: u32,
        max: u32,
        field: ErrorField,
    },
    /// Error when an Icmpv6 payload is found in an IPv4 packet.
    Icmpv6InIpv4,
}

impl std::error::Error for ValueError {}

impl std::fmt::Display for ValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ValueError::*;
        match self {
            Ipv4OptionsLengthBad(options_len) => {
                write!(f, "Bad IPv4 'options_len'. The IPv4 options length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 40 bytes.", options_len)
            }
            Ipv4PayloadLengthTooLarge(total_length) => {
                write!(f, "IPv4 'total_legnth' too large. The IPv4 header and payload have a larger size ({} bytes) than can be be represented by the 'total_legnth' field in the IPv4 header.", total_length)
            }
            Ipv6PayloadLengthTooLarge(size) => {
                write!(f, "IPv6 'payload_length' too large. The IPv6 header block & payload size ({} bytes) is larger then what can be be represented by the 'payload_length' field in the IPv6 header.", size)
            }
            Ipv6ExtensionPayloadTooSmall(size) => {
                write!(f, "IPv6 extensions header payload length is too small. The payload size ({} bytes) is less then 6 octets which is the minimum IPv6 extension header payload size.", size)
            }
            Ipv6ExtensionPayloadTooLarge(size) => {
                write!(f, "IPv6 extensions header payload length is too large. The payload size ({} bytes) is larger then what can be be represented by the 'extended header size' field in an IPv6 extension header.", size)
            }
            Ipv6ExtensionPayloadLengthUnaligned(size) => {
                write!(f, "IPv6 extensions header 'payload length ({} bytes) + 2' is not multiple of 8 (+ 2 for the `next_header` and `header_length` fields). This is required as the header length field can only express lengths in multiple of 8 bytes.", size)
            }
            IpAuthenticationHeaderBadIcvLength(size) => {
                write!(f, "IP authentication header 'raw_icv' value has a length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 1016 bytes.", size)
            }
            Ipv4ExtensionNotReferenced(ip_protocol_number) => {
                write!(f, "IPv4 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the 'protocol' field of the IPv4 header.", ip_protocol_number)
            }
            Ipv6ExtensionHopByHopNotAtStart => {
                write!(f, "IPv6 extensions hop-by-hop is not located directly after the IPv6 header (required by IPv6).")
            }
            Ipv6ExtensionNotReferenced(ip_protocol_number) => {
                write!(f, "IPv6 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the IPv6 header.", ip_protocol_number)
            }
            Ipv6ExtensionNotDefinedReference(ip_protocol_number) => {
                write!(f, "IPv6 extensions '{:?}' is referenced by the 'next_header' field of an extension headers or the IPv6 header but is not defined in the 'Ipv6Extensions'.", ip_protocol_number)
            }
            UdpPayloadLengthTooLarge(length) => {
                write!(f, "UDP 'length' too large. The UDP length ({} bytes) is larger then what can be be represented by the 'length' field in the UDP header.", length)
            }
            TcpLengthTooLarge(length) => {
                write!(f, "TCP length too large. The TCP packet length ({} bytes) is larger then what is supported.", length)
            }
            U8TooLarge { value, max, field } => {
                write!(
                    f,
                    "The value {} of the field '{}' is larger then the allowed maximum of {}.",
                    value, field, max
                )
            }
            U16TooLarge { value, max, field } => {
                write!(
                    f,
                    "The value {} of the field '{}' is larger then the allowed maximum of {}.",
                    value, field, max
                )
            }
            U32TooLarge { value, max, field } => {
                write!(
                    f,
                    "The value {} of the field '{}' is larger then the allowed maximum of {}.",
                    value, field, max
                )
            }
            Icmpv6InIpv4 => {
                write!(f, "ICMPv6 packet can not be combined with IPv4 headers.")
            }
        }
    }
}

///Fields that can produce errors when serialized.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ErrorField {
    Ipv4PayloadLength,
    Ipv4Dscp,
    Ipv4Ecn,
    Ipv4FragmentsOffset,
    Ipv6FlowLabel,
    /// Ipv6 fragment header fragment offset field.
    Ipv6FragmentOffset,
    ///VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
    ///VlanTaggingHeader.vlan_identifier
    VlanTagVlanId,
}

impl std::fmt::Display for ErrorField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ErrorField::*;
        match self {
            Ipv4PayloadLength => write!(f, "Ipv4Header.payload_len"),
            Ipv4Dscp => write!(f, "Ipv4Header.differentiated_services_code_point"),
            Ipv4Ecn => write!(f, "Ipv4Header.explicit_congestion_notification"),
            Ipv4FragmentsOffset => write!(f, "Ipv4Header.fragments_offset"),
            Ipv6FlowLabel => write!(f, "Ipv6Header.flow_label"),
            Ipv6FragmentOffset => write!(f, "Ipv6FragmentHeader.fragment_offset"),
            VlanTagPriorityCodePoint => write!(f, "SingleVlanHeader.priority_code_point"),
            VlanTagVlanId => write!(f, "SingleVlanHeader.vlan_identifier"),
        }
    }
}

fn max_check_u8(value: u8, max: u8, field: ErrorField) -> Result<(), ValueError> {
    use crate::ValueError::U8TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U8TooLarge { value, max, field })
    }
}

fn max_check_u16(value: u16, max: u16, field: ErrorField) -> Result<(), ValueError> {
    use crate::ValueError::U16TooLarge;
    if value <= max {
        Ok(())
    } else {
        Err(U16TooLarge { value, max, field })
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
