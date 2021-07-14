//! A zero allocation library for parsing & writing a bunch of packet based protocols (EthernetII, IPv4, IPv6, UDP, TCP ...).
//! 
//! Currently supported are:
//! * Ethernet II
//! * IEEE 802.1Q VLAN Tagging Header
//! * IPv4
//! * IPv6 (missing extension headers, but supporting skipping them)
//! * UDP
//! * TCP
//! 
//! # Usage
//! 
//! First, add the following to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! etherparse = "0.9.0"
//! ```
//! 
//! Next, add this to your crate root:
//! 
//! ```
//! extern crate etherparse;
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
//! * [`SlicedPacket.from_ethernet`](struct.SlicedPacket.html#method.from_ethernet) for parsing from an Ethernet II header downwards
//! * [`SlicedPacket.from_ip`](struct.SlicedPacket.html#method.from_ip) for parsing from an IPv4 or IPv6 downwards
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
//! * [`PacketHeaders.from_ethernet_slice`](struct.PacketHeaders.html#method.from_ethernet_slice) for parsing from an Ethernet II header downwards
//! * [`PacketHeaders.from_ip_slice`](struct.PacketHeaders.html#method.from_ip_slice) for parsing from an IPv4 or IPv6 downwards
//!
//! ## Manually slicing & parsing packets
//! It is also possible to manually slice & parse a packet. For each header type there is are metods that create a slice or struct from a memory slice. 
//! 
//! Have a look at the documentation for the <NAME>Slice.from_slice methods, if you want to create your own slices:
//! 
//! * [`Ethernet2HeaderSlice.from_slice`](struct.Ethernet2HeaderSlice.html#method.from_slice)
//! * [`SingleVlanHeaderSlice.from_slice`](struct.SingleVlanHeaderSlice.html#method.from_slice)
//! * [`DoubleVlanHeaderSlice.from_slice`](struct.DoubleVlanHeaderSlice.html#method.from_slice)
//! * [`Ipv4HeaderSlice.from_slice`](struct.Ipv4HeaderSlice.html#method.from_slice)
//! * [`Ipv6HeaderSlice.from_slice`](struct.Ipv6HeaderSlice.html#method.from_slice)
//! * [`Ipv6ExtensionHeader.from_slice`](struct.Ipv6ExtensionHeader.html)
//! * [`UdpHeaderSlice.from_slice`](struct.UdpHeaderSlice.html#method.from_slice)
//! * [`TcpHeaderSlice.from_slice`](struct.TcpHeaderSlice.html#method.from_slice)
//! 
//! And for deserialization into the corresponding header structs have a look at:
//! 
//! * [`Ethernet2Header.read`](struct.Ethernet2Header.html#method.read) & [`Ethernet2Header.read_from_slice`](struct.Ethernet2Header.html#method.read_from_slice)
//! * [`SingleVlanHeader.read`](struct.SingleVlanHeader.html#method.read) & [`SingleVlanHeader.read_from_slice`](struct.SingleVlanHeader.html#method.read_from_slice)
//! * [`DoubleVlanHeader.read`](struct.DoubleVlanHeader.html#method.read) & [`DoubleVlanHeader.read_from_slice`](struct.DoubleVlanHeader.html#method.read_from_slice)
//! * [`IpHeader.read`](enum.IpHeader.html#method.read) & [`IpHeader.read_from_slice`](enum.IpHeader.html#method.read_from_slice)
//! * [`Ipv4Header.read`](struct.Ipv4Header.html#method.read) & [`Ipv4Header.read_from_slice`](struct.Ipv4Header.html#method.read_from_slice)
//! * [`Ipv6Header.read`](struct.Ipv6Header.html#method.read) & [`Ipv6Header.read_from_slice`](struct.Ipv6Header.html#method.read_from_slice)
//! * [`UdpHeader.read`](struct.UdpHeader.html#method.read) & [`UdpHeader.read_from_slice`](struct.UdpHeader.html#method.read_from_slice)
//! * [`TcpHeader.read`](struct.TcpHeader.html#method.read) & [`TcpHeader.read_from_slice`](struct.TcpHeader.html#method.read_from_slice)
//! 
//! # How to generate fake packet data?
//! ## Packet Builder
//! The PacketBuilder struct provides a high level interface for quickly creating network packets. The PacketBuilder will automatically set fields which can be deduced from the content and compositions of the packet itself (e.g. checksums, lengths, ethertype, ip protocol number).
//! 
//! [Example:](https://github.com/JulianSchmid/etherparse/blob/0.8.0/examples/write_udp.rs)
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
//! There is also an [example for TCP packets](https://github.com/JulianSchmid/etherparse/blob/0.8.0/examples/write_tcp.rs) available.
//! 
//! Check out the [PacketBuilder documentation](struct.PacketBuilder.html) for more informations.
//! 
//! ## Manually serialising each header
//! Alternativly it is possible to manually build a packet ([example](https://github.com/JulianSchmid/etherparse/blob/0.8.0/examples/write_ipv4_udp.rs)). Generally each struct representing a header has a "write" method that allows it to be serialized. These write methods sometimes automatically calculate checksums and fill them in. In case this is unwanted behavior (e.g. if you want to generate a packet with an invalid checksum), it is also possible to call a "write_raw" method that will simply serialize the data without doing checksum calculations.
//! 
//! Read the documentations of the different methods for a more details:
//! 
//! * [`Ethernet2Header.write`](struct.Ethernet2Header.html#method.write)
//! * [`SingleVlanHeader.write`](struct.SingleVlanHeader.html#method.write)
//! * [`DoubleVlanHeader.write`](struct.DoubleVlanHeader.html#method.write)
//! * [`Ipv4Header.write`](struct.Ipv4Header.html#method.write)
//! * [`Ipv4Header.write_raw`](struct.Ipv4Header.html#method.write_raw)
//! * [`Ipv6Header.write`](struct.Ipv6Header.html#method.write)
//! * [`UdpHeader.write`](struct.UdpHeader.html#method.write)
//! * [`TcpHeader.write`](struct.TcpHeader.html#method.write)
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

use std::io;
use std::fmt;
use std::error::Error;

mod link;
pub use crate::link::ethernet::*;
pub use crate::link::vlan_tagging::*;

mod internet;
pub use crate::internet::ip::*;
pub use crate::internet::ip_authentication::*;
pub use crate::internet::ipv4::*;
pub use crate::internet::ipv4_extensions::*;
pub use crate::internet::ipv6::*;
pub use crate::internet::ipv6_extensions::*;
pub use crate::internet::ipv6_generic_extension::*;
pub use crate::internet::ipv6_fragment::*;

mod transport;
pub use crate::transport::tcp::*;
pub use crate::transport::udp::*;
pub use crate::transport::TransportHeader;

mod packet_builder;
pub use crate::packet_builder::*;

mod packet_decoder;
pub use crate::packet_decoder::*;

mod packet_slicing;
pub use crate::packet_slicing::*;

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
pub mod packet_filter;

///Contains the size when serialized.
pub trait SerializedSize {
    const SERIALIZED_SIZE: usize;
}

///Errors that can occur when reading.
#[derive(Debug)]
pub enum ReadError {
    ///Whenever an std::io::Error gets triggerd during a write it gets forwarded via this enum value.
    IoError(std::io::Error),
    ///Error when an unexpected end of a slice was reached even though more data was expected to be present (expected minimum size as argument).
    UnexpectedEndOfSlice(usize),
    ///Error when a double vlan tag was expected but the ether type of the the first vlan header does not an vlan header ether type.
    ///The value is the unexpected ether type value in the outer vlan header.
    DoubleVlanOuterNonVlanEtherType(u16),
    ///Error when the ip header version is not supported (only 4 & 6 are supported). The value is the version that was received.
    IpUnsupportedVersion(u8),
    ///Error when the ip header version field is not equal 4. The value is the version that was received.
    Ipv4UnexpectedVersion(u8),
    ///Error when the ipv4 header length is smaller then the header itself (5).
    Ipv4HeaderLengthBad(u8),
    ///Error when the total length field is too small to contain the header itself.
    Ipv4TotalLengthTooSmall(u16),
    ///Error when then ip header version field is not equal 6. The value is the version that was received.
    Ipv6UnexpectedVersion(u8),
    ///Error when more then 7 header extensions are present (according to RFC82000 this should never happen).
    Ipv6TooManyHeaderExtensions,
    ///Error if the ipv6 hop by hop header does not occur directly after the ipv6 header (see rfc8200 chapter 4.1.)
    Ipv6HopByHopHeaderNotAtStart,
    ///Error if the header length in the ip authentication header is smaller then the minimum size of 1.
    IpAuthenticationHeaderTooSmallPayloadLength(u8),
    ///Error given if the data_offset field in a TCP header is smaller then the minimum size of the tcp header itself.
    TcpDataOffsetTooSmall(u8),
}

impl ReadError {
    ///Adds an offset value to the UnexpectedEndOfSlice error.
    pub fn add_slice_offset(self, offset: usize) -> ReadError {
        use crate::ReadError::*;
        match self {
            UnexpectedEndOfSlice(value) => UnexpectedEndOfSlice(value + offset),
            value => value
        }
    }

    /// Returns the `std::io::Error` value if the `ReadError` is an `IoError`.
    /// Otherwise `None is returned.
    pub fn io_error(self) -> Option<std::io::Error> {
        match self {
            ReadError::IoError(value) => Some(value),
            _ => None
        }
    }
    /// Returns the expected minimum size if the error is an `UnexpectedEndOfSlice`.
    pub fn unexpected_end_of_slice_min_expected_size(self) -> Option<usize> {
        match self {
            ReadError::UnexpectedEndOfSlice(value) => Some(value),
            _ => None
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ReadError::*;

        match self {
            IoError(err) => err.fmt(f),
            UnexpectedEndOfSlice(expected_minimum_size) => { // usize
                write!(f, "ReadError: Unexpected end of slice. The given slice contained less then minimum required {} bytes.", expected_minimum_size)
            },
            DoubleVlanOuterNonVlanEtherType(ether_type) => { //u16
                write!(f, "ReadError: Expected a double vlan header, but the ether type field value {} of the outer vlan header is a non vlan header ether type.", ether_type)
            },
            IpUnsupportedVersion(version_number) => { // u8
                write!(f, "ReadError: Unsupported IP version number. The IP header contained the unsupported version number {}.", version_number)
            },
            Ipv4UnexpectedVersion(version_number) => { //u8
                write!(f, "ReadError: Unexpected IP version number. Expected an IPv4 Header but the header contained the version number {}.", version_number)
            },
            Ipv4HeaderLengthBad(header_length) => { //u8
                write!(f, "ReadError: Bad IPv4 header length. The header length value {} in the IPv4 header is smaller then the ipv4 header.", header_length)
            },
            Ipv4TotalLengthTooSmall(total_length_field) => { //u16
                write!(f, "ReadError: Bad IPv4 total length. The total length value {} in the IPv4 header is smaller then the ipv4 header itself.", total_length_field)
            },
            Ipv6UnexpectedVersion(version_number) => { //u8
                write!(f, "ReadError: Unexpected IP version number. Expected an IPv6 Header but the header contained the version number {}.", version_number)
            },
            Ipv6TooManyHeaderExtensions => {
                write!(f, "ReadError: Too many IPv6 header extensions. There are more then 7 extension headers present, this not supported.")
            },
            Ipv6HopByHopHeaderNotAtStart => {
                write!(f, "ReadError: Encountered an IPv6 hop-by-hop header somwhere else then directly after the IPv6 header. This is not allowed according to RFC 8200.")
            },
            IpAuthenticationHeaderTooSmallPayloadLength(length) => {
                write!(f, "ReadError: Authentication header payload size is smaller then 1 ({}) which is smaller then the minimum size of the header.", length)
            },
            TcpDataOffsetTooSmall(data_offset) => { //u8
                write!(f, "ReadError: TCP data offset too small. The data offset value {} in the tcp header is smaller then the tcp header itself.", data_offset)
            },
        }
    }
}

impl Error for ReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ReadError::IoError(ref err) => Some(err),
            _ => None
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
            _ => None
        }
    }
    /// Returns the `std::io::Error` value if the `WriteError` is an `ValueError`.
    /// Otherwise `None` is returned.
    pub fn value_error(self) -> Option<ValueError> {
        match self {
            WriteError::ValueError(value) => Some(value),
            _ => None
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

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use WriteError::*;
        match self {
            IoError(err) => err.fmt(f),
            ValueError(err) => {
                write!(f, "ValueError: {}", err)
            },
            SliceTooSmall(size) => {
                write!(f, "SliceTooSmall: The slice given to write to is too small (required to be at least {} bytes large)", size)
            }
        }
    }
}

impl Error for WriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use WriteError::*;
        match self {
            IoError(ref err) => Some(err),
            ValueError(ref err) => Some(err),
            SliceTooSmall(_) => None
        }
    }
}

///Errors in the given data
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValueError {
    ///Error when the ipv4 options length is too big or not aligned (cannot be bigger then 40 bytes and must be a multiple of 4 bytes).
    Ipv4OptionsLengthBad(usize),
    ///Error when a given payload & ipv4 header is bigger then what fits inside an ipv4 total_length field.
    Ipv4PayloadLengthTooLarge(usize),
    ///Error when a given payload & ipv6 header block is bigger then what fits inside an ipv6 payload_length field.
    Ipv6PayloadLengthTooLarge(usize),
    ///Error when a given payload size is smaller then 6 octets which is the minimum ipv6 extended header size (`Ipv6GenericExtensionHeader::MAX_PAYLOAD_LEN`).
    Ipv6ExtensionPayloadTooSmall(usize),
    ///Error when a given payload size is bigger then what fits inside an ipv6 extended header size (`Ipv6GenericExtensionHeader::MAX_PAYLOAD_LEN`).
    Ipv6ExtensionPayloadTooLarge(usize),
    ///Error when a given payload length is not aligned to be a multiple of 8 octets when 6 is substracted and can not be represented by the header length field.
    Ipv6ExtensionPayloadLengthUnaligned(usize),
    ///Error when a given authentication header icv size is not a multiple of 4 bytes or bigger then 1016 bytes and therefor can not be represented in the header length field.
    IpAuthenticationHeaderBadIcvLength(usize),
    ///Error when a header in `Ipv4Extensions` is never written as it is never referenced by any of the other `next_header` fields or the initial `protocol`.
    Ipv4ExtensionNotReferenced(IpNumber),
    ///Error when a hop-by-hop header is not referenced as the first header after the ipv6 header but as a later extension header.
    Ipv6ExtensionHopByHopNotAtStart,
    ///Error when a header in `Ipv6Extensions` is never written as it is never referenced by any of the other `next_header` fields or the initial ip number.
    Ipv6ExtensionNotReferenced(IpNumber),
    ///Error when a header in `Ipv6Extensions` is referenced multiple times or is referenced and not defined.
    Ipv6ExtensionNotDefinedReference(IpNumber),
    ///Error when a given payload is bigger then what fits inside an udp packet
    ///Note that a the maximum payload size, as far as udp is conceirned, is max_value(u16) - 8. The 8 is for the size of the udp header itself.
    UdpPayloadLengthTooLarge(usize),
    ///Error when a given payload + tcp header options is bigger then what fits inside an tcp packet
    ///Note that a the maximum size, as far as tcp is conceirned, is max_value(u16) - tcp_header.data_offset()*4. The data_offset is for the size of the udp header itself.
    TcpLengthTooLarge(usize),
    ///Error when a u8 field in a header has a larger value then supported.
    U8TooLarge{value: u8, max: u8, field: ErrorField},
    ///Error when a u16 field in a header has a larger value then supported.
    U16TooLarge{value: u16, max: u16, field: ErrorField},
    ///Error when a u32 field in a header has a larger value then supported.
    U32TooLarge{value: u32, max: u32, field: ErrorField}
}

impl Error for ValueError {

}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ValueError::*;
        match self {
            Ipv4OptionsLengthBad(options_len) => { //usize
                write!(f, "Bad IPv4 'options_len'. The IPv4 options length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 40 bytes.", options_len)
            },
            Ipv4PayloadLengthTooLarge(total_length) => { //usize
                write!(f, "IPv4 'total_legnth' too large. The IPv4 header and payload have a larger size ({} bytes) than can be be represented by the 'total_legnth' field in the IPv4 header.", total_length)
            },
            Ipv6PayloadLengthTooLarge(size) => { //usize
                write!(f, "IPv6 'payload_length' too large. The IPv6 header block & payload size ({} bytes) is larger then what can be be represented by the 'payload_length' field in the IPv6 header.", size)
            },
            Ipv6ExtensionPayloadTooSmall(size) => {
                write!(f, "IPv6 extensions header payload length is too small. The payload size ({} bytes) is less then 6 octets which is the minimum IPv6 extension header payload size.", size)
            },
            Ipv6ExtensionPayloadTooLarge(size) => {
                write!(f, "IPv6 extensions header payload length is too large. The payload size ({} bytes) is larger then what can be be represented by the 'extended header size' field in an IPv6 extension header.", size)
            },
            Ipv6ExtensionPayloadLengthUnaligned(size) => {
                write!(f, "IPv6 extensions header 'payload length ({} bytes) + 2' is not multiple of 8 (+ 2 for the `next_header` and `header_length` fields). This is required as the header length field can only express lengths in multiple of 8 bytes.", size)
            },
            IpAuthenticationHeaderBadIcvLength(size) => {
                write!(f, "IP authentication header 'raw_icv' value has a length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 1016 bytes.", size)
            },
            Ipv4ExtensionNotReferenced(ip_protocol_number) => {
                write!(f, "IPv4 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the 'protocol' field of the IPv4 header.", ip_protocol_number)
            }
            Ipv6ExtensionHopByHopNotAtStart => {
                write!(f, "IPv6 extensions hop-by-hop is not located directly after the IPv6 header (required by IPv6).")
            },
            Ipv6ExtensionNotReferenced(ip_protocol_number) => {
                write!(f, "IPv6 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the IPv6 header.", ip_protocol_number)
            },
            Ipv6ExtensionNotDefinedReference(ip_protocol_number) => {
                write!(f, "IPv6 extensions '{:?}' is referenced by the 'next_header' field of an extension headers or the IPv6 header but is not defined in the 'Ipv6Extensions'.", ip_protocol_number)
            },
            UdpPayloadLengthTooLarge(length) => { //usize
                write!(f, "UDP 'length' too large. The UDP length ({} bytes) is larger then what can be be represented by the 'length' field in the UDP header.", length)
            }, 
            TcpLengthTooLarge(length) => {  //usize
                write!(f, "TCP length too large. The TCP packet length ({} bytes) is larger then what is supported.", length)
            },
            U8TooLarge{value, max, field} => {
                write!(f, "The value {} of the field '{}' is larger then the allowed maximum of {}.", value, field, max)
            },
            U16TooLarge{value, max, field} => {
                write!(f, "The value {} of the field '{}' is larger then the allowed maximum of {}.", value, field, max)
            },
            U32TooLarge{value, max, field} => {
                write!(f, "The value {} of the field '{}' is larger then the allowed maximum of {}.", value, field, max)
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

impl fmt::Display for ErrorField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ErrorField::*;
        match self {
            Ipv4PayloadLength => write!(f, "Ipv4Header.payload_len"),
            Ipv4Dscp => write!(f, "Ipv4Header.differentiated_services_code_point"),
            Ipv4Ecn => write!(f, "Ipv4Header.explicit_congestion_notification"),
            Ipv4FragmentsOffset => write!(f, "Ipv4Header.fragments_offset"),
            Ipv6FlowLabel => write!(f, "Ipv6Header.flow_label"),
            Ipv6FragmentOffset => write!(f, "Ipv6FragmentHeader.fragment_offset"),
            VlanTagPriorityCodePoint => write!(f, "SingleVlanHeader.priority_code_point"),
            VlanTagVlanId => write!(f, "SingleVlanHeader.vlan_identifier")
        }
    }
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

//NOTE: Replace this with std::Iterator::step_by as soon as it is in stable (see https://github.com/rust-lang/rust/issues/27741)
struct RangeStep {
    start: usize,
    end: usize,
    step: usize 
}

impl RangeStep {
    fn new(start: usize, end: usize, step: usize) -> RangeStep {
        RangeStep {
            start,
            end,
            step 
        }
    }
}

impl Iterator for RangeStep {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        if self.start < self.end {
            let result = self.start;
            self.start = result + self.step;
            Some(result)
        } else {
            None
        }
    }
}