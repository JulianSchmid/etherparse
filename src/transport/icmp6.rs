use super::super::*;

use crate::transport::icmp4;

use std::slice::from_raw_parts;

/// Module containing ICMPv6 related constants
pub mod icmpv6 {

    /// ICMPv6 type value indicating a "Destination Unreachable" message.
    pub const TYPE_DST_UNREACH: u8 = 1;

    /// ICMPv6 type value indicating a "Packet Too Big" message.
    pub const TYPE_PACKET_TOO_BIG: u8 = 2;

    /// ICMPv6 type value indicating a "Time Exceeded" message.
    pub const TYPE_TIME_EXCEEDED: u8 = 3;

    /// ICMPv6 type value indicating a "Parameter Problem" message.
    pub const TYPE_PARAM_PROB: u8 = 4;

    /// ICMPv6 type value indicating an "Echo Request" message.
    pub const TYPE_ECHO_REQUEST: u8 = 128;

    /// ICMPv6 type value indicating an "Echo Reply" message.
    pub const TYPE_ECHO_REPLY: u8 = 129;

    /// ICMPv6 type value indicating a "Multicast Listener Query" message.
    pub const TYPE_MULTICAST_LISTENER_QUERY: u8 = 130;

    /// ICMPv6 type value indicating a "Multicast Listener Report" message.
    pub const TYPE_MULTICAST_LISTENER_REPORT: u8 = 131;

    /// ICMPv6 type value indicating a "Multicast Listener Done" message.
    pub const TYPE_MULTICAST_LISTENER_REDUCTION: u8 = 132;

    /// ICMPv6 type value indicating a "Router Solicitation" message.
    pub const TYPE_ROUTER_SOLICITATION: u8 = 133;

    /// ICMPv6 type value indicating a "Router Advertisement" message.
    pub const TYPE_ROUTER_ADVERTISEMENT: u8 = 134;

    /// ICMPv6 type value indicating a "Neighbor Solicitation" message.
    pub const TYPE_NEIGHBOR_SOLICITATION: u8 = 135;

    /// ICMPv6 type value indicating a "Neighbor Advertisement" message.
    pub const TYPE_NEIGHBOR_ADVERTISEMENT: u8 = 136;

    /// ICMPv6 type value indicating a "Redirect Message" message.
    pub const TYPE_REDIRECT_MESSAGE: u8 = 137;

    /// ICMPv6 type value indicating a "Router Renumbering" message.
    pub const TYPE_ROUTER_RENUMBERING: u8 = 138;

    /// ICMPv6 type value indicating a "Inverse Neighbor Discovery Solicitation" message.
    pub const TYPE_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION: u8 = 141;

    /// ICMPv6 type value indicating a "Inverse Neighbor Discovery Advertisement" message.
    pub const TYPE_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT: u8 = 142;

    /// ICMPv6 type value indicating a "" message.
    pub const TYPE_EXT_ECHO_REQUEST: u8 = 160;

    /// ICMPv6 type value indicating a "" message.
    pub const TYPE_EXT_ECHO_REPLY: u8 = 161;

    /// ICMPv6 destination unreachable code for "no route to destination".
    pub const CODE_DST_UNREACH_NOROUTE: u8 = 0;

    /// ICMPv6 destination unreachable code for "communication
    /// with destination administratively prohibited".
    pub const CODE_DST_UNREACH_PROHIBITED: u8 = 1;

    /// ICMPv6 destination unreachable code for "beyond scope
    /// of source address".
    pub const CODE_DST_UNREACH_BEYONDSCOPE: u8 = 2;

    /// ICMPv6 destination unreachable code for "address unreachable".
    pub const CODE_DST_UNREACH_ADDR: u8 = 3;

    /// ICMPv6 destination unreachable code for "port unreachable".
    pub const CODE_DST_UNREACH_PORT: u8 = 4;
}

use icmpv6::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmp6DestinationUnreachable {
    Unknown{code:u8}, // unparsed
    NoRoute,
    Admin,
    BeyondScope,
    Address,
    NoPort,
}

impl Icmp6DestinationUnreachable {
    pub fn from(icmp_code: u8) -> Icmp6DestinationUnreachable {
        use Icmp6DestinationUnreachable::*;
        match icmp_code {
            CODE_DST_UNREACH_NOROUTE => NoRoute,
            CODE_DST_UNREACH_PROHIBITED => Admin,
            CODE_DST_UNREACH_BEYONDSCOPE => BeyondScope,
            CODE_DST_UNREACH_ADDR => Address,
            CODE_DST_UNREACH_PORT => NoPort,
            _ => Unknown{code: icmp_code},
        }
    }

    /// Returns the code value of the destination unreachable
    pub fn code(&self) -> u8 {
        use Icmp6DestinationUnreachable::*;
        match self {
            Unknown{code} => *code,
            NoRoute => CODE_DST_UNREACH_NOROUTE,
            Admin => CODE_DST_UNREACH_PROHIBITED,
            BeyondScope => CODE_DST_UNREACH_BEYONDSCOPE,
            Address => CODE_DST_UNREACH_ADDR,
            NoPort => CODE_DST_UNREACH_PORT,
        }
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmp6Type {
    Raw{icmp_type: u8, icmp_code: u8, four_bytes: [u8;4]},
    DestinationUnreachable(Icmp6DestinationUnreachable),
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest(icmp4::IcmpEchoHeader),
    EchoReply(icmp4::IcmpEchoHeader),
    // implement the rest later
}

impl Icmp6Type {
    // could just use 'num-derive' package, but this lib has no deps, so keeping
    // with that tradition; see https://enodev.fr/posts/rusticity-convert-an-integer-to-an-enum.html
    fn from(icmp_type: u8, icmp_code: u8, four_bytes: [u8;4]) -> Icmp6Type {
        use Icmp6Type::*;
        match icmp_type {
            TYPE_DST_UNREACH => 
                DestinationUnreachable(Icmp6DestinationUnreachable::from(icmp_code)),
            TYPE_PACKET_TOO_BIG => PacketTooBig,
            TYPE_TIME_EXCEEDED => TimeExceeded,
            TYPE_PARAM_PROB => ParameterProblem,
            TYPE_ECHO_REQUEST => EchoRequest(IcmpEchoHeader::from(four_bytes)),
            TYPE_ECHO_REPLY => EchoReply(IcmpEchoHeader::from(four_bytes)),
            _ => Raw{icmp_type, icmp_code, four_bytes},
        }
    }

    fn to_bytes(&self) -> (u8, u8, [u8;4]) {
        use Icmp6Type::*;
        match self {
            Raw{icmp_type, icmp_code, four_bytes} => (*icmp_type, *icmp_code, *four_bytes),
            DestinationUnreachable(icmp_code) => 
            (TYPE_DST_UNREACH, (icmp_code.code()), [0;4]),
            PacketTooBig => (TYPE_PACKET_TOO_BIG, 0, [0;4]),
            TimeExceeded => (TYPE_TIME_EXCEEDED, 0, [0;4]),
            ParameterProblem => (TYPE_PARAM_PROB, 0, [0;4]),
            EchoRequest(echo) => (TYPE_ECHO_REQUEST, 0, echo.to_bytes()),
            EchoReply(echo) => (TYPE_ECHO_REPLY, 0, echo.to_bytes()),
        }
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6Header {
    pub icmp_type: Icmp6Type,
    pub icmp_chksum: u16,
}

impl Icmp6Header {
    pub const SERIALIZED_SIZE: usize = 8;
    pub fn header_len(&self) -> usize {
        8
    }

    pub fn new(icmp_type: Icmp6Type) -> Icmp6Header {
        Icmp6Header{
            icmp_type,
            icmp_chksum: 0, // will be filled in later
        }
    }

    ///Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        let cksum_be = self.icmp_chksum.to_be_bytes();
        let (icmp_type, icmp_code, four_bytes) = self.icmp_type.to_bytes();
        writer.write_all(&[
            icmp_type,
            icmp_code,
            cksum_be[0],
            cksum_be[1],
            four_bytes[0],
            four_bytes[1],
            four_bytes[2],
            four_bytes[3],
        ]).map_err(WriteError::from)
    }

    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u32::MAX as usize) - Icmp4Header::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::Ipv6PayloadLengthTooLarge(payload.len()));
        }

        let (icmp_type, icmp_code, four_bytes) = self.icmp_type.to_bytes();
        let msg_len = payload.len() + Icmp6Header::SERIALIZED_SIZE;
        //calculate the checksum; icmp4 will always take an ip4 header
        Ok(
                // NOTE: rfc4443 section 2.3 - Icmp6 *does* use a pseudoheader, 
                // unlike Icmp4
                checksum::Sum16BitWords::new()
                .add_16bytes(ip_header.source)
                .add_16bytes(ip_header.destination)
                .add_2bytes([0, ip_number::IPV6_ICMP])
                .add_2bytes((msg_len as u16).to_be_bytes())
                .add_2bytes([icmp_type, icmp_code])
                .add_4bytes(four_bytes)
                .add_slice(payload)
                .ones_complement()
                .to_be()
        )
    }

    /// Reads an icmp6 header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Icmp6Header, &[u8]), ReadError> {
        Ok((
            Icmp6HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Icmp6Header::SERIALIZED_SIZE..]
        ))
    }
}

///A slice containing an icmp6 header of a network package. Struct allows the selective read of fields in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icmp6HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Icmp6HeaderSlice<'a> {
    /// Creates a slice containing an icmp6 header.
    #[inline]
    pub fn from_slice(slice: &'a[u8]) -> Result<Icmp6HeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < Icmp6Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Icmp6Header::SERIALIZED_SIZE));
        }

        //done
        Ok(Icmp6HeaderSlice{
            // SAFETY:
            // Safe as slice length is checked to be at least
            // Icmp6Header::SERIALIZED_SIZE (8) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    Icmp6Header::SERIALIZED_SIZE
                )
            }
        })
    }
    /// Decode all the fields and copy the results to a UdpHeader struct
    #[inline]
    pub fn to_header(&self) -> Icmp6Header {
        Icmp6Header {
            icmp_type: self.icmp_type(),
            icmp_chksum: self.icmp_chksum(),
        }
    }

    pub fn icmp_type(&self) -> Icmp6Type {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmp6Header::SERIALIZED_SIZE (8).
        unsafe {
            Icmp6Type::from(
                *self.slice.get_unchecked(0),
                *self.slice.get_unchecked(1),
                [
                    *self.slice.get_unchecked(4),
                    *self.slice.get_unchecked(5),
                    *self.slice.get_unchecked(6),
                    *self.slice.get_unchecked(7),
                ]
            )
        }
    }

    #[inline]
    pub fn icmp_code(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmp6Header::SERIALIZED_SIZE (8).
        unsafe {
            *self.slice.get_unchecked(0)
        }
    }

    #[inline]
    pub fn icmp_chksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    /// Returns the slice containing the icmp6 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}