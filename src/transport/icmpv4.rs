use std::slice::from_raw_parts;
use super::super::*;

/// Module containing ICMPv4 related types and constants
pub mod icmpv4 {

    /// ICMP destination unreachable code for "Net Unreachable" (from [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_NET: u8 = 0;

    /// ICMP destination unreachable code for "Host Unreachable" (from [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_HOST: u8 = 1;

    /// ICMP destination unreachable code for "Protocol Unreachable" (from [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_PROTOCOL: u8 = 2;

    /// ICMP destination unreachable code for "Port Unreachable" (from [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_PORT: u8 = 3;

    /// ICMP destination unreachable code for "Fragmentation Needed and Don't Fragment was Set" (from [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_NEEDFRAG: u8 = 4;

    /// ICMP destination unreachable code for "Source Route Failed" (from [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_SRCFAIL: u8 = 5;

    /// ICMP destination unreachable code for "Destination Network Unknown" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_NET_UNKNOWN: u8 =  6;

    /// ICMP destination unreachable code for "Destination Host Unknown" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_HOST_UNKNOWN: u8 = 7;

    /// ICMP destination unreachable code for "Source Host Isolated" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_ISOLATED: u8 = 8;

    /// ICMP destination unreachable code for "Communication with Destination Network is Administratively Prohibited" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_NET_PROHIB: u8 = 9;

    /// ICMP destination unreachable code for "Communication with Destination Host is Administratively Prohibited" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_HOST_PROHIB: u8 = 10;

    /// ICMP destination unreachable code for "Destination Network Unreachable for Type of Service" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_TOSNET: u8 = 11;

    /// ICMP destination unreachable code for "Destination Host Unreachable for Type of Service" (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_TOSHOST: u8 = 12;

    /// ICMP destination unreachable code for "Communication Administratively Prohibited" (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
    pub const CODE_DST_UNREACH_FILTER_PROHIB: u8 = 13;

    /// ICMP destination unreachable code for "Host Precedence Violation" (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
    pub const CODE_DST_UNREACH_HOST_PRECEDENCE: u8 = 14;

    /// ICMP destination unreachable code for "Precedence cutoff in effect" (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
    pub const CODE_DST_UNREACH_PRECEDENCE_CUTOFF: u8 = 15;

    /// "Destination Unreachable" ICMP header for IPv4 (without the invoking packet).
    ///
    /// # Description in RFC 792:
    ///
    /// If, according to the information in the gateway's routing tables,
    /// the network specified in the internet destination field of a
    /// datagram is unreachable, e.g., the distance to the network is
    /// infinity, the gateway may send a destination unreachable message
    /// to the internet source host of the datagram.  In addition, in some
    /// networks, the gateway may be able to determine if the internet
    /// destination host is unreachable.  Gateways in these networks may
    /// send destination unreachable messages to the source host when the
    /// destination host is unreachable.
    ///
    /// If, in the destination host, the IP module cannot deliver the
    /// datagram  because the indicated protocol module or process port is
    /// not active, the destination host may send a destination
    /// unreachable message to the source host.
    ///
    /// Another case is when a datagram must be fragmented to be forwarded
    /// by a gateway yet the Don't Fragment flag is on.  In this case the
    /// gateway must discard the datagram and may return a destination
    /// unreachable message.
    ///
    /// Codes 0, 1, 4, and 5 may be received from a gateway.  Codes 2 and
    /// 3 may be received from a host.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum DestUnreachableHeader {
        /// In case of an unknown icmp code is received the header elements are stored raw.
        Raw{
            /// ICMP code (present in the 2nd byte of the ICMP packet).
            code: u8,
            /// Bytes located at th 5th, 6th, 7th and 8th position of the ICMP packet.
            bytes5to8: [u8;4],
        },
        /// Network unreachable error.
        Network,
        /// Host unreachable error.
        Host,
        /// Transport protocol not supported error.
        Protocol,
        /// Port unreachable error.
        Port,
        /// Fragmentation would be needed but the don't fragment bit is set.
        FragmentationNeeded{ next_hop_mtu: u16 },
        /// Source Route Failed
        SourceFail,
        /// Destination Network Unknown (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        NetworkUnknown,
        /// Destination Host Unknown (no route to host known) (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        HostUnknown,
        /// Source Host Isolated - obsolete (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        Isolated,
        /// Communication with Destination Network is Administratively Prohibited (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        NetworkProhibited,
        /// Communication with Destination Host is Administratively Prohibited (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        HostProhibitive,
        /// Destination Network Unreachable for Type of Service (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        TosNetwork,
        /// Destination Host Unreachable for Type of Service (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        TosHost,
        /// Cannot forward because packet administratively filtered (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
        FilterProhibited,
        /// Required level of precidence not supported (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
        HostPrecidence,
        /// Packet was below minimum precidence (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
        PrecedenceCutoff,
    }

    impl DestUnreachableHeader {

        /// Decode destination unreachable icmp packet from the code (2nd byte)
        /// and the 5th-8th bytes (inclusive) of the raw packet data.
        #[inline]
        pub fn from_bytes(code: u8, bytes5to8: [u8;4]) -> DestUnreachableHeader {
            use DestUnreachableHeader::*;

            match code {
                CODE_DST_UNREACH_NET => Network,
                CODE_DST_UNREACH_HOST => Host,
                CODE_DST_UNREACH_PROTOCOL => Protocol,
                CODE_DST_UNREACH_PORT => Port,
                CODE_DST_UNREACH_NEEDFRAG => FragmentationNeeded {
                    next_hop_mtu: u16::from_be_bytes([bytes5to8[2], bytes5to8[3]]),
                },
                CODE_DST_UNREACH_SRCFAIL => SourceFail,
                CODE_DST_UNREACH_NET_UNKNOWN => NetworkUnknown,
                CODE_DST_UNREACH_HOST_UNKNOWN => HostUnknown,
                CODE_DST_UNREACH_ISOLATED => Isolated,
                CODE_DST_UNREACH_NET_PROHIB => NetworkProhibited,
                CODE_DST_UNREACH_HOST_PROHIB => HostProhibitive,
                CODE_DST_UNREACH_TOSNET => TosNetwork,
                CODE_DST_UNREACH_TOSHOST => TosHost,
                CODE_DST_UNREACH_FILTER_PROHIB => FilterProhibited,
                CODE_DST_UNREACH_HOST_PRECEDENCE => HostPrecidence,
                CODE_DST_UNREACH_PRECEDENCE_CUTOFF => PrecedenceCutoff,
                // default to Raw
                code => Raw{
                    code,
                    bytes5to8
                },
            }
        }

        /// Returns the icmp code value of the destination unreachable packet.
        #[inline]
        pub fn code(&self) -> u8 {
            use DestUnreachableHeader::*;
            match self {
                Raw{ code, bytes5to8: _ } => *code,
                Network => CODE_DST_UNREACH_NET,
                Host => CODE_DST_UNREACH_HOST,
                Protocol => CODE_DST_UNREACH_PROTOCOL,
                Port => CODE_DST_UNREACH_PORT,
                FragmentationNeeded{ next_hop_mtu: _} => CODE_DST_UNREACH_NEEDFRAG,
                SourceFail => CODE_DST_UNREACH_SRCFAIL,
                NetworkUnknown => CODE_DST_UNREACH_NET_UNKNOWN,
                HostUnknown => CODE_DST_UNREACH_HOST_UNKNOWN,
                Isolated => CODE_DST_UNREACH_ISOLATED,
                NetworkProhibited => CODE_DST_UNREACH_NET_PROHIB,
                HostProhibitive => CODE_DST_UNREACH_HOST_PROHIB,
                TosNetwork => CODE_DST_UNREACH_TOSNET,
                TosHost => CODE_DST_UNREACH_TOSHOST,
                FilterProhibited => CODE_DST_UNREACH_FILTER_PROHIB,
                HostPrecidence => CODE_DST_UNREACH_HOST_PRECEDENCE,
                PrecedenceCutoff => CODE_DST_UNREACH_PRECEDENCE_CUTOFF,
            }
        }

        /// Returns the 5th-8th bytes (inclusive) of the raw icmp packet data
        pub fn bytes5to8(&self) -> [u8;4] {
            use DestUnreachableHeader::*;

            match self {
                Raw{ code: _, bytes5to8 } => *bytes5to8,
                Network | Host | Protocol | Port => [0;4],
                FragmentationNeeded{ next_hop_mtu } => {
                    let be = next_hop_mtu.to_be_bytes();
                    [0, 0, be[0], be[1]]
                },
                SourceFail | NetworkUnknown | HostUnknown |
                Isolated | NetworkProhibited | HostProhibitive |
                TosNetwork | TosHost | FilterProhibited |
                HostPrecidence | PrecedenceCutoff => [0;4],
            }
        }
    }

} // mod icmpv4

use icmpv4::*;

// for simplicity + muscle memory, pattern against libc consts
pub const ICMP_V4_ECHOREPLY: u8 =       0; /* Echo Reply                   */
pub const ICMP_V4_DEST_UNREACH: u8 =    3; /* Destination Unreachable      */
pub const ICMP_V4_SOURCE_QUENCH: u8 =   4; /* Source Quench                */
pub const ICMP_V4_REDIRECT: u8 =        5; /* Redirect (change route)      */
pub const ICMP_V4_ECHO: u8 =            8; /* Echo Request                 */
pub const ICMP_V4_TIME_EXCEEDED: u8 =  11; /* Time Exceeded                */
pub const ICMP_V4_PARAMETERPROB: u8 =  12; /* Parameter Problem            */
pub const ICMP_V4_TIMESTAMP: u8 =      13; /* Timestamp Request            */
pub const ICMP_V4_TIMESTAMPREPLY: u8 = 14; /* Timestamp Reply              */
pub const ICMP_V4_INFO_REQUEST: u8 =   15; /* Information Request          */
pub const ICMP_V4_INFO_REPLY: u8 =     16; /* Information Reply            */
pub const ICMP_V4_ADDRESS: u8 =        17; /* Address Mask Request         */
pub const ICMP_V4_ADDRESSREPLY: u8 =   18; /* Address Mask Reply           */

/// Starting contents of an ICMPv4 packet without the checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icmp4Type {
    /// Used to encode unparsed/unknown ICMP headers
    Raw{icmp_type: u8, icmp_code: u8, bytes5to8: [u8;4] },
    EchoReply(IcmpEchoHeader),
    DestinationUnreachable(icmpv4::DestUnreachableHeader),
    SourceQuench,
    Redirect,
    EchoRequest(IcmpEchoHeader),
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    InfoRequest,
    InfoReply,
    AddressRequest,
    AddressReply,
}

impl Icmp4Type {
    // could just use 'num-derive' package, but this lib has no deps, so keeping
    // with that tradition; see https://enodev.fr/posts/rusticity-convert-an-integer-to-an-enum.html
    pub fn from(icmp_type: u8, icmp_code: u8, bytes5to8: [u8;4]) -> Icmp4Type {
        use Icmp4Type::*;
        match icmp_type {
            ICMP_V4_ECHOREPLY => EchoReply(IcmpEchoHeader::from_bytes(bytes5to8)),
            ICMP_V4_DEST_UNREACH => DestinationUnreachable(DestUnreachableHeader::from_bytes(icmp_code, bytes5to8)),
            ICMP_V4_SOURCE_QUENCH => SourceQuench,
            ICMP_V4_REDIRECT => Redirect,
            ICMP_V4_ECHO=> EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8)),
            ICMP_V4_TIME_EXCEEDED => TimeExceeded,
            ICMP_V4_PARAMETERPROB => ParameterProblem,
            ICMP_V4_TIMESTAMP => TimestampRequest,
            ICMP_V4_TIMESTAMPREPLY => TimestampReply,
            ICMP_V4_INFO_REQUEST => InfoRequest,
            ICMP_V4_INFO_REPLY => InfoReply,
            ICMP_V4_ADDRESS => AddressRequest,
            ICMP_V4_ADDRESSREPLY => AddressReply,
            // unknown/unparsed type - just return as Raw
            _ => Raw{icmp_type, icmp_code, bytes5to8}
        }
    }

    /// Return the icmp_type, icmp_code, and the second 4 bytes
    /// of the ICMP payload.
    pub fn to_bytes(&self) -> (u8, u8, [u8;4]) {
        use Icmp4Type::*;
        match &self {
            Raw{icmp_type, icmp_code, bytes5to8} => (*icmp_type, *icmp_code, *bytes5to8),
            EchoReply(echo) => {
                (ICMP_V4_ECHOREPLY, 0, echo.to_bytes())
            },
            DestinationUnreachable(value) => (ICMP_V4_DEST_UNREACH, value.code(), value.bytes5to8()),
            SourceQuench => (ICMP_V4_SOURCE_QUENCH, 0, [0;4]),
            Redirect => (ICMP_V4_REDIRECT, 0, [0;4]),
            EchoRequest(echo) => {
                (ICMP_V4_ECHO, 0, echo.to_bytes())
            },
            TimeExceeded => (ICMP_V4_TIME_EXCEEDED, 0, [0;4]),
            ParameterProblem => (ICMP_V4_PARAMETERPROB, 0, [0;4]),
            TimestampRequest => (ICMP_V4_TIMESTAMP, 0, [0;4]),
            TimestampReply => (ICMP_V4_TIMESTAMPREPLY, 0, [0;4]),
            InfoRequest => (ICMP_V4_INFO_REQUEST, 0, [0;4]),
            InfoReply => (ICMP_V4_INFO_REPLY, 0, [0;4]),
            AddressRequest => (ICMP_V4_ADDRESS, 0, [0;4]),
            AddressReply => (ICMP_V4_ADDRESSREPLY, 0, [0;4]),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp4Header {
    pub icmp_type: Icmp4Type,
    pub icmp_chksum : u16,
}

impl Icmp4Header {
    pub const SERIALIZED_SIZE: usize = 8;

    #[inline]
    pub fn header_len(&self) -> usize {
        Icmp4Header::SERIALIZED_SIZE
    }

    pub fn new(icmp_type: Icmp4Type) -> Icmp4Header {
        // Note: will calculate checksum on send
        Icmp4Header { icmp_type, icmp_chksum: 0 }
    }

    /// Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        let cksum_be = self.icmp_chksum.to_be_bytes();
        let (icmp_type, icmp_code, bytes5to8) = self.icmp_type.to_bytes();
        writer.write_all(&[
            icmp_type as u8,
            icmp_code,
            cksum_be[0],
            cksum_be[1],
            bytes5to8[0],
            bytes5to8[1],
            bytes5to8[2],
            bytes5to8[3],
        ]).map_err(WriteError::from)
    }

    pub fn calc_checksum_ipv4(&self, _ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError>{
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u32::MAX as usize) - Icmp4Header::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::Ipv4PayloadLengthTooLarge(payload.len()));
        }

        let (icmp_type, icmp_code, bytes5to8) = self.icmp_type.to_bytes();
        //calculate the checksum; icmp4 will always take an ip4 header
        Ok(
                checksum::Sum16BitWords::new()
                // NOTE: RFC792 - ICMP4 checksum does not use a pseudo-header
                // for the checksum; only the message itself
                .add_2bytes([icmp_type, icmp_code])
                .add_4bytes(bytes5to8)
                .add_slice(payload)
                .ones_complement()
                .to_be()
        )
    }

    /// Reads an icmp4 header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Icmp4Header, &[u8]), ReadError> {
        Ok((
            Icmp4HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Icmp4Header::SERIALIZED_SIZE..]
        ))
    }
}

///A slice containing an icmp4 header of a network package. Struct allows the selective read of fields in the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icmp4HeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> Icmp4HeaderSlice<'a> {
    /// Creates a slice containing an icmp4 header.
    #[inline]
    pub fn from_slice(slice: &'a[u8]) -> Result<Icmp4HeaderSlice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < Icmp4Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Icmp4Header::SERIALIZED_SIZE));
        }

        //done
        Ok(Icmp4HeaderSlice{
            // SAFETY:
            // Safe as slice length is checked to be at least
            // Icmp4Header::SERIALIZED_SIZE (8) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    Icmp4Header::SERIALIZED_SIZE
                )
            }
        })
    }


    /// Decode all the fields and copy the results to a Icmp4Header struct
    #[inline]
    pub fn to_header(&self) -> Icmp4Header  {
        let icmp_type = self.icmp_type();
        Icmp4Header {
            icmp_type,
            icmp_chksum: self.icmp_chksum(),
        }
    }

    pub fn icmp_type(&self) -> Icmp4Type  {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmp4Header::SERIALIZED_SIZE (8).
        unsafe {
            Icmp4Type::from(
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
        // at least the length of Icmp4Header::SERIALIZED_SIZE (8).
        unsafe {
            *self.slice.get_unchecked(1)
        }
    }

    #[inline]
    pub fn icmp_chksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmp4Header::SERIALIZED_SIZE (8).
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    /// Returns the slice containing the icmp4 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}