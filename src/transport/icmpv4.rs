use super::super::*;

use arrayvec::ArrayVec;
use std::slice::from_raw_parts;

/// Module containing ICMPv4 related types and constants
pub mod icmpv4 {

    /// ICMPv4 type value indicating a "Echo Reply" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_ECHO_REPLY: u8 = 0;

    /// ICMPv4 type value indicating a "Destination Unreachable" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_DEST_UNREACH: u8 = 3;

    /// ICMPv4 type value indicating a "Source Quench (Deprecated)" message (defined in in [RFC 792](https://tools.ietf.org/html/rfc792), deprecated in [RFC 6633](https://tools.ietf.org/html/rfc6633)).
    pub const TYPE_SOURCE_QUENCH: u8 = 4;

    /// ICMPv4 type value indicating a "Redirect" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_REDIRECT: u8 = 5;

    /// ICMPv4 type value indicating a "Alternate Host Address (Deprecated)" message (deprecated in [RFC 6918](https://tools.ietf.org/html/rfc6918)).
    pub const TYPE_ALTERNATE_HOST_ADDRESS: u8 = 6;

    /// ICMPv4 type value indicating a "Echo Request" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_ECHO_REQUEST: u8 = 8;

    /// ICMPv4 type value indicating a "Router Advertisement" message (defined in [RFC 1256](https://tools.ietf.org/html/rfc1256)).
    pub const TYPE_ROUTER_ADVERTISEMENT: u8 = 9;

    /// ICMPv4 type value indicating a "Router Solicitation" message (defined in [RFC 1256](https://tools.ietf.org/html/rfc1256)).
    pub const TYPE_ROUTER_SOLICITATION: u8 = 10;

    /// ICMPv4 type value indicating a "Time Exceeded" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_TIME_EXCEEDED: u8 = 11;

    /// ICMPv4 type value indicating a "Parameter Problem" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_PARAMETER_PROBLEM: u8 = 12;

    /// ICMPv4 type value indicating a "Timestamp" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_TIMESTAMP: u8 = 13;

    /// ICMPv4 type value indicating a "Timestamp Reply" message (defined in [RFC 792](https://tools.ietf.org/html/rfc792)).
    pub const TYPE_TIMESTAMP_REPLY: u8 = 14;

    /// ICMPv4 type value indicating a "Information Request (Deprecated)" message (defined in in [RFC 792](https://tools.ietf.org/html/rfc792), deprecated in [RFC 6918](https://tools.ietf.org/html/rfc6918)).
    pub const TYPE_INFO_REQUEST: u8 = 15;

    /// ICMPv4 type value indicating a "Information Reply (Deprecated)" message (defined in in [RFC 792](https://tools.ietf.org/html/rfc792), deprecated in [RFC 6918](https://tools.ietf.org/html/rfc6918)).
    pub const TYPE_INFO_REPLY: u8 = 16;

    /// ICMPv4 type value indicating a "Address Mask Request (Deprecated)" message (defined in in [RFC 950](https://tools.ietf.org/html/rfc950), deprecated in [RFC 6918](https://tools.ietf.org/html/rfc6918)).
    pub const TYPE_ADDRESS: u8 = 17;

    /// ICMPv4 type value indicating a "Address Mask Reply (Deprecated)" message (defined in in [RFC 950](https://tools.ietf.org/html/rfc950), deprecated in [RFC 6918](https://tools.ietf.org/html/rfc6918)).
    pub const TYPE_ADDRESSREPLY: u8 = 18;

    /// ICMP destination unreachable code for "Net Unreachable" (defined in [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_NET: u8 = 0;

    /// ICMP destination unreachable code for "Host Unreachable" (defined in [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_HOST: u8 = 1;

    /// ICMP destination unreachable code for "Protocol Unreachable" (defined in [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_PROTOCOL: u8 = 2;

    /// ICMP destination unreachable code for "Port Unreachable" (defined in [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_PORT: u8 = 3;

    /// ICMP destination unreachable code for "Fragmentation Needed and Don't Fragment was Set" (defined in [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_NEED_FRAG: u8 = 4;

    /// ICMP destination unreachable code for "Source Route Failed" (defined in [RFC 792](https://tools.ietf.org/html/rfc792))
    pub const CODE_DST_UNREACH_SOURCE_ROUTE_FAILED: u8 = 5;

    /// ICMP destination unreachable code for "Destination Network Unknown" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_NET_UNKNOWN: u8 = 6;

    /// ICMP destination unreachable code for "Destination Host Unknown" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_HOST_UNKNOWN: u8 = 7;

    /// ICMP destination unreachable code for "Source Host Isolated" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_ISOLATED: u8 = 8;

    /// ICMP destination unreachable code for "Communication with Destination Network is Administratively Prohibited" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_NET_PROHIB: u8 = 9;

    /// ICMP destination unreachable code for "Communication with Destination Host is Administratively Prohibited" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_HOST_PROHIB: u8 = 10;

    /// ICMP destination unreachable code for "Destination Network Unreachable for Type of Service" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_TOS_NET: u8 = 11;

    /// ICMP destination unreachable code for "Destination Host Unreachable for Type of Service" (defined in [RFC 1122](https://tools.ietf.org/html/rfc1122))
    pub const CODE_DST_UNREACH_TOS_HOST: u8 = 12;

    /// ICMP destination unreachable code for "Communication Administratively Prohibited" (defined in [RFC 1812](https://tools.ietf.org/html/rfc1812))
    pub const CODE_DST_UNREACH_FILTER_PROHIB: u8 = 13;

    /// ICMP destination unreachable code for "Host Precedence Violation" (defined in [RFC 1812](https://tools.ietf.org/html/rfc1812))
    pub const CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION: u8 = 14;

    /// ICMP destination unreachable code for "Precedence cutoff in effect" (defined in [RFC 1812](https://tools.ietf.org/html/rfc1812))
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
        /// Network unreachable error.
        Network,
        /// Host unreachable error.
        Host,
        /// Transport protocol not supported error.
        Protocol,
        /// Port unreachable error.
        Port,
        /// Fragmentation would be needed but the don't fragment bit is set.
        FragmentationNeeded { next_hop_mtu: u16 },
        /// Source Route Failed
        SourceRouteFailed,
        /// Destination Network Unknown (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        NetworkUnknown,
        /// Destination Host Unknown (no route to host known) (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        HostUnknown,
        /// Source Host Isolated - obsolete (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        Isolated,
        /// Communication with Destination Network is Administratively Prohibited (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        NetworkProhibited,
        /// Communication with Destination Host is Administratively Prohibited (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        HostProhibited,
        /// Destination Network Unreachable for Type of Service (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        TosNetwork,
        /// Destination Host Unreachable for Type of Service (from [RFC 1122](https://tools.ietf.org/html/rfc1122))
        TosHost,
        /// Cannot forward because packet administratively filtered (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
        FilterProhibited,
        /// Required level of precidence not supported (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
        HostPrecedenceViolation,
        /// Packet was below minimum precidence (from [RFC 1812](https://tools.ietf.org/html/rfc1812))
        PrecedenceCutoff,
    }

    impl DestUnreachableHeader {

        /// Tries to convert the code [`u8`] value and next_hop_mtu to a [`DestUnreachableHeader`] value.
        ///
        /// Returns [`None`] in case the code value is not known as a destination unreachable code.
        pub fn from_values(code_u8: u8, next_hop_mtu: u16) -> Option<DestUnreachableHeader> {
            use DestUnreachableHeader::*;
            match code_u8 {
                CODE_DST_UNREACH_NET => Some(Network),
                CODE_DST_UNREACH_HOST => Some(Host),
                CODE_DST_UNREACH_PROTOCOL => Some(Protocol),
                CODE_DST_UNREACH_PORT => Some(Port),
                CODE_DST_UNREACH_NEED_FRAG => Some(FragmentationNeeded { next_hop_mtu }),
                CODE_DST_UNREACH_SOURCE_ROUTE_FAILED => Some(SourceRouteFailed),
                CODE_DST_UNREACH_NET_UNKNOWN => Some(NetworkUnknown),
                CODE_DST_UNREACH_HOST_UNKNOWN => Some(HostUnknown),
                CODE_DST_UNREACH_ISOLATED => Some(Isolated),
                CODE_DST_UNREACH_NET_PROHIB => Some(NetworkProhibited),
                CODE_DST_UNREACH_HOST_PROHIB => Some(HostProhibited),
                CODE_DST_UNREACH_TOS_NET => Some(TosNetwork),
                CODE_DST_UNREACH_TOS_HOST => Some(TosHost),
                CODE_DST_UNREACH_FILTER_PROHIB => Some(FilterProhibited),
                CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION => Some(HostPrecedenceViolation),
                CODE_DST_UNREACH_PRECEDENCE_CUTOFF => Some(PrecedenceCutoff),
                _ => None,
            }
        }

        /// Returns the icmp code value of the destination unreachable packet.
        #[inline]
        pub fn code_u8(&self) -> u8 {
            use DestUnreachableHeader::*;
            match self {
                Network => CODE_DST_UNREACH_NET,
                Host => CODE_DST_UNREACH_HOST,
                Protocol => CODE_DST_UNREACH_PROTOCOL,
                Port => CODE_DST_UNREACH_PORT,
                FragmentationNeeded { next_hop_mtu: _ } => CODE_DST_UNREACH_NEED_FRAG,
                SourceRouteFailed => CODE_DST_UNREACH_SOURCE_ROUTE_FAILED,
                NetworkUnknown => CODE_DST_UNREACH_NET_UNKNOWN,
                HostUnknown => CODE_DST_UNREACH_HOST_UNKNOWN,
                Isolated => CODE_DST_UNREACH_ISOLATED,
                NetworkProhibited => CODE_DST_UNREACH_NET_PROHIB,
                HostProhibited => CODE_DST_UNREACH_HOST_PROHIB,
                TosNetwork => CODE_DST_UNREACH_TOS_NET,
                TosHost => CODE_DST_UNREACH_TOS_HOST,
                FilterProhibited => CODE_DST_UNREACH_FILTER_PROHIB,
                HostPrecedenceViolation => CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION,
                PrecedenceCutoff => CODE_DST_UNREACH_PRECEDENCE_CUTOFF,
            }
        }
    }

    /// ICMPv4 "Redirect" code value for "Redirect Datagram for the Network (or subnet)".
    pub const CODE_REDIRECT_FOR_NETWORK: u8 = 0;

    /// ICMPv4 "Redirect" code value for "Redirect Datagram for the Host".
    pub const CODE_REDIRECT_FOR_HOST: u8 = 1;

    /// ICMPv4 "Redirect" code value for "Redirect Datagram for the Type of Service and Network".
    pub const CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK: u8 = 2;

    /// ICMPv4 "Redirect" code value for "Redirect Datagram for the Type of Service and Host".
    pub const CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST: u8 = 3;

    /// Code value in an ICMPv4 Redirect message.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum RedirectCode {
        /// Redirect Datagram for the Network (or subnet)
        RedirectForNetwork = 0,
        /// Redirect Datagram for the Host
        RedirectForHost = 1,
        /// Redirect Datagram for the Type of Service and Network
        RedirectForTypeOfServiceAndNetwork = 2,
        /// Redirect datagrams for the Type of Service and Host
        RedirectForTypeOfServiceAndHost = 3,
    }

    impl RedirectCode {
        /// Tries to convert a code [`u8`] value to a [`RedirectCode`] value.
        ///
        /// Returns [`None`] in case the code value is not known as a redirect code.
        #[inline]
        pub fn from_u8(code_u8: u8) -> Option<RedirectCode> {
            use RedirectCode::*;
            match code_u8 {
                CODE_REDIRECT_FOR_NETWORK => Some(RedirectForNetwork),
                CODE_REDIRECT_FOR_HOST => Some(RedirectForHost),
                CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK => Some(RedirectForTypeOfServiceAndNetwork),
                CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST => Some(RedirectForTypeOfServiceAndHost),
                _ => None,
            }
        }

        /// Returns the [`u8`] value of the code.
        #[inline]
        pub fn code_u8(&self) -> u8 {
            *self as u8
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RedirectHeader {
        pub code: RedirectCode,
        pub gateway_internet_address: [u8; 4],
    }

    /// ICMPv4 "Time Exceeded" code value for "Time to Live exceeded in Transit".
    pub const CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT: u8 = 0;

    /// ICMPv4 "Time Exceeded" code value for "Fragment Reassembly Time Exceeded".
    pub const CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED: u8 = 1;

    /// Code values for ICMPv4 time exceeded message.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum TimeExceededCode {
        /// Time-to-live exceeded in transit.
        TtlExceededInTransit = 0,
        /// Fragment reassembly time exceeded.
        FragmentReassemblyTimeExceeded = 1,
    }

    impl TimeExceededCode {
        /// Tries to convert a code [`u8`] value to a [`TimeExceededCode`] value.
        ///
        /// Returns [`None`] in case the code value is not known as a time exceeded code.
        #[inline]
        pub fn from_u8(code_u8: u8) -> Option<TimeExceededCode> {
            use TimeExceededCode::*;
            match code_u8 {
                CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT => Some(TtlExceededInTransit),
                CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED => Some(FragmentReassemblyTimeExceeded),
                _ => None
            }
        }

        /// Returns the [`u8`] value of the code.
        #[inline]
        pub fn code_u8(&self) -> u8 {
            *self as u8
        }
    }

    /// A ICMPv4 timestamp or timestamp response message.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TimestampMessage {
        pub id: u16,
        pub seq: u16,
        pub originate_timestamp: u32,
        pub receive_timestamp: u32,
        pub transmit_timestamp: u32,
    }

    impl TimestampMessage {
        /// The size in bytes/octets of a timestamp request or timestamp response message.
        pub const SERIALIZED_SIZE: usize = 20;

        /// Decodes the timestamp message part of an ICMPv4 message.
        pub fn from_bytes(bytes: [u8;16]) -> TimestampMessage {
            TimestampMessage{
                id: u16::from_be_bytes([bytes[0], bytes[1]]),
                seq: u16::from_be_bytes([bytes[2], bytes[3]]),
                originate_timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                receive_timestamp: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                transmit_timestamp: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            }
        }
    }

    /// ICMPv4 "Parameter Problem" code value for "Pointer indicates the error".
    pub const CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR: u8 = 0;

    /// ICMPv4 "Parameter Problem" code value for "Missing a Required Option".
    pub const CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION: u8 = 1;

    /// ICMPv4 "Parameter Problem" code value for "Bad Length".
    pub const CODE_PARAMETER_PROBLEM_BAD_LENGTH: u8 = 2;

    /// The header of an ICMPv4 Parameter Problems (contents up to
    /// the offending ip header).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ParameterProblemHeader {
        /// Identifies the octet where an error was detected.
        ///
        /// The value is the pointer pointing to the offending octet in
        /// the offending packet.
        PointerIndicatesError(u8),
        /// Missing a Required Option
        MissingRequiredOption,
        /// Bad Length
        BadLength,
    }

    impl ParameterProblemHeader {
        /// Tries to convert the code [`u8`] value and pointer to a [`ParameterProblemHeader`] value.
        ///
        /// Returns [`None`] in case the code value is not known as a parameter problem code.
        pub fn from_values(code_u8: u8, pointer: u8) -> Option<ParameterProblemHeader> {
            use ParameterProblemHeader::*;
            match code_u8 {
                CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR => Some(PointerIndicatesError(pointer)),
                CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION => Some(MissingRequiredOption),
                CODE_PARAMETER_PROBLEM_BAD_LENGTH => Some(BadLength),
                _ => None,
            }
        }
    }

} // mod icmpv4

use icmpv4::*;

/// Starting contents of an ICMPv4 packet without the checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icmpv4Type {
    /// Unknown ICMP type & code.
    ///
    /// In case of an unknown ICMP type and code combination is received the
    /// header elements are stored raw.
    Unknown {
        /// ICMP type (present in the first byte of the ICMP packet).
        type_u8: u8,
        /// ICMP code (present in the 2nd byte of the ICMP packet).
        code_u8: u8,
        /// Bytes located at th 5th, 6th, 7th and 8th position of the ICMP packet.
        bytes5to8: [u8; 4],
    },

    /// Echo Reply (defined in RFC792)
    EchoReply(IcmpEchoHeader),
    
    DestinationUnreachable(DestUnreachableHeader),

    Redirect(RedirectHeader),

    /// Echo Request (defined in RFC792)
    EchoRequest(IcmpEchoHeader),
    TimeExceeded(TimeExceededCode),
    ParameterProblem(ParameterProblemHeader),
    TimestampRequest(TimestampMessage),
    TimestampReply(TimestampMessage),
}

impl Icmpv4Type {
    /// Returns the length in bytes/octets of the header of
    /// this ICMPv4 message type.
    #[inline]
    pub fn header_len(&self) -> usize {
        use Icmpv4Type::*;
        match self {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            }
            | EchoReply(_)
            | DestinationUnreachable(_)
            | Redirect(_)
            | EchoRequest(_)
            | TimeExceeded(_)
            | ParameterProblem(_) => 8,
            TimestampRequest(_) | TimestampReply(_) => TimestampMessage::SERIALIZED_SIZE,
        }
    }

    /// If the ICMP type has a fixed size returns the number of
    /// bytes that should be present after the header of this type.
    #[inline]
    pub fn fixed_payload_size(&self) -> Option<usize> {
        use Icmpv4Type::*;
        match self {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            }
            | EchoReply(_)
            | DestinationUnreachable(_)
            | Redirect(_)
            | EchoRequest(_)
            | TimeExceeded(_)
            | ParameterProblem(_) => None,
            TimestampRequest(_) | TimestampReply(_) => Some(0),
        }
    }

    /// Calculate the ICMP checksum value.
    pub fn calc_checksum(&self, payload: &[u8]) -> u16 {
        use Icmpv4Type::*;
        match self {
            Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => checksum::Sum16BitWords::new()
                .add_2bytes([*type_u8, *code_u8])
                .add_4bytes(*bytes5to8),
            EchoReply(header) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_ECHO_REPLY, 0])
                .add_2bytes(header.id.to_be_bytes())
                .add_2bytes(header.seq.to_be_bytes()),
            DestinationUnreachable(ref header) => {
                use DestUnreachableHeader::*;
                match header {
                    Network => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET]),
                    Host => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST]),
                    Protocol => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_PROTOCOL]),
                    Port => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_PORT]),
                    FragmentationNeeded { next_hop_mtu } => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NEED_FRAG])
                        .add_2bytes(next_hop_mtu.to_be_bytes()),
                    SourceRouteFailed => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_SOURCE_ROUTE_FAILED]),
                    NetworkUnknown => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_UNKNOWN]),
                    HostUnknown => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_UNKNOWN]),
                    Isolated => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_ISOLATED]),
                    NetworkProhibited => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_PROHIB]),
                    HostProhibited => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_PROHIB]),
                    TosNetwork => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_NET]),
                    TosHost => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_HOST]),
                    FilterProhibited => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_FILTER_PROHIB]),
                    HostPrecedenceViolation => checksum::Sum16BitWords::new().add_2bytes([
                        TYPE_DEST_UNREACH,
                        CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION,
                    ]),
                    PrecedenceCutoff => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_PRECEDENCE_CUTOFF]),
                }
            }
            Redirect(header) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_REDIRECT, header.code as u8])
                .add_4bytes(header.gateway_internet_address),
            EchoRequest(header) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_ECHO_REQUEST, 0])
                .add_2bytes(header.id.to_be_bytes())
                .add_2bytes(header.seq.to_be_bytes()),
            TimeExceeded(code) => {
                checksum::Sum16BitWords::new().add_2bytes([TYPE_TIME_EXCEEDED, *code as u8])
            }
            ParameterProblem(header) => {
                use ParameterProblemHeader::*;
                match header {
                    PointerIndicatesError(pointer) => checksum::Sum16BitWords::new()
                        .add_2bytes([
                            TYPE_PARAMETER_PROBLEM,
                            CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR,
                        ])
                        .add_2bytes([*pointer, 0]),
                    MissingRequiredOption => checksum::Sum16BitWords::new().add_2bytes([
                        TYPE_PARAMETER_PROBLEM,
                        CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION,
                    ]),
                    BadLength => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_PARAMETER_PROBLEM, CODE_PARAMETER_PROBLEM_BAD_LENGTH]),
                }
            }
            TimestampRequest(msg) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_TIMESTAMP, 0])
                .add_2bytes(msg.id.to_be_bytes())
                .add_2bytes(msg.seq.to_be_bytes())
                .add_4bytes(msg.originate_timestamp.to_be_bytes())
                .add_4bytes(msg.receive_timestamp.to_be_bytes())
                .add_4bytes(msg.transmit_timestamp.to_be_bytes()),
            TimestampReply(msg) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_TIMESTAMP_REPLY, 0])
                .add_2bytes(msg.id.to_be_bytes())
                .add_2bytes(msg.seq.to_be_bytes())
                .add_4bytes(msg.originate_timestamp.to_be_bytes())
                .add_4bytes(msg.receive_timestamp.to_be_bytes())
                .add_4bytes(msg.transmit_timestamp.to_be_bytes()),
        }
        .add_slice(payload)
        .ones_complement()
        .to_be()
    }
}

/// A header of an ICMPv4 packet.
///
/// What is part of the header depends on the ICMPv4 type
/// and code. But usually the static sized elements are part
/// of the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv4Header {
    pub icmp_type: Icmpv4Type,
    pub checksum: u16,
}

impl Icmpv4Header {
    /// Minimum number of bytes/octets an Icmpv4Header takes up
    /// in serialized form.
    pub const MIN_SERIALIZED_SIZE: usize = 8;

    /// Maximum number of bytes/octets an Icmpv4Header takes up
    /// in serialized form.
    ///
    /// Currently this number is determined by the biggest
    /// supported ICMPv4 header type, which is currently the
    /// "Timestamp" and "Timestamp Reply Message".
    pub const MAX_SERIALIZED_SIZE: usize = 20;

    /// Length in bytes/octets of this header type.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.icmp_type.header_len()
    }

    /// If the ICMP type has a fixed size returns the number of
    /// bytes that should be present after the header of this type.
    #[inline]
    pub fn fixed_payload_size(&self) -> Option<usize> {
        self.icmp_type.fixed_payload_size()
    }

    /// Constructs an [`Icmpv4Header`] using the given type
    /// and the checksum set to 0.
    pub fn new(icmp_type: Icmpv4Type) -> Icmpv4Header {
        // Note: will calculate checksum on send
        Icmpv4Header {
            icmp_type,
            checksum: 0,
        }
    }

    /// Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()).map_err(WriteError::from)
    }

    /// Calculates & updates the checksum in the header.
    ///
    /// Note this method assumes that all unused bytes/octets
    /// are filled with zeroes.
    pub fn update_checksum(&mut self, payload: &[u8]) {
        self.checksum = self.icmp_type.calc_checksum(payload);
    }

    /// Reads an icmp4 header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Icmpv4Header, &[u8]), ReadError> {
        let header = Icmpv4Slice::from_slice(slice)?.header();
        let rest = &slice[header.header_len()..];
        Ok((header, rest))
    }

    /// Converts the header to the on the wire bytes.
    pub fn to_bytes(&self) -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {
        let checksum_be = self.checksum.to_be_bytes();
        let re_zero =
            |type_u8: u8, code_u8: u8| -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {

                #[cfg_attr(rustfmt, rustfmt_skip)]
                let mut re = ArrayVec::from([
                    type_u8, code_u8, checksum_be[0], checksum_be[1],
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 20.
                unsafe {
                    re.set_len(8);
                }
                re
            };

        let re_2u16 = |type_u8: u8,
                       code_u8: u8,
                       a_u16: u16,
                       b_u16: u16|
         -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {
            let a = a_u16.to_be_bytes();
            let b = b_u16.to_be_bytes();

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let mut re = ArrayVec::from([
                type_u8, code_u8, checksum_be[0], checksum_be[1],
                a[0], a[1], b[0], b[1],
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]);
            // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 20.
            unsafe {
                re.set_len(8);
            }
            re
        };

        let re_4u8 = |type_u8: u8,
                      code_u8: u8,
                      bytes5to8: [u8; 4]|
         -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let mut re = ArrayVec::from([
                type_u8, code_u8, checksum_be[0], checksum_be[1],
                bytes5to8[0], bytes5to8[1], bytes5to8[2], bytes5to8[3],
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]);
            // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 20.
            unsafe {
                re.set_len(8);
            }
            re
        };

        let re_timestamp_msg = |type_u8: u8,
                                msg: &TimestampMessage|
         -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {
            let id = msg.id.to_be_bytes();
            let seq = msg.seq.to_be_bytes();
            let o = msg.originate_timestamp.to_be_bytes();
            let r = msg.receive_timestamp.to_be_bytes();
            let t = msg.transmit_timestamp.to_be_bytes();

            #[cfg_attr(rustfmt, rustfmt_skip)]
            ArrayVec::from([
                type_u8, 0, checksum_be[0], checksum_be[1],
                id[0], id[1], seq[0], seq[1],
                o[0], o[1], o[2], o[3],
                r[0], r[1], r[2], r[3],
                t[0], t[1], t[2], t[3],
            ])
        };

        use Icmpv4Type::*;
        match self.icmp_type {
            Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => re_4u8(type_u8, code_u8, bytes5to8),
            EchoReply(echo) => re_2u16(TYPE_ECHO_REPLY, 0, echo.id, echo.seq),
            DestinationUnreachable(ref dest) => {
                use DestUnreachableHeader::*;
                match dest {
                    Network => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET),
                    Host => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST),
                    Protocol => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_PROTOCOL),
                    Port => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_PORT),
                    FragmentationNeeded { next_hop_mtu } => {
                        let m_be = next_hop_mtu.to_be_bytes();
                        re_4u8(
                            TYPE_DEST_UNREACH,
                            CODE_DST_UNREACH_NEED_FRAG,
                            [0, 0, m_be[0], m_be[1]],
                        )
                    }
                    SourceRouteFailed => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_SOURCE_ROUTE_FAILED),
                    NetworkUnknown => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_UNKNOWN),
                    HostUnknown => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_UNKNOWN),
                    Isolated => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_ISOLATED),
                    NetworkProhibited => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_PROHIB),
                    HostProhibited => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_PROHIB),
                    TosNetwork => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_NET),
                    TosHost => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_HOST),
                    FilterProhibited => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_FILTER_PROHIB),
                    HostPrecedenceViolation => re_zero(
                        TYPE_DEST_UNREACH,
                        CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION,
                    ),
                    PrecedenceCutoff => {
                        re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_PRECEDENCE_CUTOFF)
                    }
                }
            }
            Redirect(ref msg) => {
                re_4u8(TYPE_REDIRECT, msg.code as u8, msg.gateway_internet_address)
            }
            EchoRequest(echo) => re_2u16(TYPE_ECHO_REQUEST, 0, echo.id, echo.seq),
            TimeExceeded(code) => re_zero(TYPE_TIME_EXCEEDED, code as u8),
            ParameterProblem(ref header) => {
                use ParameterProblemHeader::*;
                match header {
                    PointerIndicatesError(pointer) => re_4u8(
                        TYPE_PARAMETER_PROBLEM,
                        CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR,
                        [*pointer, 0, 0, 0],
                    ),
                    MissingRequiredOption => re_zero(
                        TYPE_PARAMETER_PROBLEM,
                        CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION,
                    ),
                    BadLength => re_zero(TYPE_PARAMETER_PROBLEM, CODE_PARAMETER_PROBLEM_BAD_LENGTH),
                }
            }
            TimestampRequest(ref msg) => re_timestamp_msg(TYPE_TIMESTAMP, msg),
            TimestampReply(ref msg) => re_timestamp_msg(TYPE_TIMESTAMP_REPLY, msg),
        }
    }
}

/// A slice containing an ICMPv4 network package.
///
/// Struct allows the selective read of fields in the ICMPv4
/// packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icmpv4Slice<'a> {
    slice: &'a [u8],
}

impl<'a> Icmpv4Slice<'a> {
    /// Creates a slice containing an ICMPv4 packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` `ReadError::UnexpectedEndOfSlice`
    /// if the given slice is too small.
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Icmpv4Slice<'a>, ReadError> {
        // check length
        use ReadError::*;
        if slice.len() < Icmpv4Header::MIN_SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(Icmpv4Header::MIN_SERIALIZED_SIZE));
        }

        // SAFETY:
        // Safe as it is previously checked that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        let icmp_type: u8 = unsafe { *slice.get_unchecked(0) };
        let icmp_code: u8 = unsafe { *slice.get_unchecked(1) };

        // check type specific length
        match icmp_type {
            TYPE_TIMESTAMP_REPLY | TYPE_TIMESTAMP => {
                if 0 == icmp_code {
                    if TimestampMessage::SERIALIZED_SIZE != slice.len() {
                        return Err(UnexpectedLenOfSlice {
                            expected: TimestampMessage::SERIALIZED_SIZE,
                            actual: slice.len(),
                        });
                    }
                }
            }
            _ => {}
        }

        //done
        Ok(Icmpv4Slice { slice })
    }

    /// Decode the header values into an [`Icmpv4Header`] struct.
    #[inline]
    pub fn header(&self) -> Icmpv4Header {
        let icmp_type = self.icmp_type();
        Icmpv4Header {
            icmp_type,
            checksum: self.checksum(),
        }
    }

    /// Number of bytes/octets that will be converted into a
    /// [`Icmpv4Header`] when [`Icmpv4Slice::header`] gets called.
    #[inline]
    pub fn header_len(&self) -> usize {
        match self.type_u8() {
            TYPE_TIMESTAMP | TYPE_TIMESTAMP_REPLY => if 0 == self.code_u8() {
                TimestampMessage::SERIALIZED_SIZE
            } else {
                8
            },
            _ => 8,
        }
    }

    /// Decode the header values (excluding the checksum) into an [`Icmpv4Type`] enum.
    pub fn icmp_type(&self) -> Icmpv4Type {
        use Icmpv4Type::*;

        unsafe fn timestamp_message(ptr: *const u8) -> TimestampMessage {
            TimestampMessage {
                id: get_unchecked_be_u16(ptr.add(4)),
                seq: get_unchecked_be_u16(ptr.add(6)),
                originate_timestamp: get_unchecked_be_u32(ptr.add(8)),
                receive_timestamp: get_unchecked_be_u32(ptr.add(12)),
                transmit_timestamp: get_unchecked_be_u32(ptr.add(16)),
            }
        }

        match self.type_u8() {
            TYPE_ECHO_REPLY => {
                if 0 == self.code_u8() {
                    return EchoReply(IcmpEchoHeader::from_bytes(self.bytes5to8()));
                }
            }
            TYPE_DEST_UNREACH => {
                use DestUnreachableHeader::*;
                match self.code_u8() {
                    CODE_DST_UNREACH_NET => return DestinationUnreachable(Network),
                    CODE_DST_UNREACH_HOST => return DestinationUnreachable(Host),
                    CODE_DST_UNREACH_PROTOCOL => return DestinationUnreachable(Protocol),
                    CODE_DST_UNREACH_PORT => return DestinationUnreachable(Port),
                    CODE_DST_UNREACH_NEED_FRAG => {
                        return DestinationUnreachable(FragmentationNeeded {
                            // SAFETY:
                            // Safe as the contructor checks that the slice has
                            // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
                            next_hop_mtu: unsafe {
                                get_unchecked_be_u16(self.slice.as_ptr().add(6))
                            },
                        });
                    }
                    CODE_DST_UNREACH_SOURCE_ROUTE_FAILED => return DestinationUnreachable(SourceRouteFailed),
                    CODE_DST_UNREACH_NET_UNKNOWN => return DestinationUnreachable(NetworkUnknown),
                    CODE_DST_UNREACH_HOST_UNKNOWN => return DestinationUnreachable(HostUnknown),
                    CODE_DST_UNREACH_ISOLATED => return DestinationUnreachable(Isolated),
                    CODE_DST_UNREACH_NET_PROHIB => {
                        return DestinationUnreachable(NetworkProhibited)
                    }
                    CODE_DST_UNREACH_HOST_PROHIB => return DestinationUnreachable(HostProhibited),
                    CODE_DST_UNREACH_TOS_NET => return DestinationUnreachable(TosNetwork),
                    CODE_DST_UNREACH_TOS_HOST => return DestinationUnreachable(TosHost),
                    CODE_DST_UNREACH_FILTER_PROHIB => {
                        return DestinationUnreachable(FilterProhibited)
                    }
                    CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION => {
                        return DestinationUnreachable(HostPrecedenceViolation)
                    }
                    CODE_DST_UNREACH_PRECEDENCE_CUTOFF => {
                        return DestinationUnreachable(PrecedenceCutoff)
                    }
                    _ => {}
                }
            }
            TYPE_REDIRECT => {
                use RedirectCode::*;
                let code = match self.code_u8() {
                    CODE_REDIRECT_FOR_NETWORK => Some(RedirectForNetwork),
                    CODE_REDIRECT_FOR_HOST => Some(RedirectForHost),
                    CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK => {
                        Some(RedirectForTypeOfServiceAndNetwork)
                    }
                    CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST => Some(RedirectForTypeOfServiceAndHost),
                    _ => None,
                };
                if let Some(code) = code {
                    return Redirect(RedirectHeader {
                        code,
                        gateway_internet_address: self.bytes5to8(),
                    });
                }
            }
            TYPE_ECHO_REQUEST => {
                if 0 == self.code_u8() {
                    return EchoRequest(IcmpEchoHeader::from_bytes(self.bytes5to8()));
                }
            }
            TYPE_TIME_EXCEEDED => {
                use TimeExceededCode::*;
                match self.code_u8() {
                    CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT => {
                        return TimeExceeded(TtlExceededInTransit);
                    }
                    CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED => {
                        return TimeExceeded(FragmentReassemblyTimeExceeded);
                    }
                    _ => {}
                }
            }
            TYPE_PARAMETER_PROBLEM => {
                use ParameterProblemHeader::*;
                match self.code_u8() {
                    CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR => {
                        return ParameterProblem(PointerIndicatesError(
                            // SAFETY:
                            // Safe as the contructor checks that the slice has
                            // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
                            unsafe { *self.slice.get_unchecked(4) },
                        ));
                    }
                    CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION => {
                        return ParameterProblem(MissingRequiredOption);
                    }
                    CODE_PARAMETER_PROBLEM_BAD_LENGTH => {
                        return ParameterProblem(BadLength);
                    }
                    _ => {}
                }
            }
            TYPE_TIMESTAMP => {
                if 0 == self.code_u8() {
                    // SAFETY:
                    // Safe as the contructor checks that the slice has
                    // the length of TimestampMessage::SERIALIZED_SIZE (20).
                    unsafe {
                        return TimestampRequest(timestamp_message(self.slice.as_ptr()));
                    }
                }
            }
            TYPE_TIMESTAMP_REPLY => {
                if 0 == self.code_u8() {
                    // SAFETY:
                    // Safe as the contructor checks that the slice has
                    // the length of TimestampMessage::SERIALIZED_SIZE (20).
                    unsafe {
                        return TimestampReply(timestamp_message(self.slice.as_ptr()));
                    }
                }
            }
            _ => {}
        }

        Unknown {
            type_u8: self.type_u8(),
            code_u8: self.code_u8(),
            bytes5to8: self.bytes5to8(),
        }
    }

    /// Returns "type" value in the ICMPv4 header.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns "code" value in the ICMPv4 header.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns "checksum" value in the ICMPv4 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the bytes from position 4 till and including the 8th position
    /// in the ICMPv4 header.
    ///
    /// These bytes located at th 5th, 6th, 7th and 8th position of the ICMP
    /// packet can depending on the ICMPv4 type and code contain additional data.
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns a slice to the bytes not covered by `.header()`.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // explicitly inlined the code to determine the
        // length of the payload to make the cecking of the
        // usafe code easier.
        let header_len = match self.type_u8() {
            // SAFETY:
            // Lenght safe as the contructor checks that the slice has
            // the length of TimestampMessage::SERIALIZED_SIZE (20)
            // for the messages types TYPE_TIMESTAMP and TYPE_TIMESTAMP_REPLY.
            TYPE_TIMESTAMP | TYPE_TIMESTAMP_REPLY => if 0 == self.code_u8() {
                TimestampMessage::SERIALIZED_SIZE
            } else {
                8
            },
            // SAFETY:
            // Lneght safe as the contructor checks that the slice has
            // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE(8) for
            // all message types.
            _ => 8,
        };
        // SAFETY:
        // Lenghts have been depending on type in the constructor of the
        // ICMPv4Slice.
        unsafe { from_raw_parts(self.slice.as_ptr().add(header_len), self.slice.len() - header_len) }
    }

    /// Returns the slice containing the ICMPv4 packet.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
