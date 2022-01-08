use std::slice::from_raw_parts;

use super::super::*;



#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpEchoHeader {
    pub seq: u16,
    pub id: u16,
}

impl IcmpEchoHeader {
    // return the seq + id in Network Byte Order as a u32
    pub fn to_be_wire(&self) -> u32 {
        let seq_be = self.seq.to_be_bytes();
        let id_be = self.id.to_be_bytes();
        u32::from_be_bytes([seq_be[0], seq_be[1], id_be[0], id_be[1]])
    }

    pub fn from(four_bytes: u32) -> IcmpEchoHeader {
        let arr = four_bytes.to_be_bytes();
        IcmpEchoHeader{
            seq: u16::from_be_bytes([arr[0], arr[1]]),
            id: u16::from_be_bytes([arr[2], arr[3]]),
        }
    }
}


/* UNREACH codes */
pub const ICMP4_UNREACH_NET : u8 =          0;       /* bad net */
pub const ICMP4_UNREACH_HOST : u8 =         1;       /* bad host */
pub const ICMP4_UNREACH_PROTOCOL : u8 =     2;       /* bad protocol */
pub const ICMP4_UNREACH_PORT : u8 =         3;       /* bad port */
pub const ICMP4_UNREACH_NEEDFRAG : u8 =     4;       /* IP_DF caused drop */
pub const ICMP4_UNREACH_SRCFAIL : u8 =      5;       /* src route failed */
pub const ICMP4_UNREACH_NET_UNKNOWN : u8 =  6;       /* unknown net */
pub const ICMP4_UNREACH_HOST_UNKNOWN : u8 = 7;       /* unknown host */
pub const ICMP4_UNREACH_ISOLATED : u8 =     8;       /* src host isolated */
pub const ICMP4_UNREACH_NET_PROHIB : u8 =   9;       /* net denied */
pub const ICMP4_UNREACH_HOST_PROHIB : u8 =  10;      /* host denied */
pub const ICMP4_UNREACH_TOSNET : u8 =       11;      /* bad tos for net */
pub const ICMP4_UNREACH_TOSHOST : u8 =      12;     /* bad tos for host */
pub const ICMP4_UNREACH_FILTER_PROHIB: u8 = 13;     /* admin prohib */
pub const ICMP4_UNREACH_HOST_PRECEDENCE:u8= 14;     /* host prec vio. */
pub const ICMP4_UNREACH_PRECEDENCE_CUTOFF: u8= 15;      /* prec cutoff */


/// Icmp Dest Unreachables, Time Exceeded, and other Icmp packet types
/// included an Encapsulated packet as payload.  
/// 
/// Note that we cannot guarantee that this is a complete packet.
/// * IPv4/RFC791 says this the encapsulated packet is the full IP header \
///     and "at least" 8 bytes of the the IP payload, e.g., the src+dst ports \
///     if the protocol is UDP/TCP/SCTP
/// * IPv6/RFC4443 S3.1 says this is "As much of invoking packet as possible \
///     without the ICMPv6 packet exceeding the minimum IPv6 MTU"
/// but ultimately it's up to the router and not all routers in the Internet
/// are RFC compliant.  Be careful when parsing this struct as the packet
/// may truncate arbitrarily
/// 
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmp4DestinationUnreachable {
    Network = ICMP4_UNREACH_NET as isize,
    Host = ICMP4_UNREACH_HOST_UNKNOWN as isize,
    Port = ICMP4_UNREACH_PORT as isize,
    Protocol = ICMP4_UNREACH_PROTOCOL as isize,
    // TODO, fill in more
}

impl Icmp4DestinationUnreachable {
    pub fn from(_icmp_code: u8) -> Icmp4DestinationUnreachable {
        // TODO ... fill in the map
        Icmp4DestinationUnreachable::Host
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmp4Type {
    Raw{icmp_type: u8, icmp_code: u8, four_bytes: u32},  // used to encode unparsed/unknown ICMP headers
    EchoReply(IcmpEchoHeader),
    DestinationUnreachable(Icmp4DestinationUnreachable),
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
    fn from(icmp_type: u8, icmp_code: u8, four_bytes: u32) -> Icmp4Type {
        use Icmp4Type::*;
        match icmp_type {
            ICMP_V4_ECHOREPLY => EchoReply(IcmpEchoHeader::from(four_bytes)),
            ICMP_V4_DEST_UNREACH => DestinationUnreachable(Icmp4DestinationUnreachable::from(icmp_code)),
            ICMP_V4_SOURCE_QUENCH => SourceQuench,
            ICMP_V4_REDIRECT => Redirect,
            ICMP_V4_ECHO=> EchoRequest(IcmpEchoHeader::from(four_bytes)),
            ICMP_V4_TIME_EXCEEDED => TimeExceeded,
            ICMP_V4_PARAMETERPROB => ParameterProblem,
            ICMP_V4_TIMESTAMP => TimestampRequest,
            ICMP_V4_TIMESTAMPREPLY => TimestampReply,
            ICMP_V4_INFO_REQUEST => InfoRequest,
            ICMP_V4_INFO_REPLY => InfoReply,
            ICMP_V4_ADDRESS => AddressRequest,
            ICMP_V4_ADDRESSREPLY => AddressReply,
            // unknown/unparsed type - just return as Raw
            _ => Raw{icmp_type, icmp_code, four_bytes}
        }
    }

    /// Return the icmp_type, icmp_code, and the second 4 bytes
    /// of the ICMP payload, in big endian format
    fn to_be_wire(&self) -> (u8, u8, u32) {
        use Icmp4Type::*;
        match &self {
            Raw{icmp_type, icmp_code, four_bytes} => (*icmp_type, *icmp_code, *four_bytes),
            EchoReply(echo) => {
                (ICMP_V4_ECHOREPLY, 0, echo.to_be_wire())
            },
            DestinationUnreachable(code) => (ICMP_V4_DEST_UNREACH, *code as u8, 0),
            SourceQuench => (ICMP_V4_SOURCE_QUENCH, 0, 0),
            Redirect => (ICMP_V4_REDIRECT, 0, 0),
            EchoRequest(echo) => {
                (ICMP_V4_ECHO, 0, echo.to_be_wire())
            },
            TimeExceeded => (ICMP_V4_TIME_EXCEEDED, 0, 0),
            ParameterProblem => (ICMP_V4_PARAMETERPROB, 0, 0),
            TimestampRequest => (ICMP_V4_TIMESTAMP, 0, 0),
            TimestampReply => (ICMP_V4_TIMESTAMPREPLY, 0, 0),
            InfoRequest => (ICMP_V4_INFO_REQUEST, 0, 0),
            InfoReply => (ICMP_V4_INFO_REPLY, 0, 0),
            AddressRequest => (ICMP_V4_ADDRESS, 0, 0),
            AddressReply => (ICMP_V4_ADDRESSREPLY, 0, 0),
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

    ///Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        let cksum_be = self.icmp_chksum.to_be_bytes();
        let (icmp_type, icmp_code, four_bytes) = self.icmp_type.to_be_wire();
        let four_bytes_arr = four_bytes.to_be_bytes();
        writer.write_all(&[
            icmp_type as u8,
            icmp_code,
            cksum_be[0],
            cksum_be[1],
            four_bytes_arr[0],
            four_bytes_arr[1],
            four_bytes_arr[2],
            four_bytes_arr[3],
        ]).map_err(WriteError::from)
    }

    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError>{
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u32::MAX as usize) - Icmp4Header::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::Ipv4PayloadLengthTooLarge(payload.len()));
        }

        let (icmp_type, icmp_code, four_bytes) = self.icmp_type.to_be_wire();
        //calculate the checksum; icmp4 will always take an ip4 header
        Ok(
                checksum::Sum16BitWords::new()
                .add_4bytes(ip_header.source)
                .add_4bytes(ip_header.destination)
                .add_2bytes([0, ip_number::ICMP])
                .add_2bytes((payload.len() as u16).to_be_bytes())
                .add_2bytes([icmp_type, icmp_code])
                .add_4bytes(four_bytes.to_be_bytes())
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
            icmp_type: icmp_type,
            icmp_chksum: self.icmp_chksum(),
        }
    }

    pub fn icmp_type(&self) -> Icmp4Type  {
        // already checked slice len in ::from_slice()
        let four_bytes = 
        unsafe {
            get_unchecked_be_u32(self.slice.as_ptr().add(4))
        };
        Icmp4Type::from(self.slice[0], self.slice[1], four_bytes)
    }

    #[inline]
    pub fn icmp_code(&self) -> u8 {
        // already checked slice len in ::from_slice()
        self.slice[1]
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
}