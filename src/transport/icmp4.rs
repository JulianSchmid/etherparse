use std::{slice::from_raw_parts, fmt::Display};

use super::super::*;


/**
 * Generic ICMP Header - applies to IcmpV4Header and IcmpV6Header
 */

pub trait IcmpHeader {
    fn get_raw_code(&self) -> u8;
    fn get_raw_type(&self) -> u8;
    fn get_checksum(&self) -> u16;
    /// this u32 data has different meaning by the Icmp Message Type
    /// For example, 
    /// * with Echo Request/Reply, it's (seq: u16, id: u16)
    /// * with Dest unreachable, it's reserved
    fn get_type_dependent_data(&self) -> u32;
}


// Make sure all Icmp4 + Icmp6 headers have a default Display
impl Display for dyn IcmpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "type={} code={}", self.get_raw_type(), self.get_raw_code())
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
pub enum IcmpV4Type {
    EchoReply = ICMP_V4_ECHOREPLY as isize,
    DestinationUnreachable = ICMP_V4_DEST_UNREACH as isize,
    SourceQuench = ICMP_V4_SOURCE_QUENCH as isize,
    Redirect = ICMP_V4_REDIRECT as isize,
    EchoRequest = ICMP_V4_ECHO as isize,
    TimeExceeded = ICMP_V4_TIME_EXCEEDED as isize,
    ParameterProblem = ICMP_V4_PARAMETERPROB as isize,
    TimestampRequest = ICMP_V4_TIMESTAMP as isize,
    TimestampReply = ICMP_V4_TIMESTAMPREPLY as isize,
    InfoRequest = ICMP_V4_INFO_REQUEST as isize,
    InfoReply = ICMP_V4_INFO_REPLY as isize,
    AddressRequest = ICMP_V4_ADDRESS as isize,
    AddressReply = ICMP_V4_ADDRESSREPLY as isize,
}

impl IcmpV4Type {
    // could just use 'num-derive' package, but this lib has no deps, so keeping
    // with that tradition; see https://enodev.fr/posts/rusticity-convert-an-integer-to-an-enum.html
    fn from(val: u8) -> Result<IcmpV4Type, ValueError> {
        use IcmpV4Type::*;
        match val {
            ICMP_V4_ECHOREPLY => Ok(EchoReply),
            ICMP_V4_DEST_UNREACH => Ok(DestinationUnreachable),
            ICMP_V4_SOURCE_QUENCH => Ok(SourceQuench),
            ICMP_V4_REDIRECT => Ok(Redirect),
            ICMP_V4_ECHO=> Ok(EchoRequest),
            ICMP_V4_TIME_EXCEEDED => Ok(TimeExceeded),
            ICMP_V4_PARAMETERPROB => Ok(ParameterProblem),
            ICMP_V4_TIMESTAMP => Ok(TimestampRequest),
            ICMP_V4_TIMESTAMPREPLY => Ok(TimestampReply),
            ICMP_V4_INFO_REQUEST => Ok(InfoRequest),
            ICMP_V4_INFO_REPLY => Ok(InfoReply),
            ICMP_V4_ADDRESS => Ok(AddressRequest),
            ICMP_V4_ADDRESSREPLY => Ok(AddressReply),
            _ => Err(ValueError::Icmp4Unknown{icmp_type: val}),
        }
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpEchoHeader {
    pub seq: u16,
    pub id: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpV4Header {
    pub icmp_type: IcmpV4Type,
    pub icmp_code : u8,
    pub icmp_chksum : u16,
    pub echo_header : Option<IcmpEchoHeader>,
}

impl IcmpV4Header {
    pub const SERIALIZED_SIZE: usize = 8;
    pub fn header_len(&self) -> usize {
        IcmpV4Header::SERIALIZED_SIZE
    }

    ///Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        let cksum_be = self.icmp_chksum.to_be_bytes();
        let rest_be = self.get_type_dependent_data().to_be_bytes();
        writer.write_all(&[
            self.icmp_type as u8,
            self.icmp_code,
            cksum_be[0],
            cksum_be[1],
            rest_be[0],
            rest_be[1],
            rest_be[2],
            rest_be[3],
        ]).map_err(WriteError::from)
    }

    pub fn calc_checksum_ipv4(&self, _ip_header: &Ipv4Header, _payload: &[u8]) -> Result<u16, ValueError>{
        // TODO...
        Ok(0u16)
    }

    /// Reads an icmp4 header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(IcmpV4Header, &[u8]), ReadError> {
        Ok((
            Icmp4HeaderSlice::from_slice(slice)?.to_header()
                .map_err(|_| { ReadError::UnexpectedEndOfSlice(IcmpV4Header::SERIALIZED_SIZE)})?,
            &slice[IcmpV4Header::SERIALIZED_SIZE..]
        ))
    }
}

impl IcmpHeader for IcmpV4Header {
    fn get_raw_type(&self) -> u8 {
        self.icmp_type as u8
    }
    fn get_raw_code(&self) -> u8 {
        0u8
    }
    fn get_checksum(&self) -> u16 {
        0u16
    }

    fn get_type_dependent_data(&self) -> u32 {
        use IcmpV4Type::*;
        match self.icmp_type {
            EchoRequest| EchoReply => {
                if let Some(echo_header) = &self.echo_header {
                    let seq_be = echo_header.seq.to_be_bytes();
                    let id_be = echo_header.id.to_be_bytes();
                    u32::from_be_bytes([seq_be[0], seq_be[1], id_be[0], id_be[1]])
                } else {
                    // caller never setup the IcmpEchoHeader
                    // just assume seq = id = 0
                    0
                }
            },
            _ => 0 // TODO: fill out other exceptions for this data...
        }
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
        if slice.len() < IcmpV4Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(IcmpV4Header::SERIALIZED_SIZE));
        }

        //done
        Ok(Icmp4HeaderSlice{
            // SAFETY:
            // Safe as slice length is checked to be at least
            // IcmpV4Header::SERIALIZED_SIZE (8) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    IcmpV4Header::SERIALIZED_SIZE
                )
            }
        })
    }


    fn parse_echo_header(&self) -> Option<IcmpEchoHeader> {
        use IcmpV4Type::*;
        if let Ok(icmp_type) = self.icmp_type() {
            if (icmp_type == EchoReply) || (icmp_type == EchoRequest) {
                let seq: u16 = u16::from_be_bytes([self.slice[4], self.slice[5]]);
                let id: u16 = u16::from_be_bytes([self.slice[6], self.slice[7]]);
                return Some(IcmpEchoHeader{
                    seq,
                    id,
                });
            }
        }
        None
    }

    /// Decode all the fields and copy the results to a UdpHeader struct
    #[inline]
    pub fn to_header(&self) -> Result<IcmpV4Header, ValueError> {
        Ok(IcmpV4Header {
            icmp_type: self.icmp_type()?,
            icmp_code: self.icmp_code()?,
            icmp_chksum: self.icmp_chksum()?,
            echo_header: self.parse_echo_header(),
        })
    }

    pub fn icmp_type(&self) -> Result<IcmpV4Type, ValueError> {
        // already checked slice len in ::from_slice()
        IcmpV4Type::from(self.slice[0])
    }

    pub fn icmp_code(&self) -> Result<u8, ValueError> {
        // already checked slice len in ::from_slice()
        Ok(self.slice[1])
    }

    pub fn icmp_chksum(&self) -> Result<u16, ValueError> {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of UdpHeader::SERIALIZED_SIZE (8).
        unsafe {
            Ok(get_unchecked_be_u16(self.slice.as_ptr().add(2)))
        }
    }
}