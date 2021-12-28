use std::{slice::from_raw_parts, fmt::Display};

use super::super::*;


/**
 * Generic ICMP Header - applies to IcmpV4Header and IcmpV6Header
 */

pub trait IcmpHeader {
    fn get_raw_code(&self) -> u8;
    fn get_raw_type(&self) -> u8;
    fn get_checksum(&self) -> u16;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpV4Header {
    icmp_type: IcmpV4Type,
    icmp_code : u8,
    pub icmp_chksum : u16,
}
impl IcmpV4Header {
    pub const SERIALIZED_SIZE: usize = 16;
    pub fn header_len(&self) -> usize {
        8
    }
    ///Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        // TODO ... implement the rest
        let cksum_be = self.icmp_chksum.to_be_bytes();
        writer.write_all(&[
            self.icmp_type as u8,
            self.icmp_code,
            cksum_be[0],
            cksum_be[1],
        ]).map_err(WriteError::from)
    }
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError>{
        // TODO...
        Ok(0u16)
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
    /// Decode all the fields and copy the results to a UdpHeader struct
    #[inline]
    pub fn to_header(&self) -> Result<IcmpV4Header, ValueError> {
        Ok(IcmpV4Header {
            icmp_type: self.icmp_type()?,
            icmp_code: self.icmp_code()?,
            icmp_chksum: self.icmp_chksum()?,
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