use super::super::*;

use std::slice::from_raw_parts;

pub const ICMP6_DST_UNREACH: u8 =       1;
pub const ICMP6_PACKET_TOO_BIG: u8 =    2;
pub const ICMP6_TIME_EXCEEDED: u8 =     3;
pub const ICMP6_PARAM_PROB: u8 =        4;   
// silly spec, intentially gap
pub const ICMP6_ECHO_REQUEST: u8 =  128;
pub const ICMP6_ECHO_REPLY: u8 =    129;
pub const MLD_LISTENER_QUERY: u8 =  130;
pub const MLD_LISTENER_REPORT: u8 =  131;
pub const MLD_LISTENER_REDUCTION: u8 =  132;
pub const ICMPV6_EXT_ECHO_REQUEST: u8 =  160;
pub const ICMPV6_EXT_ECHO_REPLY: u8 =  161;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpV6Type {
    DestinationUnreachable = ICMP6_DST_UNREACH as isize,
    PacketTooBig = ICMP6_PACKET_TOO_BIG as isize,
    TimeExceeded = ICMP6_TIME_EXCEEDED as isize,
    ParameterProblem = ICMP6_PARAM_PROB as isize,
    EchoRequest = ICMP6_ECHO_REQUEST as isize,
    EchoReply = ICMP6_ECHO_REPLY as isize,
    // implement the rest later
}

impl IcmpV6Type {
    // could just use 'num-derive' package, but this lib has no deps, so keeping
    // with that tradition; see https://enodev.fr/posts/rusticity-convert-an-integer-to-an-enum.html
    fn from(val: u8) -> Result<IcmpV6Type, ValueError> {
        use IcmpV6Type::*;
        match val {
            ICMP6_DST_UNREACH => Ok(DestinationUnreachable),
            ICMP6_PACKET_TOO_BIG => Ok(PacketTooBig),
            ICMP6_TIME_EXCEEDED => Ok(TimeExceeded),
            ICMP6_PARAM_PROB => Ok(ParameterProblem),
            ICMP6_ECHO_REQUEST => Ok(EchoRequest),
            ICMP6_ECHO_REPLY => Ok(EchoReply),
            _ => Err(ValueError::Icmp6Unknown{icmp_type: val}),
        }
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpV6Header {
    icmp_type: IcmpV6Type,
    icmp_code : u8,
    pub icmp_chksum: u16,
}

impl IcmpV6Header {
    pub const SERIALIZED_SIZE: usize = 8;
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

    pub fn calc_checksum_ipv6(&self, _ip_header: &Ipv6Header, _payload: &[u8]) -> Result<u16, ValueError> {
        // TODO...
        Ok(0u16)
    }

    /// Reads an icmp6 header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(IcmpV6Header, &[u8]), ReadError> {
        Ok((
            Icmp6HeaderSlice::from_slice(slice)?.to_header()
                .map_err(|_| { ReadError::UnexpectedEndOfSlice(IcmpV6Header::SERIALIZED_SIZE)})?,
            &slice[IcmpV6Header::SERIALIZED_SIZE..]
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
        if slice.len() < IcmpV6Header::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(IcmpV6Header::SERIALIZED_SIZE));
        }

        //done
        Ok(Icmp6HeaderSlice{
            // SAFETY:
            // Safe as slice length is checked to be at least
            // IcmpV6Header::SERIALIZED_SIZE (8) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    IcmpV6Header::SERIALIZED_SIZE
                )
            }
        })
    }
    /// Decode all the fields and copy the results to a UdpHeader struct
    #[inline]
    pub fn to_header(&self) -> Result<IcmpV6Header, ValueError> {
        Ok(IcmpV6Header {
            icmp_type: self.icmp_type()?,
            icmp_code: self.icmp_code()?,
            icmp_chksum: self.icmp_chksum()?,
        })
    }

    pub fn icmp_type(&self) -> Result<IcmpV6Type, ValueError> {
        // already checked slice len in ::from_slice()
        IcmpV6Type::from(self.slice[0])
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