use super::super::*;

extern crate byteorder;
use self::byteorder::{WriteBytesExt};

/// IP Authentication Header (rfc4302)
pub struct IpAuthenticationHeader<'a> {
    /// Type of content after this header (traffic class/protocol number)
    next_header: u8,
    /// Security Parameters Index
    spi: u32,
    /// This unsigned 32-bit field contains a counter value that 
    /// increases by one for each packet sent.
    sequence_number: u32,
    /// Integrity Check Value-ICV (variable)
    icv: &'a[u8],
}

impl<'a> IpAuthenticationHeader<'a> {

    

}