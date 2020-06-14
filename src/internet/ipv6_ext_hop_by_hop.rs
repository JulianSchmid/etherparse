use super::super::*;

extern crate byteorder;
use self::byteorder::{WriteBytesExt};

///IPv6 hop by hop header (only minimal data interpretation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6HopByHopHeader<'a> {
    ///Type of content after this header (protocol number)
    pub next_header: u8,
    ////The options contained in the hop by hop header.
    pub options: &'a [u8]
}

impl<'a> Ipv6HopByHopHeader<'a> {
    ///Creates a IPv6 hop by hop extension header with the given data.
    /// # Arguments
    ///
    /// * `next_header` - type of content after this header (protocol number)
    /// * `options` - slice containing the options. This does NOT contain the `next header` and `extended header length.
    pub fn new_raw(next_header: u8, options: &'a [u8]) -> Ipv6HopByHopHeader<'a> {
        Ipv6HopByHopHeader{
            next_header,
            options
        }
    }

    /// Read an Ipv6HopByHopHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &'a [u8]) -> Result<(Ipv6HopByHopHeader<'a>, &'a[u8]), ReadError> {
        let s = Ipv6HopByHopHeaderSlice::from_slice(slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((
            header, 
            rest
        ))
    }

    /// Writes a given IPv6 hop by hop header to the current position.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {

        use ValueError::*;

        // check if the options are not too big
        // the max length is defined by the max number that can fit into the
        // hdr ext len (+ 6 for the first six octets that are not part of the length).
        const MAX_OPTIONS_LEN: usize = 6 + 8*0xff;

        if self.options.len() > MAX_OPTIONS_LEN {
            Err(WriteError::ValueError(
                Ipv6HopByHopOptionsTooLarge(self.options.len())
            ))
        } else {
            writer.write_u8(self.next_header)?;

            // + 8 (and -1) to ensure no underflow can happen 
            // - 6 as the first 6 octets are not counted in the length
            // + 7 to ensure the result is round up
            let len: u8 = ((self.options.len() + 8 - 6 + 7) / 8 - 1) as u8;
            writer.write_u8(len)?;
            writer.write_all(&self.options)?;
            // add padding
            let padding_len = (usize::from(len) + 1)*8 - (self.options.len() + 8 - 6);
            if padding_len > 0 {
                const PADDING: [u8;7] = [0;7];
                writer.write_all(&PADDING[..padding_len])?;
            }
            Ok(())
        }
    }

}

/// Slice containing an IPv6 hop by hop header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6HopByHopHeaderSlice<'a> {
    /// The options contained in the hop by hop header.
    slice: &'a [u8]
}

impl<'a> Ipv6HopByHopHeaderSlice<'a> {

    /// Creates a hop by hop header slice from a slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<Ipv6HopByHopHeaderSlice<'a>, ReadError> {
        let len = super::ipv6_generic_ext_len_from_slice(slice)?;
        Ok(Ipv6HopByHopHeaderSlice {
            slice: &slice[..len]
        })
    }

    /// Returns the slice containing the ipv6 extension header
    #[inline]
    pub fn slice(&self) -> &'a[u8] {
        self.slice
    }

    /// Returns the id of the next header (see IpTrafficClass for a definition of all ids).
    pub fn next_header(&self) -> u8 {
        self.slice[0]
    }

    /// Returns a slice containing the raw options.
    pub fn raw_options(&self) -> &'a[u8] {
        &self.slice[2..]
    }

    /// Decode some of the fields and copy the results to a 
    /// Ipv6HopByHopHeader struct together with a slice 
    /// containing the non decoded parts.
    pub fn to_header(&self) -> Ipv6HopByHopHeader<'a> {
        return Ipv6HopByHopHeader{
            next_header: self.next_header(),
            options: self.raw_options()
        }
    }
}
