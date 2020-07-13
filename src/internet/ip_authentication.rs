use super::super::*;

extern crate byteorder;
use self::byteorder::{BigEndian, ByteOrder, WriteBytesExt};

/// IP Authentication Header (rfc4302)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpAuthenticationHeader<'a> {
    /// Type of content after this header (traffic class/protocol number)
    pub next_header: u8,
    /// Security Parameters Index
    pub spi: u32,
    /// This unsigned 32-bit field contains a counter value that 
    /// increases by one for each packet sent.
    pub sequence_number: u32,
    /// Encoded Integrity Check Value-ICV (variable)
    pub raw_icv: &'a[u8],
}

impl<'a> IpAuthenticationHeader<'a> {

    /// Create a new authentication header with the given parameters.
    pub fn new(
        next_header: u8,
        spi: u32,
        sequence_number: u32,
        raw_icv: &'a [u8]
    ) -> IpAuthenticationHeader<'a> {
        IpAuthenticationHeader {
            next_header,
            spi,
            sequence_number,
            raw_icv
        }
    }

    /// Read an  authentication header from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &'a [u8]) -> Result<(IpAuthenticationHeader<'a>, &'a[u8]), ReadError> {
        let s = IpAuthenticationHeaderSlice::from_slice(slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((
            header, 
            rest
        ))
    }

    /// Writes the given authentication header to the current position.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use ValueError::*;

        // check that icv is a multiple of 4 octets
        if 0 != self.raw_icv.len() % 4 {
            return Err(
                WriteError::ValueError(
                    // + 4 for the sequence number
                    IpAuthenticationHeaderBadIcvLength(self.raw_icv.len())
                )
            );
        }

        // check that the icv is not larger then what can be represented
        // (minus one for the sequence number)
        const MAX_ICV_LEN: usize = (0b1111_1111 - 1) * 4;
        if self.raw_icv.len() > MAX_ICV_LEN {
            return Err(
                WriteError::ValueError(
                    // + 4 for the sequence number
                    IpAuthenticationHeaderBadIcvLength(self.raw_icv.len())
                )
            );
        }

        let len = ((self.raw_icv.len() / 4) + 1) as u8;
        writer.write_u8(self.next_header)?;
        writer.write_u8(len)?;
        //reserved
        writer.write_u8(0)?;
        writer.write_u8(0)?;
        writer.write_u32::<BigEndian>(self.spi)?;
        writer.write_u32::<BigEndian>(self.sequence_number)?;
        writer.write_all(self.raw_icv)?;
        Ok(())
    }
}

/// A slice containing an IP Authentication Header (rfc4302)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpAuthenticationHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> IpAuthenticationHeaderSlice<'a> {
    
    /// Creates a ip authentication header slice from a slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<IpAuthenticationHeaderSlice<'a>, ReadError> {
        
        // check slice length
        use crate::ReadError::*;
        if slice.len() < 8 {
            return Err(UnexpectedEndOfSlice(8));
        }

        // check header length minimum size
        if slice[1] < 1 {
            return Err(IpAuthenticationHeaderTooSmallPayloadLength(slice[1]));
        }

        // check length
        // note: The unit is different then all other ipv6 extension headers.
        //       In the other headers the lenth is in 8 octets, but for authentication
        //       headers the length is in 4 octets.
        let len = ((slice[1] as usize) + 2)*4;
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(len));
        }

        // all good
        Ok(IpAuthenticationHeaderSlice{
            slice: &slice[..len]
        })
    }

    pub fn slice(&self) -> &'a[u8] {
        self.slice
    }

    /// Returns the id of the next header (see IpTrafficClass for a definition of all ids).
    pub fn next_header(&self) -> u8 {
        self.slice[0]
    }

    /// Read the security parameters index from the slice
    pub fn spi(&self) -> u32 {
        BigEndian::read_u32(&self.slice[4..8])
    }

    /// This unsigned 32-bit field contains a counter value that 
    /// increases by one for each packet sent.
    pub fn sequence_number(&self) -> u32 {
        BigEndian::read_u32(&self.slice[8..12])
    }

    /// Return a slice with the raw integrity check value
    pub fn raw_icv(&self) -> &'a[u8] {
        &self.slice[12..]
    }

    /// Decode some of the fields and copy the results to a 
    /// Ipv6ExtensionHeader struct together with a slice pointing
    /// to the non decoded parts.
    pub fn to_header(&self) -> IpAuthenticationHeader<'a> {
        IpAuthenticationHeader {
            next_header: self.next_header(),
            spi: self.spi(),
            sequence_number: self.sequence_number(),
            raw_icv: self.raw_icv(),
        }
    }
}
