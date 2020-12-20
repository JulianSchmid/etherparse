use super::super::*;

extern crate byteorder;
use self::byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::fmt::{Debug, Formatter};

/// IP Authentication Header (rfc4302)
#[derive(Clone)]
pub struct IpAuthenticationHeader {
    /// Type of content after this header (internet protocol number)
    pub next_header: u8,
    /// Security Parameters Index
    pub spi: u32,
    /// This unsigned 32-bit field contains a counter value that 
    /// increases by one for each packet sent.
    pub sequence_number: u32,
    /// Length in 4-octets (maximum valid value is 0xfe) of data filled in the 
    /// `raw_icv_buffer`.
    raw_icv_len: u8,
    /// Buffer containing the "Encoded Integrity Check Value-ICV" (variable).
    /// The length of the used data can be set via the `variable` (must be a multiple of 4 bytes).
    raw_icv_buffer: [u8;0xfe*4],
}

impl Debug for IpAuthenticationHeader {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(formatter, "IpAuthenticationHeader {{ next_header: {}, spi: {}, sequence_number: {}, raw_icv: {:?} }}", 
            self.next_header,
            self.spi,
            self.sequence_number,
            self.raw_icv())
    }
}

impl PartialEq for IpAuthenticationHeader {
    fn eq(&self, other: &Self) -> bool {
        self.next_header == other.next_header &&
        self.spi == other.spi &&
        self.sequence_number == other.sequence_number &&
        self.raw_icv() == other.raw_icv()
    }
}

impl Eq for IpAuthenticationHeader {}

impl<'a> IpAuthenticationHeader {

    pub const MAX_ICV_LEN: usize = 0xfe*4;

    /// Create a new authentication header with the given parameters.
    ///
    /// Note: The length of the raw_icv slice must be a multiple of 4
    /// and the maximum allowed length is 1016 bytes
    /// (`IpAuthenticationHeader::MAX_ICV_LEN`). If the slice length does
    /// not fullfill these requirements the value is not copied and an
    /// `Err(ValueError::IpAuthenticationHeaderBadIcvLength)` is returned.
    /// If successfull an Ok(()) is returned.
    pub fn new(
        next_header: u8,
        spi: u32,
        sequence_number: u32,
        raw_icv: &'a [u8]
    ) -> Result<IpAuthenticationHeader, ValueError> {
        if raw_icv.len() > IpAuthenticationHeader::MAX_ICV_LEN || 0 != raw_icv.len() % 4 {
            use ValueError::*;
            Err(IpAuthenticationHeaderBadIcvLength(raw_icv.len()))
        } else {
            let mut result = IpAuthenticationHeader {
                next_header,
                spi,
                sequence_number,
                raw_icv_len: (raw_icv.len() / 4) as u8,
                raw_icv_buffer: [0;IpAuthenticationHeader::MAX_ICV_LEN]
            };
            result.raw_icv_buffer[..raw_icv.len()].copy_from_slice(raw_icv);
            Ok(result)
        }
    }

    /// Read an  authentication header from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &'a [u8]) -> Result<(IpAuthenticationHeader, &'a[u8]), ReadError> {
        let s = IpAuthenticationHeaderSlice::from_slice(slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((
            header, 
            rest
        ))
    }

    /// Read an authentication header from the current reader position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<IpAuthenticationHeader, ReadError> {
        let next_header = reader.read_u8()?;
        let payload_len = reader.read_u8()?;

        // payload len must be at least 1
        if payload_len < 1 {
            use ReadError::*;
            Err(IpAuthenticationHeaderTooSmallPayloadLength(payload_len))
        } else {
            // skip reserved
            reader.read_u8()?;
            reader.read_u8()?;
            // read the rest of the header
            Ok(IpAuthenticationHeader {
                next_header,
                spi: reader.read_u32::<BigEndian>()?,
                sequence_number: reader.read_u32::<BigEndian>()?,
                raw_icv_len: payload_len - 1,
                raw_icv_buffer: {
                    let mut buffer = [0;0xfe*4];
                    reader.read_exact(&mut buffer[..usize::from(payload_len - 1)*4])?;
                    buffer
                },
            })
        }
    }

    /// Returns a slice the raw icv value.
    pub fn raw_icv(&self) -> &[u8] {
        &self.raw_icv_buffer[..usize::from(self.raw_icv_len)*4]
    }

    /// Sets the icv value to the given raw value. The length of the slice must be
    /// a multiple of 4 and the maximum allowed length is 1016 bytes
    /// (`IpAuthenticationHeader::MAX_ICV_LEN`). If the slice length does
    /// not fullfill these requirements the value is not copied and an
    /// `Err(ValueError::IpAuthenticationHeaderBadIcvLength)` is returned.
    /// If successfull an Ok(()) is returned.
    pub fn set_raw_icv(&mut self, raw_icv: &[u8]) -> Result<(),ValueError> {
        if raw_icv.len() > IpAuthenticationHeader::MAX_ICV_LEN || 0 != raw_icv.len() % 4 {
            use ValueError::*;
            Err(IpAuthenticationHeaderBadIcvLength(raw_icv.len()))
        } else {
            self.raw_icv_buffer[..raw_icv.len()].copy_from_slice(raw_icv);
            self.raw_icv_len = (raw_icv.len() / 4) as u8;
            Ok(())
        }
    }

    /// Writes the given authentication header to the current position.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_u8(self.next_header)?;
        debug_assert!(self.raw_icv_len != 0xff);
        writer.write_u8(self.raw_icv_len + 1)?;
        //reserved
        writer.write_u8(0)?;
        writer.write_u8(0)?;
        writer.write_u32::<BigEndian>(self.spi)?;
        writer.write_u32::<BigEndian>(self.sequence_number)?;
        writer.write_all(self.raw_icv())?;
        Ok(())
    }

    ///Length of the header in bytes.
    pub fn header_len(&self) -> usize {
        12 + usize::from(self.raw_icv_len)*4
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
    pub fn to_header(&self) -> IpAuthenticationHeader {
        IpAuthenticationHeader::new(
            self.next_header(),
            self.spi(),
            self.sequence_number(),
            self.raw_icv(),
        ).unwrap()
    }
}
