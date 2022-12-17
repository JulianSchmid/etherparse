use super::super::*;

use std::fmt::{Debug, Formatter};
use std::slice::from_raw_parts;

/// Deprecated use [IpAuthenticationHeader] instead.
#[deprecated(
    since = "0.10.1",
    note = "Please use the type IpAuthenticationHeader instead"
)]
pub type IPv6AuthenticationHeader = IpAuthenticationHeader;

/// IP Authentication Header (rfc4302)
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpAuthenticationHeader {
    /// IP protocol number specifying the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definition of the known values.
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
    #[cfg_attr(feature = "serde", serde(skip), serde(default = "default_raw_icv_buffer"))]
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
    pub fn from_slice(slice: &'a [u8]) -> Result<(IpAuthenticationHeader, &'a[u8]), ReadError> {
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
        
        let start = {
            let mut start = [0;4+4+4];
            reader.read_exact(&mut start)?;
            start
        };

        let next_header = start[0];
        let payload_len = start[1];

        // payload len must be at least 1
        if payload_len < 1 {
            use ReadError::*;
            Err(IpAuthenticationHeaderTooSmallPayloadLength(payload_len))
        } else {
            // read the rest of the header
            Ok(IpAuthenticationHeader {
                next_header,
                spi: u32::from_be_bytes(
                    [
                        start[4],
                        start[5],
                        start[6],
                        start[7],
                    ]
                ),
                sequence_number: u32::from_be_bytes(
                    [
                        start[8],
                        start[9],
                        start[10],
                        start[11],
                    ]
                ),
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

        let spi_be = self.spi.to_be_bytes();
        let sequence_number_be = self.sequence_number.to_be_bytes();
        debug_assert!(self.raw_icv_len != 0xff);

        writer.write_all(
            &[
                self.next_header,
                self.raw_icv_len + 1,
                0,
                0,
                spi_be[0],
                spi_be[1],
                spi_be[2],
                spi_be[3],
                sequence_number_be[0],
                sequence_number_be[1],
                sequence_number_be[2],
                sequence_number_be[3],
            ]
        )?;
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
        if slice.len() < 12 {
            return Err(UnexpectedEndOfSlice(12));
        }

        // SAFETY: 
        // Safe the slice length gets checked to be at least 12 beforehand.
        let payload_len_enc = unsafe {
            *slice.get_unchecked(1)
        };

        // check header length minimum size
        if payload_len_enc < 1 {
            return Err(IpAuthenticationHeaderTooSmallPayloadLength(payload_len_enc));
        }

        // check length
        // note: The unit is different then all other ipv6 extension headers.
        //       In the other headers the lenth is in 8 octets, but for authentication
        //       headers the length is in 4 octets.
        let len = ((payload_len_enc as usize) + 2)*4;
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(len));
        }

        // all good
        Ok(IpAuthenticationHeaderSlice{
            // SAFETY:
            // Safe as slice len is checked to be at last len above.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    len
                )
            }
        })
    }

    /// Creates a ip authentication header slice from a slice (assumes slice size & content was validated before).
    ///
    /// # Safety
    ///
    /// This method assumes that the slice was previously validated to contain
    /// a valid authentification header. This means the slice length must at
    /// least be at least 8 and `(slice[1] + 2)*4`. The data that the
    /// slice points must also be valid (meaning no nullptr or alike allowed).
    ///
    /// If these precondtions are not fullfilled the behavior of this function
    /// and the methods of the return IpAuthenticationHeaderSlice will be undefined.
    pub unsafe fn from_slice_unchecked(slice: &'a[u8]) -> IpAuthenticationHeaderSlice<'a> {
        IpAuthenticationHeaderSlice{
            slice: from_raw_parts(
                slice.as_ptr(),
                ((*slice.get_unchecked(1) as usize) + 2)*4
            )
        }
    }

    /// Returns the slice containing the authentification header.
    #[inline]
    pub fn slice(&self) -> &'a[u8] {
        self.slice
    }

    /// Returns the IP protocol number of the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definition of the known values.
    #[inline]
    pub fn next_header(&self) -> u8 {
        // SAFETY:
        // Safe as slice length is checked in the constructor
        // to be at least 12.
        unsafe {
            *self.slice.get_unchecked(0)
        }
    }

    /// Read the security parameters index from the slice
    #[inline]
    pub fn spi(&self) -> u32 {
        // SAFETY:
        // Safe as slice length is checked in the constructor
        // to be at least 12.
        unsafe {
            get_unchecked_be_u32(self.slice.as_ptr().add(4))
        }
    }

    /// This unsigned 32-bit field contains a counter value that 
    /// increases by one for each packet sent.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        // SAFETY:
        // Safe as slice length is checked in the constructor
        // to be at least 12.
        unsafe {
            get_unchecked_be_u32(self.slice.as_ptr().add(8))
        }
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

#[feature("serde")]
/// Used to create an empty buffer when deserializing using `serde`
fn default_raw_icv_buffer() -> [u8;0xfe*4] {
    [0;0xfe*4]
}
