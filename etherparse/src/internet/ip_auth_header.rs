use super::super::*;

use std::fmt::{Debug, Formatter};

/// Deprecated use [IpAuthHeader] instead.
#[deprecated(
    since = "0.10.1",
    note = "Please use the type IpAuthHeader instead"
)]
pub type IPv6AuthenticationHeader = IpAuthHeader;

/// Deprecated use [IpAuthHeader] instead.
#[deprecated(
    since = "0.14.0",
    note = "Please use the type IpAuthHeader instead"
)]
pub type IpAuthenticationHeader = IpAuthHeader;

/// IP Authentication Header (rfc4302)
#[derive(Clone)]
pub struct IpAuthHeader {
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
    raw_icv_buffer: [u8; 0xfe * 4],
}

impl Debug for IpAuthHeader {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), std::fmt::Error> {
        let mut s = formatter.debug_struct("IpAuthHeader");
        s.field("next_header", &self.next_header);
        s.field("spi", &self.spi);
        s.field("sequence_number", &self.sequence_number);
        s.field("raw_icv", &self.raw_icv());
        s.finish()
    }
}

impl PartialEq for IpAuthHeader {
    fn eq(&self, other: &Self) -> bool {
        self.next_header == other.next_header
            && self.spi == other.spi
            && self.sequence_number == other.sequence_number
            && self.raw_icv() == other.raw_icv()
    }
}

impl Eq for IpAuthHeader {}

impl<'a> IpAuthHeader {
    pub const MAX_ICV_LEN: usize = 0xfe * 4;

    /// Create a new authentication header with the given parameters.
    ///
    /// Note: The length of the raw_icv slice must be a multiple of 4
    /// and the maximum allowed length is 1016 bytes
    /// (`IpAuthHeader::MAX_ICV_LEN`). If the slice length does
    /// not fullfill these requirements the value is not copied and an
    /// `Err(ValueError::IpAuthenticationHeaderBadIcvLength)` is returned.
    /// If successfull an Ok(()) is returned.
    pub fn new(
        next_header: u8,
        spi: u32,
        sequence_number: u32,
        raw_icv: &'a [u8],
    ) -> Result<IpAuthHeader, ValueError> {
        if raw_icv.len() > IpAuthHeader::MAX_ICV_LEN || 0 != raw_icv.len() % 4 {
            use ValueError::*;
            Err(IpAuthenticationHeaderBadIcvLength(raw_icv.len()))
        } else {
            let mut result = IpAuthHeader {
                next_header,
                spi,
                sequence_number,
                raw_icv_len: (raw_icv.len() / 4) as u8,
                raw_icv_buffer: [0; IpAuthHeader::MAX_ICV_LEN],
            };
            result.raw_icv_buffer[..raw_icv.len()].copy_from_slice(raw_icv);
            Ok(result)
        }
    }

    /// Read an  authentication header from a slice and return the header & unused parts of the slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<(IpAuthHeader, &'a [u8]), ReadError> {
        let s = IpAuthHeaderSlice::from_slice(slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((header, rest))
    }

    /// Read an authentication header from the current reader position.
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<IpAuthHeader, ReadError> {
        let start = {
            let mut start = [0; 4 + 4 + 4];
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
            Ok(IpAuthHeader {
                next_header,
                spi: u32::from_be_bytes([start[4], start[5], start[6], start[7]]),
                sequence_number: u32::from_be_bytes([start[8], start[9], start[10], start[11]]),
                raw_icv_len: payload_len - 1,
                raw_icv_buffer: {
                    let mut buffer = [0; 0xfe * 4];
                    reader.read_exact(&mut buffer[..usize::from(payload_len - 1) * 4])?;
                    buffer
                },
            })
        }
    }

    /// Returns a slice the raw icv value.
    pub fn raw_icv(&self) -> &[u8] {
        &self.raw_icv_buffer[..usize::from(self.raw_icv_len) * 4]
    }

    /// Sets the icv value to the given raw value. The length of the slice must be
    /// a multiple of 4 and the maximum allowed length is 1016 bytes
    /// (`IpAuthHeader::MAX_ICV_LEN`). If the slice length does
    /// not fullfill these requirements the value is not copied and an
    /// `Err(ValueError::IpAuthenticationHeaderBadIcvLength)` is returned.
    /// If successfull an Ok(()) is returned.
    pub fn set_raw_icv(&mut self, raw_icv: &[u8]) -> Result<(), ValueError> {
        if raw_icv.len() > IpAuthHeader::MAX_ICV_LEN || 0 != raw_icv.len() % 4 {
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

        writer.write_all(&[
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
        ])?;
        writer.write_all(self.raw_icv())?;
        Ok(())
    }

    ///Length of the header in bytes.
    pub fn header_len(&self) -> usize {
        12 + usize::from(self.raw_icv_len) * 4
    }
}
