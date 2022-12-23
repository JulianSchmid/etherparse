use crate::*;
use std::io;

///Ethernet II header.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ethernet2Header {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ether_type: u16,
}

impl SerializedSize for Ethernet2Header {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 14;
}

impl Ethernet2Header {
    /// Creates a ethernet slice from an other slice.
    #[deprecated(since = "0.10.1", note = "Use Ethernet2Header::from_slice instead.")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ethernet2Header, &[u8]), ReadError> {
        Ethernet2Header::from_slice(slice)
    }

    /// Read an Ethernet2Header from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Ethernet2Header, &[u8]), ReadError> {
        Ok((
            Ethernet2HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Ethernet2Header::SERIALIZED_SIZE..],
        ))
    }

    /// Read an Ethernet2Header from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 14]) -> Ethernet2Header {
        Ethernet2Header {
            destination: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
            source: [bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]],
            ether_type: u16::from_be_bytes([bytes[12], bytes[13]]),
        }
    }

    /// Reads an Ethernet-II header from the current position of the read argument.
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<Ethernet2Header, io::Error> {
        let buffer = {
            let mut buffer = [0; Ethernet2Header::SERIALIZED_SIZE];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(
            // SAFETY: Safe as the buffer contains exactly the needed Ethernet2Header::SERIALIZED_SIZE bytes.
            unsafe {
                Ethernet2HeaderSlice::from_slice_unchecked(&buffer)
            }.to_header()
        )
    }

    /// Serialize the header to a given slice. Returns the unused part of the slice.
    pub fn write_to_slice<'a>(&self, slice: &'a mut [u8]) -> Result<&'a mut [u8], WriteError> {
        use self::WriteError::*;
        //length check
        if slice.len() < Ethernet2Header::SERIALIZED_SIZE {
            Err(SliceTooSmall(Ethernet2Header::SERIALIZED_SIZE))
        } else {
            slice[..Ethernet2Header::SERIALIZED_SIZE].copy_from_slice(&self.to_bytes());
            Ok(&mut slice[Ethernet2Header::SERIALIZED_SIZE..])
        }
    }

    /// Writes a given Ethernet-II header to the current position of the write argument.
    #[inline]
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        14
    }

    /// Returns the serialized form of the header as a statically
    /// sized byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 14] {
        let ether_type_be = self.ether_type.to_be_bytes();
        [
            self.destination[0],
            self.destination[1],
            self.destination[2],
            self.destination[3],
            self.destination[4],
            self.destination[5],
            self.source[0],
            self.source[1],
            self.source[2],
            self.source[3],
            self.source[4],
            self.source[5],
            ether_type_be[0],
            ether_type_be[1],
        ]
    }
}
