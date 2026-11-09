use crate::icmpv6::{NdpOptionHeader, NdpOptionReadError, NdpOptionType};

/// Recursive DNS Server (RDNSS) option slice (RFC 8106, Section 5.1, type 25).
///
/// The option layout is:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     Type      |     Length    |           Reserved            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                           Lifetime                            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  :            Addresses of IPv6 Recursive DNS Servers            :
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This slice stores the full serialized option, including the
/// `Type` and `Length` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveDnsServerOptionSlice<'a> {
    slice: &'a [u8],
}

impl<'a> RecursiveDnsServerOptionSlice<'a> {
    const FIXED_PART_LEN: usize = 8;
    const LIFETIME_OFFSET: usize = 4;

    /// Decodes exactly one complete option, including its type and length bytes.
    ///
    /// Requires an odd length of at least three eight-byte units (one or more
    /// IPv6 server addresses). Returns an error for a wrong type, an invalid
    /// encoded length, or a slice whose size differs from that length.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, NdpOptionReadError> {
        if slice.len() < Self::FIXED_PART_LEN {
            return Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::RDNSS,
                expected_size: Self::FIXED_PART_LEN,
                actual_size: slice.len(),
            });
        }

        let (header, _) = NdpOptionHeader::from_slice(slice)?;
        if NdpOptionType::RDNSS != header.option_type {
            return Err(NdpOptionReadError::UnexpectedHeader {
                expected_option_id: NdpOptionType::RDNSS,
                actual_option_id: header.option_type,
                expected_length_units: header.length_units,
                actual_length_units: header.length_units,
            });
        }

        let length_units = header.length_units;
        if length_units == 0 {
            return Err(NdpOptionReadError::ZeroLength {
                option_id: NdpOptionType::RDNSS,
            });
        }

        if length_units < 3 || length_units % 2 == 0 {
            let expected_length_units = (length_units + 1).max(3);

            return Err(NdpOptionReadError::UnexpectedHeader {
                expected_option_id: NdpOptionType::RDNSS,
                actual_option_id: header.option_type,
                expected_length_units,
                actual_length_units: length_units,
            });
        }

        let expected_total_size = header.byte_len();
        if slice.len() != expected_total_size {
            return Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::RDNSS,
                expected_size: expected_total_size,
                actual_size: slice.len(),
            });
        }

        Ok(Self { slice })
    }

    /// Return the option type value (25).
    pub const fn option_type(&self) -> NdpOptionType {
        NdpOptionType::RDNSS
    }

    /// Returns the serialized option bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the lifetime of the advertised recursive DNS servers in seconds.
    pub fn lifetime(&self) -> u32 {
        u32::from_be_bytes(*self.slice[Self::LIFETIME_OFFSET..].first_chunk().unwrap())
    }

    /// Iterates over the server addresses as borrowed, network-order IPv6 octets.
    pub fn servers(&self) -> impl ExactSizeIterator<Item = &'a [u8; 16]> {
        self.slice[Self::FIXED_PART_LEN..]
            .chunks_exact(16)
            // Each chunk is exactly one IPv6 address.
            .map(|chunk| chunk.first_chunk().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_validate() {
        let mut bytes = [0; 40];
        bytes[..8].copy_from_slice(&[25, 5, 0, 0, 1, 2, 3, 4]);
        bytes[8..24].fill(1);
        bytes[24..].fill(2);
        let option = RecursiveDnsServerOptionSlice::from_slice(&bytes).unwrap();
        assert_eq!(option.lifetime(), 0x01020304);
        assert_eq!(option.servers().len(), 2);
        assert!(option.servers().eq([&[1; 16], &[2; 16]]));
        for length in 0..=5 {
            bytes[1] = length;
            let size = length as usize * 8;
            assert_eq!(
                RecursiveDnsServerOptionSlice::from_slice(&bytes[..size]).is_ok(),
                length == 3 || length == 5
            );
            if length >= 3 {
                assert!(RecursiveDnsServerOptionSlice::from_slice(&bytes[..size - 1]).is_err());
            }
        }
    }
}
