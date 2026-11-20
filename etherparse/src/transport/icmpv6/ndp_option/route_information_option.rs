use core::ops::Shr;

use crate::icmpv6::{NdpOptionHeader, NdpOptionReadError, NdpOptionType};

/// Route Information option slice (RFC 4191, Section 2.3, type 24).
///
/// The option layout is:
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     | Prefix Length |Resvd|Prf|Resvd|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Route Lifetime                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Prefix (Variable Length)                    |
/// .                                                               .
/// .                                                               .
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This slice stores the full serialized option, including the
/// `Type` and `Length` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteInformationOptionSlice<'a> {
    slice: &'a [u8],
}

impl<'a> RouteInformationOptionSlice<'a> {
    const FIXED_PART_LEN: usize = 8;
    const PREFIX_LENGTH_OFFSET: usize = 2;
    const FLAGS_OFFSET: usize = 3;
    const NUMBER_PREF_BITS: u8 = 2;
    const OFFET_PREF_BITS: u8 = 3;
    const ROUTE_LIFETIME_OFFSET: usize = 4;

    /// Decodes exactly one complete option, including its type and length bytes.
    ///
    /// Returns an error for a wrong type, a length other than 1, 2 or 3
    /// eight-byte units, a prefix longer than the encoded space (or 128 bits),
    /// or a slice whose size differs from the encoded length.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, NdpOptionReadError> {
        if slice.len() < Self::FIXED_PART_LEN {
            return Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::ROUTE_INFORMATION,
                expected_size: Self::FIXED_PART_LEN,
                actual_size: slice.len(),
            });
        }

        let (header, _) = NdpOptionHeader::from_slice(slice)?;
        if NdpOptionType::ROUTE_INFORMATION != header.option_type {
            return Err(NdpOptionReadError::UnexpectedHeader {
                expected_option_id: NdpOptionType::ROUTE_INFORMATION,
                actual_option_id: header.option_type,
                expected_length_units: header.length_units,
                actual_length_units: header.length_units,
            });
        }

        if 0 == header.length_units {
            return Err(NdpOptionReadError::ZeroLength {
                option_id: header.option_type,
            });
        }

        let prefix_length = slice[Self::PREFIX_LENGTH_OFFSET];
        if prefix_length > 128 {
            return Err(NdpOptionReadError::InvalidRoutePrefixLength { prefix_length });
        }

        let valid = match header.length_units {
            1 => prefix_length == 0,
            2 => prefix_length <= 64,
            3 => true,
            _ => false,
        };

        if !valid {
            return Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::ROUTE_INFORMATION,
                expected_size: match prefix_length {
                    0 => 8,
                    1..=64 => 16,
                    _ => 24,
                },
                actual_size: header.byte_len(),
            });
        }

        let expected_size = header.byte_len();
        if expected_size != slice.len() {
            return Err(NdpOptionReadError::UnexpectedSize {
                option_id: header.option_type,
                expected_size,
                actual_size: slice.len(),
            });
        }

        Ok(Self { slice })
    }

    /// Return the option type value (24).
    pub const fn option_type(&self) -> NdpOptionType {
        NdpOptionType::ROUTE_INFORMATION
    }

    /// Returns the serialized option bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the prefix length (in bits).
    pub fn prefix_length(&self) -> u8 {
        self.slice[Self::PREFIX_LENGTH_OFFSET]
    }

    /// Returns the raw two-bit route preference: 0 = medium, 1 = high,
    /// 3 = low. The reserved value 2 is returned unchanged.
    pub fn route_preference(&self) -> u8 {
        let flags = self.slice[Self::FLAGS_OFFSET];
        let mask = u8::MAX.shr(8 - Self::NUMBER_PREF_BITS);
        (flags >> Self::OFFET_PREF_BITS) & mask
    }

    /// Returns the route lifetime in seconds.
    pub fn valid_route_lifetime(&self) -> u32 {
        u32::from_be_bytes(
            *self.slice[Self::ROUTE_LIFETIME_OFFSET..]
                .first_chunk()
                .unwrap(),
        )
    }

    /// Returns the prefix bytes with all bits beyond the prefix length set to zero.
    pub fn prefix(&self) -> [u8; 16] {
        let prefix_length = self.prefix_length();
        let length = prefix_length.div_ceil(8) as usize;
        let mut octets = [0u8; 16];
        octets[..length]
            .copy_from_slice(&self.slice[Self::FIXED_PART_LEN..Self::FIXED_PART_LEN + length]);
        let remaining_bits = prefix_length % 8;
        if remaining_bits != 0 {
            octets[length - 1] &= u8::MAX << (8 - remaining_bits);
        }
        octets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_type_and_as_bytes() {
        let mut bytes = [0xff; 24];
        bytes[..8].copy_from_slice(&[24, 3, 65, 0x18, 0, 0, 0, 60]);
        let option = RouteInformationOptionSlice::from_slice(&bytes).unwrap();

        assert_eq!(NdpOptionType::ROUTE_INFORMATION, option.option_type());
        assert_eq!(&bytes, option.as_bytes());
        assert_eq!(65, option.prefix_length());
        assert_eq!(3, option.route_preference());
        assert_eq!(60, option.valid_route_lifetime());

        let mut prefix = [0; 16];
        prefix[..8].fill(0xff);
        prefix[8] = 0x80;
        assert_eq!(prefix, option.prefix());
    }

    #[test]
    fn from_slice() {
        for (length_units, prefix_length) in [(1, 0), (2, 64), (3, 64), (3, 128)] {
            let mut bytes = [0xab; 24];
            bytes[..8].copy_from_slice(&[24, length_units, prefix_length, 0, 0, 0, 0, 0]);
            let size = usize::from(length_units) * 8;
            let option = RouteInformationOptionSlice::from_slice(&bytes[..size]).unwrap();

            let mut prefix = [0; 16];
            prefix[..usize::from(prefix_length / 8)].fill(0xab);
            assert_eq!(prefix_length, option.prefix_length());
            assert_eq!(prefix, option.prefix());
        }
    }

    #[test]
    fn from_slice_errors() {
        for (length_units, prefix_length, actual_size, expected_size) in [
            (3, 128, 23, 24), // Truncated option.
            (1, 1, 8, 16),    // No space for prefix bits.
            (2, 65, 16, 24),  // Only 64 prefix bits fit.
            (4, 0, 32, 8),    // Invalid option length.
        ] {
            let mut bytes = [0; 32];
            bytes[..3].copy_from_slice(&[24, length_units, prefix_length]);
            assert_eq!(
                Err(NdpOptionReadError::UnexpectedSize {
                    option_id: NdpOptionType::ROUTE_INFORMATION,
                    expected_size,
                    actual_size,
                }),
                RouteInformationOptionSlice::from_slice(&bytes[..actual_size])
            );
        }

        let mut bytes = [0; 24];
        bytes[..3].copy_from_slice(&[24, 3, 129]);
        assert_eq!(
            Err(NdpOptionReadError::InvalidRoutePrefixLength { prefix_length: 129 }),
            RouteInformationOptionSlice::from_slice(&bytes)
        );
    }
}
