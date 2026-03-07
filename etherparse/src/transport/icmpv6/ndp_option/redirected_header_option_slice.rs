use crate::icmpv6::{NdpOptionReadError, NdpOptionType};

/// Redirected Header option slice (RFC 4861, Section 4.6.3, type 4).
///
/// The option layout is:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |            Reserved           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                       IP header + data                        ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This slice stores the full serialized option, including the
/// `Type` and `Length` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectedHeaderOptionSlice<'a> {
    slice: &'a [u8],
}

impl<'a> RedirectedHeaderOptionSlice<'a> {
    /// Length in bytes of the fixed part (`Type`, `Length`, and reserved fields).
    const FIXED_PART_LEN: usize = 8;

    pub fn from_slice(slice: &'a [u8]) -> Result<Self, NdpOptionReadError> {
        if slice.len() >= Self::FIXED_PART_LEN {
            Ok(Self { slice })
        } else {
            Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::REDIRECTED_HEADER,
                expected_size: Self::FIXED_PART_LEN,
                actual_size: slice.len(),
            })
        }
    }

    /// Returns the option type value (4).
    pub const fn option_type(&self) -> NdpOptionType {
        NdpOptionType::REDIRECTED_HEADER
    }

    /// Returns the serialized option bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the redirected packet bytes carried by the option.
    pub fn redirected_packet(&self) -> &'a [u8] {
        &self.slice[Self::FIXED_PART_LEN..]
    }
}
