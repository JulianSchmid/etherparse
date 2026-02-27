use super::NDP_OPTION_HEADER_LEN;
use crate::icmpv6::{NdpOptionReadError, NdpOptionType};

/// Target Link-Layer Address option slice (RFC 4861, Section 4.6.1, type 2).
///
/// The option layout is:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |    Link-Layer Address ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This slice stores the full serialized option, including the
/// `Type` and `Length` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetLinkLayerAddressOptionSlice<'a> {
    slice: &'a [u8],
}

impl<'a> TargetLinkLayerAddressOptionSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, NdpOptionReadError> {
        if slice.len() >= NDP_OPTION_HEADER_LEN {
            Ok(Self { slice })
        } else {
            Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::TARGET_LINK_LAYER_ADDRESS,
                expected_size: NDP_OPTION_HEADER_LEN,
                actual_size: slice.len(),
            })
        }
    }

    /// Returns the option type value (2).
    pub const fn option_type(&self) -> NdpOptionType {
        NdpOptionType::TARGET_LINK_LAYER_ADDRESS
    }

    /// Returns the serialized option bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the link-layer address bytes carried by the option.
    pub fn link_layer_address(&self) -> &'a [u8] {
        &self.slice[NDP_OPTION_HEADER_LEN..]
    }
}
