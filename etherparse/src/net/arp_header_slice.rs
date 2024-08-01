use crate::{
    err::{self, Layer},
    ArpHeader, LenSource,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> ArpHeaderSlice<'a> {
    pub(crate) fn from_slice(slice: &'a [u8]) -> Result<(Self, &[u8]), err::LenError> {
        if slice.len() < ArpHeader::LEN {
            return Err(err::LenError {
                required_len: ArpHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::ArpHeader,
                layer_start_offset: 0,
            });
        }
        Ok((
            Self {
                slice: &slice[0..ArpHeader::LEN],
            },
            &slice[ArpHeader::LEN..],
        ))
    }

    pub(crate) fn to_header(&self) -> Result<(ArpHeader, &[u8]), err::LenError> {
        // SAFETY:
        // This is safe as the slice length is checked to be
        // at least ArpHeader::LEN
        // at the start of the function.
        ArpHeader::from_slice(&self.slice)
    }
}
