use crate::{
    err::{self, Layer, LenError},
    ArpHeader, LenSource,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxArpHeaderSlice<'a> {
    pub(crate) payload: &'a [u8],
}

impl<'a> LaxArpHeaderSlice<'a> {
    pub(crate) fn from_slice(
        slice: &'a [u8],
    ) -> Result<(Self, &'a [u8]), err::ip::LaxHeaderSliceError> {
        if slice.len() < 8 {
            return Err(err::ip::LaxHeaderSliceError::Len(LenError {
                required_len: 8,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::ArpHeader,
                layer_start_offset: 0,
            }));
        }

        Ok((
            Self {
                payload: &slice[..8],
            },
            &slice[8..],
        ))
    }

    pub fn to_header(&self) -> Result<ArpHeader, err::LenError> {
        ArpHeader::from_slice(self.payload).map(|e| e.0)
    }
}
