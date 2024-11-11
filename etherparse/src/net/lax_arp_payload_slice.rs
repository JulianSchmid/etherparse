use crate::{
    err::{self, Layer},
    ArpHeader, LenSource,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxArpPayloadSlice<'a> {
    pub(crate) payload: &'a [u8],
}

impl<'a> LaxArpPayloadSlice<'a> {
    pub(crate) fn from_slice(
        head: &ArpHeader,
        slice: &'a [u8],
    ) -> Result<Self, err::ip::LaxHeaderSliceError> {
        if slice.len() != head.expected_payload_len() {
            return Err(err::ip::LaxHeaderSliceError::Len(err::LenError {
                required_len: head.expected_payload_len(),
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::ArpPayload,
                layer_start_offset: 0,
            }));
        }

        Ok(Self { payload: slice })
    }

    pub(crate) fn len(&self) -> usize {
        self.payload.len()
    }
}
