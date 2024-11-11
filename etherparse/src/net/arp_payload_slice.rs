use crate::{
    err::{self, Layer},
    ArpHeader, LenSource,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ArpPayloadSlice<'a> {
    pub payload: &'a [u8],
}

impl<'a> ArpPayloadSlice<'a> {
    pub(crate) fn from_slice(head: &ArpHeader, slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() != head.expected_payload_len() {
            return Err(err::LenError {
                required_len: head.expected_payload_len(),
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::ArpPayload,
                layer_start_offset: 0,
            });
        }

        Ok(Self { payload: slice })
    }
}
