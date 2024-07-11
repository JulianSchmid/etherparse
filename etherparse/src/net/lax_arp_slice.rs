use crate::{err::{self, ip::LaxHeaderSliceError}, LaxArpHeaderSlice, LaxArpPayloadSlice};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxArpSlice<'a> {
    pub(crate) header: LaxArpHeaderSlice<'a>,
    pub(crate) payload: LaxArpPayloadSlice<'a>,
}

impl<'a> LaxArpSlice<'a> {
    pub(crate) fn from_slice(slice: &'a [u8]) -> Result<Self, err::ip::LaxHeaderSliceError> {
        let (header, slice) = LaxArpHeaderSlice::from_slice(slice)?;
        let payload = LaxArpPayloadSlice::from_slice(
            &header
                .to_header()
                .map_err(|e| LaxHeaderSliceError::Len(e))?,
            slice,
        )?;
        Ok(Self { header, payload })
    }
}
