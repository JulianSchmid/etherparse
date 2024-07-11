use crate::{err, ArpHeaderSlice, ArpPayloadSlice};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpSlice<'a> {
    pub(crate) header: ArpHeaderSlice<'a>,
    pub(crate) payload: ArpPayloadSlice<'a>,
}

impl<'a> ArpSlice<'a> {
    pub(crate) fn from_slice(slice: &'a [u8]) -> Result<Self,  err::LenError> {
        let (header, slice) = ArpHeaderSlice::from_slice(slice)?;
        let payload = ArpPayloadSlice::from_slice(&header.to_header()?.0, slice)?;
        Ok(Self { header, payload })
    }

    pub(crate) fn header(&self) -> &ArpHeaderSlice<'a> {
        &self.header
    }
    
    pub(crate) fn len(&self) -> usize {
        self.payload.len() + 8
    }
}