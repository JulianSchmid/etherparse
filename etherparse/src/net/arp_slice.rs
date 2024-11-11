use crate::{err, ArpHeaderSlice, ArpPayloadSlice};

use super::ArpHeader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArpSlice<'a> {
    pub(crate) header: ArpHeaderSlice<'a>,
    pub(crate) payload: ArpPayloadSlice<'a>,
}

impl<'a> ArpSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        let (header, slice) = ArpHeaderSlice::from_slice(slice)?;
        let payload = ArpPayloadSlice::from_slice(&header.to_header()?.0, slice)?;
        Ok(Self { header, payload })
    }

    #[inline]
    pub fn header(&self) -> &ArpHeaderSlice<'a> {
        &self.header
    }

    #[inline]
    pub fn payload(&self) -> &ArpPayloadSlice<'a> {
        &self.payload
    }

    pub fn len(&self) -> usize {
        ArpHeader::LEN + self.payload.payload.len()
    }
}
