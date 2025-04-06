use crate::{
    err::{macsec, Layer, LenError},
    *,
};

/// MACsec packet (SecTag header & payload).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacsecSlice<'a> {
    pub header: MacsecHeaderSlice<'a>,
    pub payload: MacsecPayloadSlice<'a>,
}

impl<'a> MacsecSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<MacsecSlice<'a>, macsec::HeaderSliceError> {
        use macsec::HeaderSliceError::Len;

        let header = MacsecHeaderSlice::from_slice(slice)?;

        // validate the length of the slice if the short length is set
        let payload_slice = if header.short_length().value() > 0 {
            let required_len = header.slice().len() + usize::from(header.short_length().value());
            if slice.len() < required_len {
                return Err(Len(LenError {
                    required_len,
                    len: slice.len(),
                    len_source: LenSource::MacsecShortLength,
                    layer: Layer::MacsecPacket,
                    layer_start_offset: 0,
                }));
            }
            // SAFETY: Safe as the length was verified above to be at least required_len.
            unsafe { core::slice::from_raw_parts(slice.as_ptr(), required_len) }
        } else {
            // SAFETY: Safe as the header is a subslice of the original slice.
            unsafe {
                core::slice::from_raw_parts(
                    slice.as_ptr().add(header.slice().len()),
                    slice.len() - header.slice().len(),
                )
            }
        };

        let payload = if let Some(ether_type) = header.next_ether_type() {
            MacsecPayloadSlice::Unmodified(EtherPayloadSlice {
                ether_type,
                payload: payload_slice,
            })
        } else {
            MacsecPayloadSlice::Modified(payload_slice)
        };

        Ok(MacsecSlice { header, payload })
    }

    /// Get the ether payload if the macsec packet is unencrypted & unmodified.
    pub fn ether_payload(&self) -> Option<EtherPayloadSlice<'a>> {
        if let MacsecPayloadSlice::Unmodified(e) = &self.payload {
            Some(e.clone())
        } else {
            None
        }
    }

    /// Get the ether type of the payload if the macsec packet is unencrypted & unmodified.
    pub fn next_ether_type(&self) -> Option<EtherType> {
        self.header.next_ether_type()
    }
}
