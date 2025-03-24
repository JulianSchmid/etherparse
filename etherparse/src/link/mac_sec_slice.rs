use crate::{
    err::{macsec, Layer, LenError},
    *,
};

///
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacSecSlice<'a> {
    pub header: MacSecHeaderSlice<'a>,
    pub payload: MacSecPayloadSlice<'a>,
}

impl<'a> MacSecSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<MacSecSlice<'a>, macsec::HeaderSliceError> {
        use macsec::HeaderSliceError::Len;

        let header = MacSecHeaderSlice::from_slice(slice)?;

        // validate the length of the slice if the short length is set
        let payload_slice = if header.short_length().value() > 0 {
            let required_len = header.slice().len() + usize::from(header.short_length().value());
            if slice.len() < required_len {
                return Err(Len(LenError {
                    required_len,
                    len: slice.len(),
                    len_source: LenSource::MacSecShortLength,
                    layer: Layer::MacSecPacket,
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
            MacSecPayloadSlice::Unmodified(EtherPayloadSlice {
                ether_type,
                payload: payload_slice,
            })
        } else {
            MacSecPayloadSlice::Modified(payload_slice)
        };

        Ok(MacSecSlice { header, payload })
    }
}
