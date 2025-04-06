use crate::{err::macsec, *};

/// MACsec packet (SecTag header & payload).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxMacsecSlice<'a> {
    pub header: MacsecHeaderSlice<'a>,
    pub payload: LaxMacsecPayloadSlice<'a>,
}

impl<'a> LaxMacsecSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<LaxMacsecSlice<'a>, macsec::HeaderSliceError> {
        let header = MacsecHeaderSlice::from_slice(slice)?;
        // validate the length of the slice if the short length is set
        let (incomplete, payload_slice) = if header.short_length().value() > 0 {
            let required_len = header.slice().len() + usize::from(header.short_length().value());
            if slice.len() < required_len {
                (true, slice)
            } else {
                (
                    false,
                    // SAFETY: Safe as the length was verified above to be at least required_len.
                    unsafe { core::slice::from_raw_parts(slice.as_ptr(), required_len) },
                )
            }
        } else {
            (
                false,
                // SAFETY: Safe as the header is a subslice of the original slice.
                unsafe {
                    core::slice::from_raw_parts(
                        slice.as_ptr().add(header.slice().len()),
                        slice.len() - header.slice().len(),
                    )
                },
            )
        };

        let payload = if let Some(ether_type) = header.next_ether_type() {
            LaxMacsecPayloadSlice::Unmodified(LaxEtherPayloadSlice {
                incomplete,
                ether_type,
                payload: payload_slice,
            })
        } else {
            LaxMacsecPayloadSlice::Modified {
                incomplete,
                payload: payload_slice,
            }
        };

        Ok(LaxMacsecSlice { header, payload })
    }

    /// Get the ether payload if the macsec packet is unencrypted & unmodified.
    pub fn ether_payload(&self) -> Option<LaxEtherPayloadSlice<'a>> {
        if let LaxMacsecPayloadSlice::Unmodified(e) = &self.payload {
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
