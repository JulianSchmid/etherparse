use crate::{
    err::{Layer, LenError, LenSource},
    UdpHeader, UdpHeaderSlice,
};

/// Slice containing the UDP headers & payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSlice<'a> {
    slice: &'a [u8],
}

impl<'a> UdpSlice<'a> {
    /// Decode length from UDP header and restrict slice to the length
    /// of the header including the payload.
    ///
    /// Note that this method fall backs to the length of the slice
    /// in the case the length field in the UDP header is set to zero.
    pub fn from_slice(slice: &'a [u8]) -> Result<UdpSlice<'a>, LenError> {
        // slice header
        let header = UdpHeaderSlice::from_slice(slice)?;

        // validate the length of the slice
        let len: usize = header.length().into();
        if slice.len() < len {
            return Err(LenError {
                required_len: len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::UdpPayload,
                layer_start_offset: 0,
            });
        }

        // fallback to the slice length in
        if len == 0 {
            Ok(UdpSlice { slice })
        } else {
            // validate the length
            if len < UdpHeader::LEN {
                // TODO: Should this replaced with a custom error?
                Err(LenError {
                    required_len: UdpHeader::LEN,
                    len,
                    len_source: LenSource::UdpHeaderLen,
                    layer: Layer::UdpHeader,
                    layer_start_offset: 0,
                })
            } else {
                Ok(UdpSlice {
                    // SAFETY: Safe as slice.len() was validated before to
                    // be at least as big as "len".
                    slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), len) },
                })
            }
        }
    }

    /// Return the slice containing the UDP header.
    pub fn header(&'a self) -> UdpHeaderSlice<'a> {
        UdpHeaderSlice {
            slice: unsafe {
                // SAFETY: Safe as the slice length was verified
                // to be at least UdpHeader::LEN by "from_slice".
                core::slice::from_raw_parts(self.slice.as_ptr(), UdpHeader::LEN)
            },
        }
    }

    /// Returns the slice containing the UDP payload.
    pub fn payload(&'a self) -> &'a [u8] {
        unsafe {
            // SAFETY: Safe as the slice length was verified
            // to be at least UdpHeader::LEN by "from_slice".
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(UdpHeader::LEN),
                self.slice.len() - UdpHeader::LEN,
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug_clone_eq(
            udp_base in udp_any()
        ) {
            let payload: [u8;4] = [1,2,3,4];
            let mut data = Vec::with_capacity(
                udp_base.header_len() +
                payload.len()
            );
            let mut udp = udp_base.clone();
            udp.length = (UdpHeader::LEN + payload.len()) as u16;
            data.extend_from_slice(&udp.to_bytes());
            data.extend_from_slice(&payload);

            // decode packet
            let slice = UdpSlice::from_slice(&data).unwrap();

            // check debug output
            prop_assert_eq!(
                format!("{:?}", slice),
                format!(
                    "UdpSlice {{ slice: {:?} }}",
                    &data[..],
                )
            );
            prop_assert_eq!(slice.clone(), slice);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            udp_base in udp_any()
        ) {
            let payload: [u8;4] = [1,2,3,4];
            let data = {
                let mut data = Vec::with_capacity(
                    udp_base.header_len() +
                    payload.len()
                );
                let mut udp = udp_base.clone();
                udp.length = (UdpHeader::LEN + payload.len()) as u16;
                data.extend_from_slice(&udp.to_bytes());
                data.extend_from_slice(&payload);
                data
            };

            // normal decode
            {
                let slice = UdpSlice::from_slice(&data).unwrap();
                {
                    let header = slice.header();
                    assert_eq!(header.source_port(), udp_base.source_port);
                    assert_eq!(header.destination_port(), udp_base.destination_port);
                    assert_eq!(header.checksum(), udp_base.checksum);
                    assert_eq!(header.length() as usize, payload.len() + UdpHeader::LEN);
                }
                assert_eq!(payload, slice.payload());
            }

            // decode a payload smaller then the given slice
            {
                let mut mod_data = data.clone();
                let reduced_len = (UdpHeader::LEN + payload.len() - 1) as u16;
                // inject the reduced length
                {
                    let rl_be = reduced_len.to_be_bytes();
                    mod_data[4] = rl_be[0];
                    mod_data[5] = rl_be[1];
                }

                let slice = UdpSlice::from_slice(&mod_data).unwrap();
                {
                    let header = slice.header();
                    assert_eq!(header.source_port(), udp_base.source_port);
                    assert_eq!(header.destination_port(), udp_base.destination_port);
                    assert_eq!(header.checksum(), udp_base.checksum);
                    assert_eq!(header.length(), reduced_len);
                }
                assert_eq!(&payload[..payload.len() - 1], slice.payload());
            }

            // if length is zero the length given by the slice should be used
            {
                // inject zero as length
                let mut mod_data = data.clone();
                mod_data[4] = 0;
                mod_data[5] = 0;

                let slice = UdpSlice::from_slice(&mod_data).unwrap();
                {
                    let header = slice.header();
                    assert_eq!(header.source_port(), udp_base.source_port);
                    assert_eq!(header.destination_port(), udp_base.destination_port);
                    assert_eq!(header.checksum(), udp_base.checksum);
                    assert_eq!(header.length(), 0);
                }
                assert_eq!(&payload, slice.payload());
            }

            // too little data to even decode the header
            for len in 0..UdpHeader::LEN {
                assert_eq!(
                    UdpSlice::from_slice(&data[..len]).unwrap_err(),
                    LenError {
                        required_len: UdpHeader::LEN,
                        len,
                        len_source: LenSource::Slice,
                        layer: Layer::UdpHeader,
                        layer_start_offset: 0,
                    }
                );
            }

            // slice length smaller then the length described in the header
            assert_eq!(
                UdpSlice::from_slice(&data[..data.len() - 1]).unwrap_err(),
                LenError {
                    required_len: data.len(),
                    len: data.len() - 1,
                    len_source: LenSource::Slice,
                    layer: Layer::UdpPayload,
                    layer_start_offset: 0,
                }
            );

            // length in header smaller than the header itself
            {
                let mut mod_data = data.clone();
                // inject the reduced length
                {
                    let len_be = ((UdpHeader::LEN - 1) as u16).to_be_bytes();
                    mod_data[4] = len_be[0];
                    mod_data[5] = len_be[1];
                }
                assert_eq!(
                    UdpSlice::from_slice(&mod_data).unwrap_err(),
                    LenError {
                        required_len: UdpHeader::LEN,
                        len: UdpHeader::LEN - 1,
                        len_source: LenSource::UdpHeaderLen,
                        layer: Layer::UdpHeader,
                        layer_start_offset: 0
                    }
                );
            }
        }
    }
}
