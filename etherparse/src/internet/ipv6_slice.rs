use crate::err::{ipv6::SliceError, Layer, LenError, LenSource};
use crate::{IpPayload, Ipv6ExtensionsSlice, Ipv6Header, Ipv6HeaderSlice};

/// Slice containing the IPv6 headers & payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Slice<'a> {
    pub(crate) header: Ipv6HeaderSlice<'a>,
    pub(crate) exts: Ipv6ExtensionsSlice<'a>,
    pub(crate) payload: IpPayload<'a>,
}

impl<'a> Ipv6Slice<'a> {
    /// Decode IPv6 header, extension headers and determine the payload
    /// length based on the `payload_length` field in the IPv6 header.
    pub fn from_slice(slice: &'a [u8]) -> Result<Ipv6Slice<'a>, SliceError> {
        // try reading the header
        let header = Ipv6HeaderSlice::from_slice(slice).map_err(|err| {
            use crate::err::ipv6::HeaderSliceError::*;
            match err {
                Len(err) => SliceError::Len(err),
                Content(err) => SliceError::Header(err),
            }
        })?;

        // restrict slice by the length specified in the header
        let (header_payload, len_source) =
            if 0 == header.payload_length() && slice.len() > Ipv6Header::LEN {
                // In case the payload_length is 0 assume that the entire
                // rest of the slice is part of the packet until the jumbogram
                // parameters can be parsed.

                // TODO: Add payload length parsing from the jumbogram
                (
                    unsafe {
                        core::slice::from_raw_parts(
                            slice.as_ptr().add(Ipv6Header::LEN),
                            slice.len() - Ipv6Header::LEN,
                        )
                    },
                    LenSource::Slice,
                )
            } else {
                let payload_len = usize::from(header.payload_length());
                let expected_len = Ipv6Header::LEN + payload_len;
                if slice.len() < expected_len {
                    return Err(SliceError::Len(LenError {
                        required_len: expected_len,
                        len: slice.len(),
                        len_source: LenSource::Slice,
                        layer: Layer::Ipv6Packet,
                        layer_start_offset: 0,
                    }));
                } else {
                    (
                        unsafe {
                            core::slice::from_raw_parts(
                                slice.as_ptr().add(Ipv6Header::LEN),
                                payload_len,
                            )
                        },
                        LenSource::Ipv6HeaderPayloadLen,
                    )
                }
            };

        // parse extension headers
        let (exts, payload_ip_number, payload) =
            Ipv6ExtensionsSlice::from_slice(header.next_header(), header_payload).map_err(
                |err| {
                    // modify length errors
                    use crate::err::ipv6_exts::HeaderSliceError::*;
                    match err {
                        Len(mut err) => {
                            err.len_source = LenSource::Ipv6HeaderPayloadLen;
                            err.layer_start_offset += Ipv6Header::LEN;
                            SliceError::Len(err)
                        }
                        Content(err) => SliceError::Exts(err),
                    }
                },
            )?;

        let fragmented = exts.is_fragmenting_payload();
        Ok(Ipv6Slice {
            header,
            exts,
            payload: IpPayload {
                ip_number: payload_ip_number,
                fragmented,
                len_source,
                payload,
            },
        })
    }

    /// Returns a slice containing the IPv6 header.
    #[inline]
    pub fn header(&self) -> Ipv6HeaderSlice<'a> {
        self.header
    }

    /// Returns a slice containing the IPv6 extension headers.
    #[inline]
    pub fn extensions(&self) -> &Ipv6ExtensionsSlice<'a> {
        &self.exts
    }

    /// Returns a slice containing the data after the IPv6 header
    /// and IPv6 extensions headers.
    #[inline]
    pub fn payload(&self) -> &IpPayload<'a> {
        &self.payload
    }

    /// Returns true if the payload is flagged as beeing fragmented.
    #[inline]
    pub fn is_payload_fragmented(&self) -> bool {
        self.payload.fragmented
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ip_number::{AUTH, IGMP, UDP},
        test_gens::*,
        Ipv6FragmentHeader,
    };
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug_clone_eq(
            ipv6_base in ipv6_any(),
            auth_base in ip_auth_any()
        ) {
            let mut auth = auth_base.clone();
            auth.next_header = IGMP;
            let payload: [u8;4] = [1,2,3,4];
            let mut data = Vec::with_capacity(
                ipv6_base.header_len() +
                auth.header_len() +
                payload.len()
            );
            let mut ipv6 = ipv6_base.clone();
            ipv6.next_header = AUTH;
            ipv6.payload_length = (auth.header_len() + payload.len()) as u16;
            data.extend_from_slice(&ipv6.to_bytes());
            data.extend_from_slice(&auth.to_bytes());
            data.extend_from_slice(&payload);

            // decode packet
            let slice = Ipv6Slice::from_slice(&data).unwrap();

            // check debug output
            prop_assert_eq!(
                format!("{:?}", slice),
                format!(
                    "Ipv6Slice {{ header: {:?}, exts: {:?}, payload: {:?} }}",
                    slice.header(),
                    slice.extensions(),
                    slice.payload()
                )
            );
            prop_assert_eq!(slice.clone(), slice);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            ipv6_base in ipv6_any(),
            auth_base in ip_auth_any()
        ) {
            let payload: [u8;6] = [1,2,3,4,5,6];

            // build packets
            let data_without_ext = {
                let mut data = Vec::with_capacity(
                    ipv6_base.header_len() +
                    payload.len() +
                    4
                );
                let mut ipv6 = ipv6_base.clone();
                ipv6.payload_length = (payload.len()) as u16;
                ipv6.next_header = UDP;
                data.extend_from_slice(&ipv6.to_bytes());
                data.extend_from_slice(&payload);
                data.extend_from_slice(&[0,0,0,0]);
                data
            };
            let data_with_ext = {
                let payload: [u8;6] = [1,2,3,4,5,6];
                let mut data = Vec::with_capacity(
                    ipv6_base.header_len() +
                    auth_base.header_len() +
                    payload.len() +
                    4
                );
                let mut ipv6 = ipv6_base.clone();
                ipv6.payload_length = (auth_base.header_len() + payload.len()) as u16;
                ipv6.next_header = AUTH;
                let mut auth = auth_base.clone();
                auth.next_header = UDP;
                data.extend_from_slice(&ipv6.to_bytes());
                data.extend_from_slice(&auth.to_bytes());
                data.extend_from_slice(&payload);
                data.extend_from_slice(&[0,0,0,0]);
                data
            };

            // parsing without extensions (normal length)
            {
                let actual = Ipv6Slice::from_slice(&data_without_ext).unwrap();
                prop_assert_eq!(actual.header().slice(), &data_without_ext[..ipv6_base.header_len()]);
                prop_assert!(actual.extensions().first_header().is_none());
                prop_assert_eq!(
                    actual.payload(),
                    &IpPayload{
                        ip_number: UDP.into(),
                        fragmented: false,
                        len_source: LenSource::Ipv6HeaderPayloadLen,
                        payload: &payload,
                    }
                );
            }

            // parsing with extensions (normal length)
            {
                let actual = Ipv6Slice::from_slice(&data_with_ext).unwrap();
                prop_assert_eq!(actual.header().slice(), &data_with_ext[..ipv6_base.header_len()]);
                let (expected, _, _) = Ipv6ExtensionsSlice::from_slice(AUTH, &data_with_ext[ipv6_base.header_len()..]).unwrap();
                prop_assert_eq!(
                    actual.extensions(),
                    &expected
                );
                prop_assert_eq!(
                    actual.payload(),
                    &IpPayload{
                        ip_number: UDP.into(),
                        fragmented: false,
                        len_source: LenSource::Ipv6HeaderPayloadLen,
                        payload: &payload,
                    }
                );
            }

            // parsing without extensions (zero length, fallback to slice length)
            {
                // inject zero as payload length
                let mut data = data_without_ext.clone();
                data[4] = 0;
                data[5] = 0;
                let actual = Ipv6Slice::from_slice(&data).unwrap();
                prop_assert_eq!(actual.header().slice(), &data[..ipv6_base.header_len()]);
                prop_assert!(actual.extensions().first_header().is_none());
                prop_assert_eq!(
                    actual.payload(),
                    &IpPayload{
                        ip_number: UDP.into(),
                        fragmented: false,
                        len_source: LenSource::Slice,
                        payload: &data[ipv6_base.header_len()..],
                    }
                );
            }

            // parsing with extensions (zero length, fallback to slice length)
            {
                // inject zero as payload length
                let mut data = data_with_ext.clone();
                data[4] = 0;
                data[5] = 0;
                let actual = Ipv6Slice::from_slice(&data).unwrap();
                prop_assert_eq!(actual.header().slice(), &data[..ipv6_base.header_len()]);
                let (expected, _, _) = Ipv6ExtensionsSlice::from_slice(AUTH, &data[ipv6_base.header_len()..]).unwrap();
                prop_assert_eq!(
                    actual.extensions(),
                    &expected
                );
                prop_assert_eq!(
                    actual.payload(),
                    &IpPayload{
                        ip_number: UDP.into(),
                        fragmented: false,
                        len_source: LenSource::Slice,
                        payload: &data[ipv6_base.header_len() + auth_base.header_len()..],
                    }
                );
            }

            // header content error
            {
                use crate::err::ipv6::HeaderError;
                // inject invalid ip version
                let mut data = data_without_ext.clone();
                data[0] = data[0] & 0x0f; // version 0
                prop_assert_eq!(
                    Ipv6Slice::from_slice(&data).unwrap_err(),
                    SliceError::Header(
                        HeaderError::UnexpectedVersion{ version_number: 0 }
                    )
                );
            }

            // header length error
            for len in 0..Ipv6Header::LEN {
                prop_assert_eq!(
                    Ipv6Slice::from_slice(&data_without_ext[..len]).unwrap_err(),
                    SliceError::Len(
                        LenError{
                            required_len: Ipv6Header::LEN,
                            len,
                            len_source: LenSource::Slice,
                            layer: Layer::Ipv6Header,
                            layer_start_offset: 0
                        }
                    )
                );
            }

            // payload length error without auth header
            {
                use crate::err::{LenError, LenSource, Layer};

                let required_len = ipv6_base.header_len() + payload.len();
                prop_assert_eq!(
                    Ipv6Slice::from_slice(&data_without_ext[..required_len - 1]).unwrap_err(),
                    SliceError::Len(LenError{
                        required_len: required_len,
                        len: required_len - 1,
                        len_source: LenSource::Slice,
                        layer: Layer::Ipv6Packet,
                        layer_start_offset: 0,
                    })
                );
            }

            // payload length error auth header
            {
                use crate::err::{LenError, LenSource, Layer};

                let required_len = ipv6_base.header_len() + auth_base.header_len() + payload.len();
                prop_assert_eq!(
                    Ipv6Slice::from_slice(&data_with_ext[..required_len - 1]).unwrap_err(),
                    SliceError::Len(LenError{
                        required_len: required_len,
                        len: required_len - 1,
                        len_source: LenSource::Slice,
                        layer: Layer::Ipv6Packet,
                        layer_start_offset: 0,
                    })
                );
            }

            // auth length error
            {
                use crate::err::{LenError, LenSource, Layer};

                // inject payload length that is smaller then the auth header
                let mut data = data_with_ext.clone();
                let payload_len_too_small = auth_base.header_len() - 1;
                {
                    let plts = (payload_len_too_small as u16).to_be_bytes();
                    data[4] = plts[0];
                    data[5] = plts[1];
                }

                prop_assert_eq!(
                    Ipv6Slice::from_slice(&data).unwrap_err(),
                    SliceError::Len(
                        LenError{
                            required_len: auth_base.header_len(),
                            len: auth_base.header_len() - 1,
                            len_source: LenSource::Ipv6HeaderPayloadLen,
                            layer: Layer::IpAuthHeader,
                            layer_start_offset: ipv6_base.header_len(),
                        }
                    )
                );
            }

            // auth content error
            {
                use crate::err::{ip_auth, ipv6_exts};

                // inject zero as auth header length
                let mut data = data_with_ext.clone();
                data[ipv6_base.header_len() + 1] = 0;

                prop_assert_eq!(
                    Ipv6Slice::from_slice(&data).unwrap_err(),
                    SliceError::Exts(ipv6_exts::HeaderError::IpAuth(
                        ip_auth::HeaderError::ZeroPayloadLen
                    ))
                );
            }
        }
    }

    #[test]
    fn is_payload_fragmented() {
        use crate::ip_number::{IPV6_FRAG, UDP};

        // not fragmented
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: 0,
                next_header: UDP,
                hop_limit: 4,
                source: [0; 16],
                destination: [0; 16],
            }
            .to_bytes();
            assert_eq!(
                false,
                Ipv6Slice::from_slice(&data)
                    .unwrap()
                    .is_payload_fragmented()
            );
        }

        // fragmented
        {
            let ipv6_frag = Ipv6FragmentHeader {
                next_header: UDP,
                fragment_offset: 0.try_into().unwrap(),
                more_fragments: true,
                identification: 0,
            };
            let ipv6 = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: ipv6_frag.header_len() as u16,
                next_header: IPV6_FRAG,
                hop_limit: 4,
                source: [0; 16],
                destination: [0; 16],
            };

            let mut data = Vec::with_capacity(ipv6.header_len() + ipv6_frag.header_len());
            data.extend_from_slice(&ipv6.to_bytes());
            data.extend_from_slice(&ipv6_frag.to_bytes());
            assert!(Ipv6Slice::from_slice(&data)
                .unwrap()
                .is_payload_fragmented());
        }
    }
}
