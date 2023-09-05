use crate::{
    err::{ipv4::SliceError, Layer, LenError, LenSource},
    IpAuthHeaderSlice, IpNumber, IpPayload, Ipv4ExtensionsSlice, Ipv4HeaderSlice,
};

/// Slice containing the IPv4 headers & payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Slice<'a> {
    pub(crate) header: Ipv4HeaderSlice<'a>,
    pub(crate) exts: Ipv4ExtensionsSlice<'a>,
    pub(crate) payload: IpPayload<'a>,
}

impl<'a> Ipv4Slice<'a> {
    /// Separates and validates IPv4 headers (including extension headers)
    /// in the given slice and determine the sub-slice containing the payload
    /// of the IPv4 packet.
    ///
    /// Note that his function returns an [`crate::err::LenError`] if the given slice
    /// contains less data then the `total_len` field in the IPv4 header indicates
    /// should be present.
    ///
    /// If you want to ignore these kind of length errors based on the length
    /// fields in the IP headers use [`Ipv4Slice::from_slice_lax`] instead.
    pub fn from_slice(slice: &[u8]) -> Result<Ipv4Slice, SliceError> {
        use crate::ip_number::AUTH;

        // decode the header
        let header = Ipv4HeaderSlice::from_slice(slice).map_err(|err| {
            use crate::err::ipv4::HeaderSliceError::*;
            match err {
                Len(err) => SliceError::Len(err),
                Content(err) => SliceError::Header(err),
            }
        })?;

        // validate total_len at least contains the header
        let header_total_len: usize = header.total_len().into();
        if header_total_len < header.slice().len() {
            return Err(SliceError::Len(LenError {
                required_len: header.slice().len(),
                len: header_total_len,
                len_source: LenSource::Ipv4HeaderTotalLen,
                layer: Layer::Ipv4Packet,
                layer_start_offset: 0,
            }));
        }

        // check slice length based on the total length
        let header_payload = if slice.len() < header_total_len {
            return Err(SliceError::Len(LenError {
                required_len: header_total_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::Ipv4Packet,
                layer_start_offset: 0,
            }));
        } else {
            unsafe {
                core::slice::from_raw_parts(
                    slice.as_ptr().add(header.slice().len()),
                    header_total_len - header.slice().len(),
                )
            }
        };

        // decode the authentication header if needed
        let fragmented = header.is_fragmenting_payload();
        match header.protocol() {
            AUTH => {
                use crate::err::ip_auth::HeaderSliceError as E;

                // parse extension headers
                let auth = match IpAuthHeaderSlice::from_slice(header_payload) {
                    Ok(s) => s,
                    Err(err) => match err {
                        E::Len(mut l) => {
                            // change the length source to the ipv4 header
                            l.len_source = LenSource::Ipv4HeaderTotalLen;
                            l.layer_start_offset += header.slice().len();
                            return Err(SliceError::Len(l));
                        }
                        E::Content(err) => return Err(SliceError::Exts(err)),
                    },
                };

                // remove the extension header from the payload
                let payload = unsafe {
                    core::slice::from_raw_parts(
                        header_payload.as_ptr().add(auth.slice().len()),
                        header_payload.len() - auth.slice().len(),
                    )
                };
                let ip_number = auth.next_header();
                Ok(Ipv4Slice {
                    header,
                    exts: Ipv4ExtensionsSlice { auth: Some(auth) },
                    payload: IpPayload {
                        ip_number,
                        fragmented,
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        payload,
                    },
                })
            }
            ip_number => Ok(Ipv4Slice {
                header,
                exts: Ipv4ExtensionsSlice { auth: None },
                payload: IpPayload {
                    ip_number,
                    fragmented,
                    len_source: LenSource::Ipv4HeaderTotalLen,
                    payload: header_payload,
                },
            }),
        }
    }

    /// Seperates and validates IPv4 headers (including extension headers) &
    /// the payload from the given slice with less strict length checks
    /// (usefull for cut off packet or for packets with unset length fields).
    ///
    /// If you want to only receive correct IpPayloads use [`Ipv4Slice::from_slice`]
    /// instead.
    ///
    /// The main usecases for this functions are:
    ///
    /// * Parsing packets that have been cut off. This is, for example, usefull to
    ///   parse packets returned via ICMP as these usually only contain the start.
    /// * Parsing packets where the `total_len` (for IPv4) have not yet been set.
    ///   This can be usefull when parsing packets which have been recorded in a
    ///   layer before the length field was set (e.g. before the operating
    ///   system set the length fields).
    ///
    /// # Differences to `from_slice`:
    ///
    /// The main differences is that the function ignores inconsistent
    /// `total_len` values (in IPv4 headers). When the total_length value in the IPv4
    /// header is inconsistant the length of the given slice is used as a substitute.
    ///
    /// You can check if the slice length was used as a substitude by checking
    /// if the `len_source` value in the returned [`IpPayload`] is set to
    /// [`LenSource::Slice`]. If a substitution was not needed `len_source`
    /// is set to [`LenSource::Ipv4HeaderTotalLen`].
    ///
    /// # When is the slice length used as a fallback?
    ///
    /// For IPv4 packets the slice length is used as a fallback/substitude
    /// if the `total_length` field in the IPv4 header is:
    ///
    ///  * Bigger then the given slice (payload cannot fully be seperated).
    ///  * Too small to contain at least the IPv4 header.
    pub fn from_slice_lax(slice: &[u8]) -> Result<Ipv4Slice, SliceError> {
        use crate::ip_number::AUTH;

        // decode the header
        let header = Ipv4HeaderSlice::from_slice(slice).map_err(|err| {
            use crate::err::ipv4::HeaderSliceError::*;
            match err {
                Len(err) => SliceError::Len(err),
                Content(err) => SliceError::Header(err),
            }
        })?;

        // validate total_len at least contains the header
        let header_total_len: usize = header.total_len().into();
        let (header_payload, len_source) =
            if header_total_len >= header.slice().len() && header_total_len <= slice.len() {
                (
                    unsafe {
                        core::slice::from_raw_parts(
                            slice.as_ptr().add(header.slice().len()),
                            header_total_len - header.slice().len(),
                        )
                    },
                    LenSource::Ipv4HeaderTotalLen,
                )
            } else {
                (
                    unsafe {
                        core::slice::from_raw_parts(
                            slice.as_ptr().add(header.slice().len()),
                            slice.len() - header.slice().len(),
                        )
                    },
                    LenSource::Slice,
                )
            };

        // decode the authentification header if needed
        let fragmented = header.is_fragmenting_payload();
        match header.protocol() {
            AUTH => {
                use crate::err::ip_auth::HeaderSliceError as E;

                // parse extension headers
                let auth = match IpAuthHeaderSlice::from_slice(header_payload) {
                    Ok(s) => s,
                    Err(err) => match err {
                        E::Len(mut l) => {
                            // change the length source to the ipv4 header
                            l.len_source = LenSource::Ipv4HeaderTotalLen;
                            l.layer_start_offset += header.slice().len();
                            return Err(SliceError::Len(l));
                        }
                        E::Content(err) => return Err(SliceError::Exts(err)),
                    },
                };

                // remove the extension header from the payload
                let payload = unsafe {
                    core::slice::from_raw_parts(
                        header_payload.as_ptr().add(auth.slice().len()),
                        header_payload.len() - auth.slice().len(),
                    )
                };
                let ip_number = auth.next_header();
                Ok(Ipv4Slice {
                    header,
                    exts: Ipv4ExtensionsSlice { auth: Some(auth) },
                    payload: IpPayload {
                        ip_number,
                        fragmented,
                        len_source,
                        payload,
                    },
                })
            }
            ip_number => Ok(Ipv4Slice {
                header,
                exts: Ipv4ExtensionsSlice { auth: None },
                payload: IpPayload {
                    ip_number,
                    fragmented,
                    len_source,
                    payload: header_payload,
                },
            }),
        }
    }

    /// Returns a slice containing the IPv4 header.
    #[inline]
    pub fn header(&self) -> Ipv4HeaderSlice {
        self.header
    }

    /// Returns a slice containing the IPv4 extension headers.
    #[inline]
    pub fn extensions(&self) -> Ipv4ExtensionsSlice {
        self.exts
    }

    /// Returns a slice containing the data after the IPv4 header
    /// and IPv4 extensions headers.
    #[inline]
    pub fn payload(&self) -> &IpPayload<'a> {
        &self.payload
    }

    /// Returns the ip number the type of payload of the IPv4 packet.
    ///
    /// This function returns the ip number stored in the last
    /// IPv4 header or extension header.
    #[inline]
    pub fn payload_ip_number(&self) -> IpNumber {
        self.payload.ip_number
    }

    /// Returns true if the payload is flagged as being fragmented.
    #[inline]
    pub fn is_payload_fragmented(&self) -> bool {
        self.header.is_fragmenting_payload()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{ip_number, test_gens::*, IpHeader, Ipv4Header};
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug_clone_eq(
            ipv4_base in ipv4_any(),
            auth in ip_auth_any()
        ) {
            let payload: [u8;4] = [1,2,3,4];
            let mut data = Vec::with_capacity(
                ipv4_base.header_len() +
                auth.header_len() +
                payload.len()
            );
            let mut ipv4 = ipv4_base.clone();
            ipv4.protocol = crate::ip_number::AUTH;
            ipv4.set_payload_len(auth.header_len() + payload.len()).unwrap();
            data.extend_from_slice(&ipv4.to_bytes());
            data.extend_from_slice(&auth.to_bytes());
            data.extend_from_slice(&payload);

            // decode packet
            let slice = Ipv4Slice::from_slice(&data).unwrap();

            // check debug output
            prop_assert_eq!(
                format!("{:?}", slice),
                format!(
                    "Ipv4Slice {{ header: {:?}, exts: {:?}, payload: {:?} }}",
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
            ipv4_base in ipv4_any(),
            auth in ip_auth_any()
        ) {
            let payload: [u8;6] = [1,2,3,4,5,6];

            // build packets
            let data_without_ext = {
                let mut data = Vec::with_capacity(
                    ipv4_base.header_len() +
                    payload.len() +
                    4
                );
                let mut ipv4 = ipv4_base.clone();
                ipv4.set_payload_len(payload.len()).unwrap();
                ipv4.protocol = crate::ip_number::UDP;
                data.extend_from_slice(&ipv4.to_bytes());
                data.extend_from_slice(&payload);
                data.extend_from_slice(&[0,0,0,0]);
                data
            };
            let data_with_ext = {
                let payload: [u8;6] = [1,2,3,4,5,6];
                let mut data = Vec::with_capacity(
                    ipv4_base.header_len() +
                    auth.header_len() +
                    payload.len() +
                    4
                );
                let mut ipv4 = ipv4_base.clone();
                ipv4.set_payload_len(auth.header_len() + payload.len()).unwrap();
                ipv4.protocol = crate::ip_number::AUTH;
                data.extend_from_slice(&ipv4.to_bytes());
                data.extend_from_slice(&auth.to_bytes());
                data.extend_from_slice(&payload);
                data.extend_from_slice(&[0,0,0,0]);
                data
            };

            // parsing without extensions
            {
                let actual = Ipv4Slice::from_slice(&data_without_ext).unwrap();
                prop_assert_eq!(actual.header().slice(), &data_without_ext[..ipv4_base.header_len()]);
                prop_assert!(actual.extensions().auth.is_none());
                prop_assert_eq!(
                    &actual.payload,
                    &IpPayload{
                        ip_number: ip_number::UDP.into(),
                        fragmented: ipv4_base.is_fragmenting_payload(),
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        payload: &payload
                    }
                );
                prop_assert_eq!(actual.payload_ip_number(), ip_number::UDP.into());
            }

            // parsing with extensions
            {
                let actual = Ipv4Slice::from_slice(&data_with_ext).unwrap();
                prop_assert_eq!(actual.header().slice(), &data_with_ext[..ipv4_base.header_len()]);
                prop_assert_eq!(
                    actual.extensions().auth.unwrap(),
                    IpAuthHeaderSlice::from_slice(&data_with_ext[ipv4_base.header_len()..]).unwrap()
                );
                prop_assert_eq!(
                    &actual.payload,
                    &IpPayload{
                        ip_number: auth.next_header.into(),
                        fragmented: ipv4_base.is_fragmenting_payload(),
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        payload: &payload
                    }
                );
                prop_assert_eq!(actual.payload_ip_number(), auth.next_header.into());
            }

            // header length error
            for len in 0..Ipv4Header::MIN_LEN {
                prop_assert_eq!(
                    Ipv4Slice::from_slice(&data_without_ext[..len]).unwrap_err(),
                    SliceError::Len(
                        LenError{
                            required_len: Ipv4Header::MIN_LEN,
                            len,
                            len_source: LenSource::Slice,
                            layer: Layer::Ipv4Header,
                            layer_start_offset: 0,
                        }
                    )
                );
            }

            // header content error
            {
                use crate::err::ipv4::HeaderError;
                // inject invalid icv
                let mut data = data_without_ext.clone();
                data[0] = data[0] & 0xf0; // icv 0
                prop_assert_eq!(
                    Ipv4Slice::from_slice(&data).unwrap_err(),
                    SliceError::Header(
                        HeaderError::HeaderLengthSmallerThanHeader { ihl: 0 }
                    )
                );
            }

            // payload length error without auth header
            {
                use crate::err::{LenError, LenSource, Layer};

                let required_len = ipv4_base.header_len() + payload.len();
                prop_assert_eq!(
                    Ipv4Slice::from_slice(&data_without_ext[..required_len - 1]).unwrap_err(),
                    SliceError::Len(LenError{
                        required_len: required_len,
                        len: required_len - 1,
                        len_source: LenSource::Slice,
                        layer: Layer::Ipv4Packet,
                        layer_start_offset: 0,
                    })
                );
            }

            // payload length error auth header
            {
                use crate::err::{LenError, LenSource, Layer};

                let required_len = ipv4_base.header_len() + auth.header_len() + payload.len();
                prop_assert_eq!(
                    Ipv4Slice::from_slice(&data_with_ext[..required_len - 1]).unwrap_err(),
                    SliceError::Len(LenError{
                        required_len: required_len,
                        len: required_len - 1,
                        len_source: LenSource::Slice,
                        layer: Layer::Ipv4Packet,
                        layer_start_offset: 0,
                    })
                );
            }

            // auth length error
            {
                use crate::err::{LenError, LenSource, Layer};

                // inject a total_length that is smaller then the auth header
                let mut data = data_with_ext.clone();
                let total_len_too_small = ipv4_base.header_len() + auth.header_len() - 1;
                {
                    let tltsm = (total_len_too_small as u16).to_be_bytes();
                    data[2] = tltsm[0];
                    data[3] = tltsm[1];
                }

                prop_assert_eq!(
                    Ipv4Slice::from_slice(&data).unwrap_err(),
                    SliceError::Len(
                        LenError{
                            required_len: auth.header_len(),
                            len: auth.header_len() - 1,
                            len_source: LenSource::Ipv4HeaderTotalLen,
                            layer: Layer::IpAuthHeader,
                            layer_start_offset: ipv4_base.header_len(),
                        }
                    )
                );
            }

            // auth content error
            {
                use crate::err::ip_auth::HeaderError;

                // inject zero as auth header length
                let mut data = data_with_ext.clone();
                data[ipv4_base.header_len() + 1] = 0;

                prop_assert_eq!(
                    Ipv4Slice::from_slice(&data).unwrap_err(),
                    SliceError::Exts(
                        HeaderError::ZeroPayloadLen
                    )
                );
            }
        }
    }

    fn combine_v4(v4: &Ipv4Header, ext: &crate::Ipv4Extensions, payload: &[u8]) -> crate::IpHeader {
        use crate::ip_number::{AUTH, UDP};
        crate::IpHeader::Version4(
            {
                let mut v4 = v4.clone();
                v4.protocol = if ext.auth.is_some() { AUTH } else { UDP };
                v4.total_len = (v4.header_len() + ext.header_len() + payload.len()) as u16;
                v4.header_checksum = v4.calc_header_checksum();
                v4
            },
            ext.clone(),
        )
    }

    proptest! {
        #[test]
        fn from_slice_lax(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any()
        ) {
            use crate::err::{self, ipv4::{HeaderError::*, SliceError::*}};

            let payload = [1,2,3,4];

            // empty error
            assert_eq!(
                Ipv4Slice::from_slice_lax(&[]),
                Err(Len(err::LenError {
                    required_len: 20,
                    len: 0,
                    len_source: err::LenSource::Slice,
                    layer: err::Layer::Ipv4Header,
                    layer_start_offset: 0,
                }))
            );

            // build a buffer with a valid packet
            let header = combine_v4(&v4, &v4_exts, &payload);
            let mut buffer = Vec::with_capacity(header.header_len() + payload.len() + 1);
            header.write(&mut buffer).unwrap();
            buffer.extend_from_slice(&payload);
            buffer.push(1); // add some value to check the return slice

            // normal read
            {
                let actual = Ipv4Slice::from_slice_lax(&buffer).unwrap();
                assert_eq!(&actual.header.to_header(), header.v4().unwrap().0);
                assert_eq!(&actual.extensions().to_header(), header.v4().unwrap().1);
                assert_eq!(
                    actual.payload,
                    IpPayload{
                        ip_number: header.next_header().unwrap(),
                        fragmented: header.is_fragmenting_payload(),
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        payload: &payload
                    }
                );
            }

            // error len smaller then min header len
            for len in 1..Ipv4Header::MIN_LEN {
                assert_eq!(
                    Ipv4Slice::from_slice_lax(&buffer[..len]),
                    Err(Len(err::LenError {
                        required_len: Ipv4Header::MIN_LEN,
                        len,
                        len_source: err::LenSource::Slice,
                        layer: err::Layer::Ipv4Header,
                        layer_start_offset: 0,
                    }))
                );
            }

            // ihl value error
            {
                let mut bad_ihl_buffer = buffer.clone();
                for bad_ihl in 0..5 {
                    bad_ihl_buffer[0] = (bad_ihl_buffer[0] & 0xf0) | bad_ihl;
                    assert_eq!(
                        IpHeader::ipv4_from_slice_lax(&bad_ihl_buffer),
                        Err(Header(HeaderLengthSmallerThanHeader { ihl: bad_ihl }))
                    );
                }
            }

            // ihl len error
            for short_ihl in 5..usize::from(v4.ihl()) {
                assert_eq!(
                    IpHeader::ipv4_from_slice_lax(&buffer[..4*short_ihl]),
                    Err(Len(err::LenError {
                        required_len: usize::from(v4.ihl())*4,
                        len: 4*short_ihl,
                        len_source: err::LenSource::Slice,
                        layer: err::Layer::Ipv4Header,
                        layer_start_offset: 0,
                    }))
                );
            }

            // total_len bigger then slice len (fallback to slice len)
            for payload_len in 0..payload.len(){
                let actual = IpHeader::ipv4_from_slice_lax(&buffer[..v4.header_len() + v4_exts.header_len() + payload_len]).unwrap();
                assert_eq!(&actual.0, &header);
                assert_eq!(
                    actual.1,
                    IpPayload{
                        ip_number: header.next_header().unwrap(),
                        fragmented: header.is_fragmenting_payload(),
                        len_source: LenSource::Slice,
                        payload: &payload[..payload_len]
                    }
                );
            }

            // len error ipv4 extensions
            if v4_exts.header_len() > 0 {
                IpHeader::ipv4_from_slice_lax(&buffer[..v4.header_len() + 1]).unwrap_err();
            }

            // content error ipv4 extensions
            if v4_exts.auth.is_some() {
                use err::ip_auth::HeaderError::ZeroPayloadLen;

                // introduce a auth header zero payload error
                let mut errored_buffer = buffer.clone();
                // inject length zero into auth header (not valid, will
                // trigger a content error)
                errored_buffer[v4.header_len() + 1] = 0;
                assert_eq!(
                    IpHeader::ipv4_from_slice_lax(&errored_buffer),
                    Err(Exts(ZeroPayloadLen))
                );
            }

            // total length smaller the header (fallback to slice len)
            {
                let bad_total_len = (v4.header_len() - 1) as u16;

                let mut buffer = buffer.clone();
                // inject bad total_len
                let bad_total_len_be = bad_total_len.to_be_bytes();
                buffer[2] = bad_total_len_be[0];
                buffer[3] = bad_total_len_be[1];

                let actual = IpHeader::ipv4_from_slice_lax(&buffer[..]).unwrap();

                let (v4_header, v4_exts) = header.v4().unwrap();
                let expected_headers = IpHeader::Version4(
                    {
                        let mut expected_v4 = v4_header.clone();
                        expected_v4.total_len = bad_total_len;
                        expected_v4
                    },
                    v4_exts.clone()
                );
                assert_eq!(&expected_headers, &actual.0);
                assert_eq!(
                    actual.1,
                    IpPayload{
                        ip_number: header.next_header().unwrap(),
                        fragmented: header.is_fragmenting_payload(),
                        len_source: LenSource::Slice,
                        payload: &buffer[v4_header.header_len() + v4_exts.header_len()..],
                    }
                );
            }
        }
    }

    #[test]
    fn is_payload_fragmented() {
        use crate::ip_number::UDP;
        // non-fragmented
        {
            let payload: [u8; 6] = [1, 2, 3, 4, 5, 6];
            let ipv4 =
                Ipv4Header::new(payload.len() as u16, 1, UDP, [3, 4, 5, 6], [7, 8, 9, 10]).unwrap();
            let data = {
                let mut data = Vec::with_capacity(ipv4.header_len() + payload.len());
                data.extend_from_slice(&ipv4.to_bytes());
                data.extend_from_slice(&payload);
                data
            };

            let slice = Ipv4Slice::from_slice(&data).unwrap();
            assert!(false == slice.is_payload_fragmented());
        }
        // fragmented
        {
            let payload: [u8; 6] = [1, 2, 3, 4, 5, 6];
            let mut ipv4 =
                Ipv4Header::new(payload.len() as u16, 1, UDP, [3, 4, 5, 6], [7, 8, 9, 10]).unwrap();
            ipv4.fragment_offset = 123.try_into().unwrap();
            let data = {
                let mut data = Vec::with_capacity(ipv4.header_len() + payload.len());
                data.extend_from_slice(&ipv4.to_bytes());
                data.extend_from_slice(&payload);
                data
            };

            let slice = Ipv4Slice::from_slice(&data).unwrap();
            assert!(slice.is_payload_fragmented());
        }
    }
}
