use crate::{
    err::{ip, Layer, LenError, LenSource},
    *,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternetSlice<'a> {
    /// The ipv4 header & the decoded extension headers.
    Ipv4(Ipv4Slice<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(Ipv6Slice<'a>),
}

impl<'a> InternetSlice<'a> {
    /// Returns a refernce to the `Ipv4Slice` if `self` is a `InternetSlice::Ipv4`.
    pub fn ipv4(&self) -> Option<&Ipv4Slice> {
        use InternetSlice::*;
        match self {
            Ipv4(slice) => Some(slice),
            Ipv6(_) => None,
        }
    }

    /// Returns a refernce to the `Ipv6Slice` if `self` is a `InternetSlice::Ipv6`.
    pub fn ipv6(&self) -> Option<&Ipv6Slice> {
        use InternetSlice::*;
        match self {
            Ipv4(_) => None,
            Ipv6(slice) => Some(slice),
        }
    }

    /// Returns true if the payload is fragmented.
    pub fn is_fragmenting_payload(&self) -> bool {
        match self {
            InternetSlice::Ipv4(s) => s.is_payload_fragmented(),
            InternetSlice::Ipv6(s) => s.is_payload_fragmented(),
        }
    }

    /// Return the source address as an std::net::Ipvddr (requires
    /// crate feature `std`).
    #[cfg(feature = "std")]
    pub fn source_addr(&self) -> std::net::IpAddr {
        match self {
            InternetSlice::Ipv4(s) => s.header().source_addr().into(),
            InternetSlice::Ipv6(s) => s.header().source_addr().into(),
        }
    }

    /// Return the destination address as an std::net::IpAddr (requires
    /// crate feature `std`).
    #[cfg(feature = "std")]
    pub fn destination_addr(&self) -> std::net::IpAddr {
        match self {
            InternetSlice::Ipv4(s) => s.header().destination_addr().into(),
            InternetSlice::Ipv6(s) => s.header().destination_addr().into(),
        }
    }

    /// Returns a slice containing the data after the IP header
    /// and IP extensions headers.
    #[inline]
    pub fn payload(&self) -> &IpPayload<'a> {
        use InternetSlice::*;
        match self {
            Ipv4(ipv4) => ipv4.payload(),
            Ipv6(ipv6) => ipv6.payload(),
        }
    }

    /// Returns the ip number the type of payload of the IP packet.
    ///
    /// This function returns the ip number stored in the last
    /// IP header or extension header.
    #[inline]
    pub fn payload_ip_number(&self) -> IpNumber {
        use InternetSlice::*;
        match self {
            Ipv4(ipv4) => ipv4.payload().ip_number,
            Ipv6(ipv6) => ipv6.payload().ip_number,
        }
    }

    /// Seperates and validates IP headers (including extension headers)
    /// in the given slice and determine the sub-slice containing the payload
    /// of the IP packet.
    pub fn from_ip_slice(slice: &[u8]) -> Result<InternetSlice, err::ip::SliceError> {
        use crate::ip_number::AUTH;
        use err::ip::SliceError::*;
        use InternetSlice::*;

        if slice.is_empty() {
            Err(Len(err::LenError {
                required_len: 1,
                len: slice.len(),
                len_source: err::LenSource::Slice,
                layer: err::Layer::IpHeader,
                layer_start_offset: 0,
            }))
        } else {
            // SAFETY: Safe as slice is not empty.
            let first_byte = unsafe { slice.get_unchecked(0) };
            match first_byte >> 4 {
                4 => {
                    let ihl = first_byte & 0xf;

                    // check that the ihl has at least the lenght of the base IPv4 header
                    if ihl < 5 {
                        use err::ip::HeaderError::Ipv4HeaderLengthSmallerThanHeader;
                        return Err(IpHeader(Ipv4HeaderLengthSmallerThanHeader { ihl }));
                    }

                    // check there is enough data for the header
                    let header_len = (usize::from(ihl)) * 4;
                    if slice.len() < header_len {
                        return Err(Len(err::LenError {
                            required_len: header_len,
                            len: slice.len(),
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv4Header,
                            layer_start_offset: 0,
                        }));
                    }

                    // check the total_length can contain the header
                    //
                    // SAFETY:
                    // Safe as the slice length is checked to be at least
                    // 5*4 (5 for the minimum of the ihl) just before.
                    let total_length = unsafe { get_unchecked_be_u16(slice.as_ptr().add(2)) };
                    if total_length < header_len as u16 {
                        use err::ip::HeaderError::Ipv4TotalLengthSmallerThanHeader;
                        return Err(IpHeader(Ipv4TotalLengthSmallerThanHeader {
                            total_length,
                            min_expected_length: header_len as u16,
                        }));
                    }

                    // SAFETY:
                    // Safe as the slice length is checked to be at least
                    // header_len or greater above.
                    let header = unsafe {
                        Ipv4HeaderSlice::from_slice_unchecked(core::slice::from_raw_parts(
                            slice.as_ptr(),
                            header_len,
                        ))
                    };

                    // validate the total length agains the slice
                    let total_length_usize: usize = total_length.into();
                    let header_payload = if slice.len() < total_length_usize {
                        return Err(Len(LenError {
                            required_len: total_length_usize,
                            len: slice.len(),
                            len_source: LenSource::Slice,
                            layer: Layer::Ipv4Packet,
                            layer_start_offset: 0,
                        }));
                    } else {
                        unsafe {
                            core::slice::from_raw_parts(
                                // SAFETY: Safe as slice.len() >= header_len was validated
                                // in a if statement above.
                                slice.as_ptr().add(header_len),
                                // SAFETY: Safe as total_length >= header_len was verfied in an
                                // if statement above as well as that slice.len() >= total_length_usize.
                                total_length_usize - header_len,
                            )
                        }
                    };

                    // slice extension headers
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
                                        return Err(Len(l));
                                    }
                                    E::Content(err) => {
                                        return Err(IpHeader(ip::HeaderError::Ipv4Ext(err)))
                                    }
                                },
                            };

                            // remove the extension header from the payload
                            let payload = unsafe {
                                core::slice::from_raw_parts(
                                    header_payload.as_ptr().add(auth.slice().len()),
                                    header_payload.len() - auth.slice().len(),
                                )
                            };
                            Ok(Ipv4(Ipv4Slice {
                                header,
                                exts: Ipv4ExtensionsSlice { auth: Some(auth) },
                                payload: IpPayload {
                                    ip_number: auth.next_header().into(),
                                    fragmented,
                                    len_source: LenSource::Ipv4HeaderTotalLen,
                                    payload,
                                },
                            }))
                        }
                        ip_number => Ok(Ipv4(Ipv4Slice {
                            header,
                            exts: Ipv4ExtensionsSlice { auth: None },
                            payload: IpPayload {
                                ip_number: ip_number.into(),
                                fragmented,
                                len_source: LenSource::Ipv4HeaderTotalLen,
                                payload: header_payload,
                            },
                        })),
                    }
                }
                6 => {
                    // check length
                    if slice.len() < Ipv6Header::LEN {
                        return Err(Len(err::LenError {
                            required_len: Ipv6Header::LEN,
                            len: slice.len(),
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv6Header,
                            layer_start_offset: 0,
                        }));
                    }

                    let header = unsafe {
                        Ipv6HeaderSlice::from_slice_unchecked(core::slice::from_raw_parts(
                            slice.as_ptr(),
                            Ipv6Header::LEN,
                        ))
                    };

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
                                return Err(Len(LenError {
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
                        Ipv6ExtensionsSlice::from_slice(header.next_header(), header_payload)
                            .map_err(|err| {
                                // modify length errors
                                use crate::err::ipv6_exts::HeaderSliceError as I;
                                match err {
                                    I::Len(mut err) => {
                                        err.len_source = LenSource::Ipv6HeaderPayloadLen;
                                        err.layer_start_offset += Ipv6Header::LEN;
                                        Len(err)
                                    }
                                    I::Content(err) => IpHeader(ip::HeaderError::Ipv6Ext(err)),
                                }
                            })?;

                    let fragmented = exts.is_fragmenting_payload();
                    Ok(Ipv6(Ipv6Slice {
                        header,
                        exts,
                        payload: IpPayload {
                            ip_number: payload_ip_number.into(),
                            fragmented,
                            len_source,
                            payload,
                        },
                    }))
                }
                version_number => Err(IpHeader(err::ip::HeaderError::UnsupportedIpVersion {
                    version_number,
                })),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn debug_clone_eq() {
        // ipv4
        {
            let mut header: Ipv4Header = Default::default();
            header.protocol = ip_number::UDP;
            header.set_payload_len(0).unwrap();
            let buffer = header.to_bytes().unwrap();

            let ipv4 = Ipv4Slice::from_slice(&buffer).unwrap();
            let slice = InternetSlice::Ipv4(ipv4.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(format!("{:?}", slice), format!("Ipv4({:?})", ipv4));
        }
        // ipv6
        {
            let header = Ipv6Header {
                payload_length: 0,
                next_header: ip_number::UDP,
                ..Default::default()
            };
            let buffer = header.to_bytes().unwrap();
            let ipv6 = Ipv6Slice::from_slice(&buffer).unwrap();
            let slice = InternetSlice::Ipv6(ipv6.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(format!("{:?}", slice), format!("Ipv6({:?})", ipv6));
        }
    }

    #[test]
    fn is_fragmenting_payload() {
        for fragment in [false, true] {
            use ip_number::UDP;
            // ipv4
            {
                let mut ipv4 = Ipv4Header::new(0, 1, UDP, [3, 4, 5, 6], [7, 8, 9, 10]);
                if fragment {
                    ipv4.fragments_offset = 123;
                }

                let data = ipv4.to_bytes().unwrap();
                let ipv4_slice = Ipv4Slice::from_slice(&data).unwrap();
                assert_eq!(
                    fragment,
                    InternetSlice::Ipv4(ipv4_slice).is_fragmenting_payload()
                );
            }

            // ipv6
            {
                let ipv6_frag = Ipv6FragmentHeader {
                    next_header: UDP,
                    fragment_offset: 0,
                    more_fragments: fragment,
                    identification: 0,
                };
                let ipv6 = Ipv6Header {
                    traffic_class: 0,
                    flow_label: 1,
                    payload_length: ipv6_frag.header_len() as u16,
                    next_header: ip_number::IPV6_FRAG,
                    hop_limit: 4,
                    source: [1; 16],
                    destination: [2; 16],
                };
                let mut data = Vec::with_capacity(ipv6.header_len() + ipv6_frag.header_len());
                data.extend_from_slice(&ipv6.to_bytes().unwrap());
                data.extend_from_slice(&ipv6_frag.to_bytes().unwrap());

                assert_eq!(
                    fragment,
                    InternetSlice::Ipv6(Ipv6Slice::from_slice(&data).unwrap())
                        .is_fragmenting_payload()
                );
            }
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn source_addr() {
        // ipv4
        {
            let data = Ipv4Header::new(0, 1, 2.into(), [3, 4, 5, 6], [7, 8, 9, 10])
                .to_bytes()
                .unwrap();
            assert_eq!(
                IpAddr::V4(Ipv4Addr::from([3, 4, 5, 6])),
                InternetSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).source_addr()
            );
        }

        // ipv6
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1,
                payload_length: 0,
                next_header: ip_number::IGMP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            }
            .to_bytes()
            .unwrap();

            assert_eq!(
                IpAddr::V6(Ipv6Addr::from([1; 16])),
                InternetSlice::Ipv6(Ipv6Slice::from_slice(&data[..]).unwrap()).source_addr()
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn destination_addr() {
        use crate::ip_number::UDP;

        // ipv4
        {
            let data = Ipv4Header::new(0, 1, UDP, [3, 4, 5, 6], [7, 8, 9, 10])
                .to_bytes()
                .unwrap();
            assert_eq!(
                IpAddr::V4(Ipv4Addr::from([7, 8, 9, 10])),
                InternetSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).destination_addr()
            );
        }

        // ipv6
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1,
                payload_length: 0,
                next_header: ip_number::IGMP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            }
            .to_bytes()
            .unwrap();

            assert_eq!(
                IpAddr::V6(Ipv6Addr::from([2; 16])),
                InternetSlice::Ipv6(Ipv6Slice::from_slice(&data).unwrap()).destination_addr()
            );
        }
    }

    #[test]
    fn payload() {
        let payload: [u8; 4] = [1, 2, 3, 4];
        // ipv4
        {
            let header = Ipv4Header::new(
                payload.len() as u16,
                1,
                ip_number::UDP,
                [3, 4, 5, 6],
                [7, 8, 9, 10],
            );
            let mut data = Vec::with_capacity(header.header_len() + payload.len());
            data.extend_from_slice(&header.to_bytes().unwrap());
            data.extend_from_slice(&payload);
            assert_eq!(
                InternetSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).payload(),
                &IpPayload {
                    ip_number: ip_number::UDP.into(),
                    fragmented: header.is_fragmenting_payload(),
                    len_source: LenSource::Ipv4HeaderTotalLen,
                    payload: &payload,
                }
            );
        }

        // ipv6
        {
            let header = Ipv6Header {
                traffic_class: 0,
                flow_label: 1,
                payload_length: payload.len() as u16,
                next_header: ip_number::UDP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            };
            let mut data = Vec::with_capacity(header.header_len() + payload.len());
            data.extend_from_slice(&header.to_bytes().unwrap());
            data.extend_from_slice(&payload);
            assert_eq!(
                InternetSlice::Ipv6(Ipv6Slice::from_slice(&data[..]).unwrap()).payload(),
                &IpPayload {
                    ip_number: ip_number::UDP.into(),
                    fragmented: false,
                    len_source: LenSource::Ipv6HeaderPayloadLen,
                    payload: &payload,
                }
            );
        }
    }

    #[test]
    fn payload_ip_number() {
        use crate::ip_number::{IGMP, UDP};

        // ipv4
        {
            let data = Ipv4Header::new(0, 1, UDP, [3, 4, 5, 6], [7, 8, 9, 10])
                .to_bytes()
                .unwrap();
            assert_eq!(
                UDP,
                InternetSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap())
                    .payload_ip_number()
            );
        }

        // ipv6
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1,
                payload_length: 0,
                next_header: IGMP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            }
            .to_bytes()
            .unwrap();

            assert_eq!(
                IGMP,
                InternetSlice::Ipv6(Ipv6Slice::from_slice(&data).unwrap())
                    .payload_ip_number()
            );
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            ipv4_header in ipv4_any(),
            ipv4_exts in ipv4_extensions_with(ip_number::UDP),
            ipv6_header in ipv6_any(),
            mut ipv6_exts in ipv6_extensions_with(ip_number::UDP)
        ) {
            let payload = [1,2,3,4];

            // setup header length & fields
            let ipv4_header = {
                let mut header = ipv4_header;
                header.protocol = if ipv4_exts.auth.is_some() {
                    ip_number::AUTH
                } else {
                    ip_number::UDP
                };
                header.payload_len = (ipv4_exts.header_len() + payload.len()) as u16;
                header.header_checksum = header.calc_header_checksum().unwrap();
                header
            };

            let ipv4 = IpHeader::Version4(
                ipv4_header.clone(),
                ipv4_exts.clone()
            );

            let ipv6_header = {
                let mut header = ipv6_header;
                header.next_header = ipv6_exts.set_next_headers(ip_number::UDP);
                header.payload_length = (ipv6_exts.header_len() + payload.len()) as u16;
                header
            };

            let ipv6 = IpHeader::Version6(
                ipv6_header.clone(),
                ipv6_exts.clone()
            );

            // happy path v4
            {
                // build packet
                let mut data = Vec::with_capacity(ipv4.header_len() + payload.len());
                ipv4.write(&mut data).unwrap();
                data.extend_from_slice(&payload);

                // run test
                let actual = InternetSlice::from_ip_slice(&data).unwrap();
                assert!(actual.ipv6().is_none());
                let actual = actual.ipv4().unwrap().clone();
                assert_eq!(actual.header.to_header(), ipv4_header);
                assert_eq!(actual.extensions().to_header(), ipv4_exts);
                assert_eq!(
                    actual.payload,
                    IpPayload{
                        ip_number: ip_number::UDP.into(),
                        fragmented: ipv4_header.is_fragmenting_payload(),
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        payload: &payload
                    }
                );
            }

            // happy path v6
            {
                // build packet
                let mut data = Vec::with_capacity(ipv6.header_len() + payload.len());
                ipv6.write(&mut data).unwrap();
                data.extend_from_slice(&payload);

                // run test
                let actual = crate::InternetSlice::from_ip_slice(&data).unwrap();
                assert!(actual.ipv4().is_none());
                let actual = actual.ipv6().unwrap().clone();
                assert_eq!(actual.header.to_header(), ipv6_header);
                assert_eq!(
                    Ipv6Extensions::from_slice(
                        ipv6_header.next_header,
                        actual.extensions().slice()
                    ).unwrap().0,
                    ipv6_exts
                );
                assert_eq!(
                    actual.payload,
                    IpPayload{
                        ip_number: ip_number::UDP.into(),
                        fragmented: ipv6_exts.is_fragmenting_payload(),
                        len_source: LenSource::Ipv6HeaderPayloadLen,
                        payload: &payload
                    }
                );
            }

            // ipv6 with zero payload length (should fallback to the slice length)
            {
                let ipv6_header = {
                    let mut header = ipv6_header.clone();
                    // set the payload length to zero so the payload identifier
                    // has to fallback to the slice length
                    header.payload_length = 0;
                    header
                };

                // build packet
                let mut data = Vec::with_capacity(ipv6.header_len() + payload.len());
                ipv6_header.write(&mut data).unwrap();
                ipv6_exts.write(&mut data, ipv6_header.next_header).unwrap();
                data.extend_from_slice(&payload);

                // run test
                let actual = crate::InternetSlice::from_ip_slice(&data).unwrap();
                assert!(actual.ipv4().is_none());
                let actual = actual.ipv6().unwrap().clone();
                assert_eq!(actual.header.to_header(), ipv6_header);
                assert_eq!(
                    Ipv6Extensions::from_slice(
                        ipv6_header.next_header,
                        actual.extensions().slice()
                    ).unwrap().0,
                    ipv6_exts
                );
                assert_eq!(
                    actual.payload,
                    IpPayload{
                        ip_number: ip_number::UDP.into(),
                        fragmented: ipv6_exts.is_fragmenting_payload(),
                        len_source: LenSource::Slice,
                        payload: &payload
                    }
                );
            }

        }
    }
}
