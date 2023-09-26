use crate::{
    err::{ip, Layer, LenError, LenSource},
    *,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpSlice<'a> {
    /// The ipv4 header & the decoded extension headers.
    Ipv4(Ipv4Slice<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(Ipv6Slice<'a>),
}

/// Deprecated use [`crate::IpSlice`] instead.
#[cfg(feature = "std")]
#[deprecated(since = "0.14.0", note = "Deprecated use etherparse::IpSlice instead")]
pub use IpSlice as InternetSlice;

impl<'a> IpSlice<'a> {
    /// Returns a reference to the `Ipv4Slice` if `self` is a `IpSlice::Ipv4`.
    pub fn ipv4(&self) -> Option<&Ipv4Slice> {
        use IpSlice::*;
        match self {
            Ipv4(slice) => Some(slice),
            Ipv6(_) => None,
        }
    }

    /// Returns a reference to the `Ipv6Slice` if `self` is a `IpSlice::Ipv6`.
    pub fn ipv6(&self) -> Option<&Ipv6Slice> {
        use IpSlice::*;
        match self {
            Ipv4(_) => None,
            Ipv6(slice) => Some(slice),
        }
    }

    /// Returns true if the payload is fragmented.
    pub fn is_fragmenting_payload(&self) -> bool {
        match self {
            IpSlice::Ipv4(s) => s.is_payload_fragmented(),
            IpSlice::Ipv6(s) => s.is_payload_fragmented(),
        }
    }

    /// Return the source address as an std::net::Ipvddr (requires
    /// crate feature `std`).
    #[cfg(feature = "std")]
    pub fn source_addr(&self) -> std::net::IpAddr {
        match self {
            IpSlice::Ipv4(s) => s.header().source_addr().into(),
            IpSlice::Ipv6(s) => s.header().source_addr().into(),
        }
    }

    /// Return the destination address as an std::net::IpAddr (requires
    /// crate feature `std`).
    #[cfg(feature = "std")]
    pub fn destination_addr(&self) -> std::net::IpAddr {
        match self {
            IpSlice::Ipv4(s) => s.header().destination_addr().into(),
            IpSlice::Ipv6(s) => s.header().destination_addr().into(),
        }
    }

    /// Returns a slice containing the data after the IP header
    /// and IP extensions headers.
    #[inline]
    pub fn payload(&self) -> &IpPayload<'a> {
        use IpSlice::*;
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
        use IpSlice::*;
        match self {
            Ipv4(ipv4) => ipv4.payload().ip_number,
            Ipv6(ipv6) => ipv6.payload().ip_number,
        }
    }

    /// Separates and validates IP headers (including extension headers)
    /// in the given slice and determine the sub-slice containing the payload
    /// of the IP packet.
    pub fn from_ip_slice(slice: &[u8]) -> Result<IpSlice, err::ip::SliceError> {
        use crate::ip_number::AUTH;
        use err::ip::{SliceError::*, HeaderError::*, HeadersError::*};
        use IpSlice::*;

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

                    // check that the ihl has at least the length of the base IPv4 header
                    if ihl < 5 {
                        return Err(IpHeaders(Ip(Ipv4HeaderLengthSmallerThanHeader { ihl })));
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

                    // SAFETY:
                    // Safe as the slice length is checked to be at least
                    // header_len or greater above.
                    let header = unsafe {
                        Ipv4HeaderSlice::from_slice_unchecked(core::slice::from_raw_parts(
                            slice.as_ptr(),
                            header_len,
                        ))
                    };

                    // check the total_length at least contains the header
                    let total_len = usize::from(header.total_len());
                    if total_len < header_len {
                        return Err(Len(LenError {
                            required_len: header_len,
                            len: total_len,
                            len_source: LenSource::Ipv4HeaderTotalLen,
                            layer: Layer::Ipv4Packet,
                            layer_start_offset: 0,
                        }));
                    }

                    // validate the total length against the slice
                    let header_payload = if slice.len() < total_len {
                        return Err(Len(LenError {
                            required_len: total_len,
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
                                // SAFETY: Safe as total_length >= header_len was verified in an
                                // if statement above as well as that slice.len() >= total_length_usize.
                                total_len - header_len,
                            )
                        }
                    };

                    // slice extension headers
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
                                        return Err(Len(l));
                                    }
                                    E::Content(err) => {
                                        return Err(IpHeaders(ip::HeadersError::Ipv4Ext(err)))
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
                                    ip_number: auth.next_header(),
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
                                ip_number,
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
                                    I::Content(err) => IpHeaders(ip::HeadersError::Ipv6Ext(err)),
                                }
                            })?;

                    let fragmented = exts.is_fragmenting_payload();
                    Ok(Ipv6(Ipv6Slice {
                        header,
                        exts,
                        payload: IpPayload {
                            ip_number: payload_ip_number,
                            fragmented,
                            len_source,
                            payload,
                        },
                    }))
                }
                version_number => Err(IpHeaders(Ip(UnsupportedIpVersion {
                    version_number,
                }))),
            }
        }
    }

    /// Seperates IP headers (include extension headers) & the IP payload from the given
    /// slice with less strict length checks (usefull for cut off packet or for packets with
    /// unset length fields).
    ///
    /// If you want to only receive correct IpPayloads use [`IpSlice::from_slice`]
    /// instead.
    ///
    /// The main usecases for this functions are:
    ///
    /// * Parsing packets that have been cut off. This is, for example, usefull to
    ///   parse packets returned via ICMP as these usually only contain the start.
    /// * Parsing packets where the `total_len` (for IPv4) or `payload_length` (for IPv6)
    ///   have not yet been set. This can be usefull when parsing packets which have been
    ///   recorded in a layer before the length field was set (e.g. before the operating
    ///   system set the length fields).
    ///
    /// # Differences to `from_ip_slice`:
    ///
    /// The main differences is that the function ignores inconsistent
    /// `total_len` (in IPv4 headers) and `payload_length` (in IPv6 headers)
    /// values. When these length values in the IP header are inconsistant the
    /// length of the given slice is used as a substitute.
    ///
    /// You can check if the slice length was used as a substitude by checking
    /// if `result.payload().len_source` is set to [`LenSource::Slice`].
    /// If a substitution was not needed `len_source` is set to
    /// [`LenSource::Ipv4HeaderTotalLen`] or [`LenSource::Ipv6HeaderPayloadLen`].
    ///
    /// # When is the slice length used as a fallback?
    ///
    /// For IPv4 packets the slice length is used as a fallback/substitude
    /// if the `total_length` field in the IPv4 header is:
    ///
    ///  * Bigger then the given slice (payload cannot fully be seperated).
    ///  * Too small to contain at least the IPv4 header.
    ///
    /// For IPv6 packet the slice length is used as a fallback/substitude
    /// if the `payload_length` is
    ///
    /// * Bigger then the given slice (payload cannot fully be seperated).
    /// * The value `0`.
    pub fn from_ip_slice_lax(slice: &[u8]) -> Result<IpSlice, err::ip::SliceError> {
        use crate::ip_number::AUTH;
        use err::ip::{SliceError::*, HeaderError::*, HeadersError::*};
        use IpSlice::*;

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
                        return Err(IpHeaders(Ip(Ipv4HeaderLengthSmallerThanHeader { ihl })));
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

                    // SAFETY:
                    // Safe as the slice length is checked to be at least
                    // header_len or greater above.
                    let header = unsafe {
                        Ipv4HeaderSlice::from_slice_unchecked(core::slice::from_raw_parts(
                            slice.as_ptr(),
                            header_len,
                        ))
                    };

                    // check the total_lenat least contains the header
                    let total_len = usize::from(header.total_len());

                    let (header_payload, len_source) =
                        if total_len >= header_len && slice.len() >= total_len {
                            (
                                unsafe {
                                    core::slice::from_raw_parts(
                                        // SAFETY: Safe as slice.len() >= header_len was validated
                                        // in a if statement above.
                                        slice.as_ptr().add(header_len),
                                        // SAFETY: Safe as total_length >= header_len was verfied in an
                                        // if statement above as well as that slice.len() >= total_length_usize.
                                        total_len - header_len,
                                    )
                                },
                                LenSource::Ipv4HeaderTotalLen,
                            )
                        } else {
                            // fallback to slice len
                            (
                                unsafe {
                                    core::slice::from_raw_parts(
                                        // SAFETY: Safe as slice.len() >= header_len was validated
                                        // in a if statement above.
                                        slice.as_ptr().add(header_len),
                                        // SAFETY: Safe as slice.len() >= header_len was validated
                                        // in a if statement above.
                                        slice.len() - header_len,
                                    )
                                },
                                LenSource::Slice,
                            )
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
                                        l.len_source = len_source;
                                        l.layer_start_offset += header.slice().len();
                                        return Err(Len(l));
                                    }
                                    E::Content(err) => {
                                        return Err(IpHeaders(ip::HeadersError::Ipv4Ext(err)))
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
                                    ip_number: auth.next_header(),
                                    fragmented,
                                    len_source,
                                    payload,
                                },
                            }))
                        }
                        ip_number => Ok(Ipv4(Ipv4Slice {
                            header,
                            exts: Ipv4ExtensionsSlice { auth: None },
                            payload: IpPayload {
                                ip_number,
                                fragmented,
                                len_source,
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

                    // restrict slice by the length specified in the header (if possible)
                    let payload_len = usize::from(header.payload_length());
                    let (header_payload, len_source) = if 0 == header.payload_length()
                        || slice.len() - Ipv6Header::LEN < payload_len
                    {
                        // TODO: Add payload length parsing from the jumbogram for the zero case
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
                        (
                            unsafe {
                                core::slice::from_raw_parts(
                                    slice.as_ptr().add(Ipv6Header::LEN),
                                    payload_len,
                                )
                            },
                            LenSource::Ipv6HeaderPayloadLen,
                        )
                    };

                    // parse extension headers
                    let (exts, payload_ip_number, payload) =
                        Ipv6ExtensionsSlice::from_slice(header.next_header(), header_payload)
                            .map_err(|err| {
                                // modify length errors
                                use crate::err::ipv6_exts::HeaderSliceError as I;
                                match err {
                                    I::Len(mut err) => {
                                        err.len_source = len_source;
                                        err.layer_start_offset += Ipv6Header::LEN;
                                        Len(err)
                                    }
                                    I::Content(err) => IpHeaders(ip::HeadersError::Ipv6Ext(err)),
                                }
                            })?;

                    let fragmented = exts.is_fragmenting_payload();
                    Ok(Ipv6(Ipv6Slice {
                        header,
                        exts,
                        payload: IpPayload {
                            ip_number: payload_ip_number,
                            fragmented,
                            len_source,
                            payload,
                        },
                    }))
                }
                version_number => Err(IpHeaders(Ip(UnsupportedIpVersion {
                    version_number,
                }))),
            }
        }
    }
}

impl<'a> From<Ipv4Slice<'a>> for IpSlice<'a> {
    fn from(value: Ipv4Slice<'a>) -> Self {
        IpSlice::Ipv4(value)
    }
}

impl<'a> From<Ipv6Slice<'a>> for IpSlice<'a> {
    fn from(value: Ipv6Slice<'a>) -> Self {
        IpSlice::Ipv6(value)
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
            let buffer = header.to_bytes();

            let ipv4 = Ipv4Slice::from_slice(&buffer).unwrap();
            let slice = IpSlice::Ipv4(ipv4.clone());

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
            let buffer = header.to_bytes();
            let ipv6 = Ipv6Slice::from_slice(&buffer).unwrap();
            let slice = IpSlice::Ipv6(ipv6.clone());

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
                let mut ipv4 = Ipv4Header::new(0, 1, UDP, [3, 4, 5, 6], [7, 8, 9, 10]).unwrap();
                if fragment {
                    ipv4.fragment_offset = 123.try_into().unwrap();
                }

                let data = ipv4.to_bytes();
                let ipv4_slice = Ipv4Slice::from_slice(&data).unwrap();
                assert_eq!(fragment, IpSlice::Ipv4(ipv4_slice).is_fragmenting_payload());
            }

            // ipv6
            {
                let ipv6_frag = Ipv6FragmentHeader {
                    next_header: UDP,
                    fragment_offset: IpFragOffset::ZERO,
                    more_fragments: fragment,
                    identification: 0,
                };
                let ipv6 = Ipv6Header {
                    traffic_class: 0,
                    flow_label: 1.try_into().unwrap(),
                    payload_length: ipv6_frag.header_len() as u16,
                    next_header: ip_number::IPV6_FRAG,
                    hop_limit: 4,
                    source: [1; 16],
                    destination: [2; 16],
                };
                let mut data = Vec::with_capacity(ipv6.header_len() + ipv6_frag.header_len());
                data.extend_from_slice(&ipv6.to_bytes());
                data.extend_from_slice(&ipv6_frag.to_bytes());

                assert_eq!(
                    fragment,
                    IpSlice::Ipv6(Ipv6Slice::from_slice(&data).unwrap()).is_fragmenting_payload()
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
                .unwrap()
                .to_bytes();
            assert_eq!(
                IpAddr::V4(Ipv4Addr::from([3, 4, 5, 6])),
                IpSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).source_addr()
            );
        }

        // ipv6
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: 0,
                next_header: ip_number::IGMP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            }
            .to_bytes();

            assert_eq!(
                IpAddr::V6(Ipv6Addr::from([1; 16])),
                IpSlice::Ipv6(Ipv6Slice::from_slice(&data[..]).unwrap()).source_addr()
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
                .unwrap()
                .to_bytes();

            assert_eq!(
                IpAddr::V4(Ipv4Addr::from([7, 8, 9, 10])),
                IpSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).destination_addr()
            );
        }

        // ipv6
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: 0,
                next_header: ip_number::IGMP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            }
            .to_bytes();

            assert_eq!(
                IpAddr::V6(Ipv6Addr::from([2; 16])),
                IpSlice::Ipv6(Ipv6Slice::from_slice(&data).unwrap()).destination_addr()
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
            )
            .unwrap();
            let mut data = Vec::with_capacity(header.header_len() + payload.len());
            data.extend_from_slice(&header.to_bytes());
            data.extend_from_slice(&payload);
            assert_eq!(
                IpSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).payload(),
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
                flow_label: 1.try_into().unwrap(),
                payload_length: payload.len() as u16,
                next_header: ip_number::UDP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            };
            let mut data = Vec::with_capacity(header.header_len() + payload.len());
            data.extend_from_slice(&header.to_bytes());
            data.extend_from_slice(&payload);
            assert_eq!(
                IpSlice::Ipv6(Ipv6Slice::from_slice(&data[..]).unwrap()).payload(),
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
                .unwrap()
                .to_bytes();
            assert_eq!(
                UDP,
                IpSlice::Ipv4(Ipv4Slice::from_slice(&data[..]).unwrap()).payload_ip_number()
            );
        }

        // ipv6
        {
            let data = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: 0,
                next_header: IGMP,
                hop_limit: 4,
                source: [1; 16],
                destination: [2; 16],
            }
            .to_bytes();

            assert_eq!(
                IGMP,
                IpSlice::Ipv6(Ipv6Slice::from_slice(&data).unwrap()).payload_ip_number()
            );
        }
    }

    proptest! {
        #[test]
        fn from_ip_slice(
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
                header.total_len = (header.header_len() + ipv4_exts.header_len() + payload.len()) as u16;
                header.header_checksum = header.calc_header_checksum();
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
                let actual = IpSlice::from_ip_slice(&data).unwrap();
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
                let actual = crate::IpSlice::from_ip_slice(&data).unwrap();
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
                let actual = crate::IpSlice::from_ip_slice(&data).unwrap();
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

    proptest! {
        #[test]
        fn from_ip_slice_lax(
            ipv4_header in ipv4_any(),
            ipv4_exts in ipv4_extensions_with(ip_number::UDP),
            ipv6_header in ipv6_any(),
            mut ipv6_exts in ipv6_extensions_with(ip_number::UDP)
        ) {
            use err::ip::{SliceError::*, HeadersError::*, HeaderError::*};
            use err::ip_auth::HeaderError::*;
            use crate::IpHeader;

            // zero payload
            assert_eq!(
                IpSlice::from_ip_slice_lax(&[]),
                Err(Len(err::LenError{
                    required_len: 1,
                    len: 0,
                    len_source: err::LenSource::Slice,
                    layer: err::Layer::IpHeader,
                    layer_start_offset: 0,
                }))
            );

            // unknown version number
            for bad_version in 0..0xfu8 {
                if bad_version != 4 && bad_version != 6 {
                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&[bad_version << 4]),
                        Err(IpHeaders(Ip(UnsupportedIpVersion {
                            version_number: bad_version,
                        })))
                    );
                }
            }

            let payload = [1,2,3,4];

            // IPv4
            {
                // setup header length & fields
                let ipv4_header = {
                    let mut header = ipv4_header;
                    header.protocol = if ipv4_exts.auth.is_some() {
                        ip_number::AUTH
                    } else {
                        ip_number::UDP
                    };
                    header.total_len = (header.header_len() + ipv4_exts.header_len() + payload.len()) as u16;
                    header.header_checksum = header.calc_header_checksum();
                    header
                };

                let ipv4 = IpHeader::Version4(
                    ipv4_header.clone(),
                    ipv4_exts.clone()
                );

                // build packet
                let mut buffer = Vec::with_capacity(ipv4.header_len() + payload.len());
                ipv4.write(&mut buffer).unwrap();
                buffer.extend_from_slice(&payload);

                // happy path v4
                {
                    // run test
                    let actual = IpSlice::from_ip_slice_lax(&buffer).unwrap();
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

                // ihl smaller then 5 error
                for bad_ihl in 0..5u8 {
                    let mut buffer = buffer.clone();

                    // inject bad IHL
                    buffer[0] = (buffer[0] & 0xf0u8) | bad_ihl;

                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&buffer),
                        Err(IpHeaders(Ip(Ipv4HeaderLengthSmallerThanHeader { ihl: bad_ihl })))
                    );
                }

                // slice smaller then header error
                for bad_len in 1..ipv4_header.header_len() {
                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&buffer[..bad_len]),
                        Err(Len(err::LenError{
                            required_len: ipv4_header.header_len(),
                            len: bad_len,
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv4Header,
                            layer_start_offset: 0,
                        }))
                    );
                }

                // total len smaller then header
                for bad_len in 1..ipv4_header.header_len() {
                    let mut buffer = buffer.clone();

                    // inject bad total length
                    let bad_len_be = (bad_len as u16).to_be_bytes();
                    buffer[2] = bad_len_be[0];
                    buffer[3] = bad_len_be[1];

                    // expect a valid parse with length source "slice"
                    let actual = IpSlice::from_ip_slice_lax(&buffer).unwrap();
                    let actual = actual.ipv4().unwrap().clone();
                    let mut expected_header = ipv4_header.clone();
                    expected_header.total_len = bad_len as u16;
                    assert_eq!(actual.header.to_header(), expected_header);
                    assert_eq!(actual.extensions().to_header(), ipv4_exts);
                    assert_eq!(
                        actual.payload,
                        IpPayload{
                            ip_number: ip_number::UDP.into(),
                            fragmented: ipv4_header.is_fragmenting_payload(),
                            len_source: LenSource::Slice,
                            payload: &payload
                        }
                    );
                }

                // total len bigger then slice
                {
                    let bad_len = (buffer.len() + 1) as u16;
                    let mut buffer = buffer.clone();

                    // inject bad total length
                    let bad_len_be = (bad_len as u16).to_be_bytes();
                    buffer[2] = bad_len_be[0];
                    buffer[3] = bad_len_be[1];

                    // expect a valid parse with length source "slice"
                    let actual = IpSlice::from_ip_slice_lax(&buffer).unwrap();
                    let actual = actual.ipv4().unwrap().clone();
                    let mut expected_header = ipv4_header.clone();
                    expected_header.total_len = bad_len as u16;
                    assert_eq!(actual.header.to_header(), expected_header);
                    assert_eq!(actual.extensions().to_header(), ipv4_exts);
                    assert_eq!(
                        actual.payload,
                        IpPayload{
                            ip_number: ip_number::UDP.into(),
                            fragmented: ipv4_header.is_fragmenting_payload(),
                            len_source: LenSource::Slice,
                            payload: &payload
                        }
                    );
                }

                // auth ext header len error
                if ipv4_exts.auth.is_some() {
                    let bad_len = ipv4_header.header_len() + ipv4_exts.header_len() - 1;
                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&buffer[..bad_len]),
                        Err(Len(err::LenError{
                            required_len: ipv4_exts.header_len(),
                            len: bad_len - ipv4_header.header_len(),
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::IpAuthHeader,
                            layer_start_offset: ipv4_header.header_len(),
                        }))
                    );
                }

                // auth ext header content error
                if ipv4_exts.auth.is_some() {
                    let mut buffer = buffer.clone();
                    buffer[ipv4_header.header_len() + 1] = 0;
                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&buffer),
                        Err(IpHeaders(Ipv4Ext(ZeroPayloadLen)))
                    );
                }
            }

            // IPv6
            {
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

                // build packet
                let mut buffer = Vec::with_capacity(ipv6.header_len() + payload.len());
                ipv6.write(&mut buffer).unwrap();
                buffer.extend_from_slice(&payload);

                // happy path v6
                {
                    // run test
                    let actual = crate::IpSlice::from_ip_slice(&buffer).unwrap();
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

                // len error when parsing header
                for bad_len in 1..ipv6_header.header_len() {
                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&buffer[..bad_len]),
                        Err(Len(err::LenError{
                            required_len: ipv6_header.header_len(),
                            len: bad_len,
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv6Header,
                            layer_start_offset: 0,
                        }))
                    );
                }

                // ipv6 with zero payload length (should fallback to the slice length)
                {
                    let mut buffer = buffer.clone();

                    // inject 0 as payload len
                    buffer[4] = 0;
                    buffer[5] = 0;

                    // run test
                    let actual = crate::IpSlice::from_ip_slice(&buffer).unwrap();
                    let actual = actual.ipv6().unwrap().clone();
                    let mut expected_header = ipv6_header.clone();
                    expected_header.payload_length = 0;
                    assert_eq!(actual.header.to_header(), expected_header);
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

                // payload len bigger then slice
                {
                    let mut buffer = buffer.clone();

                    // inject 0 as payload len
                    let bad_payload_len = (buffer.len() - ipv6_header.header_len() + 1) as u16;
                    let bad_payload_len_be = bad_payload_len.to_be_bytes();
                    buffer[4] = bad_payload_len_be[0];
                    buffer[5] = bad_payload_len_be[1];

                    // run test
                    let actual = crate::IpSlice::from_ip_slice_lax(&buffer).unwrap();
                    let actual = actual.ipv6().unwrap().clone();
                    let mut expected_header = ipv6_header.clone();
                    expected_header.payload_length = bad_payload_len;

                    assert_eq!(actual.header.to_header(), expected_header);
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

                // extension length error
                if ipv6_exts.header_len() > 0 {
                    let bad_len = Ipv6Header::LEN + ipv6_exts.header_len() - 1;
                    assert!(
                        IpSlice::from_ip_slice_lax(&buffer[..bad_len]).is_err()
                    );
                }

                // extension content error
                if ipv6_exts.auth.is_some() {
                    use err::ip::HeadersError::Ipv6Ext;
                    use err::ipv6_exts::HeaderError::IpAuth;

                    // introduce a auth header zero payload error
                    let mut buffer = buffer.clone();
                    let auth_offset = ipv6_header.header_len() +
                        ipv6_exts.hop_by_hop_options.as_ref().map(|h| h.header_len()).unwrap_or(0) +
                        ipv6_exts.destination_options.as_ref().map(|h| h.header_len()).unwrap_or(0) +
                        ipv6_exts.routing.as_ref().map(|h| h.routing.header_len()).unwrap_or(0) +
                        // routing.final_destination_options skiped, as after auth
                        ipv6_exts.fragment.as_ref().map(|h| h.header_len()).unwrap_or(0);

                    // inject length zero into auth header (not valid, will
                    // trigger a content error)
                    buffer[auth_offset + 1] = 0;
                    assert_eq!(
                        IpSlice::from_ip_slice_lax(&buffer),
                        Err(IpHeaders(Ipv6Ext(IpAuth(ZeroPayloadLen))))
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn from_ipv4_slice(
            ipv4_header in ipv4_unknown()
        ) {
            let mut header = ipv4_header.clone();
            header.total_len = (header.header_len() + 4) as u16;

            let mut buffer = Vec::with_capacity(header.total_len.into());
            buffer.extend_from_slice(&header.to_bytes()[..]);
            buffer.extend_from_slice(&[1,2,3,4]);
            let s = Ipv4Slice::from_slice(&buffer).unwrap();
            let actual: IpSlice = s.clone().into();
            assert_eq!(IpSlice::Ipv4(s), actual);
        }
    }

    proptest! {
        #[test]
        fn from_ipv6_slice(
            ipv6_header in ipv6_unknown()
        ) {
            let mut header = ipv6_header.clone();
            header.payload_length = 4;

            let mut buffer = Vec::with_capacity(header.header_len() + 4);
            buffer.extend_from_slice(&header.to_bytes()[..]);
            buffer.extend_from_slice(&[1,2,3,4]);
            let s = Ipv6Slice::from_slice(&buffer).unwrap();
            let actual: IpSlice = s.clone().into();
            assert_eq!(IpSlice::Ipv6(s), actual);
        }
    }
}
