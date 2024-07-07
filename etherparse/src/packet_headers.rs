use crate::err::LenError;

use super::*;

/// Decoded packet headers (data link layer and lower).
///
/// You can use
///
/// * [`PacketHeaders::from_ethernet_slice`]
/// * [`PacketHeaders::from_ether_type`]
/// * [`PacketHeaders::from_ip_slice`]
///
/// depending on your starting header to parse the headers in a slice and get this
/// struct as a result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketHeaders<'a> {
    /// Ethernet II header if present.
    pub link: Option<LinkHeader>,
    /// Address Resolution Protocol if present.
    pub arp: Option<ArpHeader>,
    /// Single or double vlan headers if present.
    pub vlan: Option<VlanHeader>,
    /// IPv4 or IPv6 header and IP extension headers if present.
    pub net: Option<NetHeaders>,
    /// TCP or UDP header if present.
    pub transport: Option<TransportHeader>,
    /// Payload of the last parsed layer.
    pub payload: PayloadSlice<'a>,
}

impl<'a> PacketHeaders<'a> {
    /// Decodes a network packet into different headers from a slice that starts with an Ethernet II header.
    ///
    /// The result is returned as a [`PacketHeaders`] struct.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{Ethernet2Header, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ethernet2([1,2,3,4,5,6],     //source mac
    /// #               [7,8,9,10,11,12]) //destination mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //destination ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
    /// # // payload of the udp packet
    /// # let payload = [1,2,3,4,5,6,7,8];
    /// # // get some memory to store the serialized data
    /// # let mut complete_packet = Vec::<u8>::with_capacity(
    /// #     builder.size(payload.len())
    /// # );
    /// # builder.write(&mut complete_packet, &payload).unwrap();
    /// #
    /// # // skip ethernet 2 header so we can parse from there downwards
    /// # let packet = &complete_packet[Ethernet2Header::LEN..];
    /// #
    /// use etherparse::{ether_type, PacketHeaders};
    ///
    /// match PacketHeaders::from_ether_type(ether_type::IPV4, packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ethernet_slice(slice: &'a [u8]) -> Result<PacketHeaders, err::packet::SliceError> {
        use err::packet::SliceError::Len;

        let (ethernet, rest) = Ethernet2Header::from_slice(slice).map_err(Len)?;
        let mut result = Self::from_ether_type(ethernet.ether_type, rest);

        match &mut result {
            // inject ethernet header into the result
            Ok(result) => result.link = Some(LinkHeader::Ethernet2(ethernet)),
            // add the ethernet header to the overall offset in case there is a length error
            Err(Len(err)) => err.layer_start_offset += Ethernet2Header::LEN,
            _ => {}
        }
        result
    }

    /// Tries to decode a network packet into different headers using the
    /// given `ether_type` number to identify the first header.
    ///
    /// The result is returned as a [`PacketHeaders`] struct. Currently supported
    /// ether type numbers are:
    ///
    /// * `ether_type::IPV4`
    /// * `ether_type::IPV6`
    /// * `ether_type::VLAN_TAGGED_FRAME`
    /// * `ether_type::PROVIDER_BRIDGING`
    /// * `ether_type::VLAN_DOUBLE_TAGGED_FRAME`
    ///
    /// If an unsupported ether type is given the given slice will be set as payload
    /// and all other fields will be set to `None`.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{Ethernet2Header, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ethernet2([1,2,3,4,5,6],     //source mac
    /// #               [7,8,9,10,11,12]) //destination mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //destination ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
    /// # // payload of the udp packet
    /// # let payload = [1,2,3,4,5,6,7,8];
    /// # // get some memory to store the serialized data
    /// # let mut complete_packet = Vec::<u8>::with_capacity(
    /// #     builder.size(payload.len())
    /// # );
    /// # builder.write(&mut complete_packet, &payload).unwrap();
    /// #
    /// # // skip ethernet 2 header so we can parse from there downwards
    /// # let packet = &complete_packet[Ethernet2Header::LEN..];
    /// #
    /// use etherparse::{ether_type, PacketHeaders};
    ///
    /// match PacketHeaders::from_ether_type(ether_type::IPV4, packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ether_type(
        mut ether_type: EtherType,
        slice: &'a [u8],
    ) -> Result<PacketHeaders, err::packet::SliceError> {
        use err::packet::SliceError::*;

        let mut rest = slice;

        // helper function to add the current offset to length errors
        let add_offset = |mut len_error: LenError, rest: &[u8]| -> LenError {
            len_error.layer_start_offset += unsafe {
                // SAFETY: Safe as rest is a subslice of slice.
                rest.as_ptr().offset_from(slice.as_ptr()) as usize
            };
            len_error
        };

        let mut result = PacketHeaders {
            link: None,
            arp: None,
            vlan: None,
            net: None,
            transport: None,
            payload: PayloadSlice::Ether(EtherPayloadSlice {
                ether_type,
                payload: rest,
            }),
        };

        use ether_type::*;

        result.vlan = match ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                use crate::VlanHeader::*;
                let (outer, outer_rest) = SingleVlanHeader::from_slice(rest).map_err(Len)?;

                //set the rest & ether_type for the following operations
                rest = outer_rest;
                ether_type = outer.ether_type;
                result.payload = PayloadSlice::Ether(EtherPayloadSlice {
                    ether_type,
                    payload: rest,
                });

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                        let (inner, inner_rest) = SingleVlanHeader::from_slice(rest)
                            .map_err(|err| Len(err.add_offset(SingleVlanHeader::LEN)))?;

                        //set the rest & ether_type for the following operations
                        rest = inner_rest;
                        ether_type = inner.ether_type;
                        result.payload = PayloadSlice::Ether(EtherPayloadSlice {
                            ether_type,
                            payload: rest,
                        });

                        Some(Double(DoubleVlanHeader { outer, inner }))
                    }
                    //no second vlan header detected -> single vlan header
                    _ => Some(Single(outer)),
                }
            }
            //no vlan header
            _ => None,
        };

        // parse ip
        match ether_type {
            IPV4 => {
                // read ipv4 header & extensions and payload slice
                let (ip, ip_payload) = IpHeaders::from_ipv4_slice(rest).map_err(|err| {
                    use err::ipv4::SliceError as I;
                    match err {
                        I::Len(err) => Len(add_offset(err, rest)),
                        I::Header(err) => Ipv4(err),
                        I::Exts(err) => Ipv4Exts(err),
                    }
                })?;

                // set the next
                rest = ip_payload.payload;
                result.net = Some(ip.into());
                result.payload = PayloadSlice::Ip(ip_payload.clone());

                // decode transport layer
                let (transport, payload) = read_transport(ip_payload).map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(add_offset(err, rest)),
                        I::Content(err) => Tcp(err),
                    }
                })?;

                result.transport = transport;
                result.payload = payload;
            }
            IPV6 => {
                // read ipv6 header & extensions and payload slice
                let (ip, ip_payload) = IpHeaders::from_ipv6_slice(rest).map_err(|err| {
                    use err::ipv6::SliceError as I;
                    match err {
                        I::Len(err) => Len(add_offset(err, rest)),
                        I::Header(err) => Ipv6(err),
                        I::Exts(err) => Ipv6Exts(err),
                    }
                })?;

                //set the ip result & rest
                rest = ip_payload.payload;
                result.net = Some(ip.into());
                result.payload = PayloadSlice::Ip(ip_payload.clone());

                // decode transport layer
                let (transport, payload) = read_transport(ip_payload).map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(add_offset(err, rest)),
                        I::Content(err) => Tcp(err),
                    }
                })?;

                result.transport = transport;
                result.payload = payload;
            }
            ARP => {
                let (arp, rest) = ArpHeader::from_slice(rest).map_err(Len)?;

                result.arp = Some(arp);

                result.payload =
                    PayloadSlice::Arp((rest, ArpPayload::from_pkg(arp, rest).map_err(Len)?));
            }
            _ => {}
        };

        Ok(result)
    }

    /// Tries to decode an ip packet and its transport headers.
    ///
    /// Assumes the given slice starts with the first byte of the IP header.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::PacketBuilder;
    /// # // build a UDP packet
    /// # let payload = [0u8;18];
    /// # let builder = PacketBuilder::
    /// #    ipv4([192,168,1,1], //source ip
    /// #         [192,168,1,2], //destination ip
    /// #         20)            //time to life
    /// #    .udp(21,    //source port
    /// #        1234); //  destination port
    /// #
    /// # // serialize the packet
    /// # let packet = {
    /// #     let mut packet = Vec::<u8>::with_capacity(
    /// #         builder.size(payload.len())
    /// #     );
    /// #     builder.write(&mut packet, &payload).unwrap();
    /// #     packet
    /// # };
    /// use etherparse::PacketHeaders;
    ///
    /// match PacketHeaders::from_ip_slice(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ip_slice(slice: &[u8]) -> Result<PacketHeaders, err::packet::SliceError> {
        use err::packet::SliceError::*;

        // read ip headers
        let (ip_header, ip_payload) = IpHeaders::from_slice(slice).map_err(|err| {
            use err::ip::HeadersSliceError as I;
            match err {
                I::Len(err) => Len(err),
                I::Content(err) => match err {
                    err::ip::HeadersError::Ip(err) => Ip(err),
                    err::ip::HeadersError::Ipv4Ext(err) => Ipv4Exts(err),
                    err::ip::HeadersError::Ipv6Ext(err) => Ipv6Exts(err),
                },
            }
        })?;

        let mut result = PacketHeaders {
            link: None,
            arp: None,
            vlan: None,
            net: Some(ip_header.into()),
            transport: None,
            payload: PayloadSlice::Ip(ip_payload.clone()),
        };

        // cache rest for offset addition
        let rest = ip_payload.payload;

        // try to parse the transport header (only if data is not fragmented)
        let (transport, payload) = read_transport(ip_payload).map_err(|err| {
            use err::tcp::HeaderSliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += unsafe {
                        // SAFETY: Safe as rest is a subslice of slice.
                        rest.as_ptr().offset_from(slice.as_ptr()) as usize
                    };
                    Len(err)
                }
                I::Content(err) => Tcp(err),
            }
        })?;

        // update output
        result.transport = transport;
        result.payload = payload;

        Ok(result)
    }
}

/// helper function to process transport headers
fn read_transport(
    ip_payload: IpPayloadSlice,
) -> Result<(Option<TransportHeader>, PayloadSlice), err::tcp::HeaderSliceError> {
    if ip_payload.fragmented {
        Ok((None, PayloadSlice::Ip(ip_payload)))
    } else {
        // helper function to set the len source in len errors
        let add_len_source = |mut len_error: LenError| -> err::tcp::HeaderSliceError {
            // only change the len source if the lower layer has not set it
            if LenSource::Slice == len_error.len_source {
                len_error.len_source = ip_payload.len_source;
            }
            Len(len_error)
        };
        use crate::ip_number::*;
        use err::tcp::HeaderSliceError::*;
        match ip_payload.ip_number {
            ICMP => Icmpv4Slice::from_slice(ip_payload.payload)
                .map_err(add_len_source)
                .map(|value| {
                    (
                        Some(TransportHeader::Icmpv4(value.header())),
                        PayloadSlice::Icmpv4(value.payload()),
                    )
                }),
            IPV6_ICMP => Icmpv6Slice::from_slice(ip_payload.payload)
                .map_err(add_len_source)
                .map(|value| {
                    (
                        Some(TransportHeader::Icmpv6(value.header())),
                        PayloadSlice::Icmpv6(value.payload()),
                    )
                }),
            UDP => UdpHeader::from_slice(ip_payload.payload)
                .map_err(add_len_source)
                .map(|value| {
                    (
                        Some(TransportHeader::Udp(value.0)),
                        PayloadSlice::Udp(value.1),
                    )
                }),
            TCP => TcpHeader::from_slice(ip_payload.payload)
                .map_err(|err| match err {
                    Len(err) => add_len_source(err),
                    Content(err) => Content(err),
                })
                .map(|value| {
                    (
                        Some(TransportHeader::Tcp(value.0)),
                        PayloadSlice::Tcp(value.1),
                    )
                }),
            _ => Ok((None, PayloadSlice::Ip(ip_payload))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::packet::SliceError;
    use crate::test_packet::TestPacket;

    const VLAN_ETHER_TYPES: [EtherType; 3] = [
        ether_type::VLAN_TAGGED_FRAME,
        ether_type::PROVIDER_BRIDGING,
        ether_type::VLAN_DOUBLE_TAGGED_FRAME,
    ];

    #[test]
    fn debug() {
        use alloc::format;
        let header = PacketHeaders {
            link: None,
            arp: None,
            vlan: None,
            net: None,
            transport: None,
            payload: PayloadSlice::Ether(EtherPayloadSlice {
                ether_type: EtherType(0),
                payload: &[],
            }),
        };
        assert_eq!(
            &format!("{:?}", header),
            &format!(
                "PacketHeaders {{ link: {:?}, vlan: {:?}, net: {:?}, transport: {:?}, payload: {:?} }}",
                header.link,
                header.vlan,
                header.net,
                header.transport,
                header.payload
            )
        );
    }

    #[test]
    fn clone_eq() {
        let header = PacketHeaders {
            link: None,
            arp: None,
            vlan: None,
            net: None,
            transport: None,
            payload: PayloadSlice::Ether(EtherPayloadSlice {
                ether_type: EtherType(0),
                payload: &[],
            }),
        };
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn from_x_slice() {
        // no eth
        from_x_slice_vlan_variants(&TestPacket {
            link: None,
            vlan: None,
            net: None,
            transport: None,
        });

        // eth
        {
            let eth = Ethernet2Header {
                source: [1, 2, 3, 4, 5, 6],
                destination: [1, 2, 3, 4, 5, 6],
                ether_type: 0.into(),
            };
            let test = TestPacket {
                link: Some(LinkHeader::Ethernet2(eth.clone())),
                vlan: None,
                net: None,
                transport: None,
            };

            // ok ethernet header (with unknown next)
            from_x_slice_vlan_variants(&test);

            // eth len error
            {
                let data = test.to_vec(&[]);
                for len in 0..data.len() {
                    let err = LenError {
                        required_len: eth.header_len(),
                        len,
                        len_source: LenSource::Slice,
                        layer: err::Layer::Ethernet2Header,
                        layer_start_offset: 0,
                    };

                    from_slice_assert_err(&test, &data[..len], SliceError::Len(err.clone()));
                }
            }
        }
    }

    fn from_x_slice_vlan_variants(base: &TestPacket) {
        // none
        from_x_slice_ip_variants(base);

        // single vlan header
        {
            let single = SingleVlanHeader {
                pcp: 1.try_into().unwrap(),
                drop_eligible_indicator: false,
                vlan_id: 2.try_into().unwrap(),
                ether_type: 3.into(),
            };

            for vlan_ether_type in VLAN_ETHER_TYPES {
                let mut test = base.clone();
                test.set_ether_type(vlan_ether_type);
                test.vlan = Some(VlanHeader::Single(single.clone()));

                // ok vlan header
                from_x_slice_ip_variants(&test);

                // len error
                {
                    let data = test.to_vec(&[]);
                    for len in 0..single.header_len() {
                        let base_len = test.len(&[]) - single.header_len();

                        let err = LenError {
                            required_len: single.header_len(),
                            len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::VlanHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            SliceError::Len(err.clone()),
                        );
                    }
                }
            }
        }

        // double vlan header
        for outer_vlan_ether_type in VLAN_ETHER_TYPES {
            for inner_vlan_ether_type in VLAN_ETHER_TYPES {
                let double = DoubleVlanHeader {
                    outer: SingleVlanHeader {
                        pcp: 1.try_into().unwrap(),
                        drop_eligible_indicator: false,
                        vlan_id: 2.try_into().unwrap(),
                        ether_type: inner_vlan_ether_type,
                    },
                    inner: SingleVlanHeader {
                        pcp: 1.try_into().unwrap(),
                        drop_eligible_indicator: false,
                        vlan_id: 2.try_into().unwrap(),
                        ether_type: 3.into(),
                    },
                };
                let mut test = base.clone();
                test.set_ether_type(outer_vlan_ether_type);
                test.vlan = Some(VlanHeader::Double(double.clone()));

                // ok double vlan header
                from_x_slice_ip_variants(&test);

                // len error
                {
                    let data = test.to_vec(&[]);
                    for len in 0..SingleVlanHeader::LEN {
                        let base_len = test.len(&[]) - SingleVlanHeader::LEN;

                        let err = LenError {
                            required_len: SingleVlanHeader::LEN,
                            len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::VlanHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            SliceError::Len(err.clone()),
                        );
                    }
                }
            }
        }
    }

    fn from_x_slice_ip_variants(base: &TestPacket) {
        // none
        from_x_slice_transport_variants(base);

        // ipv4
        for fragmented in [false, true] {
            let ipv4 = {
                let mut ipv4 =
                    Ipv4Header::new(0, 1, 2.into(), [3, 4, 5, 6], [7, 8, 9, 10]).unwrap();
                ipv4.more_fragments = fragmented;
                ipv4
            };

            {
                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV4);
                test.net = Some(NetHeaders::Ipv4(ipv4.clone(), Default::default()));

                // ok ipv4
                from_x_slice_transport_variants(&test);

                // ipv4 len error
                {
                    let data = test.to_vec(&[]);
                    for len in 0..ipv4.header_len() {
                        let base_len = test.len(&[]) - ipv4.header_len();

                        let err = LenError {
                            required_len: ipv4.header_len(),
                            len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::Ipv4Header,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            if test.link.is_some() || test.vlan.is_some() {
                                SliceError::Len(err.clone())
                            } else {
                                SliceError::Len({
                                    if len < 1 {
                                        let mut err = err.clone();
                                        err.required_len = 1;
                                        err.layer = err::Layer::IpHeader;
                                        err
                                    } else {
                                        err.clone()
                                    }
                                })
                            },
                        );
                    }
                }

                // ipv4 content error
                {
                    let mut data = test.to_vec(&[]);
                    let ipv4_offset = data.len() - ipv4.header_len();

                    // set the ihl to 0 to trigger a content error
                    data[ipv4_offset] = 0b1111_0000 & data[ipv4_offset];

                    from_slice_assert_err(
                        &test,
                        &data,
                        if test.link.is_some() || test.vlan.is_some() {
                            SliceError::Ipv4(
                                err::ipv4::HeaderError::HeaderLengthSmallerThanHeader { ihl: 0 },
                            )
                        } else {
                            SliceError::Ip(
                                err::ip::HeaderError::Ipv4HeaderLengthSmallerThanHeader { ihl: 0 },
                            )
                        },
                    );
                }
            }

            // ipv4 extension content error
            {
                let auth = IpAuthHeader::new(0.into(), 1, 2, &[]).unwrap();

                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV4);
                test.net = Some(NetHeaders::Ipv4(
                    {
                        let mut ipv4 = ipv4.clone();
                        ipv4.protocol = ip_number::AUTH;
                        ipv4
                    },
                    Ipv4Extensions {
                        auth: Some(auth.clone()),
                    },
                ));
                test.set_payload_len(0);

                // ok ipv4 & extension
                from_x_slice_transport_variants(&test);

                // ipv4 extension len error
                for len in 0..auth.header_len() {
                    // set payload length
                    let mut test = test.clone();
                    test.set_payload_le_from_ip_on(
                        -1 * (auth.header_len() as isize) + (len as isize),
                    );

                    let data = test.to_vec(&[]);
                    let base_len = test.len(&[]) - auth.header_len();

                    let err = LenError {
                        required_len: auth.header_len(),
                        len,
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        layer: err::Layer::IpAuthHeader,
                        layer_start_offset: base_len,
                    };

                    from_slice_assert_err(
                        &test,
                        &data[..base_len + len],
                        SliceError::Len(err.clone()),
                    );
                }

                // ipv4 extension content error
                {
                    let mut data = test.to_vec(&[]);
                    let auth_offset = data.len() - auth.header_len();

                    // set the icv len too smaller then allowed
                    data[auth_offset + 1] = 0;

                    // expect an error
                    let err = err::ip_auth::HeaderError::ZeroPayloadLen;
                    from_slice_assert_err(&test, &data, SliceError::Ipv4Exts(err.clone()));
                }
            }
        }

        // ipv6
        {
            let ipv6 = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: 2,
                next_header: 3.into(),
                hop_limit: 4,
                source: [0; 16],
                destination: [0; 16],
            };

            // ipv6 header only
            {
                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV6);
                test.net = Some(NetHeaders::Ipv6(ipv6.clone(), Default::default()));
                test.set_payload_len(0);

                // ok ipv6
                from_x_slice_transport_variants(&test);

                // header len ipv6
                {
                    let data = test.to_vec(&[]);
                    for len in 0..ipv6.header_len() {
                        let base_len = test.len(&[]) - ipv6.header_len();

                        let err = err::LenError {
                            required_len: ipv6.header_len(),
                            len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::Ipv6Header,
                            layer_start_offset: base_len,
                        };

                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            if test.link.is_some() || test.vlan.is_some() {
                                SliceError::Len(err.clone())
                            } else {
                                SliceError::Len({
                                    if len < 1 {
                                        let mut err = err.clone();
                                        err.required_len = 1;
                                        err.layer = err::Layer::IpHeader;
                                        err
                                    } else {
                                        err.clone()
                                    }
                                })
                            },
                        );
                    }
                }

                // content error ipv6
                {
                    use err::ip::HeaderError::*;
                    let mut data = test.to_vec(&[]);

                    // inject an invalid ip version
                    let base_len = data.len() - ipv6.header_len();
                    data[base_len] = data[base_len] & 0b0000_1111;

                    from_slice_assert_err(
                        &test,
                        &data,
                        if test.link.is_some() || test.vlan.is_some() {
                            SliceError::Ipv6(err::ipv6::HeaderError::UnexpectedVersion {
                                version_number: 0,
                            })
                        } else {
                            SliceError::Ip(UnsupportedIpVersion { version_number: 0 })
                        },
                    );
                }
            }

            // ipv6 + extension
            for fragment in [false, true] {
                let auth = IpAuthHeader::new(ip_number::GGP, 1, 2, &[]).unwrap();
                let frag = Ipv6FragmentHeader {
                    next_header: ip_number::AUTH,
                    fragment_offset: 0.try_into().unwrap(),
                    more_fragments: fragment,
                    identification: 3,
                };

                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV6);
                test.net = Some(NetHeaders::Ipv6(
                    {
                        let mut ipv6 = ipv6.clone();
                        ipv6.next_header = ip_number::IPV6_FRAG;
                        ipv6
                    },
                    {
                        let mut exts: Ipv6Extensions = Default::default();
                        exts.fragment = Some(frag.clone());
                        exts.auth = Some(auth.clone());
                        exts
                    },
                ));
                test.set_payload_len(0);

                // ok ipv6 & extensions
                from_x_slice_transport_variants(&test);

                // ipv6 extension len error
                for len in 0..auth.header_len() {
                    // set payload length
                    let mut test = test.clone();
                    test.set_payload_le_from_ip_on(
                        -1 * (auth.header_len() as isize) + (len as isize),
                    );

                    let data = test.to_vec(&[]);
                    let base_len = test.len(&[]) - auth.header_len();

                    let err = LenError {
                        required_len: auth.header_len(),
                        len,
                        len_source: LenSource::Ipv6HeaderPayloadLen,
                        layer: err::Layer::IpAuthHeader,
                        layer_start_offset: base_len,
                    };
                    from_slice_assert_err(
                        &test,
                        &data[..base_len + len],
                        SliceError::Len(err.clone()),
                    );
                }

                // ipv6 extension content error (auth)
                {
                    let mut data = test.to_vec(&[]);
                    let auth_offset = data.len() - auth.header_len();
                    // set the icv len too smaller then allowed
                    data[auth_offset + 1] = 0;

                    let err = err::ip_auth::HeaderError::ZeroPayloadLen;
                    from_slice_assert_err(
                        &test,
                        &data,
                        SliceError::Ipv6Exts(err::ipv6_exts::HeaderError::IpAuth(err.clone())),
                    );
                }

                // ipv6 extension content error (hop by hop not at start)
                {
                    let mut data = test.to_vec(&[]);
                    let auth_offset = data.len() - auth.header_len();

                    // set the next header to be a hop-by-hop header to trigger a "not at start error"
                    data[auth_offset] = 0;

                    from_slice_assert_err(
                        &test,
                        &data,
                        SliceError::Ipv6Exts(err::ipv6_exts::HeaderError::HopByHopNotAtStart),
                    );
                }
            }
        }
    }

    fn from_x_slice_transport_variants(base: &TestPacket) {
        // none
        from_x_slice_assert_ok(base);

        // transport can only be set if ip is present
        if let Some(ip) = &base.net {
            // udp
            {
                let udp = UdpHeader {
                    source_port: 1,
                    destination_port: 2,
                    length: 3,
                    checksum: 4,
                };
                let mut test = base.clone();
                test.net = Some({
                    let mut ip = match ip {
                        NetHeaders::Ipv4(h, e) => IpHeaders::Ipv4(h.clone(), e.clone()),
                        NetHeaders::Ipv6(h, e) => IpHeaders::Ipv6(h.clone(), e.clone()),
                    };
                    ip.set_next_headers(ip_number::UDP);
                    ip.into()
                });
                test.transport = Some(TransportHeader::Udp(udp.clone()));
                test.set_payload_len(0);

                // ok decode
                from_x_slice_assert_ok(&test);

                // length error
                if false == test.is_ip_payload_fragmented() {
                    for len in 0..udp.header_len() {
                        // build new test packet
                        let mut test = test.clone();

                        // set payload length
                        test.set_payload_le_from_ip_on(len as isize);

                        // generate data
                        let data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - udp.header_len();

                        let err = LenError {
                            required_len: udp.header_len(),
                            len,
                            len_source: match test.net.as_ref().unwrap() {
                                NetHeaders::Ipv4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                NetHeaders::Ipv6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: err::Layer::UdpHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            SliceError::Len(err.clone()),
                        );
                    }
                }
            }

            // tcp
            {
                let tcp = TcpHeader::new(1, 2, 3, 4);
                let mut test = base.clone();
                test.net = Some({
                    let mut ip = match ip {
                        NetHeaders::Ipv4(h, e) => IpHeaders::Ipv4(h.clone(), e.clone()),
                        NetHeaders::Ipv6(h, e) => IpHeaders::Ipv6(h.clone(), e.clone()),
                    };
                    ip.set_next_headers(ip_number::TCP);
                    ip.into()
                });
                test.transport = Some(TransportHeader::Tcp(tcp.clone()));
                test.set_payload_len(0);

                // ok decode
                from_x_slice_assert_ok(&test);

                // error can only occur if ip does not fragment the packet
                if false == test.is_ip_payload_fragmented() {
                    // length error
                    for len in 0..(tcp.header_len() as usize) {
                        // set payload length
                        let mut test = test.clone();
                        test.set_payload_le_from_ip_on(len as isize);

                        let data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - (tcp.header_len() as usize);

                        let err = LenError {
                            required_len: tcp.header_len() as usize,
                            len,
                            len_source: match test.net.as_ref().unwrap() {
                                NetHeaders::Ipv4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                NetHeaders::Ipv6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: err::Layer::TcpHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            SliceError::Len(err.clone()),
                        );
                    }

                    // content error
                    {
                        let mut data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - (tcp.header_len() as usize);

                        // set data offset to 0 to trigger an error
                        data[base_len + 12] = data[base_len + 12] & 0b0000_1111;

                        let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 0 };
                        from_slice_assert_err(&test, &data, SliceError::Tcp(err.clone()));
                    }
                }
            }

            // icmpv4
            {
                let icmpv4 =
                    Icmpv4Header::new(Icmpv4Type::EchoReply(IcmpEchoHeader { id: 1, seq: 2 }));
                let mut test = base.clone();
                test.net = Some({
                    let mut ip = match ip {
                        NetHeaders::Ipv4(h, e) => IpHeaders::Ipv4(h.clone(), e.clone()),
                        NetHeaders::Ipv6(h, e) => IpHeaders::Ipv6(h.clone(), e.clone()),
                    };
                    ip.set_next_headers(ip_number::ICMP);
                    ip.into()
                });
                test.transport = Some(TransportHeader::Icmpv4(icmpv4.clone()));

                // ok decode
                from_x_slice_assert_ok(&test);

                // length error
                if false == test.is_ip_payload_fragmented() {
                    for len in 0..icmpv4.header_len() {
                        // set payload length
                        let mut test = test.clone();
                        test.set_payload_le_from_ip_on(len as isize);

                        let data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - icmpv4.header_len();

                        let err = LenError {
                            required_len: icmpv4.header_len(),
                            len,
                            len_source: match test.net.as_ref().unwrap() {
                                NetHeaders::Ipv4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                NetHeaders::Ipv6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: err::Layer::Icmpv4,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            SliceError::Len(err.clone()),
                        );
                    }
                }
            }

            // icmpv6
            {
                let icmpv6 =
                    Icmpv6Header::new(Icmpv6Type::EchoReply(IcmpEchoHeader { id: 1, seq: 2 }));
                let mut test = base.clone();
                test.net = Some({
                    let mut ip = match ip {
                        NetHeaders::Ipv4(h, e) => IpHeaders::Ipv4(h.clone(), e.clone()),
                        NetHeaders::Ipv6(h, e) => IpHeaders::Ipv6(h.clone(), e.clone()),
                    };
                    ip.set_next_headers(ip_number::IPV6_ICMP);
                    ip.into()
                });
                test.transport = Some(TransportHeader::Icmpv6(icmpv6.clone()));

                // ok decode
                from_x_slice_assert_ok(&test);

                // length error
                if false == test.is_ip_payload_fragmented() {
                    for len in 0..icmpv6.header_len() {
                        // set payload length
                        let mut test = test.clone();
                        test.set_payload_le_from_ip_on(len as isize);

                        let data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - icmpv6.header_len();

                        let err = LenError {
                            required_len: icmpv6.header_len(),
                            len,
                            len_source: match test.net.as_ref().unwrap() {
                                NetHeaders::Ipv4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                NetHeaders::Ipv6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: err::Layer::Icmpv6,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            SliceError::Len(err.clone()),
                        );
                    }
                }
            }
        }
    }

    fn from_x_slice_assert_ok(test_base: &TestPacket) {
        let payload = [1, 2, 3, 4];

        // set length fields in ip headers
        let test = {
            let mut test = test_base.clone();
            test.set_payload_len(payload.len());
            test
        };

        // check if fragmenting
        let is_fragmented = test.is_ip_payload_fragmented();

        // write data
        let data = test.to_vec(&payload);

        // from_ethernet_slice
        if test.link.is_some() {
            let result = PacketHeaders::from_ethernet_slice(&data).unwrap();
            assert_eq!(result.link, test.link);
            assert_eq!(result.vlan, test.vlan);
            assert_eq!(result.net, test.net);
            if is_fragmented {
                assert_eq!(result.transport, None);
            } else {
                assert_eq!(result.transport, test.transport);
                assert_eq!(result.payload.slice(), &[1, 2, 3, 4]);
            }
        }
        // from_ether_type (vlan at start)
        if test.link.is_none() && test.vlan.is_some() {
            for ether_type in VLAN_ETHER_TYPES {
                let result = PacketHeaders::from_ether_type(ether_type, &data).unwrap();
                assert_eq!(result.link, test.link);
                assert_eq!(result.vlan, test.vlan);
                assert_eq!(result.net, test.net);
                if is_fragmented {
                    assert_eq!(result.transport, None);
                } else {
                    assert_eq!(result.transport, test.transport);
                    assert_eq!(result.payload.slice(), &[1, 2, 3, 4]);
                }
            }
        }
        // from_ether_type (ip at start)
        if test.link.is_none() && test.vlan.is_none() {
            if let Some(ip) = &test.net {
                let result = PacketHeaders::from_ether_type(
                    match ip {
                        NetHeaders::Ipv4(_, _) => ether_type::IPV4,
                        NetHeaders::Ipv6(_, _) => ether_type::IPV6,
                    },
                    &data,
                )
                .unwrap();
                assert_eq!(result.link, test.link);
                assert_eq!(result.vlan, test.vlan);
                assert_eq!(result.net, test.net);
                if is_fragmented {
                    assert_eq!(result.transport, None);
                } else {
                    assert_eq!(result.transport, test.transport);
                    assert_eq!(result.payload.slice(), &[1, 2, 3, 4]);
                }
            }
        }
        // from_ip_slice
        if test.link.is_none() && test.vlan.is_none() && test.net.is_some() {
            let result = PacketHeaders::from_ip_slice(&data).unwrap();
            assert_eq!(result.link, test.link);
            assert_eq!(result.vlan, test.vlan);
            assert_eq!(result.net, test.net);
            if is_fragmented {
                assert_eq!(result.transport, None);
            } else {
                assert_eq!(result.transport, test.transport);
                assert_eq!(result.payload.slice(), &[1, 2, 3, 4]);
            }
        }
    }

    /// Check that the given errors get triggered if presented with the given
    /// data.
    fn from_slice_assert_err(test: &TestPacket, data: &[u8], err: SliceError) {
        // from_ethernet_slice
        if test.link.is_some() {
            assert_eq!(
                err.clone(),
                PacketHeaders::from_ethernet_slice(&data).unwrap_err()
            );
        }
        // from_ether_type (vlan at start)
        if test.link.is_none() && test.vlan.is_some() {
            for ether_type in VLAN_ETHER_TYPES {
                assert_eq!(
                    err.clone(),
                    PacketHeaders::from_ether_type(ether_type, &data).unwrap_err()
                );
            }
        }
        // from_ether_type (ip at start)
        if test.link.is_none() && test.vlan.is_none() {
            if let Some(ip) = &test.net {
                let err = PacketHeaders::from_ether_type(
                    match ip {
                        NetHeaders::Ipv4(_, _) => ether_type::IPV4,
                        NetHeaders::Ipv6(_, _) => ether_type::IPV6,
                    },
                    &data,
                )
                .unwrap_err();
                assert_eq!(err, err.clone());
            }
        }
        // from_ip_slice
        if test.link.is_none() && test.vlan.is_none() && test.net.is_some() {
            assert_eq!(err, PacketHeaders::from_ip_slice(&data).unwrap_err());
        }
    }
}
