use crate::{
    err::{packet::SliceError, Layer},
    *,
};

/// Helper class for laxly slicing packets.
pub(crate) struct LaxSlicedPacketCursor<'a> {
    pub offset: usize,
    pub result: LaxSlicedPacket<'a>,
}

impl<'a> LaxSlicedPacketCursor<'a> {
    pub fn parse_from_ethernet2(
        slice: &'a [u8],
    ) -> Result<LaxSlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use LinkSlice::*;

        let mut cursor = LaxSlicedPacketCursor {
            offset: 0,
            result: LaxSlicedPacket {
                link: None,
                vlan: None,
                net: None,
                transport: None,
                stop_err: None,
            },
        };

        let result = Ethernet2Slice::from_slice_without_fcs(slice)
            .map_err(|err| Len(err.add_offset(cursor.offset)))?;

        // cache the ether_type for later
        let payload = result.payload();

        // set the new data
        cursor.offset += result.header_len();
        cursor.result.link = Some(Ethernet2(result));

        // continue parsing (if required)
        match payload.ether_type {
            IPV4 => Ok(cursor.slice_ip(payload.payload)),
            IPV6 => Ok(cursor.slice_ip(payload.payload)),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                Ok(cursor.slice_vlan(payload.payload))
            }
            _ => Ok(cursor.result),
        }
    }

    pub fn parse_from_ether_type(ether_type: EtherType, slice: &'a [u8]) -> LaxSlicedPacket<'a> {
        let cursor = LaxSlicedPacketCursor {
            offset: 0,
            result: LaxSlicedPacket {
                link: Some(LinkSlice::EtherPayload(EtherPayloadSlice {
                    ether_type,
                    payload: slice,
                })),
                vlan: None,
                net: None,
                transport: None,
                stop_err: None,
            },
        };
        use ether_type::*;
        match ether_type {
            IPV4 => cursor.slice_ip(slice),
            IPV6 => cursor.slice_ip(slice),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                cursor.slice_vlan(slice)
            }
            _ => cursor.result,
        }
    }

    pub fn parse_from_ip(
        slice: &'a [u8],
    ) -> Result<LaxSlicedPacket<'a>, err::ip::LaxHeaderSliceError> {
        let (ip, stop_err) = LaxIpSlice::from_slice(slice)?;
        let is_ip_v4 = match &ip {
            LaxIpSlice::Ipv4(_) => true,
            LaxIpSlice::Ipv6(_) => false,
        };
        let payload = ip.payload().clone();
        let offset = (payload.payload.as_ptr() as usize) - (slice.as_ptr() as usize);
        Ok(LaxSlicedPacketCursor {
            offset,
            result: LaxSlicedPacket {
                link: None,
                vlan: None,
                net: Some(ip.into()),
                transport: None,
                stop_err: stop_err.map(|(stop_err, stop_layer)| {
                    use err::ipv6_exts::HeaderError as E;
                    use err::ipv6_exts::HeaderSliceError as I;
                    use err::packet::SliceError as O;
                    (
                        match stop_err {
                            I::Len(l) => O::Len(l.add_offset(offset)),
                            I::Content(c) => match c {
                                E::HopByHopNotAtStart => O::Ipv6Exts(E::HopByHopNotAtStart),
                                E::IpAuth(auth) => {
                                    if is_ip_v4 {
                                        O::Ipv4Exts(auth)
                                    } else {
                                        O::Ipv6Exts(E::IpAuth(auth))
                                    }
                                }
                            },
                        },
                        stop_layer,
                    )
                }),
            },
        }
        .slice_transport(payload))
    }

    pub fn slice_vlan(mut self, slice: &'a [u8]) -> LaxSlicedPacket<'a> {
        use ether_type::*;
        use VlanSlice::*;

        // cache the starting slice so the later combining
        // of outer & inner vlan is defined behavior (for miri)
        let outer_start_slice = slice;
        let outer = match SingleVlanSlice::from_slice(slice) {
            Ok(v) => v,
            Err(err) => {
                self.result.stop_err = Some((
                    SliceError::Len(err.add_offset(self.offset)),
                    Layer::VlanHeader,
                ));
                return self.result;
            }
        };
        self.result.vlan = Some(VlanSlice::SingleVlan(outer.clone()));
        self.offset += outer.header_len();

        //check if it is a double vlan header
        match outer.ether_type() {
            //in case of a double vlan header continue with the inner
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                let inner = match SingleVlanSlice::from_slice(outer.payload_slice()) {
                    Ok(v) => v,
                    Err(err) => {
                        self.result.stop_err = Some((
                            SliceError::Len(err.add_offset(self.offset)),
                            Layer::VlanHeader,
                        ));
                        return self.result;
                    }
                };
                self.offset += inner.header_len();

                let inner_ether_type = inner.ether_type();
                self.result.vlan = Some(DoubleVlan(DoubleVlanSlice {
                    slice: outer_start_slice,
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ip(inner.payload_slice()),
                    IPV6 => self.slice_ip(inner.payload_slice()),
                    _ => self.result,
                }
            }
            value => match value {
                IPV4 => self.slice_ip(outer.payload_slice()),
                IPV6 => self.slice_ip(outer.payload_slice()),
                _ => self.result,
            },
        }
    }

    pub fn slice_ip(mut self, slice: &'a [u8]) -> LaxSlicedPacket<'a> {
        // ip slice
        let ip = match LaxIpSlice::from_slice(slice) {
            Ok(ip) => ip,
            Err(e) => {
                use err::ip::LaxHeaderSliceError as I;
                use err::packet::SliceError as O;
                self.result.stop_err = Some(match e {
                    I::Len(mut l) => {
                        l.layer_start_offset += self.offset;
                        (O::Len(l), Layer::IpHeader)
                    }
                    I::Content(c) => (O::Ip(c), Layer::IpHeader),
                });
                return self.result;
            }
        };
        self.result.net = Some(ip.0.clone().into());

        // stop in case there was a stop error in the ip extension headers
        if let Some((stop_err, stop_layer)) = ip.1 {
            use err::ipv6_exts::HeaderError as E;
            use err::ipv6_exts::HeaderSliceError as I;
            use err::packet::SliceError as O;
            self.result.stop_err = Some((
                match stop_err {
                    I::Len(l) => O::Len(l.add_offset(self.offset)),
                    I::Content(c) => match c {
                        E::HopByHopNotAtStart => O::Ipv6Exts(E::HopByHopNotAtStart),
                        E::IpAuth(auth) => match &ip.0 {
                            LaxIpSlice::Ipv4(_) => O::Ipv4Exts(auth),
                            LaxIpSlice::Ipv6(_) => O::Ipv6Exts(E::IpAuth(auth)),
                        },
                    },
                },
                stop_layer,
            ));
        }

        // move offset for the transport layers
        let payload = ip.0.payload().clone();
        self.offset += (payload.payload.as_ptr() as usize) - (slice.as_ptr() as usize);
        self.slice_transport(payload)
    }

    fn slice_transport(mut self, slice: LaxIpPayloadSlice<'a>) -> LaxSlicedPacket {
        use err::packet::SliceError as O;
        if slice.fragmented || self.result.stop_err.is_some() {
            // if an error occured in an upper layer or the payload is fragmented
            // stop here
            return self.result;
        }
        match slice.ip_number {
            ip_number::ICMP => match Icmpv4Slice::from_slice(slice.payload) {
                Ok(icmp) => {
                    self.offset += icmp.slice().len();
                    self.result.transport = Some(TransportSlice::Icmpv4(icmp));
                }
                Err(mut err) => {
                    err.layer_start_offset += self.offset;
                    err.len_source = slice.len_source;
                    self.result.stop_err = Some((O::Len(err), Layer::Icmpv4));
                }
            },
            ip_number::UDP => match UdpSlice::from_slice(slice.payload) {
                Ok(udp) => {
                    self.offset += udp.slice().len();
                    self.result.transport = Some(TransportSlice::Udp(udp));
                }
                Err(mut err) => {
                    err.layer_start_offset += self.offset;
                    err.len_source = slice.len_source;
                    self.result.stop_err = Some((O::Len(err), Layer::UdpHeader));
                }
            },
            ip_number::TCP => match TcpSlice::from_slice(slice.payload) {
                Ok(tcp) => {
                    self.offset += tcp.slice().len();
                    self.result.transport = Some(TransportSlice::Tcp(tcp));
                }
                Err(err) => {
                    use err::tcp::HeaderSliceError as I;
                    self.result.stop_err = Some((
                        match err {
                            I::Len(mut l) => {
                                l.layer_start_offset += self.offset;
                                l.len_source = slice.len_source;
                                O::Len(l)
                            }
                            I::Content(c) => O::Tcp(c),
                        },
                        Layer::TcpHeader,
                    ));
                }
            },
            ip_number::IPV6_ICMP => match Icmpv6Slice::from_slice(slice.payload) {
                Ok(icmp) => {
                    self.offset += icmp.slice().len();
                    self.result.transport = Some(TransportSlice::Icmpv6(icmp));
                }
                Err(mut err) => {
                    err.layer_start_offset += self.offset;
                    err.len_source = slice.len_source;
                    self.result.stop_err = Some((O::Len(err), Layer::Icmpv4));
                }
            },
            _ => {}
        }
        self.result
    }
}
