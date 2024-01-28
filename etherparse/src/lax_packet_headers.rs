use crate::{
    err::{packet::SliceError, Layer, LenError, LenSource},
    *,
};

/// Decoded packet headers (data link layer and lower) with lax length checks.
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
pub struct LaxPacketHeaders<'a> {
    /// Ethernet II header if present.
    pub link: Option<Ethernet2Header>,

    /// Single or double vlan headers if present.
    pub vlan: Option<VlanHeader>,

    /// IPv4 or IPv6 header and IP extension headers if present.
    pub net: Option<NetHeaders>,

    /// TCP or UDP header if present.
    pub transport: Option<TransportHeader>,

    /// Payload of the last parsed layer.
    pub payload: LaxPayloadSlice<'a>,

    /// Error that stopped the parsing and the layer on which the stop occurred.
    pub stop_err: Option<(err::packet::SliceError, Layer)>,
}

impl<'a> LaxPacketHeaders<'a> {
    pub fn from_ethernet_slice(slice: &'a [u8]) -> Result<LaxPacketHeaders<'a>, err::LenError> {
        let (ethernet, rest) = Ethernet2Header::from_slice(slice)?;
        let mut result = Self::from_ether_type(ethernet.ether_type, rest);
        result.link = Some(ethernet);
        if let Some((SliceError::Len(l), _)) = result.stop_err.as_mut() {
            l.layer_start_offset += Ethernet2Header::LEN;
        }
        Ok(result)
    }

    pub fn from_ether_type(mut ether_type: EtherType, slice: &'a [u8]) -> LaxPacketHeaders<'a> {
        use err::packet::SliceError::*;

        let mut rest = slice;
        let mut offset = 0;
        let mut result = LaxPacketHeaders {
            link: None,
            vlan: None,
            net: None,
            transport: None,
            payload: LaxPayloadSlice::Ether(EtherPayloadSlice {
                ether_type,
                payload: rest,
            }),
            stop_err: None,
        };

        // parse vlan header(s)
        use ether_type::*;

        result.vlan = match ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                use crate::VlanHeader::*;
                let (outer, outer_rest) = match SingleVlanHeader::from_slice(rest) {
                    Ok(value) => value,
                    Err(err) => {
                        result.stop_err = Some((Len(err), Layer::VlanHeader));
                        return result;
                    }
                };

                // set the rest & ether_type for the following operations
                rest = outer_rest;
                offset += SingleVlanHeader::LEN;
                ether_type = outer.ether_type;
                result.payload = LaxPayloadSlice::Ether(EtherPayloadSlice {
                    ether_type,
                    payload: rest,
                });

                // parse second vlan header if present
                match ether_type {
                    // second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                        let (inner, inner_rest) = match SingleVlanHeader::from_slice(rest) {
                            Ok(value) => value,
                            Err(mut err) => {
                                err.layer_start_offset += SingleVlanHeader::LEN;
                                result.stop_err = Some((Len(err), Layer::VlanHeader));
                                return result;
                            }
                        };

                        // set the rest & ether_type for the following operations
                        rest = inner_rest;
                        offset += SingleVlanHeader::LEN;
                        ether_type = inner.ether_type;
                        result.payload = LaxPayloadSlice::Ether(EtherPayloadSlice {
                            ether_type,
                            payload: rest,
                        });

                        Some(Double(DoubleVlanHeader { outer, inner }))
                    }
                    // no second vlan header detected -> single vlan header
                    _ => Some(Single(outer)),
                }
            }
            // no vlan header
            _ => None,
        };

        // parse ip
        match ether_type {
            IPV4 | IPV6 => {
                // read ipv4 header & extensions and payload slice
                let (ip, ip_payload, stop_err) = match IpHeaders::from_slice_lax(rest) {
                    Ok(value) => value,
                    Err(err) => {
                        use err::ip::LaxHeaderSliceError as I;
                        result.stop_err = Some(match err {
                            I::Len(mut l) => {
                                l.layer_start_offset += offset;
                                (Len(l), Layer::IpHeader)
                            }
                            I::Content(c) => (Ip(c), Layer::IpHeader),
                        });
                        return result;
                    }
                };

                // set the next
                result.net = Some(ip.into());
                result.payload = LaxPayloadSlice::Ip(ip_payload.clone());

                // if a stop error was encountered return it
                if let Some((err, layer)) = stop_err {
                    use err::ipv6_exts::HeaderSliceError as I;
                    result.stop_err = Some((
                        match err {
                            I::Len(mut l) => {
                                l.layer_start_offset += offset;
                                Len(l)
                            }
                            I::Content(e) => Ipv6Exts(e),
                        },
                        layer,
                    ));
                    return result;
                }

                // decode transport layer
                if false == ip_payload.fragmented {
                    // helper function to set the len source in len errors
                    let add_len_source = |mut len_error: LenError| -> err::packet::SliceError {
                        // only change the len source if the lower layer has not set it
                        if LenSource::Slice == len_error.len_source {
                            len_error.len_source = ip_payload.len_source;
                        }
                        err::packet::SliceError::Len(len_error)
                    };

                    use crate::ip_number::*;
                    use err::tcp::HeaderSliceError::*;
                    match ip_payload.ip_number {
                        ICMP => match Icmpv4Slice::from_slice(ip_payload.payload) {
                            Ok(i) => {
                                result.transport = Some(TransportHeader::Icmpv4(i.header()));
                                result.payload = LaxPayloadSlice::Icmpv4 {
                                    payload: i.payload(),
                                    incomplete: ip_payload.incomplete,
                                }
                            }
                            Err(e) => {
                                result.stop_err = Some((add_len_source(e), Layer::Icmpv4));
                            }
                        },
                        IPV6_ICMP => match Icmpv6Slice::from_slice(ip_payload.payload) {
                            Ok(i) => {
                                result.transport = Some(TransportHeader::Icmpv6(i.header()));
                                result.payload = LaxPayloadSlice::Icmpv6 {
                                    payload: i.payload(),
                                    incomplete: ip_payload.incomplete,
                                }
                            }
                            Err(e) => {
                                result.stop_err = Some((add_len_source(e), Layer::Icmpv6));
                            }
                        },
                        UDP => {
                            match UdpSlice::from_slice_lax(ip_payload.payload) {
                                Ok(u) => {
                                    result.transport = Some(TransportHeader::Udp(u.to_header()));
                                    result.payload = LaxPayloadSlice::Udp {
                                        payload: u.payload(),
                                        // TODO also check the udp header length
                                        incomplete: ip_payload.incomplete,
                                    }
                                }
                                Err(e) => {
                                    result.stop_err = Some((add_len_source(e), Layer::UdpHeader));
                                }
                            }
                        }
                        TCP => match TcpHeader::from_slice(ip_payload.payload) {
                            Ok(_) => todo!(),
                            Err(e) => match e {
                                Len(l) => {
                                    result.stop_err = Some((add_len_source(l), Layer::TcpHeader));
                                }
                                Content(c) => {
                                    result.stop_err = Some((SliceError::Tcp(c), Layer::TcpHeader));
                                }
                            },
                        },
                        _ => {}
                    }
                }
            }
            _ => {}
        };

        result
    }
}
