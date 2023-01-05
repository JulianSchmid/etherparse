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
    pub link: Option<Ethernet2Header>,
    /// Single or double vlan headers if present.
    pub vlan: Option<VlanHeader>,
    /// IPv4 or IPv6 header and IP extension headers if present.
    pub ip: Option<IpHeader>,
    /// TCP or UDP header if present.
    pub transport: Option<TransportHeader>,
    /// Rest of the packet that could not be decoded as a header (usually the payload).
    pub payload: &'a [u8],
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
    /// #               [7,8,9,10,11,12]) //destionation mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //desitionation ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); //desitnation port
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
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ethernet_slice(packet: &[u8]) -> Result<PacketHeaders, ReadError> {
        let (ethernet, mut rest) = Ethernet2Header::from_slice(packet)
            .map_err(|err| ReadError::SliceLen(err))?;
        let mut ether_type = ethernet.ether_type;

        let mut result = PacketHeaders {
            link: Some(ethernet),
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };

        //parse vlan header(s)
        use ether_type::*;

        result.vlan = match ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                use crate::VlanHeader::*;
                let (outer, outer_rest) = SingleVlanHeader::from_slice(rest).map_err(|err| {
                    ReadError::SliceLen(err.add_offset(packet.len() - rest.len()))
                })?;

                //set the rest & ether_type for the following operations
                rest = outer_rest;
                ether_type = outer.ether_type;

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                        let (inner, inner_rest) =
                            SingleVlanHeader::from_slice(rest).map_err(|err| {
                                ReadError::SliceLen(
                                    err.add_offset(packet.len() - rest.len()),
                                )
                            })?;

                        //set the rest & ether_type for the following operations
                        rest = inner_rest;
                        ether_type = inner.ether_type;

                        Some(Double(DoubleVlanHeader { outer, inner }))
                    }
                    //no second vlan header detected -> single vlan header
                    _ => Some(Single(outer)),
                }
            }
            //no vlan header
            _ => None,
        };

        //parse ip (if present)
        match ether_type {
            IPV4 => {
                let (ip, ip_rest) = Ipv4Header::from_slice(rest).map_err(|err| {
                    use err::ipv4::HeaderSliceError as I;
                    use ReadError as O;
                    match err {
                        I::SliceLen(err) => {
                            O::SliceLen(err.add_offset(packet.len() - rest.len()))
                        }
                        I::Content(err) => O::Ipv4Header(err),
                    }
                })?;
                let fragmented = ip.is_fragmenting_payload();
                let (ip_ext, ip_protocol, ip_ext_rest) =
                    Ipv4Extensions::from_slice(ip.protocol, ip_rest).map_err(|err| {
                        use err::ip_auth::HeaderSliceError as I;
                        use ReadError as O;
                        match err {
                            I::SliceLen(err) => O::SliceLen(
                                err.add_offset(packet.len() - ip_rest.len()),
                            ),
                            I::Content(err) => O::IpAuthHeader(err),
                        }
                    })?;

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version4(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) =
                        read_transport(ip_protocol, packet.len() - rest.len(), rest)?;

                    //assign to the output
                    rest = transport_rest;
                    result.transport = transport;
                }
            }
            IPV6 => {
                let (ip, ip_rest) = Ipv6Header::from_slice(rest).map_err(|err| {
                    use err::ipv6::HeaderSliceError as I;
                    use ReadError as O;
                    match err {
                        I::SliceLen(err) => {
                            O::SliceLen(err.add_offset(packet.len() - rest.len()))
                        }
                        I::Content(err) => O::Ipv6Header(err),
                    }
                })?;
                let (ip_ext, next_header, ip_ext_rest) =
                    Ipv6Extensions::from_slice(ip.next_header, ip_rest)
                        .map_err(|err| {
                            use err::ipv6_exts::HeaderSliceError as I;
                            use ReadError as O;
                            match err {
                                I::SliceLen(err) => {
                                    O::SliceLen(err.add_offset(packet.len() - ip_rest.len()))
                                },
                                I::Content(err) => O::Ipv6ExtsHeader(err),
                            }
                        })?;
                let fragmented = ip_ext.is_fragmenting_payload();

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version6(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) =
                        read_transport(next_header, packet.len() - rest.len(), rest)?;

                    rest = transport_rest;
                    result.transport = transport;
                }
            }
            _ => {}
        }

        //finally update the rest slice based on the cursor position
        result.payload = rest;

        Ok(result)
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
    /// #               [7,8,9,10,11,12]) //destionation mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //desitionation ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); //desitnation port
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
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ether_type(
        mut ether_type: u16,
        data: &'a [u8],
    ) -> Result<PacketHeaders, ReadError> {
        let mut rest = data;
        let mut result = PacketHeaders {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };

        //parse vlan header(s)
        use ether_type::*;

        result.vlan = match ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                use crate::VlanHeader::*;
                let (outer, outer_rest) = SingleVlanHeader::from_slice(rest)
                    .map_err(|err| ReadError::SliceLen(err))?;

                //set the rest & ether_type for the following operations
                rest = outer_rest;
                ether_type = outer.ether_type;

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                        let (inner, inner_rest) = SingleVlanHeader::from_slice(rest)
                            .map_err(|err| ReadError::SliceLen(err))?;

                        //set the rest & ether_type for the following operations
                        rest = inner_rest;
                        ether_type = inner.ether_type;

                        Some(Double(DoubleVlanHeader { outer, inner }))
                    }
                    //no second vlan header detected -> single vlan header
                    _ => Some(Single(outer)),
                }
            }
            //no vlan header
            _ => None,
        };

        //parse ip (if present)
        match ether_type {
            IPV4 => {
                let (ip, ip_rest) = Ipv4Header::from_slice(rest).map_err(|err| {
                    use err::ipv4::HeaderSliceError as I;
                    use ReadError as O;
                    match err {
                        I::SliceLen(err) => {
                            O::SliceLen(err.add_offset(data.len() - rest.len()))
                        }
                        I::Content(err) => O::Ipv4Header(err),
                    }
                })?;
                let fragmented = ip.is_fragmenting_payload();
                let (ip_ext, ip_protocol, ip_ext_rest) =
                    Ipv4Extensions::from_slice(ip.protocol, ip_rest).map_err(|err| {
                        use err::ip_auth::HeaderSliceError as I;
                        use ReadError as O;
                        match err {
                            I::SliceLen(err) => {
                                O::SliceLen(err.add_offset(data.len() - rest.len()))
                            }
                            I::Content(err) => O::IpAuthHeader(err),
                        }
                    })?;

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version4(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) =
                        read_transport(ip_protocol, data.len() - rest.len(), rest)?;

                    //assign to the output
                    rest = transport_rest;
                    result.transport = transport;
                }
            }
            IPV6 => {
                let (ip, ip_rest) = Ipv6Header::from_slice(rest).map_err(|err| {
                    use err::ipv6::HeaderSliceError as I;
                    use ReadError as O;
                    match err {
                        I::SliceLen(err) => {
                            O::SliceLen(err.add_offset(data.len() - rest.len()))
                        }
                        I::Content(err) => O::Ipv6Header(err),
                    }
                })?;
                let (ip_ext, next_header, ip_ext_rest) =
                    Ipv6Extensions::from_slice(ip.next_header, ip_rest)
                    .map_err(|err| {
                        use err::ipv6_exts::HeaderSliceError as I;
                        use ReadError as O;
                        match err {
                            I::SliceLen(err) => {
                                O::SliceLen(err.add_offset(data.len() - ip_rest.len()))
                            },
                            I::Content(err) => O::Ipv6ExtsHeader(err),
                        }
                    })?;
                let fragmented = ip_ext.is_fragmenting_payload();

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version6(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) =
                        read_transport(next_header, data.len() - rest.len(), rest)?;

                    rest = transport_rest;
                    result.transport = transport;
                }
            }
            _ => {}
        }

        //finally update the rest slice based on the cursor position
        result.payload = rest;

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
    /// #         [192,168,1,2], //desitionation ip
    /// #         20)            //time to life
    /// #    .udp(21,    //source port
    /// #        1234); //desitnation port
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
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ip_slice(packet: &[u8]) -> Result<PacketHeaders, ReadError> {
        let mut result = PacketHeaders {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };

        let (transport_proto, rest) = {
            let (ip, transport_proto, rest) = IpHeader::from_slice(packet)
                .map_err(|err| {
                    use err::ip::HeaderSliceError as I;
                    use ReadError as O;
                    match err {
                        I::SliceLen(err) => O::SliceLen(err),
                        I::Content(err) => O::IpHeader(err),
                    }
                })?;
            // update output
            result.ip = Some(ip);
            (transport_proto, rest)
        };

        // try to parse the transport header
        let (transport, rest) = read_transport(transport_proto, packet.len() - rest.len(), rest)?;

        // update output
        result.transport = transport;
        result.payload = rest;

        Ok(result)
    }

    /// If the slice in the `payload` field contains an ethernet payload
    /// this method returns the ether type number describing the payload type.
    ///
    /// The ether type number can come from an ethernet II header or a
    /// VLAN header depending on which headers are present.
    ///
    /// In case that `ip` and/or `transport` fields are the filled None
    /// is returned, as the payload contents then are defined by a
    /// lower layer protocol described in these fields.
    pub fn payload_ether_type(&self) -> Option<u16> {
        if self.ip.is_some() || self.transport.is_some() {
            None
        } else {
            if let Some(vlan) = &self.vlan {
                use VlanHeader::*;
                match vlan {
                    Single(s) => Some(s.ether_type),
                    Double(d) => Some(d.inner.ether_type),
                }
            } else {
                if let Some(link) = &self.link {
                    Some(link.ether_type)
                } else {
                    None
                }
            }
        }
    }
}

/// helper function to process transport headers
fn read_transport(
    protocol: u8,
    offset: usize,
    rest: &[u8],
) -> Result<(Option<TransportHeader>, &[u8]), ReadError> {
    use crate::ip_number::*;
    Ok(match protocol {
        ICMP => Icmpv4Header::from_slice(rest)
            .map_err(|err| err.add_slice_offset(offset))
            .map(|value| (Some(TransportHeader::Icmpv4(value.0)), value.1))?,
        IPV6_ICMP => Icmpv6Header::from_slice(rest)
            .map_err(|err| err.add_slice_offset(offset))
            .map(|value| (Some(TransportHeader::Icmpv6(value.0)), value.1))?,
        UDP => UdpHeader::from_slice(rest)
            .map_err(|err| ReadError::SliceLen(err.add_offset(offset)))
            .map(|value| (Some(TransportHeader::Udp(value.0)), value.1))?,
        TCP => TcpHeader::from_slice(rest)
            .map_err(|err| {
                use err::tcp::HeaderSliceError as I;
                use ReadError as O;
                match err  {
                    I::SliceLen(err) => O::SliceLen(err.add_offset(offset)),
                    I::Content(err) => O::TcpHeader(err),
                }
            })
            .map(|value| (Some(TransportHeader::Tcp(value.0)), value.1))?,
        _ => (None, rest),
    })
}
