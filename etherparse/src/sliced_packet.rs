use crate::*;

/// Packet slice split into multiple slices containing the different headers & payload.
///
/// Everything that could not be parsed is stored in a slice in the field "payload".
///
/// You can use
///
/// * [`SlicedPacket::from_ethernet`]
/// * [`SlicedPacket::from_ether_type`]
/// * [`SlicedPacket::from_ip`]
///
/// depending on your starting header to slice a packet.
///
/// # Examples
///
/// Basic usage:
///
///```
/// # use etherparse::{SlicedPacket, PacketBuilder};
/// # let builder = PacketBuilder::
/// #    ethernet2([1,2,3,4,5,6],     //source mac
/// #               [7,8,9,10,11,12]) //destination mac
/// #    .ipv4([192,168,1,1], //source ip
/// #          [192,168,1,2], //destination ip
/// #          20)            //time to life
/// #    .udp(21,    //source port
/// #         1234); // destination port
/// #    //payload of the udp packet
/// #    let payload = [1,2,3,4,5,6,7,8];
/// #    //get some memory to store the serialized data
/// #    let mut packet = Vec::<u8>::with_capacity(
/// #                            builder.size(payload.len()));
/// #    builder.write(&mut packet, &payload).unwrap();
/// match SlicedPacket::from_ethernet(&packet) {
///     Err(value) => println!("Err {:?}", value),
///     Ok(value) => {
///         println!("link: {:?}", value.link);
///         println!("vlan: {:?}", value.vlan);
///         println!("net: {:?}", value.net);
///         println!("transport: {:?}", value.transport);
///     }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlicedPacket<'a> {
    /// Ethernet II header if present.
    pub link: Option<LinkSlice<'a>>,
    /// Single or double vlan headers if present.
    pub vlan: Option<VlanSlice<'a>>,
    /// IPv4 or IPv6 header, IP extension headers & payload if present.
    pub net: Option<NetSlice<'a>>,
    /// TCP or UDP header & payload if present.
    pub transport: Option<TransportSlice<'a>>,
}

impl<'a> SlicedPacket<'a> {
    /// Separates a network packet slice into different slices containing the headers from the ethernet header downwards.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function assumes the given data starts
    /// with an ethernet II header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{SlicedPacket, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ethernet2([1,2,3,4,5,6],     //source mac
    /// #               [7,8,9,10,11,12]) //destination mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //destination ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
    /// #    //payload of the udp packet
    /// #    let payload = [1,2,3,4,5,6,7,8];
    /// #    //get some memory to store the serialized data
    /// #    let mut packet = Vec::<u8>::with_capacity(
    /// #                            builder.size(payload.len()));
    /// #    builder.write(&mut packet, &payload).unwrap();
    /// match SlicedPacket::from_ethernet(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ethernet(data: &'a [u8]) -> Result<SlicedPacket, err::packet::SliceError> {
        SlicedPacketCursor::new(data).slice_ethernet2()
    }

    /// Separates a network packet slice into different slices containing the
    /// headers from the Linux Cooked Capture v1 (SLL) header downwards.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function
    /// assumes the given data starts with a Linux Cooked Capture v1 (SLL)
    /// header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{SlicedPacket, PacketBuilder, LinuxSllPacketType};
    /// # let builder = PacketBuilder::
    /// #    linux_sll(LinuxSllPacketType::OTHERHOST, //packet type
    /// #              6, //sender address valid length
    /// #              [1,2,3,4,5,6,0,0]) //sender address with padding
    /// #   .ipv4([192,168,1,1], //source ip
    /// #         [192,168,1,2], //destination ip
    /// #         20)            //time to life
    /// #   .udp(21,    //source port
    /// #        1234); //destination port
    /// #    //payload of the udp packet
    /// #    let payload = [1,2,3,4,5,6,7,8];
    /// #    //get some memory to store the serialized data
    /// #    let mut packet = Vec::<u8>::with_capacity(
    /// #                            builder.size(payload.len()));
    /// #    builder.write(&mut packet, &payload).unwrap();
    /// match SlicedPacket::from_linux_sll(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_linux_sll(data: &'a [u8]) -> Result<SlicedPacket, err::packet::SliceError> {
        SlicedPacketCursor::new(data).slice_linux_sll()
    }

    /// Separates a network packet slice into different slices containing the headers using
    /// the given `ether_type` number to identify the first header.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. Currently supported
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
    /// use etherparse::{ether_type, SlicedPacket};
    ///
    /// match SlicedPacket::from_ether_type(ether_type::IPV4, packet) {
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
        ether_type: EtherType,
        data: &'a [u8],
    ) -> Result<SlicedPacket, err::packet::SliceError> {
        use ether_type::*;
        let mut cursor = SlicedPacketCursor::new(data);
        cursor.result.link = Some(LinkSlice::EtherPayload(EtherPayloadSlice {
            ether_type,
            payload: data,
        }));
        match ether_type {
            IPV4 => cursor.slice_ipv4(),
            IPV6 => cursor.slice_ipv6(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => cursor.slice_vlan(),
            _ => Ok(cursor.result),
        }
    }

    /// Separates a network packet slice into different slices containing the headers from the ip header downwards.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function assumes the given data starts
    /// with an IPv4 or IPv6 header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{SlicedPacket, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ipv4([192,168,1,1], //source ip
    /// #         [192,168,1,2], //destination ip
    /// #         20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
    /// #    //payload of the udp packet
    /// #    let payload = [1,2,3,4,5,6,7,8];
    /// #    //get some memory to store the serialized data
    /// #    let mut packet = Vec::<u8>::with_capacity(
    /// #                            builder.size(payload.len()));
    /// #    builder.write(&mut packet, &payload).unwrap();
    /// match SlicedPacket::from_ip(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         //link & vlan fields are empty when parsing from ip downwards
    ///         assert_eq!(None, value.link);
    ///         assert_eq!(None, value.vlan);
    ///
    ///         //ip & transport (udp or tcp)
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ip(data: &'a [u8]) -> Result<SlicedPacket, err::packet::SliceError> {
        SlicedPacketCursor::new(data).slice_ip()
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
    pub fn payload_ether_type(&self) -> Option<EtherType> {
        if self.net.is_some() || self.transport.is_some() {
            None
        } else if let Some(vlan) = &self.vlan {
            use VlanSlice::*;
            match vlan {
                SingleVlan(s) => Some(s.ether_type()),
                DoubleVlan(d) => Some(d.inner().ether_type()),
            }
        } else if let Some(link) = &self.link {
            use LinkSlice::*;
            match link {
                Ethernet2(eth) => Some(eth.ether_type()),
                LinkSlice::LinuxSll(e) => match e.protocol_type() {
                    LinuxSllProtocolType::EtherType(EtherType(v))
                    | LinuxSllProtocolType::LinuxNonstandardEtherType(LinuxNonstandardEtherType(
                        v,
                    )) => Some(EtherType(v)),
                    _ => None,
                },
                EtherPayload(e) => Some(e.ether_type),
                LinkSlice::LinuxSllPayload(e) => match e.protocol_type {
                    LinuxSllProtocolType::EtherType(EtherType(v))
                    | LinuxSllProtocolType::LinuxNonstandardEtherType(LinuxNonstandardEtherType(
                        v,
                    )) => Some(EtherType(v)),
                    _ => None,
                },
            }
        } else {
            None
        }
    }

    /// Returns the last ether payload of the packet (if one is present).
    ///
    /// If VLAN header is present the payload after the most inner VLAN
    /// header is returned and if there is no VLAN header is present in the
    /// link field is returned.
    pub fn ether_payload(&self) -> Option<EtherPayloadSlice<'a>> {
        if let Some(vlan) = self.vlan.as_ref() {
            match vlan {
                VlanSlice::SingleVlan(s) => Some(s.payload()),
                VlanSlice::DoubleVlan(s) => Some(s.payload()),
            }
        } else if let Some(link) = self.link.as_ref() {
            match link {
                LinkSlice::Ethernet2(e) => Some(e.payload()),
                LinkSlice::LinuxSll(e) => match e.protocol_type() {
                    LinuxSllProtocolType::EtherType(_)
                    | LinuxSllProtocolType::LinuxNonstandardEtherType(_) => {
                        Some(EtherPayloadSlice::try_from(e.payload()).ok()?)
                    }
                    _ => None,
                },
                LinkSlice::EtherPayload(e) => Some(e.clone()),
                LinkSlice::LinuxSllPayload(e) => match e.protocol_type {
                    LinuxSllProtocolType::EtherType(_)
                    | LinuxSllProtocolType::LinuxNonstandardEtherType(_) => {
                        Some(EtherPayloadSlice::try_from(e.clone()).ok()?)
                    }
                    _ => None,
                },
            }
        } else {
            None
        }
    }

    /// Return the IP payload after the the IP header and the IP extension
    /// headers (if one is present).
    pub fn ip_payload(&self) -> Option<&IpPayloadSlice<'a>> {
        if let Some(net) = self.net.as_ref() {
            use NetSlice::*;
            match net {
                Ipv4(v) => Some(v.payload()),
                Ipv6(v) => Some(v.payload()),
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::{packet::SliceError, Layer, LenError};
    use crate::test_gens::*;
    use crate::test_packet::TestPacket;
    use proptest::prelude::*;

    const VLAN_ETHER_TYPES: [EtherType; 3] = [
        ether_type::VLAN_TAGGED_FRAME,
        ether_type::PROVIDER_BRIDGING,
        ether_type::VLAN_DOUBLE_TAGGED_FRAME,
    ];

    #[test]
    fn clone_eq() {
        let header = SlicedPacket {
            link: None,
            vlan: None,
            net: None,
            transport: None,
        };
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn debug() {
        use alloc::format;
        let header = SlicedPacket {
            link: None,
            vlan: None,
            net: None,
            transport: None,
        };
        assert_eq!(
            format!("{:?}", header),
            format!(
                "SlicedPacket {{ link: {:?}, vlan: {:?}, net: {:?}, transport: {:?} }}",
                header.link, header.vlan, header.net, header.transport,
            )
        );
    }

    #[test]
    fn ether_payload() {
        use alloc::vec::*;

        // no content
        assert_eq!(
            SlicedPacket {
                link: None,
                vlan: None,
                net: None,
                transport: None,
            }
            .ether_payload(),
            None
        );

        // only ethernet header II
        {
            let payload = [1, 2, 3, 4];
            let mut buf = Vec::with_capacity(Ethernet2Header::LEN + 4);
            buf.extend_from_slice(
                &Ethernet2Header {
                    ether_type: EtherType::WAKE_ON_LAN,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(&payload);
            assert_eq!(
                SlicedPacket::from_ethernet(&buf).unwrap().ether_payload(),
                Some(EtherPayloadSlice {
                    ether_type: EtherType::WAKE_ON_LAN,
                    payload: &payload
                })
            );
        }

        // ether type payload
        {
            let payload = [1, 2, 3, 4];
            assert_eq!(
                SlicedPacket {
                    link: Some(LinkSlice::EtherPayload(EtherPayloadSlice {
                        ether_type: EtherType::WAKE_ON_LAN,
                        payload: &payload
                    })),
                    vlan: None,
                    net: None,
                    transport: None,
                }
                .ether_payload(),
                Some(EtherPayloadSlice {
                    ether_type: EtherType::WAKE_ON_LAN,
                    payload: &payload
                })
            );
        }

        // only linux_sll payload
        {
            let payload = [1, 2, 3, 4];
            let mut buf = Vec::with_capacity(LinuxSllHeader::LEN + 4);
            buf.extend_from_slice(
                &LinuxSllHeader {
                    packet_type: LinuxSllPacketType::HOST,
                    arp_hrd_type: ArpHardwareId::ETHER,
                    sender_address_valid_length: 6,
                    sender_address: [1, 2, 3, 4, 5, 6, 0, 0],
                    protocol_type: LinuxSllProtocolType::EtherType(EtherType::WAKE_ON_LAN),
                }
                .to_bytes(),
            );
            buf.extend_from_slice(&payload);
            assert_eq!(
                SlicedPacket::from_linux_sll(&buf).unwrap().ether_payload(),
                Some(EtherPayloadSlice {
                    ether_type: EtherType::WAKE_ON_LAN,
                    payload: &payload
                })
            );
        }

        // ether type payload
        {
            let payload = [1, 2, 3, 4];
            assert_eq!(
                SlicedPacket {
                    link: Some(LinkSlice::LinuxSllPayload(LinuxSllPayloadSlice {
                        protocol_type: LinuxSllProtocolType::EtherType(EtherType::WAKE_ON_LAN),
                        payload: &payload
                    })),
                    vlan: None,
                    net: None,
                    transport: None,
                }
                .ether_payload(),
                Some(EtherPayloadSlice {
                    ether_type: EtherType::WAKE_ON_LAN,
                    payload: &payload
                })
            );
        }

        // single vlan header
        {
            let payload = [1, 2, 3, 4];
            let mut buf = Vec::with_capacity(Ethernet2Header::LEN + SingleVlanHeader::LEN + 4);
            buf.extend_from_slice(
                &Ethernet2Header {
                    ether_type: EtherType::VLAN_TAGGED_FRAME,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(
                &SingleVlanHeader {
                    ether_type: EtherType::WAKE_ON_LAN,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(&payload);
            assert_eq!(
                SlicedPacket::from_ethernet(&buf).unwrap().ether_payload(),
                Some(EtherPayloadSlice {
                    ether_type: EtherType::WAKE_ON_LAN,
                    payload: &payload
                })
            );
        }

        // double vlan header
        {
            let payload = [1, 2, 3, 4];
            let mut buf = Vec::with_capacity(Ethernet2Header::LEN + SingleVlanHeader::LEN * 2 + 4);
            buf.extend_from_slice(
                &Ethernet2Header {
                    ether_type: EtherType::VLAN_DOUBLE_TAGGED_FRAME,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(
                &SingleVlanHeader {
                    ether_type: EtherType::VLAN_TAGGED_FRAME,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(
                &SingleVlanHeader {
                    ether_type: EtherType::WAKE_ON_LAN,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(&payload);
            assert_eq!(
                SlicedPacket::from_ethernet(&buf).unwrap().ether_payload(),
                Some(EtherPayloadSlice {
                    ether_type: EtherType::WAKE_ON_LAN,
                    payload: &payload
                })
            );
        }
    }

    #[test]
    fn ip_payload() {
        use alloc::vec::*;

        // no content
        assert_eq!(
            SlicedPacket {
                link: None,
                vlan: None,
                net: None,
                transport: None,
            }
            .ip_payload(),
            None
        );

        // ipv4
        {
            let payload = [1, 2, 3, 4];
            let mut buf = Vec::with_capacity(Ipv4Header::MIN_LEN + 4);
            buf.extend_from_slice(
                &Ipv4Header {
                    protocol: IpNumber::ARIS,
                    total_len: Ipv4Header::MIN_LEN_U16 + 4,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(&payload);
            assert_eq!(
                SlicedPacket::from_ip(&buf).unwrap().ip_payload(),
                Some(&IpPayloadSlice {
                    payload: &payload,
                    ip_number: IpNumber::ARIS,
                    fragmented: false,
                    len_source: LenSource::Ipv4HeaderTotalLen,
                })
            );
        }

        // ipv6
        {
            let payload = [1, 2, 3, 4];
            let mut buf = Vec::with_capacity(Ipv6Header::LEN + 4);
            buf.extend_from_slice(
                &Ipv6Header {
                    payload_length: 4,
                    next_header: IpNumber::ARGUS,
                    ..Default::default()
                }
                .to_bytes(),
            );
            buf.extend_from_slice(&payload);
            assert_eq!(
                SlicedPacket::from_ip(&buf).unwrap().ip_payload(),
                Some(&IpPayloadSlice {
                    payload: &payload,
                    ip_number: IpNumber::ARGUS,
                    fragmented: false,
                    len_source: LenSource::Ipv6HeaderPayloadLen,
                })
            );
        }
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

        // eth payload
        {
            let data = [1, 2, 3, 4];
            let result = SlicedPacket::from_ether_type(EtherType(0x8221), &data).unwrap();
            assert_eq!(
                result,
                SlicedPacket {
                    link: Some(LinkSlice::EtherPayload(EtherPayloadSlice {
                        ether_type: EtherType(0x8221),
                        payload: &data
                    })),
                    vlan: None,
                    net: None,
                    transport: None
                }
            );
        }

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
                        layer: Layer::Ethernet2Header,
                        layer_start_offset: 0,
                    };

                    from_slice_assert_err(&test, &data[..len], SliceError::Len(err.clone()));
                }
            }
        }

        // linux_sll
        {
            let linux_sll = LinuxSllHeader {
                packet_type: LinuxSllPacketType::HOST,
                arp_hrd_type: ArpHardwareId::ETHER,
                sender_address_valid_length: 6,
                sender_address: [1, 2, 3, 4, 5, 6, 0, 0],
                protocol_type: LinuxSllProtocolType::EtherType(EtherType::WAKE_ON_LAN),
            };
            let test = TestPacket {
                link: Some(LinkHeader::LinuxSll(linux_sll.clone())),
                vlan: None,
                net: None,
                transport: None,
            };

            // eth len error
            {
                let data = test.to_vec(&[]);
                for len in 0..data.len() {
                    let err = LenError {
                        required_len: linux_sll.header_len(),
                        len,
                        len_source: LenSource::Slice,
                        layer: Layer::LinuxSllHeader,
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
                            layer: Layer::VlanHeader,
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
                            layer: Layer::VlanHeader,
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
                test.set_payload_len(0);

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
                            layer: Layer::Ipv4Header,
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
                                        err.layer = Layer::IpHeader;
                                        err
                                    } else {
                                        err.clone()
                                    }
                                })
                            },
                        );
                    }
                }

                // ipv4 content error (ihl length too small)
                {
                    use err::ip::HeaderError::*;

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
                            SliceError::Ip(Ipv4HeaderLengthSmallerThanHeader { ihl: 0 })
                        },
                    );
                }

                // ipv4 content error (total length too small)
                {
                    let mut data = test.to_vec(&[]);
                    let ipv4_offset = data.len() - ipv4.header_len();

                    // set the total length to 0 to trigger a content error
                    data[ipv4_offset + 2] = 0;
                    data[ipv4_offset + 3] = 0;

                    let err = LenError {
                        required_len: ipv4.header_len(),
                        len: 0,
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        layer: Layer::Ipv4Packet,
                        layer_start_offset: {
                            test.link.as_ref().map(|h| h.header_len()).unwrap_or(0)
                                + test.vlan.as_ref().map(|h| h.header_len()).unwrap_or(0)
                        },
                    };

                    from_slice_assert_err(&test, &data, SliceError::Len(err.clone()));
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
                        layer: Layer::IpAuthHeader,
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
                            layer: Layer::Ipv6Header,
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
                                        err.layer = Layer::IpHeader;
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
                        layer: Layer::IpAuthHeader,
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
                            layer: Layer::UdpHeader,
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
                    {
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
                                layer: Layer::TcpHeader,
                                layer_start_offset: base_len,
                            };
                            from_slice_assert_err(
                                &test,
                                &data[..base_len + len],
                                SliceError::Len(err.clone()),
                            );
                        }
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
                test.set_payload_len(0);

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
                            layer: Layer::Icmpv4,
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
                test.set_payload_len(0);

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
                            layer: Layer::Icmpv6,
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
        fn assert_test_result(test: &TestPacket, expected_payload: &[u8], result: &SlicedPacket) {
            // check if fragmenting
            let is_fragmented = test.is_ip_payload_fragmented();

            // check headers
            assert_eq!(
                test.link,
                match result.link.as_ref() {
                    Some(s) => match s {
                        LinkSlice::Ethernet2(e) => Some(LinkHeader::Ethernet2(e.to_header())),
                        LinkSlice::LinuxSll(e) => Some(LinkHeader::LinuxSll(e.to_header())),
                        LinkSlice::EtherPayload(_) => None,
                        LinkSlice::LinuxSllPayload(_) => None,
                    },
                    None => None,
                }
            );
            assert_eq!(test.vlan, result.vlan.as_ref().map(|e| e.to_header()));
            assert_eq!(
                test.net,
                result.net.as_ref().map(|s: &NetSlice| -> NetHeaders {
                    match s {
                        NetSlice::Ipv4(ipv4) => NetHeaders::Ipv4(
                            ipv4.header().to_header(),
                            ipv4.extensions().to_header(),
                        ),
                        NetSlice::Ipv6(ipv6) => NetHeaders::Ipv6(
                            ipv6.header().to_header(),
                            Ipv6Extensions::from_slice(
                                ipv6.header().next_header(),
                                ipv6.extensions().slice(),
                            )
                            .unwrap()
                            .0,
                        ),
                    }
                })
            );

            // check transport header & payload
            if is_fragmented {
                assert_eq!(result.transport, None);
            } else {
                use TransportHeader as H;
                use TransportSlice as S;
                match &result.transport {
                    Some(S::Icmpv4(icmpv4)) => {
                        assert_eq!(&test.transport, &Some(H::Icmpv4(icmpv4.header())));
                        assert_eq!(icmpv4.payload(), expected_payload);
                    }
                    Some(S::Icmpv6(icmpv6)) => {
                        assert_eq!(&test.transport, &Some(H::Icmpv6(icmpv6.header())));
                        assert_eq!(icmpv6.payload(), expected_payload);
                    }
                    Some(S::Udp(s)) => {
                        assert_eq!(&test.transport, &Some(H::Udp(s.to_header())));
                    }
                    Some(S::Tcp(s)) => {
                        assert_eq!(&test.transport, &Some(H::Tcp(s.to_header())));
                    }
                    None => {
                        assert_eq!(&test.transport, &None);
                    }
                }
            }
        }

        // setup payload
        let payload = [1, 2, 3, 4];

        // set length fields in ip headers
        let test = {
            let mut test = test_base.clone();
            test.set_payload_len(payload.len());
            test
        };

        // write data
        let data = test.to_vec(&payload);

        // from_ethernet
        if test.link.is_some() {
            let result = SlicedPacket::from_ethernet(&data).unwrap();
            assert_test_result(&test, &payload, &result);
        }
        // from_ether_type (vlan at start)
        if test.link.is_none() && test.vlan.is_some() {
            for ether_type in VLAN_ETHER_TYPES {
                let result = SlicedPacket::from_ether_type(ether_type, &data).unwrap();
                assert_eq!(
                    result.link,
                    Some(LinkSlice::EtherPayload(EtherPayloadSlice {
                        ether_type,
                        payload: &data
                    }))
                );
                assert_test_result(&test, &payload, &result);
            }
        }
        // from_ether_type (ip at start)
        if test.link.is_none() && test.vlan.is_none() {
            if let Some(ip) = &test.net {
                let ether_type = match ip {
                    NetHeaders::Ipv4(_, _) => ether_type::IPV4,
                    NetHeaders::Ipv6(_, _) => ether_type::IPV6,
                };
                let result = SlicedPacket::from_ether_type(ether_type, &data).unwrap();
                assert_eq!(
                    result.link,
                    Some(LinkSlice::EtherPayload(EtherPayloadSlice {
                        ether_type,
                        payload: &data
                    }))
                );
                assert_test_result(&test, &payload, &result);
            }
        }
        // from_ip_slice
        if test.link.is_none() && test.vlan.is_none() && test.net.is_some() {
            let result = SlicedPacket::from_ip(&data).unwrap();
            assert_test_result(&test, &payload, &result);
        }
    }

    /// Check that the given errors get triggered if presented with the given
    /// data.
    fn from_slice_assert_err(test: &TestPacket, data: &[u8], err: SliceError) {
        // from_ethernet_slice
        if let Some(ref header) = test.link {
            match header {
                LinkHeader::Ethernet2(_) => {
                    assert_eq!(err.clone(), SlicedPacket::from_ethernet(&data).unwrap_err())
                }
                LinkHeader::LinuxSll(_) => assert_eq!(
                    err.clone(),
                    SlicedPacket::from_linux_sll(&data).unwrap_err()
                ),
            }
        }
        // from_ether_type (vlan at start)
        if test.link.is_none() && test.vlan.is_some() {
            for ether_type in VLAN_ETHER_TYPES {
                assert_eq!(
                    err.clone(),
                    SlicedPacket::from_ether_type(ether_type, &data).unwrap_err()
                );
            }
        }
        // from_ether_type (ip at start)
        if test.link.is_none() && test.vlan.is_none() {
            if let Some(ip) = &test.net {
                let err = SlicedPacket::from_ether_type(
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
            assert_eq!(err, SlicedPacket::from_ip(&data).unwrap_err());
        }
    }

    proptest! {
        #[test]
        fn payload_ether_type(
            ref eth in ethernet_2_unknown(),
            ref linux_sll in linux_sll_any(),
            ref vlan_outer in vlan_single_unknown(),
            ref vlan_inner in vlan_single_unknown(),
            ref ipv4 in ipv4_unknown(),
            ref udp in udp_any(),
        ) {
            use IpHeaders::*;
            use alloc::vec::Vec;

            // empty
            {
                let s = SlicedPacket{
                    link: None,
                    vlan: None,
                    net: None,
                    transport: None,
                };
                assert_eq!(None, s.payload_ether_type());
            }

            // only linux sll
            {
                let mut serialized = Vec::with_capacity(linux_sll.header_len());
                eth.write(&mut serialized).unwrap();
                let ether_type = match linux_sll.protocol_type {
                    LinuxSllProtocolType::EtherType(EtherType(v)) | LinuxSllProtocolType::LinuxNonstandardEtherType(LinuxNonstandardEtherType(v)) => Some(EtherType(v)),
                    _ => None,
                };
                if let Ok(s) = SlicedPacket::from_linux_sll(&serialized) {
                    assert_eq!(
                        ether_type,
                        s.payload_ether_type()
                    );
                }
            }

            // only ethernet
            {
                let mut serialized = Vec::with_capacity(eth.header_len());
                eth.write(&mut serialized).unwrap();
                assert_eq!(
                    Some(eth.ether_type),
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with single vlan
            {
                let mut eth_mod = eth.clone();
                eth_mod.ether_type = ether_type::VLAN_TAGGED_FRAME;

                let mut serialized = Vec::with_capacity(
                    eth_mod.header_len() +
                    vlan_outer.header_len()
                );
                eth_mod.write(&mut serialized).unwrap();
                vlan_outer.write(&mut serialized).unwrap();
                assert_eq!(
                    Some(vlan_outer.ether_type),
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with double vlan
            {
                let mut eth_mod = eth.clone();
                eth_mod.ether_type = ether_type::VLAN_TAGGED_FRAME;

                let mut vlan_outer_mod = vlan_outer.clone();
                vlan_outer_mod.ether_type = ether_type::VLAN_TAGGED_FRAME;

                let mut serialized = Vec::with_capacity(
                    eth_mod.header_len() +
                    vlan_outer_mod.header_len() +
                    vlan_inner.header_len()
                );
                eth_mod.write(&mut serialized).unwrap();
                vlan_outer_mod.write(&mut serialized).unwrap();
                vlan_inner.write(&mut serialized).unwrap();
                assert_eq!(
                    Some(vlan_inner.ether_type),
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with ip
            {
                let builder = PacketBuilder::ethernet2(eth.source, eth.destination)
                    .ip(Ipv4(ipv4.clone(), Default::default()));

                let mut serialized = Vec::with_capacity(builder.size(0));
                builder.write(&mut serialized, ipv4.protocol, &[]).unwrap();

                assert_eq!(
                    None,
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with transport
            {
                let builder = PacketBuilder::ethernet2(eth.source, eth.destination)
                    .ip(Ipv4(ipv4.clone(), Default::default()))
                    .udp(udp.source_port, udp.destination_port);
                let mut serialized = Vec::with_capacity(builder.size(0));
                builder.write(&mut serialized, &[]).unwrap();

                assert_eq!(
                    None,
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }
        }
    }
}
