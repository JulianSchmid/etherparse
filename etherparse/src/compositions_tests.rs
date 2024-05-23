use super::*;

use crate::test_gens::*;
use alloc::{vec, vec::Vec};
use proptest::prelude::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComponentTest {
    link: Option<LinkHeader>,
    vlan: Option<VlanHeader>,
    ip: Option<IpHeaders>,
    transport: Option<TransportHeader>,
    payload: Vec<u8>,
}

static VLAN_ETHER_TYPES: &'static [EtherType] = &[
    EtherType::VLAN_TAGGED_FRAME,
    EtherType::PROVIDER_BRIDGING,
    EtherType::VLAN_DOUBLE_TAGGED_FRAME,
];

impl ComponentTest {
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::with_capacity(
            match &self.link {
                Some(header) => header.header_len(),
                None => 0,
            } + match &self.vlan {
                Some(header) => header.header_len(),
                None => 0,
            } + match &self.ip {
                Some(headers) => headers.header_len(),
                None => 0,
            } + match &self.transport {
                Some(header) => header.header_len(),
                None => 0,
            } + self.payload.len(),
        );

        //fill all the elements
        match &self.link {
            Some(header) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        use crate::VlanHeader::*;
        match &self.vlan {
            Some(Single(header)) => header.write(&mut buffer).unwrap(),
            Some(Double(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        match &self.ip {
            Some(IpHeaders::Ipv4(header, exts)) => {
                header.write_raw(&mut buffer).unwrap();
                exts.write(&mut buffer, header.protocol).unwrap();
            }
            Some(IpHeaders::Ipv6(header, exts)) => {
                header.write(&mut buffer).unwrap();
                exts.write(&mut buffer, header.next_header).unwrap();
            }
            None => {}
        }
        match &self.transport {
            Some(TransportHeader::Icmpv6(header)) => header.write(&mut buffer).unwrap(),
            Some(TransportHeader::Icmpv4(header)) => header.write(&mut buffer).unwrap(),
            Some(TransportHeader::Udp(header)) => header.write(&mut buffer).unwrap(),
            Some(TransportHeader::Tcp(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        use std::io::Write;
        buffer.write(&self.payload[..]).unwrap();
        buffer
    }

    /// Serialize the headers & payload specified in the headers and check that
    /// the different decoding & slicing methods for entire packets work correctly.
    ///
    /// The following functions will be checked if they work correctly:
    /// * `SlicedPacket::from_ethernet`
    /// * `SlicedPacket::from_ip`
    /// * `PacketHeaders::from_ethernet_slice`
    /// * `PacketHeaders::from_ip_slice`
    fn run(&self) {
        // clone the test so the length fields can be adapted
        let mut test = self.clone();

        // set the payload length
        if let Some(ip) = test.ip.as_mut() {
            match ip {
                IpHeaders::Ipv4(ipv4, exts) => {
                    ipv4.set_payload_len(
                        exts.header_len()
                            + self.transport.as_ref().map_or(0, |t| t.header_len())
                            + self.payload.len(),
                    )
                    .unwrap();
                }
                IpHeaders::Ipv6(ipv6, exts) => {
                    ipv6.set_payload_length(
                        exts.header_len()
                            + self.transport.as_ref().map_or(0, |t| t.header_len())
                            + self.payload.len(),
                    )
                    .unwrap();
                }
            }
        }
        if let Some(TransportHeader::Udp(udp)) = test.transport.as_mut() {
            udp.length = udp.header_len_u16() + self.payload.len() as u16;
        }

        //packet with ethernet2 & vlan headers
        {
            //serialize to buffer
            let buffer = test.serialize();

            // PacketHeaders::from_ethernet_slice
            test.assert_headers(PacketHeaders::from_ethernet_slice(&buffer).unwrap());

            // SlicedPacket::from_ethernet
            test.assert_sliced_packet(SlicedPacket::from_ethernet(&buffer).unwrap());

            // create unexpected end of slice errors for the different headers
            for len in test.invalid_ser_lengths() {
                if let Some(len) = len {
                    assert!(PacketHeaders::from_ethernet_slice(&buffer[..len]).is_err());
                    assert!(SlicedPacket::from_ethernet(&buffer[..len]).is_err());
                }
            }
        }

        // packet data starting right after the link layer (tests from_ether_type functions)
        {
            // remove the link layer
            let ether_down = {
                let mut ether_down = test.clone();
                ether_down.link = None;
                ether_down
            };

            // serialize to buffer
            let buffer = ether_down.serialize();

            // PacketHeaders::from_ether_type
            ether_down.assert_headers(
                PacketHeaders::from_ether_type(
                    test.link.clone().unwrap().ethernet2().unwrap().ether_type,
                    &buffer[..],
                )
                .unwrap(),
            );

            // SlicedPacket::from_ether_type
            ether_down.assert_sliced_packet(
                SlicedPacket::from_ether_type(
                    test.link.clone().unwrap().ethernet2().unwrap().ether_type,
                    &buffer[..],
                )
                .unwrap(),
            );

            // create unexpected end of slice errors for the different headers
            for len in ether_down.invalid_ser_lengths() {
                if let Some(len) = len {
                    assert!(PacketHeaders::from_ether_type(
                        test.link.clone().unwrap().ethernet2().unwrap().ether_type,
                        &buffer[..len]
                    )
                    .is_err());
                    assert!(SlicedPacket::from_ether_type(
                        test.link.clone().unwrap().ethernet2().unwrap().ether_type,
                        &buffer[..len]
                    )
                    .is_err());
                }
            }
        }

        // packet from the internet layer down (without ethernet2 & vlan headers)
        if test.ip.is_some() {
            // serialize from the ip layer downwards
            let ip_down = {
                let mut ip_down = test.clone();
                ip_down.link = None;
                ip_down.vlan = None;
                ip_down
            };

            // serialize to buffer
            let buffer = ip_down.serialize();

            // PacketHeaders::from_ip_slice
            ip_down.assert_headers(PacketHeaders::from_ip_slice(&buffer).unwrap());

            // SlicedPacket::from_ip
            ip_down.assert_sliced_packet(SlicedPacket::from_ip(&buffer).unwrap());

            // create unexpected end of slice errors for the different headers
            for len in ip_down.invalid_ser_lengths() {
                if let Some(len) = len {
                    assert!(PacketHeaders::from_ip_slice(&buffer[..len]).is_err());
                    assert!(SlicedPacket::from_ip(&buffer[..len]).is_err());
                }
            }
        }
    }

    /// Creates slice lengths at which an too short slice error
    /// should be triggered.
    fn invalid_ser_lengths(&self) -> [Option<usize>; 12] {
        struct Builder {
            result: [Option<usize>; 12],
            next_index: usize,
            offset: usize,
        }

        impl Builder {
            fn add(&mut self, header_len: usize) {
                self.offset += header_len;
                self.result[self.next_index] = Some(self.offset - 1);
                self.next_index += 1;
            }
        }

        let mut builder = Builder {
            result: [None; 12],
            next_index: 0,
            offset: 0,
        };

        if let Some(link) = self.link.as_ref() {
            builder.add(link.header_len());
        }
        if let Some(vlan) = self.vlan.as_ref() {
            use VlanHeader::*;
            match vlan {
                Single(single) => builder.add(single.header_len()),
                Double(double) => {
                    builder.add(double.outer.header_len());
                    builder.add(double.inner.header_len());
                }
            }
        }
        if let Some(ip) = self.ip.as_ref() {
            use IpHeaders::*;
            match ip {
                Ipv4(header, exts) => {
                    builder.add(header.header_len());
                    if let Some(auth) = exts.auth.as_ref() {
                        builder.add(auth.header_len());
                    }
                }
                Ipv6(header, exts) => {
                    builder.add(header.header_len());
                    if let Some(e) = exts.hop_by_hop_options.as_ref() {
                        builder.add(e.header_len());
                    }
                    if let Some(e) = exts.destination_options.as_ref() {
                        builder.add(e.header_len());
                    }
                    if let Some(routing) = exts.routing.as_ref() {
                        builder.add(routing.routing.header_len());
                        if let Some(e) = routing.final_destination_options.as_ref() {
                            builder.add(e.header_len());
                        }
                    }
                    if let Some(e) = exts.fragment.as_ref() {
                        builder.add(e.header_len());
                    }
                    if let Some(e) = exts.auth.as_ref() {
                        builder.add(e.header_len());
                    }
                }
            }
        }
        if let Some(transport) = self.transport.as_ref() {
            builder.add(transport.header_len());
        }

        builder.result
    }

    fn assert_headers(&self, actual: PacketHeaders) {
        assert_eq!(self.link, actual.link);
        assert_eq!(self.vlan, actual.vlan);
        assert_eq!(self.ip, self.ip);
        assert_eq!(self.transport, actual.transport);
        assert_eq!(self.payload[..], actual.payload.slice()[..]);
    }

    fn assert_sliced_packet(&self, result: SlicedPacket) {
        //assert identity to touch the derives (code coverage hack)
        assert_eq!(result, result);

        //ethernet & vlan
        assert_eq!(
            self.link,
            match result.link.as_ref() {
                Some(l) => match l {
                    LinkSlice::Ethernet2(e) => Some(LinkHeader::Ethernet2(e.to_header())),
                    LinkSlice::LinuxSll(e) => Some(LinkHeader::LinuxSll(e.to_header())),
                    LinkSlice::EtherPayload(_) => None,
                    LinkSlice::LinuxSllPayload(_) => None,
                },
                None => None,
            }
        ); //.unwrap_or(None).map(|ref x| x.to_header()));
        assert_eq!(self.vlan, result.vlan.as_ref().map(|ref x| x.to_header()));

        //ip
        assert_eq!(self.ip, {
            use crate::NetSlice::*;
            match result.net.as_ref() {
                Some(Ipv4(actual)) => Some(IpHeaders::Ipv4(
                    actual.header().to_header(),
                    Ipv4Extensions {
                        auth: actual.extensions().auth.map(|ref x| x.to_header()),
                    },
                )),
                Some(Ipv6(actual)) => Some(IpHeaders::Ipv6(
                    actual.header().to_header(),
                    Ipv6Extensions::from_slice(
                        actual.header().next_header(),
                        actual.extensions().slice(),
                    )
                    .unwrap()
                    .0,
                )),
                None => None,
            }
        });

        // transport header
        assert_eq!(
            self.transport,
            match result.transport.as_ref() {
                Some(TransportSlice::Icmpv4(actual)) =>
                    Some(TransportHeader::Icmpv4(actual.header())),
                Some(TransportSlice::Icmpv6(actual)) =>
                    Some(TransportHeader::Icmpv6(actual.header())),
                Some(TransportSlice::Udp(actual)) => Some(TransportHeader::Udp(actual.to_header())),
                Some(TransportSlice::Tcp(actual)) => Some(TransportHeader::Tcp(actual.to_header())),
                None => None,
            }
        );
        // additional check for the contents of Unknown
        if self.transport.is_none() {
            match result.transport.as_ref() {
                None => assert!(result.transport.is_none()),
                _ => unreachable!(),
            }
        }

        //payload
        match result.transport.as_ref() {
            Some(TransportSlice::Icmpv4(icmpv4)) => {
                assert_eq!(&self.payload[..], icmpv4.payload());
            }
            Some(TransportSlice::Icmpv6(icmpv6)) => {
                assert_eq!(&self.payload[..], icmpv6.payload());
            }
            Some(TransportSlice::Udp(udp)) => {
                assert_eq!(&self.payload[..], udp.payload());
            }
            Some(TransportSlice::Tcp(tcp)) => {
                assert_eq!(&self.payload[..], tcp.payload());
            }
            // check ip next
            None => {
                if let Some(ip) = result.net.as_ref() {
                    assert_eq!(
                        &self.payload[..],
                        match ip {
                            NetSlice::Ipv4(s) => s.payload.payload,
                            NetSlice::Ipv6(s) => s.payload.payload,
                        }
                    );
                } else {
                    if let Some(vlan) = result.vlan.as_ref() {
                        assert_eq!(&self.payload[..], vlan.payload().payload);
                    } else {
                        if let Some(LinkSlice::Ethernet2(eth)) = result.link.as_ref() {
                            assert_eq!(&self.payload[..], eth.payload().payload);
                        }
                    }
                }
            }
        }
    }

    fn run_vlan(
        &self,
        outer_vlan: &SingleVlanHeader,
        inner_vlan: &SingleVlanHeader,
        ipv4: &Ipv4Header,
        ipv4_ext: &Ipv4Extensions,
        ipv6: &Ipv6Header,
        ipv6_ext: &Ipv6Extensions,
        udp: &UdpHeader,
        tcp: &TcpHeader,
        icmpv4: &Icmpv4Header,
        icmpv6: &Icmpv6Header,
    ) {
        let setup_single = |ether_type: EtherType| -> ComponentTest {
            let mut result = self.clone();
            result.vlan = Some(VlanHeader::Single({
                let mut v = inner_vlan.clone();
                v.ether_type = ether_type;
                v
            }));
            result
        };
        let setup_double =
            |outer_ether_type: EtherType, inner_ether_type: EtherType| -> ComponentTest {
                let mut result = self.clone();
                result.vlan = Some(VlanHeader::Double(DoubleVlanHeader {
                    outer: {
                        let mut v = outer_vlan.clone();
                        v.ether_type = outer_ether_type;
                        v
                    },
                    inner: {
                        let mut v = inner_vlan.clone();
                        v.ether_type = inner_ether_type;
                        v
                    },
                }));
                result
            };

        //single
        setup_single(inner_vlan.ether_type).run();
        setup_single(ether_type::IPV4).run_ipv4(ipv4, ipv4_ext, udp, tcp, icmpv4, icmpv6);
        setup_single(ether_type::IPV6).run_ipv6(ipv6, ipv6_ext, udp, tcp, icmpv4, icmpv6);

        //double
        for ether_type in VLAN_ETHER_TYPES {
            setup_double(*ether_type, inner_vlan.ether_type).run();
            setup_double(*ether_type, ether_type::IPV4)
                .run_ipv4(ipv4, ipv4_ext, udp, tcp, icmpv4, icmpv6);
            setup_double(*ether_type, ether_type::IPV6)
                .run_ipv6(ipv6, ipv6_ext, udp, tcp, icmpv4, icmpv6);
        }
    }

    fn run_ipv4(
        &self,
        ip: &Ipv4Header,
        ip_exts: &Ipv4Extensions,
        udp: &UdpHeader,
        tcp: &TcpHeader,
        icmpv4: &Icmpv4Header,
        icmpv6: &Icmpv6Header,
    ) {
        // fragmenting
        {
            let mut test = self.clone();
            test.ip = Some({
                let mut frag = ip.clone();
                if false == frag.is_fragmenting_payload() {
                    frag.more_fragments = true;
                }
                let mut header = IpHeaders::Ipv4(frag, ip_exts.clone());
                header.set_next_headers(ip.protocol);
                header
            });

            // run without transport header
            test.run();
        }

        // non fragmenting
        {
            let mut test = self.clone();
            test.ip = Some({
                let mut non_frag = ip.clone();
                non_frag.more_fragments = false;
                non_frag.fragment_offset = 0.try_into().unwrap();
                let mut header = IpHeaders::Ipv4(non_frag, ip_exts.clone());
                header.set_next_headers(ip.protocol);
                header
            });
            test.run_transport(udp, tcp, icmpv4, icmpv6);
        }
    }

    fn run_ipv6(
        &self,
        ip: &Ipv6Header,
        ip_exts: &Ipv6Extensions,
        udp: &UdpHeader,
        tcp: &TcpHeader,
        icmpv4: &Icmpv4Header,
        icmpv6: &Icmpv6Header,
    ) {
        // fragmenting
        {
            let mut test = self.clone();
            test.ip = Some({
                let mut frag = ip_exts.clone();
                if let Some(frag) = frag.fragment.as_mut() {
                    if false == frag.is_fragmenting_payload() {
                        frag.more_fragments = true;
                    }
                } else {
                    frag.fragment = Some(Ipv6FragmentHeader::new(
                        ip_number::UDP,
                        IpFragOffset::ZERO,
                        true,
                        0,
                    ));
                }
                let mut header = IpHeaders::Ipv6(ip.clone(), frag);
                header.set_next_headers(ip.next_header);
                header
            });
            test.run();
        }

        // non fragmenting
        {
            let mut test = self.clone();
            test.ip = Some({
                let mut non_frag = ip_exts.clone();
                non_frag.fragment = None;
                let mut header = IpHeaders::Ipv6(ip.clone(), non_frag);
                header.set_next_headers(ip.next_header);
                header
            });
            test.run_transport(udp, tcp, icmpv4, icmpv6);
        }
    }

    fn run_transport(
        &self,
        udp: &UdpHeader,
        tcp: &TcpHeader,
        icmpv4: &Icmpv4Header,
        icmpv6: &Icmpv6Header,
    ) {
        // unknown transport layer
        self.run();

        // udp
        {
            let mut test = self.clone();
            test.ip.as_mut().unwrap().set_next_headers(ip_number::UDP);
            test.transport = Some(TransportHeader::Udp(udp.clone()));
            test.run()
        }

        // tcp
        {
            let mut test = self.clone();
            test.ip.as_mut().unwrap().set_next_headers(ip_number::TCP);
            test.transport = Some(TransportHeader::Tcp(tcp.clone()));
            test.run()
        }

        // icmpv4
        if let Some(payload_size) = icmpv4.fixed_payload_size() {
            let mut test = self.clone();
            test.ip.as_mut().unwrap().set_next_headers(ip_number::ICMP);
            test.transport = Some(TransportHeader::Icmpv4(icmpv4.clone()));
            // resize the payload in case it does not have to be as big
            test.payload.resize(payload_size, 0);
            test.run()
        } else {
            let mut test = self.clone();
            test.ip.as_mut().unwrap().set_next_headers(ip_number::ICMP);
            test.transport = Some(TransportHeader::Icmpv4(icmpv4.clone()));
            test.run()
        }

        // icmpv6
        if let Some(payload_size) = icmpv6.fixed_payload_size() {
            let mut test = self.clone();
            test.ip
                .as_mut()
                .unwrap()
                .set_next_headers(ip_number::IPV6_ICMP);
            test.transport = Some(TransportHeader::Icmpv6(icmpv6.clone()));
            // resize the payload in case it does not have to be as big
            test.payload.resize(payload_size, 0);
            test.run()
        } else {
            let mut test = self.clone();
            test.ip
                .as_mut()
                .unwrap()
                .set_next_headers(ip_number::IPV6_ICMP);
            test.transport = Some(TransportHeader::Icmpv6(icmpv6.clone()));
            test.run()
        }
    }
}

proptest! {
    ///Test that all known packet compositions are parsed correctly.
    #[test]
    #[cfg_attr(miri, ignore)] // vec allocation reduces miri runspeed too much
    fn test_compositions(ref eth in ethernet_2_unknown(),
                         ref vlan_outer in vlan_single_unknown(),
                         ref vlan_inner in vlan_single_unknown(),
                         ref ipv4 in ipv4_unknown(),
                         ref ipv4_exts in ipv4_extensions_unknown(),
                         ref ipv6 in ipv6_unknown(),
                         ref ipv6_exts in ipv6_extensions_unknown(),
                         ref udp in udp_any(),
                         ref tcp in tcp_any(),
                         ref icmpv4 in icmpv4_header_any(),
                         ref icmpv6 in icmpv6_header_any(),
                         ref payload in proptest::collection::vec(any::<u8>(), 0..1024))
    {
        let setup_eth = | ether_type: EtherType | -> ComponentTest {
            ComponentTest {
                payload: payload.clone(),
                link: Some({
                    let mut result = eth.clone();
                    result.ether_type = ether_type;
                    LinkHeader::Ethernet2(result)
                }),
                vlan: None,
                ip: None,
                transport: None
            }
        };

        //ethernet 2: standalone, ipv4, ipv6
        setup_eth(eth.ether_type).run();
        setup_eth(ether_type::IPV4).run_ipv4(ipv4, ipv4_exts, udp, tcp, icmpv4, icmpv6);
        setup_eth(ether_type::IPV6).run_ipv6(ipv6, ipv6_exts, udp, tcp, icmpv4, icmpv6);

        //vlans
        for ether_type in VLAN_ETHER_TYPES {
            setup_eth(*ether_type).run_vlan(vlan_outer, vlan_inner, ipv4, ipv4_exts, ipv6, ipv6_exts, udp, tcp, icmpv4, icmpv6);
        }
    }
}

///Test that assert_sliced_packet is panicking when the ethernet header is missing
#[test]
#[should_panic]
fn test_packet_slicing_panics() {
    let s = SlicedPacket {
        link: None,
        vlan: None,
        net: None,
        transport: None,
    };
    ComponentTest {
        link: Some(LinkHeader::Ethernet2(Ethernet2Header {
            source: [0; 6],
            destination: [0; 6],
            ether_type: 0.into(),
        })),
        vlan: None,
        ip: None,
        transport: None,
        payload: vec![],
    }
    .assert_sliced_packet(s);
}
