use super::*;

mod internet_slice {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        // ipv4
        {
            let mut header: Ipv4Header = Default::default();
            header.protocol = ip_number::UDP;
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let ipv4 = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            let exts = Ipv4ExtensionsSlice { auth: None };
            let slice = InternetSlice::Ipv4(ipv4.clone(), exts.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(
                format!("{:?}", slice),
                format!("Ipv4({:?}, {:?})", ipv4, exts)
            );
        }
        // ipv6
        {
            let mut header: Ipv6Header = Default::default();
            header.next_header = ip_number::UDP;
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let ipv6 = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
            let exts = Ipv6ExtensionsSlice::from_slice(ip_number::UDP, &[])
                .unwrap()
                .0;
            let slice = InternetSlice::Ipv6(ipv6.clone(), exts.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(
                format!("{:?}", slice),
                format!("Ipv6({:?}, {:?})", ipv6, exts)
            );
        }
    }

    #[test]
    fn is_fragmenting_payload() {
        for is_frag in [false, true] {
            // ipv4
            {
                let mut header: Ipv4Header = Default::default();
                header.protocol = ip_number::UDP;
                header.more_fragments = is_frag;
                let buffer = {
                    let mut buffer = Vec::with_capacity(header.header_len());
                    header.write(&mut buffer).unwrap();
                    buffer
                };
                let ipv4 = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
                let exts = Ipv4ExtensionsSlice { auth: None };
                let slice = InternetSlice::Ipv4(ipv4.clone(), exts.clone());
                assert_eq!(is_frag, slice.is_fragmenting_payload());
            }
            // ipv6
            {
                let mut header: Ipv6Header = Default::default();
                header.next_header = ip_number::IPV6_FRAG;
                let frag_header = Ipv6FragmentHeader {
                    next_header: ip_number::UDP,
                    fragment_offset: 0,
                    more_fragments: is_frag,
                    identification: 0,
                };
                header.payload_length = frag_header.header_len() as u16;
                let buffer = {
                    let mut buffer =
                        Vec::with_capacity(header.header_len() + frag_header.header_len());
                    header.write(&mut buffer).unwrap();
                    frag_header.write(&mut buffer).unwrap();
                    buffer
                };
                let ipv6 = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
                let exts = Ipv6ExtensionsSlice::from_slice(
                    ip_number::IPV6_FRAG,
                    &buffer[header.header_len()..],
                )
                .unwrap()
                .0;
                let slice = InternetSlice::Ipv6(ipv6.clone(), exts.clone());

                // clone & eq
                assert_eq!(is_frag, slice.is_fragmenting_payload());
            }
        }
    }

    #[test]
    fn source_dest_addr() {
        // ipv4
        {
            use std::net::*;
            let mut header: Ipv4Header = Default::default();
            header.protocol = ip_number::UDP;
            let buffer = {
                let mut buffer = Vec::default();
                header.write(&mut buffer).unwrap();
                buffer
            };
            let ipv4 = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            let exts = Ipv4ExtensionsSlice { auth: None };
            let slice = InternetSlice::Ipv4(ipv4.clone(), exts.clone());
            assert_eq!(Ipv4Addr::new(0, 0, 0, 0), slice.source_addr());
        }
        // ipv6
        {
            use std::net::*;
            let mut header: Ipv6Header = Default::default();
            header.next_header = ip_number::IPV6_FRAG;
            let frag_header = Ipv6FragmentHeader{
                next_header: ip_number::UDP,
                fragment_offset: 0,
                more_fragments: false,
                identification: 0
            };
            header.payload_length = frag_header.header_len() as u16;
            let buffer = {
                let mut buffer = Vec::default();
                header.write(&mut buffer).unwrap();
                frag_header.write(&mut buffer).unwrap();
                buffer
            };
            let ipv6 = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
            let exts = Ipv6ExtensionsSlice::from_slice(ip_number::IPV6_FRAG, &buffer[header.header_len()..]).unwrap().0;
            let slice = InternetSlice::Ipv6(ipv6.clone(), exts.clone());
            // clone & eq
            assert_eq!(Ipv6Addr::new(0, 0, 0, 0, 0 ,0 ,0, 0), slice.destination_addr());
        }
    }
}

mod transport_slice {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        // udp
        {
            let header: UdpHeader = Default::default();
            let raw = header.to_bytes();
            let u = UdpHeaderSlice::from_slice(&raw).unwrap();
            let slice = TransportSlice::Udp(u.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(format!("{:?}", slice), format!("Udp({:?})", u));
        }
        // tcp
        {
            let header: TcpHeader = Default::default();
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len() as usize);
                header.write(&mut buffer).unwrap();
                buffer
            };
            let t = TcpHeaderSlice::from_slice(&buffer).unwrap();
            let slice = TransportSlice::Tcp(t.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(format!("{:?}", slice), format!("Tcp({:?})", t));
        }
        // unknown
        {
            let slice = TransportSlice::Unknown(ip_number::IGMP);

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(
                format!("{:?}", slice),
                format!("Unknown({:?})", ip_number::IGMP)
            );
        }
    }
}

mod sliced_packet {
    use super::*;

    #[test]
    fn from_ip_errors() {
        use crate::ReadError::*;

        //slice length error
        assert_eq!(
            SlicedPacket::from_ip(&[])
                .unwrap_err()
                .slice_len()
                .unwrap(),
            err::LenError {
                required_len: 1,
                len: 0,
                len_source: err::LenSource::Slice,
                layer: err::Layer::IpHeader,
                layer_start_offset: 0,
            }
        );

        //bad protocol number
        for i in 0u8..std::u8::MAX {
            if i >> 4 != 4 && i >> 4 != 6 {
                assert_matches!(
                    SlicedPacket::from_ip(&[i]),
                    Err(IpHeader(_))
                );
            }
        }
    }

    #[test]
    fn debug() {
        let header = SlicedPacket {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };
        assert_eq!(
            format!("{:?}", header),
            format!(
                "SlicedPacket {{ link: {:?}, vlan: {:?}, ip: {:?}, transport: {:?}, payload: {:?} }}",
                header.link,
                header.vlan,
                header.ip,
                header.transport,
                header.payload
            )
        );
    }

    #[test]
    fn clone_eq() {
        let header = SlicedPacket {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };
        assert_eq!(header.clone(), header);
    }

    proptest! {
        #[test]
        fn payload_ether_type(
            ref eth in ethernet_2_unknown(),
            ref vlan_outer in vlan_single_unknown(),
            ref vlan_inner in vlan_single_unknown(),
            ref ipv4 in ipv4_unknown(),
            ref udp in udp_any(),
        ) {
            use IpHeader::*;

            // empty
            {
                let s = SlicedPacket{
                    link: None,
                    vlan: None,
                    ip: None,
                    transport: None,
                    payload: &[]
                };
                assert_eq!(None, s.payload_ether_type());
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
                    .ip(Version4(ipv4.clone(), Default::default()));

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
                    .ip(Version4(ipv4.clone(), Default::default()))
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
