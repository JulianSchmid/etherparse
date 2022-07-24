use super::*;

mod internet_slice {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        // ipv4
        {
            let mut header : Ipv4Header = Default::default();
            header.protocol = ip_number::UDP;
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let ipv4 = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            let exts = Ipv4ExtensionsSlice {
                auth: None
            };
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
            let mut header : Ipv6Header = Default::default();
            header.next_header = ip_number::UDP;
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let ipv6 = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
            let exts = Ipv6ExtensionsSlice::from_slice(ip_number::UDP, &[]).unwrap().0;
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
                let mut header : Ipv4Header = Default::default();
                header.protocol = ip_number::UDP;
                header.more_fragments = is_frag;
                let buffer = {
                    let mut buffer = Vec::with_capacity(header.header_len());
                    header.write(&mut buffer).unwrap();
                    buffer
                };
                let ipv4 = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
                let exts = Ipv4ExtensionsSlice {
                    auth: None
                };
                let slice = InternetSlice::Ipv4(ipv4.clone(), exts.clone());
                assert_eq!(is_frag, slice.is_fragmenting_payload());
            }
            // ipv6
            {
                let mut header : Ipv6Header = Default::default();
                header.next_header = ip_number::IPV6_FRAG;
                let frag_header = Ipv6FragmentHeader{
                    next_header: ip_number::UDP,
                    fragment_offset: 0,
                    more_fragments: is_frag,
                    identification: 0
                };
                header.payload_length = frag_header.header_len() as u16;
                let buffer = {
                    let mut buffer = Vec::with_capacity(
                        header.header_len() + frag_header.header_len()
                    );
                    header.write(&mut buffer).unwrap();
                    frag_header.write(&mut buffer).unwrap();
                    buffer
                };
                let ipv6 = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
                let exts = Ipv6ExtensionsSlice::from_slice(ip_number::IPV6_FRAG, &buffer[header.header_len()..]).unwrap().0;
                let slice = InternetSlice::Ipv6(ipv6.clone(), exts.clone());

                // clone & eq
                assert_eq!(is_frag, slice.is_fragmenting_payload());
            }
        }
    }
}

mod transport_slice {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        // udp
        {
            let header : UdpHeader = Default::default();
            let raw = header.to_bytes();
            let u = UdpHeaderSlice::from_slice(&raw).unwrap();
            let slice = TransportSlice::Udp(u.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(
                format!("{:?}", slice),
                format!("Udp({:?})", u)
            );
        }
        // tcp
        {
            let header : TcpHeader = Default::default();
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
            assert_eq!(
                format!("{:?}", slice),
                format!("Tcp({:?})", t)
            );
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
        assert_matches!(
            SlicedPacket::from_ip(&[]),
            Err(UnexpectedEndOfSlice(1))
        );

        //bad protocol number
        for i in 0u8..std::u8::MAX {
            if i >> 4 != 4  &&
               i >> 4 != 6
            {
                assert_matches!(
                    SlicedPacket::from_ip(&[i]),
                    Err(IpUnsupportedVersion(_))
                );
            }
        }
    }

    #[test]
    fn debug() {
        let header = SlicedPacket{
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[]
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
        let header = SlicedPacket{
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[]
        };
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn payload_ether_type() {
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

        // with ip
        {
            let in_payload = [50,51,52,53]; 
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                .single_vlan(0x123)
                .ipv4([13,14,15,16], [17,18,19,20], 21);
            let mut serialized = Vec::with_capacity(builder.size(in_payload.len()));
            builder.write(&mut serialized, 123, &in_payload).unwrap();

            assert_eq!(
                None,
                SlicedPacket::from_ethernet(&serialized)
                    .unwrap()
                    .payload_ether_type()
            );
        }

        // with transport
        {
            let builder = PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                .single_vlan(0x123)
                .ipv4([13,14,15,16], [17,18,19,20], 21)
                .udp(48,49);
            let mut serialized = Vec::with_capacity(builder.size(0));
            builder.write(&mut serialized, &[]).unwrap();

            assert_eq!(
                None,
                SlicedPacket::from_ethernet(&serialized)
                    .unwrap()
                    .payload_ether_type()
            );
        }

        // only ethernet
        {
            let header = Ethernet2Header{
                source: [1,2,3,4,5,6], 
                destination: [7,8,9,10,11,12],
                ether_type: 1234,
            };
            let mut serialized = Vec::with_capacity(header.header_len());
            header.write(&mut serialized).unwrap();
            assert_eq!(
                Some(1234),
                SlicedPacket::from_ethernet(&serialized)
                    .unwrap()
                    .payload_ether_type()
            );
        }

        // with single vlan
        {
            let eth_header = Ethernet2Header{
                source: [1,2,3,4,5,6], 
                destination: [7,8,9,10,11,12],
                ether_type: ether_type::VLAN_TAGGED_FRAME,
            };
            let vlan_header = SingleVlanHeader {
                priority_code_point: 1,
                drop_eligible_indicator: false,
                vlan_identifier: 89,
                ether_type: 1234,
            };
            let mut serialized = Vec::with_capacity(
                eth_header.header_len() +
                vlan_header.header_len()
            );
            eth_header.write(&mut serialized).unwrap();
            vlan_header.write(&mut serialized).unwrap();
            assert_eq!(
                Some(1234),
                SlicedPacket::from_ethernet(&serialized)
                    .unwrap()
                    .payload_ether_type()
            );
        }

        // with double vlan
        {
            let eth_header = Ethernet2Header{
                source: [1,2,3,4,5,6], 
                destination: [7,8,9,10,11,12],
                ether_type: ether_type::VLAN_TAGGED_FRAME,
            };
            let outer_vlan_header = SingleVlanHeader {
                priority_code_point: 1,
                drop_eligible_indicator: false,
                vlan_identifier: 89,
                ether_type: ether_type::VLAN_TAGGED_FRAME,
            };
            let inner_vlan_header = SingleVlanHeader {
                priority_code_point: 1,
                drop_eligible_indicator: false,
                vlan_identifier: 89,
                ether_type: 1234,
            };
            let mut serialized = Vec::with_capacity(
                eth_header.header_len() +
                outer_vlan_header.header_len() +
                inner_vlan_header.header_len()
            );
            eth_header.write(&mut serialized).unwrap();
            outer_vlan_header.write(&mut serialized).unwrap();
            inner_vlan_header.write(&mut serialized).unwrap();
            assert_eq!(
                Some(1234),
                SlicedPacket::from_ethernet(&serialized)
                    .unwrap()
                    .payload_ether_type()
            );
        }
    }
}
