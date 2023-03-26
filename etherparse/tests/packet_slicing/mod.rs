use super::*;

mod sliced_packet {
    use super::*;

    #[test]
    fn from_ip_errors() {
        use crate::err::packet::IpSliceError::*;

        // slice length error
        assert_eq!(
            SlicedPacket::from_ip(&[]).unwrap_err(),
            Len(err::LenError {
                required_len: 1,
                len: 0,
                len_source: err::LenSource::Slice,
                layer: err::Layer::IpHeader,
                layer_start_offset: 0,
            })
        );

        // bad protocol number
        for i in 0u8..std::u8::MAX {
            if i >> 4 != 4 && i >> 4 != 6 {
                assert_matches!(SlicedPacket::from_ip(&[i]), Err(IpHeader(_)));
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
