use super::*;

mod packet_headers {
    use super::*;

    #[test]
    fn debug() {
        let header = PacketHeaders {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };
        assert_eq!(
            &format!("{:?}", header),
            &format!(
                "PacketHeaders {{ link: {:?}, vlan: {:?}, ip: {:?}, transport: {:?}, payload: {:?} }}",
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
        let header = PacketHeaders {
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
            use VlanHeader::*;
            use IpHeader::*;
            use TransportHeader::*;

            // none
            assert_eq!(
                None,
                PacketHeaders{
                    link: None,
                    vlan: None,
                    ip: None,
                    transport: None,
                    payload: &[]
                }.payload_ether_type()
            );

            // ethernet header only
            assert_eq!(
                Some(eth.ether_type),
                PacketHeaders{
                    link: Some(eth.clone()),
                    vlan: None,
                    ip: None,
                    transport: None,
                    payload: &[]
                }.payload_ether_type()
            );

            // single vlan header
            assert_eq!(
                Some(vlan_outer.ether_type),
                PacketHeaders{
                    link: Some(eth.clone()),
                    vlan: Some(Single(vlan_outer.clone())),
                    ip: None,
                    transport: None,
                    payload: &[]
                }.payload_ether_type()
            );

            // double vlan header
            assert_eq!(
                Some(vlan_inner.ether_type),
                PacketHeaders{
                    link: Some(eth.clone()),
                    vlan: Some(
                        Double(
                            DoubleVlanHeader {
                                outer: vlan_outer.clone(),
                                inner: vlan_inner.clone()
                            }
                        )
                    ),
                    ip: None,
                    transport: None,
                    payload: &[]
                }.payload_ether_type()
            );

            // ip present
            assert_eq!(
                None,
                PacketHeaders{
                    link: Some(eth.clone()),
                    vlan: None,
                    ip: Some(
                        Version4(ipv4.clone(), Default::default())
                    ),
                    transport: None,
                    payload: &[]
                }.payload_ether_type()
            );

            // transport present
            assert_eq!(
                None,
                PacketHeaders{
                    link: Some(eth.clone()),
                    vlan: None,
                    ip: Some(
                        Version4(ipv4.clone(), Default::default())
                    ),
                    transport: Some(
                        Udp(udp.clone())
                    ),
                    payload: &[]
                }.payload_ether_type()
            );
        }
    }
}
