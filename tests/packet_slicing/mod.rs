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
            Err(
                UnexpectedEndOfSlice(
                    UnexpectedEndOfSliceError {
                        expected_min_len: 1,
                        actual_len: 0,
                    }
                )
            )
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
}
