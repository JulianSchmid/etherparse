use super::super::*;

mod ip_header {
    use super::*;

    #[test]
    fn read_ip_header_version_error() {
        use err::ip::{HeaderError::*, HeaderSliceError::*};

        use std::io::Cursor;
        let input = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            destination: [
                21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            ],
        };
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer).unwrap();
        assert_eq!(40, buffer.len());

        //corrupt the version
        buffer[0] = 0xff;

        //deserialize with read
        {
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(
                IpHeader::read(&mut cursor).unwrap_err().content_error().unwrap(),
                UnsupportedIpVersion { version_number: 0xf }
            );
        }

        //deserialize with read_from_slice
        assert_eq!(
            IpHeader::from_slice(&buffer).unwrap_err(),
            Content(UnsupportedIpVersion { version_number: 0xf })
        );
        //also check that an error is thrown when the slice is too small
        //to even read the version
        assert_eq!(
            IpHeader::from_slice(&buffer[buffer.len()..])
                .unwrap_err(),
            SliceLen(err::SliceLenError {
                expected_min_len: 1,
                actual_len: 0,
                layer: err::Layer::IpHeader
            })
        );
    }
} // mod ip_header

mod ip_number {
    use super::*;

    #[test]
    fn is_ipv6_ext_header_value() {
        use crate::ip_number::*;
        use crate::IpNumber;
        let ext_ids = [
            IPV6_HOP_BY_HOP,
            IPV6_ROUTE,
            IPV6_FRAG,
            ENCAP_SEC,
            AUTH,
            IPV6_DEST_OPTIONS,
            MOBILITY,
            HIP,
            SHIM6 as u8,
            EXP0 as u8,
            EXP1 as u8,
        ];

        for i in 0..std::u8::MAX {
            assert_eq!(ext_ids.contains(&i), IpNumber::is_ipv6_ext_header_value(i));
        }
    }

    #[test]
    fn ip_number_eq_check() {
        use crate::ip_number::*;
        use crate::IpNumber::*;
        let pairs = &[
            (IPV6_HOP_BY_HOP, IPv6HeaderHopByHop),
            (ICMP, Icmp),
            (IGMP, Igmp),
            (GGP, Ggp),
            (IPV4, IPv4),
            (STREAM, Stream),
            (TCP, Tcp),
            (UDP, Udp),
            (IPV6, Ipv6),
            (IPV6_ROUTE, IPv6RouteHeader),
            (IPV6_FRAG, IPv6FragmentationHeader),
            (ENCAP_SEC, EncapsulatingSecurityPayload),
            (AUTH, AuthenticationHeader),
            (IPV6_DEST_OPTIONS, IPv6DestinationOptions),
            (MOBILITY, MobilityHeader),
            (HIP, Hip),
            (SHIM6, Shim6),
            (EXP0, ExperimentalAndTesting0),
            (EXP1, ExperimentalAndTesting1),
        ];
        for (raw, enum_value) in pairs {
            assert_eq!(*raw, *enum_value as u8);
        }
    }

    #[test]
    fn debug() {
        assert_eq!(
            "IPv6HeaderHopByHop",
            &format!("{:?}", IpNumber::IPv6HeaderHopByHop)
        );
    }

    #[test]
    fn clone_eq() {
        let value = IpNumber::IPv6HeaderHopByHop;
        assert_eq!(value, value.clone());
    }
} // mod ip_number
