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
                IpHeader::read(&mut cursor)
                    .unwrap_err()
                    .content_error()
                    .unwrap(),
                UnsupportedIpVersion {
                    version_number: 0xf
                }
            );
        }

        //deserialize with read_from_slice
        assert_eq!(
            IpHeader::from_slice(&buffer).unwrap_err(),
            Content(UnsupportedIpVersion {
                version_number: 0xf
            })
        );
        //also check that an error is thrown when the slice is too small
        //to even read the version
        assert_eq!(
            IpHeader::from_slice(&buffer[buffer.len()..]).unwrap_err(),
            Len(err::LenError {
                required_len: 1,
                len: 0,
                len_source: err::LenSource::Slice,
                layer: err::Layer::IpHeader,
                layer_start_offset: 0,
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
            SHIM6,
            EXP0,
            EXP1,
        ];

        for i in 0..std::u8::MAX {
            assert_eq!(ext_ids.contains(&i), IpNumber::is_ipv6_ext_header_value(i));
        }
    }

    #[test]
    fn ip_number_eq_check() {
        use crate::ip_number::*;
        use crate::IpNumber;
        let pairs = &[
            (IPV6_HOP_BY_HOP, IpNumber::IPV6_HEADER_HOP_BY_HOP),
            (ICMP, IpNumber::ICMP),
            (IGMP, IpNumber::IGMP),
            (GGP, IpNumber::GGP),
            (IPV4, IpNumber::IPV4),
            (STREAM, IpNumber::STREAM),
            (TCP, IpNumber::TCP),
            (UDP, IpNumber::UDP),
            (IPV6, IpNumber::IPV6),
            (IPV6_ROUTE, IpNumber::IPV6_ROUTE_HEADER),
            (IPV6_FRAG, IpNumber::IPV6_FRAGMENTATION_HEADER),
            (ENCAP_SEC, IpNumber::ENCAPSULATING_SECURITY_PAYLOAD),
            (AUTH, IpNumber::AUTHENTICATION_HEADER),
            (IPV6_DEST_OPTIONS, IpNumber::IPV6_DESTINATION_OPTIONS),
            (MOBILITY, IpNumber::MOBILITY_HEADER),
            (HIP, IpNumber::HIP),
            (SHIM6, IpNumber::SHIM6),
            (EXP0, IpNumber::EXPERIMENTAL_AND_TESTING_0),
            (EXP1, IpNumber::EXPERIMENTAL_AND_TESTING_1),
        ];
        for (raw, enum_value) in pairs {
            assert_eq!(*raw, u8::from(*enum_value));
        }
    }

    #[test]
    fn debug() {
        let pairs = &[
            (IpNumber::IPV6_HEADER_HOP_BY_HOP, "Ipv6HeaderHopByHop(0)"),
            (IpNumber::ICMP, "ICMP(1)"),
            (IpNumber::IGMP, "IGMP(2)"),
            (IpNumber::GGP, "GGP(3)"),
            (IpNumber::IPV4, "Ipv4(4)"),
            (IpNumber::STREAM, "Stream(5)"),
            (IpNumber::TCP, "TCP(6)"),
            (IpNumber::UDP, "UDP(17)"),
            (IpNumber::IPV6, "Ipv6(41)"),
            (IpNumber::IPV6_ROUTE_HEADER, "Ipv6RouteHeader(43)"),
            (IpNumber::IPV6_FRAGMENTATION_HEADER, "Ipv6FragmentationHeader(44)"),
            (IpNumber::ENCAPSULATING_SECURITY_PAYLOAD, "EncapsulatingSecurityPayload(50)"),
            (IpNumber::AUTHENTICATION_HEADER, "AuthenticationHeader(51)"),
            (IpNumber::IPV6_ICMP, "Ipv6_ICMP(58)"),
            (IpNumber::IPV6_DESTINATION_OPTIONS, "Ipv6DestinationOptions(60)"),
            (IpNumber::MOBILITY_HEADER, "MobilityHeader(135)"),
            (IpNumber::HIP, "HIP(139)"),
            (IpNumber::SHIM6, "SHIM6(140)"),
            (IpNumber::EXPERIMENTAL_AND_TESTING_0, "IpNumber(253)"),
            (IpNumber::EXPERIMENTAL_AND_TESTING_1, "IpNumber(254)"),
        ];
        
        for (ip_number, debug_str) in pairs {
            assert_eq!(format!("{:?}", ip_number), *debug_str);
        }
    }

    #[test]
    fn clone_eq() {
        let value = IpNumber::IPV6_HEADER_HOP_BY_HOP;
        assert_eq!(value, value.clone());
    }
} // mod ip_number
