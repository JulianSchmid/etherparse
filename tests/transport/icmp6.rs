

#[test]
fn constants() {
    use etherparse::icmpv6::*;
    // type values according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-16
    assert_eq!(  1, TYPE_DST_UNREACH);
    assert_eq!(  2, TYPE_PACKET_TOO_BIG);
    assert_eq!(  3, TYPE_TIME_EXCEEDED);
    assert_eq!(  4, TYPE_PARAM_PROB);
    assert_eq!(128, TYPE_ECHO_REQUEST);
    assert_eq!(129, TYPE_ECHO_REPLY);
    assert_eq!(130, TYPE_MULTICAST_LISTENER_QUERY);
    assert_eq!(131, TYPE_MULTICAST_LISTENER_REPORT);
    assert_eq!(132, TYPE_MULTICAST_LISTENER_REDUCTION);
    assert_eq!(133, TYPE_ROUTER_SOLICITATION);
    assert_eq!(134, TYPE_ROUTER_ADVERTISEMENT);
    assert_eq!(135, TYPE_NEIGHBOR_SOLICITATION);
    assert_eq!(136, TYPE_NEIGHBOR_ADVERTISEMENT);
    assert_eq!(137, TYPE_REDIRECT_MESSAGE);
    assert_eq!(138, TYPE_ROUTER_RENUMBERING);
    assert_eq!(141, TYPE_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION);
    assert_eq!(142, TYPE_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT);
    assert_eq!(160, TYPE_EXT_ECHO_REQUEST);
    assert_eq!(161, TYPE_EXT_ECHO_REPLY);

    // destination unreachable code values according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-2
    assert_eq!(0, CODE_DST_UNREACH_NOROUTE);
    assert_eq!(1, CODE_DST_UNREACH_PROHIBITED);
    assert_eq!(2, CODE_DST_UNREACH_BEYONDSCOPE);
    assert_eq!(3, CODE_DST_UNREACH_ADDR);
    assert_eq!(4, CODE_DST_UNREACH_PORT);
}


mod icmp6_hdr {
    use etherparse::*;
    // use super::super::*;

    #[test]
    fn icmp6_echo_marshall_unmarshall() {
        let icmp6 = Icmp6Header {
            icmp_type: Icmp6Type::EchoRequest(IcmpEchoHeader{
                seq: 1,
                id: 2,
            }),
            icmp_chksum: 0,
        };
        // serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        icmp6.write(&mut buffer).unwrap();
        let (new_icmp6, rest) = Icmp6Header::from_slice(&buffer).unwrap();
        assert_eq!(icmp6, new_icmp6);
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn ip6_echo_marshall_unmarshall() {
        let builder = PacketBuilder::
            ipv6(   
                [0xfe,0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],  //source ip
                [0xfe,0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 114],  //dst ip
                20)            //time to life
            .icmp6_echo_request(1,2);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(
                            builder.size(payload.len()));
            
        //serialize
        builder.write(&mut result, &payload).unwrap();

        let new_ip = PacketHeaders::from_ip_slice(&result).unwrap();
        if let Some(TransportHeader::Icmp6(hdr)) = new_ip.transport {
            if let Icmp6Type::EchoRequest(echo) = hdr.icmp_type {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 2);
            } else {
                panic!("Not an EchoRequest!?");
            }

        } else {
            panic!("No transport header found!?")
        }
    }
    const ICMP6_ECHO_REQUEST_BYTES: [u8; 118] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
        0xf3, 0xc2, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0xd5, 0x2f, 0x00, 0x05, 0x00, 0x01, 0xe3, 0x58,
        0xdb, 0x61, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xc0, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    const ICMP6_ECHO_REPLY_BYTES: [u8; 118] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
        0xa3, 0xde, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0xd4, 0x2f, 0x00, 0x05, 0x00, 0x01, 0xe3, 0x58,
        0xdb, 0x61, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xc0, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    #[test]
    fn verify_icmp6_checksum() {
        for (pkt, checksum) in [
                    (ICMP6_ECHO_REQUEST_BYTES, 0xd52f), 
                    (ICMP6_ECHO_REPLY_BYTES, 0xd42f)
                ] {
            // make sure we can unmarshall the correct checksum
            let request = PacketHeaders::from_ethernet_slice(&pkt).unwrap();
            let mut icmp6 = request.transport.unwrap().icmp6().unwrap();
            let valid_checksum =  icmp6.icmp_chksum;
            assert_ne!(valid_checksum, 0);  
            assert_eq!(valid_checksum, checksum);
            // reset it and recalculate
            icmp6.icmp_chksum = 0;
            let iph = match request.ip {
                Some(IpHeader::Version6(ipv6, _)) => ipv6,
                _ => panic!("Failed to parse ipv6 part of packet?!"),
            };
            assert_eq!(icmp6.calc_checksum_ipv6(&iph, request.payload),
                Ok(valid_checksum));
        }
    }

    #[test]
    fn echo_request_slice() {
        let echo = SlicedPacket::from_ethernet(&ICMP6_ECHO_REQUEST_BYTES).unwrap();
        use TransportSlice::*;
        let icmp6 = match echo.transport.unwrap() {
            Icmp6(icmp6) => icmp6,
            Icmp4(_) | Udp(_) | Tcp(_) | Unknown(_) => panic!("Misparsed header!"),
        };
        assert!(matches!(icmp6.icmp_type(), Icmp6Type::EchoRequest(_)));

    }


}