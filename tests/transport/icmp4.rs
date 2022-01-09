

mod icmp4_hdr {
    use etherparse::*;
    // use super::super::*;

    #[test]
    fn icmp4_echo_marshall_unmarshall() {
        let icmp4 = Icmp4Header {
            icmp_type: Icmp4Type::EchoRequest(IcmpEchoHeader{
                seq: 1,
                id: 2,
            }),
            icmp_chksum: 0,
        };
        // serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        icmp4.write(&mut buffer).unwrap();
        let (new_icmp4, rest) = Icmp4Header::from_slice(&buffer).unwrap();
        assert_eq!(icmp4, new_icmp4);
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn ip4_echo_marshall_unmarshall() {
        let builder = PacketBuilder::
            ipv4(   [192,168,1,1],  //source ip
                [192,168,1,2], //desitionation ip
                20)            //time to life
            .icmp4_echo_request(1,2);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(
                            builder.size(payload.len()));
            
        //serialize
        builder.write(&mut result, &payload).unwrap();

        let new_ip = PacketHeaders::from_ip_slice(&result).unwrap();
        if let Some(TransportHeader::Icmp4(hdr)) = new_ip.transport {
            if let Icmp4Type::EchoRequest(echo) = hdr.icmp_type {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 2);
            } else {
                panic!("Not an EchoRequest!?");
            }

        } else {
            panic!("No transport header found!?")
        }
    }
    const ICMP4_ECHO_REQUEST_BYTES: [u8; 98]= [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x54, 0x13, 0x6f, 0x40, 0x00, 0x40, 0x01, 0x29, 0x38, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
        0x00, 0x01, 0x08, 0x00, 0xc9, 0x99, 0x00, 0x03, 0x00, 0x01, 0x79, 0xc5, 0xd9, 0x61, 0x00, 0x00,
        0x00, 0x00, 0x18, 0x68, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37,
    ];

    const ICMP4_ECHO_REPLY_BYTES : [u8;98] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x54, 0x13, 0x70, 0x00, 0x00, 0x40, 0x01, 0x69, 0x37, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
        0x00, 0x01, 0x00, 0x00, 0xd1, 0x99, 0x00, 0x03, 0x00, 0x01, 0x79, 0xc5, 0xd9, 0x61, 0x00, 0x00,
        0x00, 0x00, 0x18, 0x68, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37,
    ];

    // real echo request/reply captured from tcpdump
    // ping 127.0.0.1 to 127.0.0.1
    #[test]
    fn pcap_echo_session() {
        let request = PacketHeaders::from_ethernet_slice(&ICMP4_ECHO_REQUEST_BYTES).unwrap();
        let request_icmp4 = request.transport.unwrap().icmp4().unwrap();
        match request_icmp4.icmp_type {
            Icmp4Type::EchoRequest(echo) => {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 3); // arbitrarily assigned by OS
            },
            _ => panic!(r#"Request didn't parse as ICMP4!?"#),
        }

        let reply  = PacketHeaders::from_ethernet_slice(&ICMP4_ECHO_REPLY_BYTES).unwrap();
        let reply_icmp4 = reply.transport.unwrap().icmp4().unwrap();
        match reply_icmp4.icmp_type {
            Icmp4Type::EchoReply(echo) => {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 3); // arbitrarily assigned by OS
            },
            _ => panic!(r#"Request didn't parse as ICMP4!?"#),
        }
        let request_iph = request.ip.unwrap();
        let reply_iph = reply.ip.unwrap();
        if let IpHeader::Version4(request_ip, _) = request_iph {
            if let IpHeader::Version4(reply_ip, _) = reply_iph {
                assert_eq!(reply_ip.source, request_ip.destination);
                assert_eq!(reply_ip.destination, request_ip.source);
            } else {
                panic!("reply ip not v4!?");
            }
        } else {
            panic!("request ip not v4!?");
        }
    }

    #[test]
    fn verify_icmp4_checksum() {
        for (pkt, checksum) in [
                (ICMP4_ECHO_REQUEST_BYTES, 0xc999), 
                (ICMP4_ECHO_REPLY_BYTES, 0xd199)
                ] {
            // make sure we can unmarshall the correct checksum
            let request = PacketHeaders::from_ethernet_slice(&pkt).unwrap();
            let mut icmp4 = request.transport.unwrap().icmp4().unwrap();
            let valid_checksum =  icmp4.icmp_chksum;
            assert_ne!(valid_checksum, 0);  
            assert_eq!(valid_checksum, checksum);
            // reset it and recalculate
            icmp4.icmp_chksum = 0;
            let iph = match request.ip {
                Some(IpHeader::Version4(ipv4, _)) => ipv4,
                _ => panic!("Failed to parse ipv4 part of packet?!"),
            };
            assert_eq!(icmp4.calc_checksum_ipv4(&iph, request.payload),
                Ok(valid_checksum));
        }
    }
}