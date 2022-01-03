

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
}