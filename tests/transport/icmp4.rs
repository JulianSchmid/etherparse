

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
}