

mod icmp4_hdr {
    use etherparse::*;
    // use super::super::*;

    #[test]
    fn icmp4_echo_marshall_unmarshall() {
        let icmp4 = IcmpV4Header {
            icmp_type: IcmpV4Type::EchoRequest,
            icmp_code: 0u8,
            icmp_chksum: 0u16,
            echo_header: Some(IcmpEchoHeader{
                seq: 1,
                id: 2,
            }),
        };
        // serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        icmp4.write(&mut buffer).unwrap();
        let (new_icmp4, rest) = IcmpV4Header::from_slice(&buffer).unwrap();
        assert_eq!(icmp4, new_icmp4);
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn ip4_echo_marshall_unmarshall() {
        let builder = PacketBuilder::
            ipv4(   [192,168,1,1],  //source ip
                [192,168,1,2], //desitionation ip
                20)            //time to life
            .icmp4( IcmpV4Type::EchoRequest,
                    0u8)
            .echo(1, 2);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(
                            builder.size(payload.len()));
            
        //serialize
        builder.write(&mut result, &payload).unwrap();

        let new_ip = PacketHeaders::from_ip_slice(&result).unwrap();
        if let Some(TransportHeader::Icmp4(hdr)) = new_ip.transport {
            assert_eq!(hdr.icmp_type, IcmpV4Type::EchoRequest);
            assert_eq!(hdr.icmp_code, 0u8);
            let echo = hdr.echo_header.unwrap();
            assert_eq!(echo.seq, 1);
            assert_eq!(echo.id, 2);

        } else {
            panic!("Transport header not Icmp4");
        }
    }
}