use super::super::*;

#[test]
fn readwrite_ip_header() {
    use std::io::Cursor;

    let inputs = [
        IpHeader::Version4({
            let mut header: Ipv4Header = Default::default();

            header.differentiated_services_code_point = 42;
            header.explicit_congestion_notification = 3;
            header.payload_len = 1234 - 20;
            header.identification = 4321;
            header.dont_fragment = true;
            header.more_fragments = false;
            header.fragments_offset = 4367;
            header.time_to_live = 8;
            header.protocol = 1;
            header.header_checksum = 43617;
            header.source = [192, 168, 1, 1];
            header.destination = [212, 10, 11, 123];

            header
        }, Default::default()),
        IpHeader::Version4({
            let mut header: Ipv4Header = Default::default();

            header.differentiated_services_code_point = 42;
            header.explicit_congestion_notification = 3;
            header.payload_len = 1234 - 20;
            header.identification = 4321;
            header.dont_fragment = false;
            header.more_fragments = true;
            header.fragments_offset = 4367;
            header.time_to_live = 8;
            header.protocol = 1;
            header.header_checksum = 51809;
            header.source = [192, 168, 1, 1];
            header.destination = [212, 10, 11, 123];
            
            header
        }, Default::default()),
        IpHeader::Version6(Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        }, Default::default())
    ];
    for input in &inputs {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer).unwrap();

        match *input {
            IpHeader::Version4(_,_) => assert_eq!(20, buffer.len()),
            IpHeader::Version6(_,_) => assert_eq!(40, buffer.len())
        }
        
        //deserialize with read
        {
            let mut cursor = Cursor::new(&buffer);
            let (result, next_header) = IpHeader::read(&mut cursor).unwrap();
            match *input {
                IpHeader::Version4(ref header,_) => {
                    assert_eq!(20, cursor.position());
                    assert_eq!(next_header, header.protocol);
                },
                IpHeader::Version6(ref header,_) => {
                    assert_eq!(40, cursor.position());
                    assert_eq!(next_header, header.next_header);
                }
            }
            assert_eq!(result, *input);
        } 

        //deserialize with read_from_slice
        {
            //add a byte to ensure that only the required data is read
            buffer.push(1);
            //return
            let result = IpHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(result.0, *input);
            match *input {
                IpHeader::Version4(ref header,_) => assert_eq!(result.1, header.protocol),
                IpHeader::Version6(ref header,_) => assert_eq!(result.1, header.next_header)
            }
            assert_eq!(result.2, &buffer[buffer.len() - 1 .. ]);
        }
    }
}

#[test]
fn read_ip_header_version_error() {
    use std::io::Cursor;
    let input = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 0x8021,
        next_header: 30,
        hop_limit: 40,
        source: [1, 2, 3, 4, 5, 6, 7, 8,
                 9,10,11,12,13,14,15,16],
        destination: [21,22,23,24,25,26,27,28,
                      29,30,31,32,33,34,35,36]
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
        assert_matches!(IpHeader::read(&mut cursor), Err(ReadError::IpUnsupportedVersion(0xf)));
    }

    //deserialize with read_from_slice
    assert_matches!(
        IpHeader::read_from_slice(&buffer), 
        Err(ReadError::IpUnsupportedVersion(0xf))
    );
    //also check that an error is thrown when the slice is too small 
    //to even read the version
    assert_matches!(
        IpHeader::read_from_slice(&buffer[buffer.len()..]), 
        Err(ReadError::UnexpectedEndOfSlice(1))
    );
}

#[test]
fn is_ipv6_ext_header_value() {
    use crate::IpNumber;
    use crate::ip_number::*;
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
        EXP1 as u8
    ];

    for i in 0..std::u8::MAX {
        assert_eq!(
            ext_ids.contains(&i),
            IpNumber::is_ipv6_ext_header_value(i)
        );
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