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
fn read_ip_header_error() {
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

mod ip_traffic_class {
    
    #[test]
    fn is_ipv6_ext_header_value() {
        use crate::IpTrafficClass;
        use crate::IpTrafficClass::*;
        let ext_ids = [
            IPv6HeaderHopByHop as u8,
            IPv6RouteHeader as u8,
            IPv6FragmentationHeader as u8,
            EncapsulatingSecurityPayload as u8,
            AuthenticationHeader as u8,
            IPv6DestinationOptions as u8,
            MobilityHeader as u8,
            Hip as u8,
            Shim6 as u8,
            ExperimentalAndTesting0 as u8,
            ExperimentalAndTesting1 as u8
        ];

        for i in 0..std::u8::MAX {
            assert_eq!(
                ext_ids.contains(&i),
                IpTrafficClass::is_ipv6_ext_header_value(i)
            );
        }
    }
}