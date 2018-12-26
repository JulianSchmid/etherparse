use super::super::*;

#[test]
fn readwrite_ip_header() {
    use std::io::Cursor;

    let inputs = [
        IpHeader::Version4(Ipv4Header {
            header_length: 5,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 43617,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        }),
        IpHeader::Version4(Ipv4Header {
            header_length: 5,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: false,
            more_fragments: true,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 51809,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        }),
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
        })
    ];
    for input in &inputs {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer).unwrap();

        match *input {
            IpHeader::Version4(_) => assert_eq!(20, buffer.len()),
            IpHeader::Version6(_) => assert_eq!(40, buffer.len())
        }
        
        //deserialize with read
        {
            let mut cursor = Cursor::new(&buffer);
            let result = IpHeader::read(&mut cursor).unwrap();
            match *input {
                IpHeader::Version4(_) => assert_eq!(20, cursor.position()),
                IpHeader::Version6(_) => assert_eq!(40, cursor.position())
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
            assert_eq!(result.1, &buffer[buffer.len() - 1 .. ]);
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

