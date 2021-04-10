use super::super::*;

#[test]
fn read() {
    use std::io::Cursor;
    const INPUT: Ipv6Header = Ipv6Header {
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
    INPUT.write(&mut buffer).unwrap();
    assert_eq!(40, buffer.len());

    //deserialize
    let mut cursor = Cursor::new(&buffer);
    let result = IpHeader::read(&mut cursor).unwrap();
    assert_eq!(40, cursor.position());

    assert_eq!(result.0, IpHeader::Version6(INPUT, Default::default()));
    assert_eq!(result.1, INPUT.next_header);
}

#[test]
fn read_write() {
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
    //deserialize (with read)
    {
        let result = Ipv6Header::read(&mut Cursor::new(&buffer)).unwrap();
        //check equivalence
        assert_eq!(input, result);
    }
    //deserialize (with read_from_slice)
    {
        let result = Ipv6Header::read_from_slice(&buffer).unwrap();
        assert_eq!(input, result.0);
        assert_eq!(&buffer[buffer.len()..], result.1);
    }
}

#[test]
fn write_errors() {
    use crate::WriteError::ValueError;
    use crate::ValueError::*;
    use crate::ErrorField::*;
    fn base() -> Ipv6Header {
        Ipv6Header {
            traffic_class: 1,
            flow_label: 0x0,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        }
    }

    fn test_write(input: &Ipv6Header) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer)
    }
    //flow label
    assert_matches!(
        test_write(&{
            let mut value = base();
            value.flow_label = 0x100000;
            value
        }), 
        Err(ValueError(U32TooLarge{value: 0x100000, max: 0xFFFFF, field: Ipv6FlowLabel})));

    //io error (not enough space)
    {
        let header = base();
        for len in 0..Ipv6Header::SERIALIZED_SIZE {
            let mut writer = TestWriter::with_max_size(len);
            assert_eq!(
                writer.error_kind(),
                header.write(&mut writer).unwrap_err().io_error().unwrap().kind()
            );
        }
    }
}

#[test]
fn read_error() {
    //wrong ip version
    {
        let buffer: [u8;20] = [0;20];
        let result = Ipv6Header::read(&mut io::Cursor::new(&buffer));
        assert_matches!(result, Err(ReadError::Ipv6UnexpectedVersion(0)))
    }
    //io error and unexpected end of slice
    {
        let buffer = {
            let mut buffer: [u8;Ipv6Header::SERIALIZED_SIZE] = [0;Ipv6Header::SERIALIZED_SIZE];
            buffer[0] = 0x60; //ip number is needed
            buffer
        };
        for len in 0..Ipv6Header::SERIALIZED_SIZE {
            // read
            assert_matches!(
                Ipv6Header::read(&mut io::Cursor::new(&buffer[0..len])),
                Err(ReadError::IoError(_))
            );

            // read from slice
            assert_matches!(
                Ipv6Header::read_from_slice(&buffer[0..len]),
                Err(ReadError::UnexpectedEndOfSlice(Ipv6Header::SERIALIZED_SIZE))
            );
        }
    }
}

#[test]
fn is_skippable_header_extension() {
    use crate::ip_number::*;

    for i in 0..0xffu8 {
        let expected = match i {
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_FRAG | AUTH | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => true,
            _ => false
        };
        assert_eq!(expected, Ipv6Header::is_skippable_header_extension(i));
    }
}

#[test]
fn skip_extension() {
    use crate::ip_number::*;

    use std::io::Cursor;
    {
        let buffer: [u8; 8] = [0;8];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, ICMP), Ok(ICMP));
        assert_eq!(0, cursor.position());
    }
    {
        let buffer: [u8; 8] = [0;8];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, IPV6_HOP_BY_HOP), Ok(0));
        assert_eq!(8, cursor.position());
    }
    {
        let buffer: [u8; 8*3] = [
            4,2,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, IPV6_ROUTE), Ok(4));
        assert_eq!(8*3, cursor.position());
    }
    {
        //fragmentation header has a fixed size -> the 2 should be ignored
        let buffer: [u8; 8*3] = [
            4,2,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, IPV6_FRAG), Ok(4));
        assert_eq!(8, cursor.position());
    }
}

#[test]
fn skip_all_extensions() {
    use crate::io::Cursor;
    //extension header values
    use crate::ip_number::*;
    //based on RFC 8200 4.1. Extension Header Order
    // & IANA https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
    const EXTENSION_IDS: [u8;9] = [
        IPV6_HOP_BY_HOP,
        IPV6_DEST_OPTIONS,
        IPV6_ROUTE,
        IPV6_FRAG,
        AUTH,
        IPV6_DEST_OPTIONS,
        MOBILITY,
        HIP,
        SHIM6,
    ];

    // note the following ids are extensions but are not skippable:
    //
    // - EncapsulatingSecurityPayload
    // - ExperimentalAndTesting0
    // - ExperimentalAndTesting0

    //no & single skipping
    {
        let buffer: [u8; 8*4] = [
            UDP,2,0,0, 0,0,0,0, //set next to udp
            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,0,
            1,2,3,4,   5,6,7,8,
        ];

        for i in 0..=u8::max_value() {
            let mut cursor = Cursor::new(&buffer);
            let reader_result = Ipv6Header::skip_all_header_extensions(&mut cursor, i);
            let slice_result = Ipv6Header::skip_all_header_extensions_in_slice(&buffer, i).unwrap();
            match EXTENSION_IDS.iter().find(|&&x| x == i) {
                Some(_) => {
                    //ipv6 header extension -> expect skip
                    assert_matches!(reader_result, Ok(UDP));
                    assert_matches!(slice_result.0, UDP);

                    let len = if i == IPV6_FRAG {
                        //fragmentation header has a fixed size
                        8
                    } else if i == AUTH {
                        //authentification headers use 4-octets to describe the length
                        8 + 2*4
                    } else {
                        buffer.len() - 8
                    };
                    assert_eq!(len, cursor.position() as usize);
                    assert_eq!(&buffer[len..], slice_result.1);
                },
                None => {
                    //non ipv6 header expect no read movement and direct return
                    assert_matches!(reader_result, Ok(next) => assert_eq!(i, next));
                    assert_eq!(0, cursor.position());

                    assert_eq!(i, slice_result.0);
                    assert_eq!(&buffer, slice_result.1);
                }
            }
        }

    }

    //creates an buffer filled with extension headers with the given ids
    fn create_buffer(ids: &[u8]) -> Vec<u8> {
        use crate::ip_number::*;

        let mut prev: u8 = ids[0];
        let mut result = Vec::with_capacity(ids.len()*8*4);
        for (index, value) in ids[1..].iter().enumerate() {
            let len: u8 = if prev == IPV6_FRAG {
                0
            } else {
                (index % 3) as u8
            };

            //write first line
            result.extend_from_slice(&[*value, len, 0, 0,  0, 0, 0, 0]);
            
            //fill rest with dummy data
            for _ in 0..len {
                result.extend_from_slice(
                    if prev == AUTH {
                        // authentification headers interpret the length as in 4-octets
                        &[0;4]
                    } else {
                        // all other headers (excluding the fragmentation header) interpret the length as in 8-octets
                        &[0;8]
                    }
                );
            }
        
            //cache prev
            prev = *value;
        }

        //add some dummy data to the end (useful for checking that the returned slice are correct)
        result.extend_from_slice(&[0, 0, 0, 0,  0, 0, 0, 0]);

        result
    }

    //skip maximum number
    {
        let ids = {
            let mut ids = Vec::with_capacity(IPV6_MAX_NUM_HEADER_EXTENSIONS);
            while ids.len() < IPV6_MAX_NUM_HEADER_EXTENSIONS {
                // fill with extension headers until filled
                ids.extend_from_slice(&EXTENSION_IDS[..std::cmp::min(EXTENSION_IDS.len(), IPV6_MAX_NUM_HEADER_EXTENSIONS - ids.len())]);
            }
            ids.push(UDP);
            ids
        };
        let buffer = create_buffer(&ids);

        //reader
        {
            let mut cursor = Cursor::new(&buffer);
            let result = Ipv6Header::skip_all_header_extensions(&mut cursor, ids[0]);
            assert_matches!(result, Ok(UDP));
            assert_eq!(buffer.len() - 8, cursor.position() as usize);
        }
        //slice
        {
            
            let result = Ipv6Header::skip_all_header_extensions_in_slice(&buffer, ids[0]).unwrap();
            assert_eq!(result.0, UDP);
            assert_eq!(result.1, &buffer[buffer.len() - 8 .. ]);
        }
    }
    //trigger "too many" error
    {
        let ids = {
            let mut ids = Vec::with_capacity(EXTENSION_IDS.len() + 5);
            ids.extend_from_slice(&EXTENSION_IDS);
            ids.push(EXTENSION_IDS[0]);
            ids.push(EXTENSION_IDS[0]);
            ids.push(EXTENSION_IDS[0]);
            ids.push(EXTENSION_IDS[0]);
            ids.push(UDP);
            ids
        };
        let buffer = create_buffer(&ids);

        //reader
        {
            let mut cursor = Cursor::new(&buffer);
            let result = Ipv6Header::skip_all_header_extensions(&mut cursor, ids[0]);
            assert_matches!(result, Err(ReadError::Ipv6TooManyHeaderExtensions));
        }
        //slice
        {
            let result = Ipv6Header::skip_all_header_extensions_in_slice(&buffer, ids[0]);
            assert_matches!(result, Err(ReadError::Ipv6TooManyHeaderExtensions));
        }
    }
    //trigger missing unexpected eof
    {
        let ids = {
            let mut ids = Vec::with_capacity(EXTENSION_IDS.len() + 1);
            ids.extend_from_slice(&EXTENSION_IDS);
            ids.push(UDP);
            ids
        };
        let buffer = create_buffer(&ids);

        // check for all offsets
        for len in 0..buffer.len() - 8 { // minus 8 for the dummy data
            //reader
            {
                let mut cursor = TestReader::new(&buffer[..len]);
                let result = Ipv6Header::skip_all_header_extensions(&mut cursor, ids[0]);
                assert_matches!(result, Err(ReadError::IoError(_)));
            }
            //slice
            {
                let result = Ipv6Header::skip_all_header_extensions_in_slice(&buffer[..len], ids[0]);
                assert_matches!(result, Err(ReadError::UnexpectedEndOfSlice(_)));
            }
        }
    }
}

#[test]
fn set_payload_lengt() {
    let mut header = Ipv6Header {
        traffic_class: 0,
        flow_label:  0,
        payload_length: 0,
        next_header: 0,
        hop_limit: 0,
        source: [0;16],
        destination: [0;16]
    };
    assert_matches!(header.set_payload_length(0), Ok(()));
    assert_eq!(header.payload_length, 0);

    const MAX: usize = std::u16::MAX as usize;
    assert_matches!(header.set_payload_length(MAX), Ok(()));
    assert_eq!(header.payload_length, MAX as u16);
    
    const OVER_MAX: usize = MAX + 1;
    assert_matches!(header.set_payload_length(OVER_MAX), 
                    Err(ValueError::Ipv6PayloadLengthTooLarge(OVER_MAX)));
}

proptest! {
    #[test]
    fn from_slice(ref input in ipv6_any()) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer).unwrap();

        //check that a too small slice triggers an error
        assert_matches!(Ipv6HeaderSlice::from_slice(&buffer[..buffer.len()-1]), Err(ReadError::UnexpectedEndOfSlice(Ipv6Header::SERIALIZED_SIZE)));

        //check that all the values are read correctly
        use std::net::Ipv6Addr;
        let slice = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(slice.slice(), &buffer[..]);
        assert_eq!(slice.version(), 6);
        assert_eq!(slice.traffic_class(), input.traffic_class);
        assert_eq!(slice.flow_label(), input.flow_label);
        assert_eq!(slice.payload_length(), input.payload_length);
        assert_eq!(slice.next_header(), input.next_header);
        assert_eq!(slice.hop_limit(), input.hop_limit);
        assert_eq!(slice.source(), input.source);
        assert_eq!(slice.source_addr(), Ipv6Addr::from(input.source));
        assert_eq!(slice.destination(), input.destination);
        assert_eq!(slice.destination_addr(), Ipv6Addr::from(input.destination));

        //test for derive
        assert_eq!(slice.clone(), slice);

        //check that the convertion back to a header struct results in the same struct
        assert_eq!(&slice.to_header(), input);
    }
}

#[test]
fn from_slice_bad_version() {
    //write an ipv4 header and check that the bad version number is detected
    let input = {
        let mut input: Ipv4Header = Default::default();
        //set the options to increase the size, 
        //otherwise an unexpected end of slice error is returned
        input.set_options(
            &[0;24]
        ).unwrap();
        input
    };
    
    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(44);
    input.write_raw(&mut buffer).unwrap();

    //check that the unexpected version id is detected
    use crate::ReadError::*;
    assert_matches!(Ipv6HeaderSlice::from_slice(&buffer[..]), Err(Ipv6UnexpectedVersion(4)));
}

#[test]
fn dbg() {
    let header: Ipv6Header = Default::default();
    println!("{:?}", header);

    let mut buffer: Vec<u8> = Vec::with_capacity(Ipv6Header::SERIALIZED_SIZE);
    header.write(&mut buffer).unwrap();
    let slice = Ipv6HeaderSlice::from_slice(&buffer[..]).unwrap();
    println!("{:?}", slice);
}

#[test]
fn eq() {
    let header: Ipv6Header = Default::default();
    assert!(header.eq(&header.clone()));
    assert!(false == header.ne(&header.clone()));

    let mut buffer: Vec<u8> = Vec::with_capacity(Ipv6Header::SERIALIZED_SIZE);
    header.write(&mut buffer).unwrap();
    let slice = Ipv6HeaderSlice::from_slice(&buffer[..]).unwrap();
    assert!(slice.eq(&slice.clone()));
    assert!(false == slice.ne(&slice.clone()));
}
