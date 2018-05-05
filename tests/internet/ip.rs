use etherparse::*;
use std;
use std::io;

#[test]
fn ipv4_new() {
    let result = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]);
    assert_eq!(Ipv4Header {
        header_length: 0,
        differentiated_services_code_point: 0,
        explicit_congestion_notification: 0,
        total_length: 15 + 20,
        identification: 0,
        dont_fragment: true,
        more_fragments: false,
        fragments_offset: 0,
        time_to_live: 4,
        protocol: IpTrafficClass::Udp as u8,
        header_checksum: 0,
        source: [1,2,3,4],
        destination: [5,6,7,8]
    }, result.unwrap());
}

#[test]
fn ipv4_new_error() {
    //border case check (no error)
    assert_matches!(Ipv4Header::new(
                        (std::u16::MAX as usize) - 20,
                        4,
                        IpTrafficClass::Udp,
                        [1,2,3,4],
                        [5,6,7,8]
                    ),
                    Ok(_));

    //check that a too large payload generates an error
    const TOO_LARGE_PAYLOAD: usize = (std::u16::MAX as usize) - 19;
    assert_matches!(Ipv4Header::new(
                        (std::u16::MAX as usize) - 19,
                        4,
                        IpTrafficClass::Udp,
                        [1,2,3,4],
                        [5,6,7,8]
                    ), 
                    Err(ValueError::Ipv4PayloadAndOptionsLengthTooLarge(TOO_LARGE_PAYLOAD)));
}

#[test]
fn ipv4_calc_header_checksum() {
    use ValueError::*;
    use ErrorField::*;
    //without options
    {
        //dont_fragment && !more_fragments
        let header = Ipv4Header {
            header_length: 5,
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            total_length: 40 + 20,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live: 4,
            protocol: IpTrafficClass::Udp as u8,
            header_checksum: 0,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        assert_eq!(0xd582, header.calc_header_checksum(&[]).unwrap());
        // !dont_fragment && more_fragments
        let header = Ipv4Header {
            header_length: 5,
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            total_length: 40 + 20,
            identification: 0,
            dont_fragment: false,
            more_fragments: true,
            fragments_offset: 0,
            time_to_live: 4,
            protocol: IpTrafficClass::Udp as u8,
            header_checksum: 0,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        assert_eq!(0xf582, header.calc_header_checksum(&[]).unwrap());
    }
    //with options
    {
        let header = Ipv4Header {
            header_length: 7,
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            total_length: 40 + 20,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live: 4,
            protocol: IpTrafficClass::Udp as u8,
            header_checksum: 0,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        };
        assert_eq!(0xc36e, header.calc_header_checksum(&[1,2,3,4,5,6,7,8]).unwrap());
    }
    //check errors
    {
        //max value check header length
        {
            let mut header = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
            header.header_length = 0x10;
            assert_matches!(header.calc_header_checksum(&[]),
                            Err(U8TooLarge{value: 0x10, max: 0xf, field: Ipv4HeaderLength}));
        }
        //max check differentiated_services_code_point
        {
            let mut header = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
            header.differentiated_services_code_point = 0x40;
            assert_matches!(header.calc_header_checksum(&[]),
                            Err(U8TooLarge{value: 0x40, max: 0x3f, field: Ipv4Dscp}));
        }
        //max check explicit_congestion_notification
        {
            let mut header = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
            header.explicit_congestion_notification = 0x4;
            assert_matches!(header.calc_header_checksum(&[]),
                            Err(U8TooLarge{value: 0x4, max: 0x3, field: Ipv4Ecn}));
        }
        //max check fragments_offset
        {
            let mut header = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
            header.fragments_offset = 0x2000;
            assert_matches!(header.calc_header_checksum(&[]),
                            Err(U16TooLarge{value: 0x2000, max: 0x1fff, field: Ipv4FragmentsOffset}));
        }
        //non 4 byte aligned options check
        {
            let header = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
            let options = vec![0;9]; //9 is non 4 byte aligned
            assert_matches!(header.calc_header_checksum(&options),
                            Err(Ipv4OptionsLengthBad(9)));
        }
        //options too large test
        {
            let header = Ipv4Header::new(15, 4, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
            let options = vec![0;11*4]; //11 is a too big number to store in the ipv4 header
            assert_matches!(header.calc_header_checksum(&options),
                            Err(Ipv4OptionsLengthBad(44)));
        }
    }
}

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
        println!("{:?}", input);
        match *input {
            IpHeader::Version4(_) => assert_eq!(20, buffer.len()),
            IpHeader::Version6(_) => assert_eq!(40, buffer.len())
        }
        
        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = IpHeader::read(&mut cursor).unwrap();
        match *input {
            IpHeader::Version4(_) => assert_eq!(20, cursor.position()),
            IpHeader::Version6(_) => assert_eq!(40, cursor.position())
        }

        assert_eq!(result, *input);
    }
}

#[test]
fn read_ip_header_ipv6() {
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

    assert_matches!(result, IpHeader::Version6(INPUT));
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

    //deserialize
    let mut cursor = Cursor::new(&buffer);
    assert_matches!(IpHeader::read(&mut cursor), Err(ReadError::IpUnsupportedVersion(0xf)));
}

#[test]
fn readwrite_ipv4_header_raw() {
    use std::io::Cursor;

    let input = Ipv4Header {
        header_length: 10,
        differentiated_services_code_point: 42,
        explicit_congestion_notification: 3,
        total_length: 1234,
        identification: 4321,
        dont_fragment: true,
        more_fragments: false,
        fragments_offset: 4367,
        time_to_live: 8,
        protocol: 1,
        header_checksum: 2345,
        source: [192, 168, 1, 1],
        destination: [212, 10, 11, 123]
    };
    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(20);
    input.write_raw(&mut buffer, &[]).unwrap();
    assert_eq!(20, buffer.len());

    //deserialize
    let mut cursor = Cursor::new(&buffer);
    let result = Ipv4Header::read(&mut cursor).unwrap();
    assert_eq!(20, cursor.position());

    //check equivalence
    assert_eq!(input, result);
}

#[test]
fn write_ipv4_raw_header_errors() {
    use WriteError::ValueError;
    use ValueError::*;
    use ErrorField::*;
    fn base() -> Ipv4Header {
        Ipv4Header{
            header_length: 10,
            differentiated_services_code_point: 42,
            explicit_congestion_notification: 3,
            total_length: 1234,
            identification: 4321,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 4367,
            time_to_live: 8,
            protocol: 1,
            header_checksum: 2345,
            source: [192, 168, 1, 1],
            destination: [212, 10, 11, 123]
        }
    };

    fn test_write(input: &Ipv4Header) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::new();
        let result = input.write_raw(&mut buffer, &[]);
        assert_eq!(0, buffer.len());
        result
    };
    //header_length
    {
        let result = test_write(&{
            let mut value = base();
            value.header_length = 0x10;
            value
        });
        assert_matches!(result, Err(ValueError(U8TooLarge{value: 0x10, max: 0xf, field: Ipv4HeaderLength})));
    }
    //dscp
    {
        let result = test_write(&{
            let mut value = base();
            value.differentiated_services_code_point = 0x40;
            value
        });
        assert_matches!(result, Err(ValueError(U8TooLarge{value: 0x40, max: 0x3f, field: Ipv4Dscp})));
    }
    //ecn
    {
        let result = test_write(&{
            let mut value = base();
            value.explicit_congestion_notification = 0x4;
            value
        });
        assert_matches!(result, Err(ValueError(U8TooLarge{value: 0x4, max: 0x3, field: Ipv4Ecn})));
    }
    //fragmentation offset
    {
        let result = test_write(&{
            let mut value = base();
            value.fragments_offset = 0x2000;
            value
        });
        assert_matches!(result, Err(ValueError(U16TooLarge{value: 0x2000, max: 0x1FFF, field: Ipv4FragmentsOffset})));
    }
    //options header length (non 4 modulo)
    {
        let mut buffer: Vec<u8> = Vec::new();
        let result = base().write_raw(&mut buffer, &vec![0;44]);
        assert_eq!(0, buffer.len());
        assert_matches!(result, Err(ValueError(Ipv4OptionsLengthBad(44))));
    }
}

#[test]
fn write_ipv4_header() {
    use std::io::Cursor;

    let mut input = Ipv4Header {
        header_length: 0,
        differentiated_services_code_point: 42,
        explicit_congestion_notification: 3,
        total_length: 1234,
        identification: 4321,
        dont_fragment: true,
        more_fragments: false,
        fragments_offset: 4367,
        time_to_live: 8,
        protocol: 1,
        header_checksum: 0,
        source: [192, 168, 1, 1],
        destination: [212, 10, 11, 123]
    };
    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(20);
    input.write(&mut buffer, &[]).unwrap();
    assert_eq!(20, buffer.len());

    //deserialize
    let mut cursor = Cursor::new(&buffer);
    let result = Ipv4Header::read(&mut cursor).unwrap();
    assert_eq!(20, cursor.position());

    //check equivalence (with calculated checksum & header_length)
    input.header_length = 5;
    input.header_checksum = input.calc_header_checksum(&[]).unwrap();
    assert_eq!(input, result);
}

#[test]
fn read_ipv4_error_header() {
    //version error
    {
        let result = Ipv4Header::read(&mut io::Cursor::new(&[0;20]));
        assert_matches!(result, Err(ReadError::Ipv4UnexpectedVersion(0)));
    }
    //io error
    {
        let result = Ipv4Header::read(&mut io::Cursor::new(&[0x40]));
        assert_matches!(result, Err(ReadError::IoError(_)));
    }
    //io error
    {
        let result = Ipv4Header::read(&mut io::Cursor::new(&[0x40;19]));
        assert_matches!(result, Err(ReadError::IoError(_)));
    }
}

#[test]
fn write_ipv4_error_header() {
    let input = Ipv4Header {
        header_length: 0,
        differentiated_services_code_point: 42,
        explicit_congestion_notification: 3,
        total_length: 1234,
        identification: 4321,
        dont_fragment: true,
        more_fragments: false,
        fragments_offset: 4367,
        time_to_live: 8,
        protocol: 1,
        header_checksum: 0,
        source: [192, 168, 1, 1],
        destination: [212, 10, 11, 123]
    };
    //serialize with non mod 4 length options
    {
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        let result = input.write(&mut buffer, &[1,2,3,4,5,6,7]);
        assert_eq!(0, buffer.len());

        use ValueError::Ipv4OptionsLengthBad;
        assert_matches!(result, Err(WriteError::ValueError(Ipv4OptionsLengthBad(7))));
    }
    //serialize with too large options length
    {
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        let result = input.write(&mut buffer, &[0;44]);
        assert_eq!(0, buffer.len());

        use ValueError::Ipv4OptionsLengthBad;
        assert_matches!(result, Err(WriteError::ValueError(Ipv4OptionsLengthBad(44))));
    }
}

#[test]
fn readwrite_ipv6_header() {
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
    //deserialize
    let result = Ipv6Header::read(&mut Cursor::new(&buffer)).unwrap();
    //check equivalence
    assert_eq!(input, result);
}

#[test]
fn write_ipv6_header_errors() {
    use WriteError::ValueError;
    use ValueError::*;
    use ErrorField::*;
    fn base() -> Ipv6Header {
        Ipv6Header {
            traffic_class: 1,
            flow_label: 0x201806,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        }
    };

    fn test_write(input: &Ipv6Header) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer)
    };
    //flow label
    assert_matches!(
        test_write(&{
            let mut value = base();
            value.flow_label = 0x100000;
            value
        }), 
        Err(ValueError(U32TooLarge{value: 0x100000, max: 0xFFFFF, field: Ipv6FlowLabel})));
}

#[test]
fn read_ipv6_error_header() {
    //wrong ip version
    {
        let buffer: [u8;20] = [0;20];
        let result = Ipv6Header::read(&mut io::Cursor::new(&buffer));
        assert_matches!(result, Err(ReadError::Ipv6UnexpectedVersion(0)))
    }
    //io error
    {
        let buffer: [u8;1] = [0x60];
        let result = Ipv6Header::read(&mut io::Cursor::new(&buffer));
        assert_matches!(result, Err(ReadError::IoError(_)));
    }
}

#[test]
fn skip_ipv6_header_extension() {
    use std::io::Cursor;
    {
        let buffer: [u8; 8] = [0;8];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor), Ok(0));
        assert_eq!(8, cursor.position());
    }
    {
        let buffer: [u8; 8*3] = [
            4,2,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor), Ok(4));
        assert_eq!(8*3, cursor.position());
    }
}

#[test]
fn skip_all_ipv6_header_extensions() {
    use io::Cursor;
    //extension header values
    use IpTrafficClass::*;
    //based on RFC 8200 4.1. Extension Header Order
    const EXTENSION_IDS: [u8;7] = [
        IPv6HeaderHopByHop as u8,
        IPv6DestinationOptions as u8,
        IPv6RouteHeader as u8,
        IPv6FragmentationHeader as u8,
        IPv6AuthenticationHeader as u8,
        IPv6EncapSecurityPayload as u8,
        IPv6DestinationOptions as u8
    ];
    const UDP: u8 = Udp as u8;

    //no & single skipping
    {
        let buffer: [u8; 8*3] = [
            UDP,2,0,0, 0,0,0,0, //set next to udp
            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,0,
        ];

        for i_as16 in 0..((u8::max_value() as u16) + 1) {
            let i = i_as16 as u8; //note: I would prefer to use the inclusive range ..= but this feature is not yet marked as stable -> replace when stable
            let mut cursor = Cursor::new(&buffer);
            let result = Ipv6Header::skip_all_header_extensions(&mut cursor, i);

            match EXTENSION_IDS.iter().find(|&&x| x == i) {
                Some(_) => {
                    //ipv6 header extension -> expect skip
                    assert_matches!(result, Ok(UDP));
                    assert_eq!(buffer.len(), cursor.position() as usize);
                },
                None => {
                    //non ipv6 header expect no read movement and direct return
                    assert_matches!(result, Ok(next) => assert_eq!(i, next));
                    assert_eq!(0, cursor.position());
                }
            }
        }

    }
    //skip 7 (max)
    {
        let buffer = vec![
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
            EXTENSION_IDS[2],1,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            EXTENSION_IDS[3],0,0,0, 0,0,0,0,
            EXTENSION_IDS[4],1,0,0, 0,0,0,0,

            0,0,0,0,                0,0,0,0,
            EXTENSION_IDS[5],0,0,0, 0,0,0,0,
            EXTENSION_IDS[6],0,0,0, 0,0,0,0,
            UDP,2,0,0, 0,0,0,0,

            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);

        let result = Ipv6Header::skip_all_header_extensions(&mut cursor, EXTENSION_IDS[0]);
        assert_matches!(result, Ok(UDP));
        assert_eq!(buffer.len(), cursor.position() as usize);
    }
    //trigger "too many" error
    {
        let buffer = vec![
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
            EXTENSION_IDS[2],0,0,0, 0,0,0,0,
            EXTENSION_IDS[3],0,0,0, 0,0,0,0,
            EXTENSION_IDS[4],0,0,0, 0,0,0,0,
            EXTENSION_IDS[5],0,0,0, 0,0,0,0,
            EXTENSION_IDS[6],0,0,0, 0,0,0,0,
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);
        let result = Ipv6Header::skip_all_header_extensions(&mut cursor, EXTENSION_IDS[0]);
        assert_matches!(result, Err(ReadError::Ipv6TooManyHeaderExtensions));
    }
}

#[test]
fn ipv4_set_payload_and_options_length() {
    let mut header = Ipv4Header::new(0, 0, IpTrafficClass::Udp, [0;4], [0;4]).unwrap();

    assert_matches!(header.set_payload_and_options_length(0), Ok(()));
    assert_eq!(header.total_length, 20);

    const MAX: usize = (std::u16::MAX as usize) - Ipv4Header::SERIALIZED_SIZE;
    assert_matches!(header.set_payload_and_options_length(MAX), Ok(()));
    assert_eq!(header.total_length, std::u16::MAX);

    const OVER_MAX: usize = MAX + 1;
    assert_matches!(header.set_payload_and_options_length(OVER_MAX), 
                    Err(ValueError::Ipv4PayloadAndOptionsLengthTooLarge(OVER_MAX)));
}

#[test]
fn ipv6_set_payload_lengt() {
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