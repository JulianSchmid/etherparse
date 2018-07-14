use etherparse::*;
use std;
use std::io;
use std::io::Write;
use proptest::prelude::*;
use super::super::*;

proptest! {
    #[test]
    fn ipv4_new(source_ip in prop::array::uniform4(any::<u8>()),
                dest_ip in prop::array::uniform4(any::<u8>()),
                ttl in any::<u8>(),
                payload_and_options_length in 0u16..(std::u16::MAX - 20))
    {
        let result = Ipv4Header::new(payload_and_options_length as usize, 
                                     ttl, 
                                     IpTrafficClass::Udp, 
                                     source_ip, 
                                     dest_ip);
        assert_eq!(Ipv4Header {
            header_length: 0,
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            total_length: payload_and_options_length + 20,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live: ttl,
            protocol: IpTrafficClass::Udp as u8,
            header_checksum: 0,
            source: source_ip,
            destination: dest_ip
        }, result.unwrap());
    }
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
}

#[test]
fn ipv4_calc_header_checksum_errors() {
    use ValueError::*;
    use ErrorField::*;
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

proptest! {
    #[test]
    fn readwrite_ipv4_header_raw(ref input in ipv4_any())
    {
        use std::io::Cursor;

        //serialize
        let expected_size = Ipv4Header::SERIALIZED_SIZE + input.1.len();
        let mut buffer: Vec<u8> = Vec::with_capacity(expected_size);

        input.0.write_raw(&mut buffer, &[]).unwrap();
        buffer.write(&input.1).unwrap();

        assert_eq!(expected_size, buffer.len());

        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = Ipv4Header::read(&mut cursor).unwrap();
        assert_eq!(20, cursor.position());

        //check equivalence
        assert_eq!(input.0, result);

        //check that the slice implementation also reads the correct values
        let slice = PacketSlice::<Ipv4Header>::from_slice(&buffer[..]).unwrap();
        assert_eq!(slice.version(), 4);
        assert_eq!(slice.ihl(), input.0.header_length);
        assert_eq!(slice.dcp(), input.0.differentiated_services_code_point);
        assert_eq!(slice.ecn(), input.0.explicit_congestion_notification);
        assert_eq!(slice.total_length(), input.0.total_length);
        assert_eq!(slice.identification(), input.0.identification);
        assert_eq!(slice.dont_fragment(), input.0.dont_fragment);
        assert_eq!(slice.more_fragments(), input.0.more_fragments);
        assert_eq!(slice.fragments_offset(), input.0.fragments_offset);
        assert_eq!(slice.ttl(), input.0.time_to_live);
        assert_eq!(slice.protocol(), input.0.protocol);
        assert_eq!(slice.header_checksum(), input.0.header_checksum);
        assert_eq!(slice.source(), input.0.source);
        assert_eq!(slice.destination(), input.0.destination);

        //check that a convertion back to a header yields the same result as the original write
        assert_eq!(slice.to_header(), input.0);
        assert_eq!(slice.options(), &input.1[..]);
    }
}

#[test]
fn ipv4_slice_bad_ihl() {
    let input = Ipv4Header {
        header_length:4,
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
    
    //check that the bad ihl results in an error
    use ReadError::*;
    assert_matches!(PacketSlice::<Ipv4Header>::from_slice(&buffer[..]), Err(Ipv4HeaderLengthBad(4)));
}

#[test]
fn ipv4_slice_bad_version() {
    //write an ipv6 header to ensure that the version field is checked
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
    
    //check that the bad ihl results in an error
    use ReadError::*;
    assert_matches!(PacketSlice::<Ipv4Header>::from_slice(&buffer[..]), Err(Ipv4UnexpectedVersion(6)));
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
fn skip_options() {
    let header_with_length = |header_length: u8| {
        Ipv4Header {
            header_length: header_length,
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
        }
    };

    //error: header length too small
    use std::io::Cursor;
    use ReadError::*;
    {
        let mut cursor = Cursor::new(Vec::new());
        assert_matches!(header_with_length(0).skip_options(&mut cursor), 
                        Err(Ipv4HeaderLengthBad(0)));
    }
    {
        let mut cursor = Cursor::new(Vec::new());
        assert_matches!(header_with_length(4).skip_options(&mut cursor), 
                        Err(Ipv4HeaderLengthBad(4)));
    }
    //no options
    {
        let mut cursor = Cursor::new(Vec::new());
        assert_matches!(header_with_length(5).skip_options(&mut cursor), 
                        Ok(()));
    }
    //out of bounds exception (no data)
    {
        let mut cursor = Cursor::new(Vec::new());
        assert_matches!(header_with_length(6).skip_options(&mut cursor), 
                        Err(IoError(_)));
    }
    //out of bounds exception (1 byte)
    {
        let mut cursor = Cursor::new(&[0;11]);
        assert_matches!(header_with_length(8).skip_options(&mut cursor), 
                        Err(IoError(_)));
    }
    //ok with 12 bytes
    {
        let mut cursor = Cursor::new(&[0;12]);
        assert_matches!(header_with_length(8).skip_options(&mut cursor), 
                        Ok(()));
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

    const HOP_BY_HOP: u8 = IpTrafficClass::IPv6HeaderHopByHop as u8;
    const ROUTE: u8 = IpTrafficClass::IPv6RouteHeader as u8;
    const FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;

    use std::io::Cursor;
    {
        let buffer: [u8; 8] = [0;8];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, HOP_BY_HOP), Ok(0));
        assert_eq!(8, cursor.position());
    }
    {
        let buffer: [u8; 8*3] = [
            4,2,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, ROUTE), Ok(4));
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
        assert_matches!(Ipv6Header::skip_header_extension(&mut cursor, FRAG), Ok(4));
        assert_eq!(8, cursor.position());
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
        IPv6FragmentationHeader as u8, //3
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
                    if i == IPv6FragmentationHeader as u8 {
                        //fragmentation header has a fixed size
                        assert_eq!(8, cursor.position() as usize);
                    } else {
                        assert_eq!(buffer.len(), cursor.position() as usize);
                    }
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
            EXTENSION_IDS[3],2,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            0,0,0,0,                0,0,0,0,
            //fragmentation header (fixed size 8 bytes)
            EXTENSION_IDS[4],5,0,0, 0,0,0,0,
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
            //fragmentation header (fixed size 8 bytes)
            EXTENSION_IDS[4],4,0,0, 0,0,0,0,
            EXTENSION_IDS[5],0,0,0, 0,0,0,0,
            EXTENSION_IDS[6],0,0,0, 0,0,0,0,
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
        ];
        let mut cursor = Cursor::new(&buffer);
        let result = Ipv6Header::skip_all_header_extensions(&mut cursor, EXTENSION_IDS[0]);
        assert_matches!(result, Err(ReadError::Ipv6TooManyHeaderExtensions));
    }
    //trigger missing unexpected eof
    {
        let buffer = vec![
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
            EXTENSION_IDS[2],1,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            EXTENSION_IDS[3],2,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            0,0,0,0,                0,0,0,0,
            //fragmentation header (fixed size 8 bytes)
            EXTENSION_IDS[4],5,0,0, 0,0,0,0,
            EXTENSION_IDS[5],0,0,0, 0,0,0,0,
            EXTENSION_IDS[6],0,0,0, 0,0,0,0,
            UDP,2,0,0, 0,0,0,0,

            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0
        ];
        println!("buffer.len(). {}", buffer.len());
        let mut cursor = Cursor::new(&buffer);
        let result = Ipv6Header::skip_all_header_extensions(&mut cursor, EXTENSION_IDS[0]);
        assert_matches!(result, Err(ReadError::IoError(_)));
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

proptest! {
    #[test]
    fn ipv6_from_slice(ref input in ipv6_any()) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer).unwrap();

        //check that a too small slice triggers an error
        assert_matches!(PacketSlice::<Ipv6Header>::from_slice(&buffer[..buffer.len()-1]), Err(ReadError::IoError(_)));

        //check that all the values are read correctly
        use std::net::Ipv6Addr;
        let slice = PacketSlice::<Ipv6Header>::from_slice(&buffer).unwrap();
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

        //check that the convertion back to a header struct results in the same struct
        assert_eq!(&slice.to_header(), input);
    }
}

#[test]
fn ipv6_from_slice_bad_version() {
    //write an ipv4 header and check that the bad version number is detected
    let input = Ipv4Header {
        header_length:4,
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
    input.write_raw(&mut buffer, &[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]).unwrap();

    //check that the unexpected version id is detected
    use ReadError::*;
    assert_matches!(PacketSlice::<Ipv6Header>::from_slice(&buffer[..]), Err(Ipv6UnexpectedVersion(4)));
}

#[test]
fn ipv6_extension_from_slice() {
    //extension header values
    use IpTrafficClass::*;
    const FRAG: u8 = IPv6FragmentationHeader as u8;
    const UDP: u8 = Udp as u8;
    let buffer: [u8; 8*3] = [
        UDP,2,0,0, 0,0,0,0, //set next to udp
        0,0,0,0,   0,0,0,0,
        0,0,0,0,   0,0,0,0,
    ];
    //fragmentation header
    {
        let slice = PacketSlice::<Ipv6ExtensionHeader>::from_slice(FRAG, &buffer).unwrap();
        assert_eq!(slice.next_header(), UDP);
        assert_eq!(slice.slice, &buffer[..8])
    }
    //other headers (using length field)
    {
        const EXTENSION_IDS_WITH_LENGTH: [u8;5] = [
            IPv6HeaderHopByHop as u8,
            IPv6DestinationOptions as u8,
            IPv6RouteHeader as u8,
            IPv6AuthenticationHeader as u8,
            IPv6EncapSecurityPayload as u8
        ];
        for id in EXTENSION_IDS_WITH_LENGTH.iter() {
            let slice = PacketSlice::<Ipv6ExtensionHeader>::from_slice(*id, &buffer).unwrap();
            assert_eq!(slice.next_header(), UDP);
            assert_eq!(slice.slice, &buffer[..])
        }
    }
}

#[test]
fn ipv6_extension_from_slice_bad_length() {
    //extension header values
    use IpTrafficClass::*;
    const FRAG: u8 = IPv6FragmentationHeader as u8;
    const UDP: u8 = Udp as u8;
    //all extension headers that use the length field
    const EXTENSION_IDS_WITH_LENGTH: [u8;5] = [
        IPv6HeaderHopByHop as u8,
        IPv6DestinationOptions as u8,
        IPv6RouteHeader as u8,
        IPv6AuthenticationHeader as u8,
        IPv6EncapSecurityPayload as u8
    ];

    //smaller then minimum extension header size (8 bytes)
    {
        let buffer: [u8; 7] = [
            UDP,2,0,0, 0,0,0
        ];
        assert_matches!(PacketSlice::<Ipv6ExtensionHeader>::from_slice(FRAG, &buffer), Err(_));
    }
    //smaller then specified size by length field
    {
        let buffer: [u8; 8*3-1] = [
            UDP,2,0,0, 0,0,0,0,
            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,
        ];
        //fragmentation header (should not trigger an error, as the length field is not used)
        {
            let slice = PacketSlice::<Ipv6ExtensionHeader>::from_slice(FRAG, &buffer).unwrap();
            assert_eq!(slice.next_header(), UDP);
            assert_eq!(slice.slice, &buffer[..8])
        }
        //all others should generate a range error
        for id in EXTENSION_IDS_WITH_LENGTH.iter() {
            let slice = PacketSlice::<Ipv6ExtensionHeader>::from_slice(*id, &buffer);
            assert_matches!(slice, Err(_));
        }
    }
}
