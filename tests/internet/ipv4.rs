use super::super::*;
use std::io;
use std::io::Write;
use proptest::prelude::*;

proptest! {
    #[test]
    fn new(source_ip in prop::array::uniform4(any::<u8>()),
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
fn new_error() {
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
fn set_payload_and_options_length() {
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
fn calc_header_checksum() {
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
fn calc_header_checksum_errors() {
    use crate::ValueError::*;
    use crate::ErrorField::*;
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
fn write_raw_errors() {
    use crate::WriteError::ValueError;
    use crate::ValueError::*;
    use crate::ErrorField::*;
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
fn write() {
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
fn read_error() {
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
    use crate::ReadError::*;
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
fn write_error() {
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

        use crate::ValueError::Ipv4OptionsLengthBad;
        assert_matches!(result, Err(WriteError::ValueError(Ipv4OptionsLengthBad(7))));
    }
    //serialize with too large options length
    {
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        let result = input.write(&mut buffer, &[0;44]);
        assert_eq!(0, buffer.len());

        use crate::ValueError::Ipv4OptionsLengthBad;
        assert_matches!(result, Err(WriteError::ValueError(Ipv4OptionsLengthBad(44))));
    }
}


proptest! {
    #[test]
    fn readwrite_header_raw(ref input in ipv4_any())
    {
        use std::io::Cursor;

        //serialize
        let expected_size = Ipv4Header::SERIALIZED_SIZE + input.1.len();
        let mut buffer: Vec<u8> = Vec::with_capacity(expected_size);

        input.0.write_raw(&mut buffer, &[]).unwrap();
        buffer.write(&input.1).unwrap();

        assert_eq!(expected_size, buffer.len());

        //deserialize (read)
        {
            let mut cursor = Cursor::new(&buffer);
            let result = Ipv4Header::read(&mut cursor).unwrap();
            assert_eq!(20, cursor.position());

            //check equivalence
            assert_eq!(input.0, result);
        }

        //deserialize (read_from_slice)
        {
            let result = Ipv4Header::read_from_slice(&buffer).unwrap();
            assert_eq!(input.0, result.0);
            assert_eq!(&buffer[Ipv4Header::SERIALIZED_SIZE..], result.1);
        }

        //check that the slice implementation also reads the correct values
        {
            use std::net::Ipv4Addr;
            let slice = Ipv4HeaderSlice::from_slice(&buffer[..]).unwrap();
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
            assert_eq!(slice.source_addr(), Ipv4Addr::from(input.0.source));
            assert_eq!(slice.destination(), input.0.destination);
            assert_eq!(slice.destination_addr(), Ipv4Addr::from(input.0.destination));

            //check that a convertion back to a header yields the same result as the original write
            assert_eq!(slice.to_header(), input.0);
            assert_eq!(slice.options(), &input.1[..]);
        }
    }
}

#[test]
fn slice_bad_ihl() {
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
    use crate::ReadError::*;
    assert_matches!(Ipv4HeaderSlice::from_slice(&buffer[..]), Err(Ipv4HeaderLengthBad(4)));
}

#[test]
fn slice_bad_version() {
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
    use crate::ReadError::*;
    assert_matches!(Ipv4HeaderSlice::from_slice(&buffer[..]), Err(Ipv4UnexpectedVersion(6)));
}
