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

    assert_matches!(result, IpHeader::Version6(INPUT));
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
fn read_error() {
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
fn skip_extension() {

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
fn skip_all_extensions() {
    use crate::io::Cursor;
    //extension header values
    use crate::IpTrafficClass::*;
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
fn extension_from_slice() {
    //extension header values
    use crate::IpTrafficClass::*;
    const FRAG: u8 = IPv6FragmentationHeader as u8;
    const UDP: u8 = Udp as u8;
    let buffer: [u8; 8*3] = [
        UDP,2,0,0, 0,0,0,0, //set next to udp
        0,0,0,0,   0,0,0,0,
        0,0,0,0,   0,0,0,0,
    ];
    //fragmentation header
    {
        let slice = Ipv6ExtensionHeaderSlice::from_slice(FRAG, &buffer).unwrap();
        assert_eq!(slice.next_header(), UDP);
        assert_eq!(slice.slice(), &buffer[..8])
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
            let slice = Ipv6ExtensionHeaderSlice::from_slice(*id, &buffer).unwrap();
            assert_eq!(slice.next_header(), UDP);
            assert_eq!(slice.slice(), &buffer[..])
        }
    }
}

#[test]
fn extension_from_slice_bad_length() {
    //extension header values
    use crate::IpTrafficClass::*;
    use self::ReadError::*;
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
        assert_matches!(Ipv6ExtensionHeaderSlice::from_slice(FRAG, &buffer), 
                        Err(UnexpectedEndOfSlice(8)));
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
            let slice = Ipv6ExtensionHeaderSlice::from_slice(FRAG, &buffer).unwrap();
            assert_eq!(slice.next_header(), UDP);
            assert_eq!(slice.slice(), &buffer[..8])
        }
        //all others should generate a range error
        for id in EXTENSION_IDS_WITH_LENGTH.iter() {
            let slice = Ipv6ExtensionHeaderSlice::from_slice(*id, &buffer);
            assert_matches!(slice, Err(UnexpectedEndOfSlice(_)));
        }
    }
}
