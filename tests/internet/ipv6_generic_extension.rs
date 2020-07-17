use super::super::*;

#[test]
fn header_new_raw_and_set_payload() {
    use ValueError::*;
    struct Test {
        payload: &'static [u8],
        expected: Result<(),ValueError>
    }

    let tests = [
        // ok
        Test{payload: &[1,2,3,4,5,6], expected: Ok(()) },
        Test{payload: &[1,2,3,4,5,6,7,8,9,10,11,12,13,14], expected: Ok(()) },
        Test{payload: &[0;0xff*8 + 6], expected: Ok(()) },
        // too small
        Test{payload: &[1,2,3,4,5], expected: Err(Ipv6ExtensionPayloadTooSmall(5)) },
        Test{payload: &[1,2,3,4], expected: Err(Ipv6ExtensionPayloadTooSmall(4)) },
        Test{payload: &[1], expected: Err(Ipv6ExtensionPayloadTooSmall(1)) },
        Test{payload: &[], expected: Err(Ipv6ExtensionPayloadTooSmall(0)) },
        // too large
        Test{payload: &[0;0xff*8 + 7], expected: Err(Ipv6ExtensionPayloadTooLarge(0xff*8 + 7)) },
    ];

    for test in tests.iter() {
        // new_raw
        {
            let actual = Ipv6GenericExtensionHeader::new_raw(123, test.payload);
            match &test.expected {
                Ok(_) => {
                    let unpacked = actual.unwrap();
                    assert_eq!(123, unpacked.next_header);
                    assert_eq!(&test.payload[..], unpacked.payload());
                },
                Err(err) => {
                    assert_eq!(Err(err.clone()), actual);
                }
            }
        }
        // set payload
        {
            let mut header = Ipv6GenericExtensionHeader::new_raw(123, &[0;6]).unwrap();
            let result = header.set_payload(test.payload);
            match &test.expected {
                Ok(_) => {
                    assert_eq!(Ok(()), result);
                    assert_eq!(test.payload, header.payload());
                },
                Err(err) => {
                    assert_eq!(Err(err.clone()), result);
                    assert_eq!(&[0;6], header.payload());
                }
            }
        }
    }

    // unaligment errors
    {
        let payload = [0;23];
        for i in 7..=23 {
            if 0 != (i - 6) % 8 {
                assert_eq!(
                    Err(Ipv6ExtensionPayloadLengthUnaligned(i)),
                    Ipv6GenericExtensionHeader::new_raw(123, &payload[..i])
                );
                {
                    let mut header = Ipv6GenericExtensionHeader::new_raw(123, &[0;6]).unwrap();
                    assert_eq!(
                        Err(Ipv6ExtensionPayloadLengthUnaligned(i)),
                        header.set_payload(&payload[..i])
                    );
                    assert_eq!(&[0;6], header.payload());
                }
            }
        }
    }
}

#[test]
fn slice_from_slice() {

    // base test
    let data = {
        let mut data = [0;6*8];
        data[0] = 1; // next header type
        data[1] = 4; // header length
        data
    };
    let actual = Ipv6GenericExtensionHeaderSlice::from_slice(&data).unwrap();
    assert_eq!(1, actual.next_header());
    assert_eq!(
        &data[..5*8],
        actual.slice()
    );
    assert_eq!(
        &data[2..5*8],
        actual.payload()
    );

    {
        let header = actual.to_header();
        assert_eq!(1, header.next_header);
        assert_eq!(&data[2..5*8], header.payload());
    }
}

#[test]
fn slice_from_slice_error() {
    // errors:
    // length smaller then 8
    {
        assert_matches!(
            Ipv6GenericExtensionHeaderSlice::from_slice(&[0;7]),
            Err(ReadError::UnexpectedEndOfSlice(8))
        );
    }
    // length smaller then spezified size
    {
        let data = {
            let mut data: [u8;4*8 - 1] = [0;4*8 - 1];
            // set length field
            data[1] = 3;
            data
        };
        assert_matches!(
            Ipv6GenericExtensionHeaderSlice::from_slice(&data),
            Err(ReadError::UnexpectedEndOfSlice(32))
        );
    }
}

#[test]
fn extension_from_slice_bad_length() {
    use crate::IpTrafficClass::*;
    use self::ReadError::*;
    const UDP: u8 = Udp as u8;

    //smaller then minimum extension header size (8 bytes)
    {
        let buffer: [u8; 7] = [
            UDP,2,0,0, 0,0,0
        ];
        assert_matches!(Ipv6GenericExtensionHeaderSlice::from_slice(&buffer), 
                        Err(UnexpectedEndOfSlice(8)));
    }
    //smaller then specified size by length field
    {
        let buffer: [u8; 8*3-1] = [
            UDP,2,0,0, 0,0,0,0,
            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,
        ];
        // should generate an error
        let slice = Ipv6GenericExtensionHeaderSlice::from_slice(&buffer);
        assert_matches!(slice, Err(UnexpectedEndOfSlice(_)));
    }
}

#[test]
fn header_type_supported() {
    use crate::IpTrafficClass::*;
    const HOP_BY_HOP: u8 = IPv6HeaderHopByHop as u8;
    const ROUTE: u8 = IPv6RouteHeader as u8;
    const OPTIONS: u8 = IPv6DestinationOptions as u8;
    const MOBILITY: u8 = MobilityHeader as u8;
    const HIP: u8 = Hip as u8;
    const SHIM6: u8 = Shim6 as u8;

    for i in 0..0xffu8 {
        let expected = match i {
            HOP_BY_HOP | ROUTE | OPTIONS | MOBILITY | HIP | SHIM6 => true,
            _ => false
        };
        assert_eq!(expected, Ipv6GenericExtensionHeader::header_type_supported(i));
        assert_eq!(expected, Ipv6GenericExtensionHeaderSlice::header_type_supported(i));
    }
}

#[test]
fn write_and_read() {
    let lengths: [usize;4] = [6, 14, 22, 30];
    let payload: [u8;30] = [
               1, 2, 3, 4, 5, 6,
         7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,
        23,24,25,26,27,28,29,30,
    ];

    for l in lengths.iter() {
        let input = Ipv6GenericExtensionHeader::new_raw(123, &payload[..*l]).unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        input.write(&mut buffer).unwrap();
        // add some dummy data to check the slice length
        buffer.push(0);
        buffer.push(1);

        {
            let actual = Ipv6GenericExtensionHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(123, actual.next_header());
            assert_eq!(&payload[..*l], actual.payload());
        }
        {
            let actual = Ipv6GenericExtensionHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(123, actual.0.next_header);
            assert_eq!(&payload[..*l], actual.0.payload());
            assert_eq!(&buffer[*l + 2..], actual.1);
        }
    }
}