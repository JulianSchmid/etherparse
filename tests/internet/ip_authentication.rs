use super::super::*;

use std::io::Cursor;

#[test]
fn new_and_set_icv() {
    use ValueError::*;

    struct Test {
        icv: &'static [u8],
        ok: bool
    }

    let tests = [
        // ok
        Test{ icv: &[], ok: true },
        Test{ icv: &[1,2,3,4], ok: true },
        Test{ icv: &[1,2,3,4,5,6,7,8], ok: true },
        Test{ icv: &[1,2,3,4,5,6,7,8,9,10,11,12], ok: true },
        Test{ icv: &[0;0xfe*4], ok: true },
        // unaligned
        Test{ icv: &[1], ok: false },
        Test{ icv: &[1,2,3], ok: false },
        Test{ icv: &[1,2,3,4,5], ok: false },
        Test{ icv: &[1,2,3,4,5,6,7], ok: false },
        // too big
        Test{ icv: &[0;0xff*4], ok: false },
    ];

    for test in tests.iter() {
        // new
        {
            let a = IpAuthenticationHeader::new(5, 6, 7, test.icv);
            if test.ok {
                let unwrapped = a.unwrap();
                assert_eq!(5, unwrapped.next_header);
                assert_eq!(6, unwrapped.spi);
                assert_eq!(7, unwrapped.sequence_number);
                assert_eq!(test.icv, unwrapped.raw_icv());
            } else {
                assert_eq!(
                    Err(IpAuthenticationHeaderBadIcvLength(test.icv.len())),
                    a
                );
            }
        }
        // set_raw_icv
        {
            let mut header = IpAuthenticationHeader::new(5, 6, 7, &[0;4]).unwrap();
            let result = header.set_raw_icv(test.icv);
            assert_eq!(5, header.next_header);
            assert_eq!(6, header.spi);
            assert_eq!(7, header.sequence_number);
            if test.ok {
                assert_eq!(Ok(()), result);
                assert_eq!(test.icv, header.raw_icv());
            } else {
                assert_eq!(
                    Err(IpAuthenticationHeaderBadIcvLength(test.icv.len())),
                    result
                );
                assert_eq!(&[0;4], header.raw_icv());
            }
        }
    }
}

proptest! {
    #[test]
    fn from_slice_slice_smaller_8(len in 0..8usize) {
        use ReadError::*;

        let data = [0;8];
        assert_matches!(
            IpAuthenticationHeaderSlice::from_slice(&data[..len]),
            Err(UnexpectedEndOfSlice(8))
        );

        assert_matches!(
            IpAuthenticationHeader::read_from_slice(&data[..len]),
            Err(UnexpectedEndOfSlice(8))
        );
    }
}

#[test]
fn from_slice_bad_header_len() {
    use ReadError::*;

    let data = [0;16];
    assert_matches!(
        IpAuthenticationHeaderSlice::from_slice(&data[..]),
        Err(IpAuthenticationHeaderTooSmallPayloadLength(0))
    );

    assert_matches!(
        IpAuthenticationHeader::read_from_slice(&data[..]),
        Err(IpAuthenticationHeaderTooSmallPayloadLength(0))
    );
}

proptest! {
    #[test]
    fn header_len(expected in ip_authentication_any()) {
        assert_eq!(expected.header_len(), expected.raw_icv().len() + 12);
    }
}

proptest! {
    #[test]
    fn write_read(expected in ip_authentication_any()) {
        let buffer = {
            let mut buffer: Vec<u8> = Vec::new();
            expected.write(&mut buffer).unwrap();

            // add some extra data
            buffer.push(1);
            buffer.push(2);

            buffer
        };

        // from_slice
        {
            let actual = IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(actual.slice(), &buffer[..buffer.len()-2]);
            assert_eq!(actual.next_header(), expected.next_header);
            assert_eq!(actual.spi(), expected.spi);
            assert_eq!(actual.sequence_number(), expected.sequence_number);
            assert_eq!(actual.raw_icv(), expected.raw_icv());
            assert_eq!(actual.to_header(), expected);
            // clone and equal check for slice
            assert_eq!(actual.clone(), actual);
        }
        // read_from_slice
        {
            let (actual, rest) = IpAuthenticationHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(rest, &buffer[buffer.len()-2..]);
        }
        // read
        {
            let mut cursor = Cursor::new(&buffer);
            let actual = IpAuthenticationHeader::read(&mut cursor).unwrap();
            assert_eq!(expected, actual);
            assert_eq!(cursor.position(), (buffer.len()-2) as u64);
        }

        // test error when the slice is smaller then the data lenght
        for len in 0..buffer.len()-3 {
            use ReadError::*;
            assert_matches!(
                IpAuthenticationHeader::read_from_slice(&buffer[..len]),
                Err(UnexpectedEndOfSlice(_))
            );
            assert_matches!(
                IpAuthenticationHeaderSlice::from_slice(&buffer[..len]),
                Err(UnexpectedEndOfSlice(_))
            );
            {
                let mut cursor = Cursor::new(&buffer[..len]);
                assert_matches!(
                    IpAuthenticationHeader::read(&mut cursor),
                    Err(IoError(_))
                );
            }
        }
    }
}

/// Test that an IoError is correctly forwarded
#[test]
pub fn write_io_error() {
    let header = IpAuthenticationHeader::new(
        1,
        2,
        3,
        &[4,5,6,7]
    ).unwrap();
    // iterate through all too short lenghts
    for len in 0..header.header_len() {
        let mut writer = TestWriter::with_max_size(len);
        assert_eq!(
            writer.error_kind(),
            header.write(&mut writer).unwrap_err().io_error().unwrap().kind()
        );
    }
}

#[test]
pub fn read_too_small_payload_len() {
    let input = [0u8;16]; // the 2nd
    let mut cursor = Cursor::new(&input);
    assert_matches!(
        IpAuthenticationHeader::read(&mut cursor),
        Err(ReadError::IpAuthenticationHeaderTooSmallPayloadLength(0))
    );
}

/// Dummy test for the clone function
#[test]
pub fn clone() {
    let a = IpAuthenticationHeader::new(0,0,0,&[0;4]);
    assert_eq!(a.clone(), a);
}

#[test]
pub fn partial_eq() {
    let a = IpAuthenticationHeader::new(0,0,0,&[0;4]);
    
    //equal
    assert!(a == IpAuthenticationHeader::new(0,0,0,&[0;4]));

    //not equal tests
    assert!(a != IpAuthenticationHeader::new(1,0,0,&[0;4]));
    assert!(a != IpAuthenticationHeader::new(0,1,0,&[0;4]));
    assert!(a != IpAuthenticationHeader::new(0,0,1,&[0;4]));
    assert!(a != IpAuthenticationHeader::new(0,0,0,&[0,1,0,0]));
    assert!(a != IpAuthenticationHeader::new(0,0,1,&[]));
    assert!(a != IpAuthenticationHeader::new(0,0,1,&[0;8]));
}

proptest! {
    #[test]
    /// Test for the manually implemented debug trait
    fn debug(input in ip_authentication_any()) {
        assert_eq!(
            &format!(
                "IpAuthenticationHeader {{ next_header: {}, spi: {}, sequence_number: {}, raw_icv: {:?} }}",
                input.next_header,
                input.spi,
                input.sequence_number,
                input.raw_icv()),
            &format!("{:?}", input)
        );
    }
}
