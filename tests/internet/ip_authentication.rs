use super::super::*;

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

// read & write
proptest! {
    #[test]
    fn write_read(
        expected in ip_authentication_any()
    ) {
        let buffer = {
            let mut buffer: Vec<u8> = Vec::new();
            expected.write(&mut buffer).unwrap();
            buffer
        };

        // check slice
        {
            let actual = IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(actual.slice(), &buffer[..]);
            assert_eq!(actual.next_header(), expected.next_header);
            assert_eq!(actual.spi(), expected.spi);
            assert_eq!(actual.sequence_number(), expected.sequence_number);
            assert_eq!(actual.raw_icv(), expected.raw_icv());
            assert_eq!(actual.to_header(), expected);
        }
        // check header
        {
            let (actual, rest) = IpAuthenticationHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(rest, &buffer[buffer.len()..]);
        }
        // test with more data then in buffer
        {
            let mut buffer2 = buffer.clone();
            buffer2.push(1);
            buffer2.push(2);
            let (actual, rest) = IpAuthenticationHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(rest, &buffer[buffer2.len()-2..]);
        }

        // test error when the slice is smaller then the data lenght
        use ReadError::*;
        assert_matches!(
            IpAuthenticationHeader::read_from_slice(&buffer[..buffer.len()-1]),
            Err(UnexpectedEndOfSlice(_))
        );
        assert_matches!(
            IpAuthenticationHeaderSlice::from_slice(&buffer[..buffer.len()-1]),
            Err(UnexpectedEndOfSlice(_))
        );
    }
}

