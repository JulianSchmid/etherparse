use super::super::*;

#[test]
fn new() {
    let e_icv = [1,2,3,4];
    let a = IpAuthenticationHeader::new(5, 6, 7, &e_icv);
    assert_eq!(5, a.next_header);
    assert_eq!(6, a.spi);
    assert_eq!(7, a.sequence_number);
    assert_eq!(e_icv, a.raw_icv);
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
        input in ip_authentication_any()
    ) {
        let expected = input.to_header();
        let buffer = {
            let mut buffer: Vec<u8> = Vec::new();
            expected.write(&mut buffer).unwrap();
            buffer
        };

        // check slice
        {
            let actual = IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(actual.slice(), &buffer[..]);
            assert_eq!(actual.next_header(), input.next_header);
            assert_eq!(actual.spi(), input.spi);
            assert_eq!(actual.sequence_number(), input.sequence_number);
            assert_eq!(actual.raw_icv(), &input.icv[..]);
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

// write with a bad data lenght (not multiple of 4)
proptest! {
    #[test]
    fn write_non_4_byte_length(
        len_u8 in 2..0xffu8
    ) {
        let icv_base_len = ((len_u8 - 1) as usize)*4;
        let icv_data = vec![0;icv_base_len];
        for offset in 1..4 {
            let header = IpAuthenticationHeader::new(
                0,0,0,&icv_data[..icv_base_len - offset]
            );
            let mut buffer: Vec<u8> = Vec::new();
            assert_eq!(
                header.write(&mut buffer).unwrap_err().value_error().unwrap(),
                ValueError::IpAuthenticationHeaderBadIcvLength(icv_base_len - offset)
            );
        }
    }
}

