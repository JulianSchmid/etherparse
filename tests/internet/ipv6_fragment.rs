use super::super::*;

use std::io::{Cursor, ErrorKind};

pub mod header {
    use super::*;

    proptest! {
        #[test]
        fn new(
            next_header in any::<u8>(),
            fragment_offset in any::<u16>(),
            more_fragments in any::<bool>(),
            identification in any::<u32>(),
        ) {
            let a = Ipv6FragmentHeader::new(
                next_header,
                fragment_offset,
                more_fragments,
                identification
            );
            assert_eq!(next_header, a.next_header);
            assert_eq!(fragment_offset, a.fragment_offset);
            assert_eq!(more_fragments, a.more_fragments);
            assert_eq!(identification, a.identification);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            input in ipv6_fragment_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let (result, rest) = Ipv6FragmentHeader::from_slice(&buffer[..]).unwrap();
                assert_eq!(input, result);
                assert_eq!(&buffer[8..], rest);
            }
            // call with not enough data in the slice
            for len in 0..=7 {
                assert_matches!(
                    Ipv6FragmentHeader::from_slice(&buffer[0..len]),
                    Err(ReadError::UnexpectedEndOfSlice(_))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn read(
            input in ipv6_fragment_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let mut cursor = Cursor::new(&buffer);
                let result = Ipv6FragmentHeader::read(&mut cursor).unwrap();
                assert_eq!(input, result);
                assert_eq!(cursor.position(), 8);
            }
            // call with not enough data in the slice
            for len in 0..=7 {
                let mut cursor = Cursor::new(&buffer[0..len]);
                assert_eq!(
                    Ipv6FragmentHeader::read(&mut cursor)
                    .unwrap_err()
                    .io_error()
                    .unwrap()
                    .kind(),
                    ErrorKind::UnexpectedEof
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write(input in ipv6_fragment_any()) {

            // normal write
            {
                let mut buffer = Vec::with_capacity(8);
                input.write(&mut buffer).unwrap();
                assert_eq!(
                    &buffer,
                    &input.to_bytes().unwrap()
                );
            }

            // too big fragment offset
            for i in 0b001..=0b111u16 {
                use crate::ValueError::*;
                use crate::ErrorField::*;

                let fragment_offset = input.fragment_offset | (i << 13);

                let input_with_bad_frag_off = {
                    let mut re = input.clone();
                    re.fragment_offset = fragment_offset;
                    re
                };

                let mut buffer = Vec::with_capacity(8);
                assert_eq!(
                    input_with_bad_frag_off
                        .write(&mut buffer)
                        .unwrap_err()
                        .value_error()
                        .unwrap(),
                    U16TooLarge{
                        value: fragment_offset,
                        max: 0b0001_1111_1111_1111,
                        field: Ipv6FragmentOffset
                    }
                );
            }

            // not enough memory for write
            for len in 0..8 {
                let mut writer = TestWriter::with_max_size(len);
                assert_eq!(
                    ErrorKind::UnexpectedEof,
                    input.write(&mut writer).unwrap_err().io_error().unwrap().kind()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(input in ipv6_fragment_any()) {
            assert_eq!(8, input.header_len());
        }
    }

    proptest!{
        #[test]
        fn is_fragmenting_payload(
            non_zero_offset in 1u16..0b0001_1111_1111_1111u16,
            identification in any::<u32>(),
            next_header in any::<u8>(),

        ) {
            // negative case
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: 0,
                    more_fragments: false,
                    identification
                };
                assert!(false == header.is_fragmenting_payload());
            }
            // positive case (non zero offset)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: non_zero_offset,
                    more_fragments: false,
                    identification
                };
                assert!(header.is_fragmenting_payload());
            }

            // positive case (more fragments)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: 0,
                    more_fragments: true,
                    identification
                };
                assert!(header.is_fragmenting_payload());
            }

            // positive case (non zero offset & more fragments)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: non_zero_offset,
                    more_fragments: true,
                    identification
                };
                assert!(header.is_fragmenting_payload());
            }
        }
    }

    proptest! {
        #[test]
        fn to_bytes(input in ipv6_fragment_any()) {

            // normal write
            {
                let fragment_offset_be = input.fragment_offset.to_be_bytes();
                let id_be = input.identification.to_be_bytes();
                assert_eq!(
                    &input.to_bytes().unwrap(),
                    &[
                        input.next_header,
                        0,
                        (
                            (fragment_offset_be[0] << 3 & 0b1111_1000u8) |
                            (fragment_offset_be[1] >> 5 & 0b0000_0111u8)
                        ),
                        (
                            (fragment_offset_be[1] & 0b0001_1111u8) |
                            if input.more_fragments {
                                0b1000_0000u8
                            } else {
                                0u8
                            }
                        ),
                        id_be[0],
                        id_be[1],
                        id_be[2],
                        id_be[3],
                    ]
                );
            }

            // too big fragment offset
            for i in 0b001..=0b111u16 {
                use crate::ValueError::*;
                use crate::ErrorField::*;

                let fragment_offset = input.fragment_offset | (i << 13);

                let input_with_bad_frag_off = {
                    let mut re = input.clone();
                    re.fragment_offset = fragment_offset;
                    re
                };

                assert_eq!(
                    input_with_bad_frag_off
                        .to_bytes()
                        .unwrap_err(),
                    U16TooLarge{
                        value: fragment_offset,
                        max: 0b0001_1111_1111_1111,
                        field: Ipv6FragmentOffset
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn dbg(input in ipv6_fragment_any()) {
            assert_eq!(
                &format!(
                    "Ipv6FragmentHeader {{ next_header: {}, fragment_offset: {}, more_fragments: {}, identification: {} }}",
                    input.next_header,
                    input.fragment_offset,
                    input.more_fragments,
                    input.identification
                ),
                &format!("{:?}", input)
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in ipv6_fragment_any()) {
            assert_eq!(input, input.clone());
        }
    }
}

pub mod slice {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(
            input in ipv6_fragment_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(slice.slice(), &buffer[..8]);
            }

            // call with not enough data in the slice
            for len in 0..=7 {
                assert_matches!(
                    Ipv6FragmentHeaderSlice::from_slice(&buffer[0..len])
                        .unwrap_err()
                        .unexpected_end_of_slice_min_expected_size()
                        .unwrap(),
                    8
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_slice_unchecked(
            input in ipv6_fragment_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
                        // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            unsafe {
                let slice = Ipv6FragmentHeaderSlice::from_slice_unchecked(&buffer[..]);
                assert_eq!(slice.slice(), &buffer[..8]);
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in ipv6_fragment_any()) {
            let buffer = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(input.next_header, slice.next_header());
            assert_eq!(input.fragment_offset, slice.fragment_offset());
            assert_eq!(input.more_fragments, slice.more_fragments());
            assert_eq!(input.identification, slice.identification());
        }
    }

    proptest! {
        #[test]
        fn is_fragmenting_payload(
            non_zero_offset in 1u16..0b0001_1111_1111_1111u16,
            identification in any::<u32>(),
            next_header in any::<u8>(),
        ) {
            // negative case
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: 0,
                    more_fragments: false,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(false == slice.is_fragmenting_payload());
            }
            // positive case (non zero offset)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: non_zero_offset,
                    more_fragments: false,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(slice.is_fragmenting_payload());
            }

            // positive case (more fragments)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: 0,
                    more_fragments: true,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(slice.is_fragmenting_payload());
            }

            // positive case (non zero offset & more fragments)
            {
                let header = Ipv6FragmentHeader {
                    next_header,
                    fragment_offset: non_zero_offset,
                    more_fragments: true,
                    identification
                };
                // slice
                let buffer = header.to_bytes().unwrap();
                let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
                assert!(slice.is_fragmenting_payload());
            }
        }
    }

    proptest! {
        #[test]
        fn to_header(input in ipv6_fragment_any()) {
            let buffer = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in ipv6_fragment_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(
                &bytes
            ).unwrap();
            assert_eq!(
                &format!(
                    "Ipv6FragmentHeaderSlice {{ slice: {:?} }}",
                    slice.slice()
                ),
                &format!("{:?}", slice)
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in ipv6_fragment_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(
                &bytes
            ).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }
}
