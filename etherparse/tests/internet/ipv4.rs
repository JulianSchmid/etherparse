use super::super::*;
use proptest::prelude::*;
use std::io::Cursor;


mod slice {
    use super::*;

    #[test]
    fn is_fragmenting_payload() {
        // not fragmenting
        {
            let buffer = {
                let mut header: Ipv4Header = Default::default();
                header.fragments_offset = 0;
                header.more_fragments = false;
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(false, slice.is_fragmenting_payload());
        }

        // fragmenting based on offset
        {
            let buffer = {
                let mut header: Ipv4Header = Default::default();
                header.fragments_offset = 1;
                header.more_fragments = false;
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert!(slice.is_fragmenting_payload());
        }

        // fragmenting based on more_fragments
        {
            let buffer = {
                let mut header: Ipv4Header = Default::default();
                header.fragments_offset = 0;
                header.more_fragments = true;
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };
            let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
            assert!(slice.is_fragmenting_payload());
        }
    }
}

#[test]
fn range_errors() {
    use crate::ErrorField::*;
    use crate::ValueError::*;

    fn test_range_methods(input: &Ipv4Header, expected: ValueError) {
        //check_ranges
        assert_eq!(expected.clone(), input.calc_header_checksum().unwrap_err());
        //write
        {
            let mut buffer: Vec<u8> = Vec::new();
            let result = input.write(&mut buffer);
            assert_eq!(0, buffer.len());
            assert_eq!(Some(expected.clone()), result.unwrap_err().value_error());
        }
        //write_raw
        {
            let mut buffer: Vec<u8> = Vec::new();
            let result = input.write_raw(&mut buffer);
            assert_eq!(0, buffer.len());
            assert_eq!(Some(expected.clone()), result.unwrap_err().value_error());
        }
    }
    //dscp
    {
        let value = {
            let mut value: Ipv4Header = Default::default();
            value.differentiated_services_code_point = 0x40;
            value
        };
        test_range_methods(
            &value,
            U8TooLarge {
                value: 0x40,
                max: 0x3f,
                field: Ipv4Dscp,
            },
        );
    }
    //ecn
    {
        let value = {
            let mut value: Ipv4Header = Default::default();
            value.explicit_congestion_notification = 0x4;
            value
        };
        test_range_methods(
            &value,
            U8TooLarge {
                value: 0x4,
                max: 0x3,
                field: Ipv4Ecn,
            },
        );
    }
    //fragmentation offset
    {
        let value = {
            let mut value: Ipv4Header = Default::default();
            value.fragments_offset = 0x2000;
            value
        };
        test_range_methods(
            &value,
            U16TooLarge {
                value: 0x2000,
                max: 0x1FFF,
                field: Ipv4FragmentsOffset,
            },
        );
    }
    //payload len
    {
        const MAX_PAYLOAD_LEN: u16 = std::u16::MAX - (Ipv4Header::LEN_MIN as u16) - 8;

        let value = {
            let mut value: Ipv4Header = Default::default();
            value.set_options(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
            value.payload_len = MAX_PAYLOAD_LEN + 1;
            value
        };
        test_range_methods(
            &value,
            U16TooLarge {
                value: MAX_PAYLOAD_LEN + 1,
                max: MAX_PAYLOAD_LEN,
                field: Ipv4PayloadLength,
            },
        );
    }
}

proptest! {
    #[test]
    fn read_errors(ref header in ipv4_any()) {
        use crate::err::ipv4::HeaderError::*;
        use crate::err::ipv4::HeaderSliceError::Content;

        // non matching version
        for version in 0..0xf {
            if 4 != version {
                let buffer = {
                    let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
                    header.write(&mut buffer).unwrap();

                    //change the ihl
                    buffer[0] = (version << 4) | (buffer[0] & 0xf); //version + ihl
                    buffer
                };

                let expected = UnexpectedVersion{
                    version_number: version,
                };

                // read
                assert_eq!(
                    Ipv4Header::read(&mut Cursor::new(&buffer))
                        .unwrap_err()
                        .content_error()
                        .unwrap(),
                    expected.clone()
                );

                // from_slice
                assert_eq!(
                    Ipv4Header::from_slice(&buffer).unwrap_err(),
                    Content(expected.clone())
                );

                // from_slice
                assert_eq!(
                    Ipv4HeaderSlice::from_slice(&buffer).unwrap_err(),
                    Content(expected.clone())
                );
            }
        }

        //bad ihl (smaller then 5)
        for ihl in 0..5 {
            let buffer = {
                let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();

                //change the ihl
                buffer[0] = (4 << 4) | ihl; //version + ihl
                buffer
            };

            let expected = HeaderLengthSmallerThanHeader{ ihl };

            // read
            assert_eq!(
                Ipv4Header::read(&mut Cursor::new(&buffer)).unwrap_err().content_error(),
                Some(expected.clone())
            );

            // read_without_version
            assert_eq!(
                Ipv4Header::read_without_version(
                    &mut Cursor::new(&buffer[1..]),
                    buffer[0] & 0xf
                ).unwrap_err().content_error(),
                Some(expected.clone())
            );

            // from_slice
            assert_eq!(
                Ipv4Header::from_slice(&buffer).unwrap_err(),
                Content(expected.clone())
            );

            // from_slice
            assert_eq!(
                Ipv4HeaderSlice::from_slice(&buffer).unwrap_err(),
                Content(expected.clone())
            );
        }

        //bad total_length
        for total_length in 0..header.header_len() {

            let buffer = {
                let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                //change the total length to be smaller then the header length
                let total_len_be = (total_length as u16).to_be_bytes();
                buffer[2] = total_len_be[0];
                buffer[3] = total_len_be[1];
                buffer
            };

            let expected = TotalLengthSmallerThanHeader{
                total_length: total_length as u16,
                min_expected_length: header.header_len() as u16,
            };

            // read
            assert_eq!(
                Ipv4Header::read(&mut Cursor::new(&buffer)).unwrap_err().content_error(),
                Some(expected.clone())
            );

            // read_without_version
            assert_eq!(
                Ipv4Header::read_without_version(
                    &mut Cursor::new(&buffer[1..]),
                    buffer[0] & 0xf
                ).unwrap_err().content_error(),
                Some(expected.clone())
            );

            // from_slice
            assert_eq!(
                Ipv4Header::from_slice(&buffer).unwrap_err(),
                Content(expected.clone())
            );

            // from_slice
            assert_eq!(
                Ipv4HeaderSlice::from_slice(&buffer).unwrap_err(),
                Content(expected.clone())
            );
        }

        //io error (bad slice length)
        {
            let buffer = {
                // create a header with some options (so a lenght check can fail there)
                let header = {
                    let mut header: Ipv4Header = Default::default();
                    header.set_options(&[1,2,3,4]).unwrap();
                    header
                };

                // serialize to buffer
                let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                buffer
            };

            // check that all too small lenghts trigger an error
            for len in 0..buffer.len() {
                // read
                assert!(
                    Ipv4Header::read(&mut Cursor::new(&buffer[..len]))
                        .unwrap_err()
                        .io_error()
                        .is_some()
                );

                // read_without_version
                if len > 0 {
                    assert!(
                        Ipv4Header::read_without_version(
                            &mut Cursor::new(&buffer[1..len]),
                            buffer[0] & 0xf
                        ).unwrap_err()
                        .io_error()
                        .is_some()
                    );
                }

                // from_slice
                use err::ipv4::HeaderSliceError::UnexpectedEndOfSlice;
                let expected_ueos = UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError{
                    expected_min_len: if len < Ipv4Header::LEN_MIN {
                        Ipv4Header::LEN_MIN
                    } else {
                        buffer.len()
                    },
                    actual_len: len,
                    layer: err::Layer::Ipv4Header
                });

                assert_eq!(
                    Ipv4Header::from_slice(&buffer[..len]).unwrap_err(),
                    expected_ueos.clone()
                );

                // from_slice
                assert_eq!(
                    Ipv4HeaderSlice::from_slice(&buffer[..len]).unwrap_err(),
                    expected_ueos.clone()
                );
            }
        }
    }
}

proptest! {
    #[test]
    fn readwrite_header_raw(ref input in ipv4_any())
    {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len());
        input.write_raw(&mut buffer).unwrap();
        assert_eq!(input.header_len(), buffer.len());

        //deserialize (read)
        {
            let mut cursor = Cursor::new(&buffer);
            let result = Ipv4Header::read(&mut cursor).unwrap();
            assert_eq!(input.header_len() as u64, cursor.position());

            //check equivalence
            assert_eq!(input, &result);
        }

        //deserialize (from_slice)
        {
            let result = Ipv4Header::from_slice(&buffer).unwrap();
            assert_eq!(input, &result.0);
            assert_eq!(&buffer[usize::from(input.header_len())..], result.1);
        }

        //check that the slice implementation also reads the correct values
        {
            use std::net::Ipv4Addr;
            let slice = Ipv4HeaderSlice::from_slice(&buffer[..]).unwrap();

            assert_eq!(slice.slice(), &buffer);

            assert_eq!(slice.version(), 4);
            assert_eq!(slice.ihl(), input.ihl());
            assert_eq!(slice.dcp(), input.differentiated_services_code_point);
            assert_eq!(slice.ecn(), input.explicit_congestion_notification);
            assert_eq!(slice.payload_len(), input.payload_len);
            assert_eq!(slice.total_len(), input.total_len());
            assert_eq!(slice.identification(), input.identification);
            assert_eq!(slice.dont_fragment(), input.dont_fragment);
            assert_eq!(slice.more_fragments(), input.more_fragments);
            assert_eq!(slice.fragments_offset(), input.fragments_offset);
            assert_eq!(slice.ttl(), input.time_to_live);
            assert_eq!(slice.protocol(), input.protocol);
            assert_eq!(slice.header_checksum(), input.header_checksum);
            assert_eq!(slice.source(), input.source);
            assert_eq!(slice.source_addr(), Ipv4Addr::from(input.source));
            assert_eq!(slice.destination(), input.destination);
            assert_eq!(slice.destination_addr(), Ipv4Addr::from(input.destination));

            //check that a convertion back to a header yields the same result as the original write
            assert_eq!(&slice.to_header(), input);
            assert_eq!(slice.options(), input.options());
        }
    }
}

proptest! {
    #[test]
    fn slice_eq(ref header in ipv4_any()) {

        let buffer_a = {
            let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            buffer
        };

        let buffer_b = {
            let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            buffer
        };

        assert_eq!(
            Ipv4HeaderSlice::from_slice(&buffer_a).unwrap(),
            Ipv4HeaderSlice::from_slice(&buffer_b).unwrap(),
        );
    }
}

#[test]
fn slice_dbg() {
    let buffer = {
        let header: Ipv4Header = Default::default();
        let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
        header.write(&mut buffer).unwrap();
        buffer
    };
    println!("{:?}", Ipv4HeaderSlice::from_slice(&buffer).unwrap());
}

proptest! {
    #[test]
    fn clone(ref header in ipv4_any()) {
        // header
        assert_eq!(header, &header.clone());

        // slice
        let buffer = {
            let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            buffer
        };
        let slice = Ipv4HeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(slice.clone(), slice.clone());
    }
}
