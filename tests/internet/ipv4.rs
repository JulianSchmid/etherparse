use super::super::*;
use std::io::Cursor;
use proptest::prelude::*;

#[test]
fn default() {
    let default : Ipv4Header = Default::default();
    assert_eq!(5, default.ihl());
    assert_eq!(0, default.differentiated_services_code_point);
    assert_eq!(0, default.explicit_congestion_notification);
    assert_eq!(0, default.payload_len);
    assert_eq!(0, default.identification);
    assert_eq!(true, default.dont_fragment);
    assert_eq!(false, default.more_fragments);
    assert_eq!(0, default.fragments_offset);
    assert_eq!(0, default.time_to_live);
    assert_eq!(0, default.protocol);
    assert_eq!(0, default.header_checksum);
    assert_eq!([0;4], default.source);
    assert_eq!([0;4], default.destination);
}

proptest! {
    #[test]
    fn eq(a in ipv4_any(),
          b in ipv4_any())
    {
        //check identity equality
        assert!(a == a);
        assert!(b == b);

        //check every field
        //differentiated_services_code_point
        assert_eq!(
            a.differentiated_services_code_point == b.differentiated_services_code_point,
            a == {
                let mut other = a.clone();
                other.differentiated_services_code_point = b.differentiated_services_code_point;
                other
            }
        );
        //explicit_congestion_notification
        assert_eq!(
            a.explicit_congestion_notification == b.explicit_congestion_notification,
            a == {
                let mut other = a.clone();
                other.explicit_congestion_notification = b.explicit_congestion_notification;
                other
            }
        );
        //payload_len
        assert_eq!(
            a.payload_len == b.payload_len,
            a == {
                let mut other = a.clone();
                other.payload_len = b.payload_len;
                other
            }
        );
        //identification
        assert_eq!(
            a.identification == b.identification,
            a == {
                let mut other = a.clone();
                other.identification = b.identification;
                other
            }
        );
        //dont_fragment
        assert_eq!(
            a.dont_fragment == b.dont_fragment,
            a == {
                let mut other = a.clone();
                other.dont_fragment = b.dont_fragment;
                other
            }
        );
        //more_fragments
        assert_eq!(
            a.more_fragments == b.more_fragments,
            a == {
                let mut other = a.clone();
                other.more_fragments = b.more_fragments;
                other
            }
        );
        //fragments_offset
        assert_eq!(
            a.fragments_offset == b.fragments_offset,
            a == {
                let mut other = a.clone();
                other.fragments_offset = b.fragments_offset;
                other
            }
        );
        //time_to_live
        assert_eq!(
            a.time_to_live == b.time_to_live,
            a == {
                let mut other = a.clone();
                other.time_to_live = b.time_to_live;
                other
            }
        );
        //protocol
        assert_eq!(
            a.protocol == b.protocol,
            a == {
                let mut other = a.clone();
                other.protocol = b.protocol;
                other
            }
        );
        //header_checksum
        assert_eq!(
            a.header_checksum == b.header_checksum,
            a == {
                let mut other = a.clone();
                other.header_checksum = b.header_checksum;
                other
            }
        );
        //source
        assert_eq!(
            a.source == b.source,
            a == {
                let mut other = a.clone();
                other.source = b.source;
                other
            }
        );
        //destination
        assert_eq!(
            a.destination == b.destination,
            a == {
                let mut other = a.clone();
                other.destination = b.destination;
                other
            }
        );

        //options
        assert_eq!(
            a.options() == b.options(),
            a == {
                let mut other = a.clone();
                other.set_options(b.options()).unwrap();
                other
            }
        );
    }
}

proptest! {
    #[test]
    fn debug(input in ipv4_any()) {
        assert_eq!(&format!("Ipv4Header {{ ihl: {}, differentiated_services_code_point: {}, explicit_congestion_notification: {}, payload_len: {}, identification: {}, dont_fragment: {}, more_fragments: {}, fragments_offset: {}, time_to_live: {}, protocol: {}, header_checksum: {}, source: {:?}, destination: {:?}, options: {:?} }}",
                input.ihl(),
                input.differentiated_services_code_point,
                input.explicit_congestion_notification,
                input.payload_len,
                input.identification,
                input.dont_fragment,
                input.more_fragments,
                input.fragments_offset,
                input.time_to_live,
                input.protocol,
                input.header_checksum,
                input.source,
                input.destination,
                input.options()
            ),
            &format!("{:?}", input)
        );
    }
}

proptest! {
    #[test]
    fn new(source_ip in prop::array::uniform4(any::<u8>()),
           dest_ip in prop::array::uniform4(any::<u8>()),
           ttl in any::<u8>(),
           payload_len in any::<u16>())
    {
        let result = Ipv4Header::new(
            payload_len,
            ttl, 
            IpNumber::Udp, 
            source_ip, 
            dest_ip
        );

        assert_eq!(result.differentiated_services_code_point, 0);
        assert_eq!(result.explicit_congestion_notification, 0);
        assert_eq!(result.payload_len, payload_len);
        assert_eq!(result.identification, 0);
        assert_eq!(result.dont_fragment, true);
        assert_eq!(result.more_fragments, false);
        assert_eq!(result.fragments_offset, 0);
        assert_eq!(result.time_to_live, ttl);
        assert_eq!(result.protocol, ip_number::UDP);
        assert_eq!(result.header_checksum, 0);
        assert_eq!(result.source, source_ip);
        assert_eq!(result.destination, dest_ip);
        assert_eq!(result.options(), &[]);
    }
}

#[test]
fn set_payload_len() {
    let mut header = Ipv4Header::new(0, 0, IpNumber::Udp, [0;4], [0;4]);

    //add options (to make sure they are included in the calculation)
    header.set_options(&[1,2,3,4]).unwrap();

    //zero check
    assert_matches!(header.set_payload_len(0), Ok(()));
    assert_eq!(header.total_len(), 24);

    //max check
    const MAX: usize = (std::u16::MAX as usize) - Ipv4Header::SERIALIZED_SIZE - 4;
    assert_matches!(header.set_payload_len(MAX), Ok(()));
    assert_eq!(header.total_len(), std::u16::MAX);

    const OVER_MAX: usize = MAX + 1;
    assert_matches!(header.set_payload_len(OVER_MAX), 
                    Err(ValueError::Ipv4PayloadLengthTooLarge(OVER_MAX)));
}

#[test]
fn set_options() {
    //length of 1
    {
        let mut header: Ipv4Header = Default::default();
        let options = [1,2,3,4];
        assert_eq!(header.set_options(&options), Ok(()));

        assert_eq!(&options, header.options());
        assert_eq!(24, header.header_len());
        assert_eq!(24, header.total_len());
        assert_eq!(6, header.ihl());

        //length 0
        assert_eq!(header.set_options(&[]), Ok(()));

        assert_eq!(&options[..0], header.options());
        assert_eq!(20, header.header_len());
        assert_eq!(20, header.total_len());
        assert_eq!(5, header.ihl());
    }
    //maximum length (40)
    {
        let mut header: Ipv4Header = Default::default();
        let options = [1,2,3,4,5,6,7,8,
                       9,10,11,12,13,14,15,16,
                       17,18,19,20,21,22,23,24,
                       25,26,27,28,29,30,31,32,
                       33,34,35,36,37,38,39,40];
        assert_eq!(header.set_options(&options), Ok(()));

        assert_eq!(&options[..], header.options());
        assert_eq!(60, header.header_len());
        assert_eq!(60, header.total_len());
        assert_eq!(15, header.ihl());
    }
    //errors
    {
        let buffer: [u8;50] = [0;50];
        for len in &[
            1usize,2,3, //unaligned
            5,6,7,
            41,44 //over max
        ] {
            let mut header: Ipv4Header = Default::default();

            //expect an error
            use self::ValueError::Ipv4OptionsLengthBad;
            assert_eq!(
                Err(Ipv4OptionsLengthBad(*len)), 
                header.set_options(&buffer[..*len])
            );

            //check value was not taken
            assert_eq!(&buffer[..0], header.options());
            assert_eq!(20, header.header_len());
            assert_eq!(20, header.total_len());
            assert_eq!(5, header.ihl());
        }
    }
}

#[test]
fn calc_header_checksum() {
    let base: Ipv4Header = Ipv4Header::new(
        40,
        4, // ttl
        IpNumber::Udp,
        [192, 168, 1, 1], // source
        [212, 10, 11, 123] // destination
    );

    //without options
    {
        //dont_fragment && !more_fragments
        let header = base.clone();
        assert_eq!(0xd582, header.calc_header_checksum().unwrap());
        // !dont_fragment && more_fragments
        let header = {
            let mut header = base.clone();
            header.dont_fragment = false;
            header.more_fragments = true;
            header
        };
        assert_eq!(0xf582, header.calc_header_checksum().unwrap());
    }
    //with options
    {
        let header = {
            let mut header = base.clone();
            header.payload_len = 40 - 8;
            header.set_options(&[1,2,3,4,5,6,7,8]).unwrap();
            header
        };
        assert_eq!(0xc36e, header.calc_header_checksum().unwrap());
    }
}

#[test]
fn range_errors() {
    use crate::ValueError::*;
    use crate::ErrorField::*;

    fn test_range_methods(input: &Ipv4Header, expected: ValueError) {
        //check_ranges
        assert_eq!(expected.clone(), 
                   input
                   .calc_header_checksum()
                   .unwrap_err());
        //write
        {
            let mut buffer: Vec<u8> = Vec::new();
            let result = input.write(&mut buffer);
            assert_eq!(0, buffer.len());
            assert_eq!(Some(expected.clone()), 
                       result
                       .unwrap_err()
                       .value_error());
        }
        //write_raw
        {
            let mut buffer: Vec<u8> = Vec::new();
            let result = input.write_raw(&mut buffer);
            assert_eq!(0, buffer.len());
            assert_eq!(Some(expected.clone()), 
                       result
                       .unwrap_err()
                       .value_error());
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
            U8TooLarge{value: 0x40, max: 0x3f, field: Ipv4Dscp}
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
            U8TooLarge{value: 0x4, max: 0x3, field: Ipv4Ecn}
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
            U16TooLarge{value: 0x2000, max: 0x1FFF, field: Ipv4FragmentsOffset}
        );
    }
    //payload len
    {
        const MAX_PAYLOAD_LEN: u16 = std::u16::MAX - (Ipv4Header::SERIALIZED_SIZE as u16) - 8;

        let value = {
            let mut value: Ipv4Header = Default::default();
            value.set_options(&[1,2,3,4,5,6,7,8]).unwrap();
            value.payload_len = MAX_PAYLOAD_LEN + 1;
            value
        };
        test_range_methods(
            &value, 
            U16TooLarge{value: MAX_PAYLOAD_LEN + 1, max: MAX_PAYLOAD_LEN, field: Ipv4PayloadLength}
        );
    }
}

proptest! {
    #[test]
    fn write(ref base_header in ipv4_any()) {
        let header = {
            let mut header = base_header.clone();
            // set the header checksum to something else to
            // ensure it is calculated during the write call
            header.header_checksum = 0;
            header
        };

        //serialize
        let buffer = {
            let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            buffer
        };
        assert_eq!(header.header_len(), buffer.len());

        //deserialize
        let mut cursor = Cursor::new(&buffer);
        let result = Ipv4Header::read(&mut cursor).unwrap();
        assert_eq!(header.header_len(), cursor.position() as usize);

        //check equivalence (with calculated checksum)
        let header_with_checksum = {
            let mut h = header.clone();
            h.header_checksum = h.calc_header_checksum().unwrap();
            h
        };
        assert_eq!(header_with_checksum, result);
    }
}

#[test]
fn write_io_error() {
    let header = {
        let mut header: Ipv4Header = Default::default();
        // set some options so that we can also provoke io errors
        // in this part of the code
        header.set_options(&[1,2,3,4,5,6,7,8]).unwrap();
        header
    };

    for len in 0..header.header_len() {
        // write
        {
            let mut writer = TestWriter::with_max_size(len);
            assert_eq!(
                writer.error_kind(),
                header.write(&mut writer).unwrap_err().io_error().unwrap().kind()
            );
        }
        // write raw
        {
            let mut writer = TestWriter::with_max_size(len);
            assert_eq!(
                writer.error_kind(),
                header.write_raw(&mut writer).unwrap_err().io_error().unwrap().kind()
            );
        }
    }
}

proptest! {
    #[test]
    fn read_errors(ref header in ipv4_any()) {
        use crate::ReadError::*;

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

                // read
                assert_matches!(
                    Ipv4Header::read(&mut Cursor::new(&buffer)),
                    Err(Ipv4UnexpectedVersion(_))
                );

                // read_from_slice
                assert_matches!(
                    Ipv4Header::read_from_slice(&buffer),
                    Err(Ipv4UnexpectedVersion(_))
                );

                // from_slice
                assert_matches!(
                    Ipv4HeaderSlice::from_slice(&buffer),
                    Err(Ipv4UnexpectedVersion(_))
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

            // read
            assert_matches!(
                Ipv4Header::read(&mut Cursor::new(&buffer)),
                Err(Ipv4HeaderLengthBad(_))
            );

            // read_without_version
            assert_matches!(
                Ipv4Header::read_without_version(
                    &mut Cursor::new(&buffer[1..]),
                    buffer[0] & 0xf
                ),
                Err(Ipv4HeaderLengthBad(_))
            );
            
            // read_from_slice
            assert_matches!(
                Ipv4Header::read_from_slice(&buffer),
                Err(Ipv4HeaderLengthBad(_))
            );

            // from_slice
            assert_matches!(
                Ipv4HeaderSlice::from_slice(&buffer),
                Err(Ipv4HeaderLengthBad(_))
            );
        }

        //bad total_length
        for total_length in 0..header.header_len() {
            use byteorder::{ByteOrder, BigEndian};

            let buffer = {
                let mut buffer: Vec<u8> = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                //change the total length to be smaller then the header length
                BigEndian::write_u16(&mut buffer[2..4], total_length as u16);
                buffer
            };

            // read
            assert_matches!(
                Ipv4Header::read(&mut Cursor::new(&buffer)),
                Err(Ipv4TotalLengthTooSmall(_))
            );

            // read_without_version
            assert_matches!(
                Ipv4Header::read_without_version(
                    &mut Cursor::new(&buffer[1..]),
                    buffer[0] & 0xf
                ),
                Err(Ipv4TotalLengthTooSmall(_))
            );

            // read_from_slice
            assert_matches!(
                Ipv4Header::read_from_slice(&buffer),
                Err(Ipv4TotalLengthTooSmall(_))
            );

            // from_slice
            assert_matches!(
                Ipv4HeaderSlice::from_slice(&buffer),
                Err(Ipv4TotalLengthTooSmall(_))
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
                assert_matches!(
                    Ipv4Header::read(&mut Cursor::new(&buffer[..len])),
                    Err(IoError(_))
                );

                // read_without_version
                if len > 0 {
                    assert_matches!(
                        Ipv4Header::read_without_version(
                            &mut Cursor::new(&buffer[1..len]),
                            buffer[0] & 0xf
                        ),
                        Err(IoError(_))
                    );
                }

                // read_from_slice
                assert_matches!(
                    Ipv4Header::read_from_slice(&buffer[..len]),
                    Err(UnexpectedEndOfSlice(_))
                );

                // from_slice
                assert_matches!(
                    Ipv4HeaderSlice::from_slice(&buffer[..len]),
                    Err(UnexpectedEndOfSlice(_))
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

        //deserialize (read_from_slice)
        {
            let result = Ipv4Header::read_from_slice(&buffer).unwrap();
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
