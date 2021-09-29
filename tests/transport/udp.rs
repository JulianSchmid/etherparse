use etherparse::*;

use super::super::*;
use std::io::{Cursor, ErrorKind};

mod udp_header {
    use super::*;

    proptest! {
        #[test]
        fn without_ipv4_checksum(
            source_port in any::<u16>(),
            destination_port in any::<u16>(),
            good_payload_length in 0..=((std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE),
            bad_payload_length in ((std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1)..=usize::MAX,
        ) {

            // normal working call
            {
                let actual = UdpHeader::without_ipv4_checksum(
                    source_port,
                    destination_port,
                    good_payload_length
                ).unwrap();
                assert_eq!(
                    actual,
                    UdpHeader{
                        source_port,
                        destination_port,
                        length: (UdpHeader::SERIALIZED_SIZE + good_payload_length) as u16,
                        checksum: 0
                    }
                );
            }

            // length too large
            {
                let actual = UdpHeader::without_ipv4_checksum(
                    source_port,
                    destination_port,
                    bad_payload_length
                ).unwrap_err();
                assert_eq!(
                    actual,
                    ValueError::UdpPayloadLengthTooLarge(bad_payload_length)
                );
            }
        }
    }

    /// Calculat the expected UDP header checksum for the tests.
    fn expected_udp_ipv4_checksum(source: [u8;4], destination: [u8;4], udp_header: &UdpHeader, payload: &[u8]) -> u16 {
        ::etherparse::checksum::Sum16BitWords::new()
        // pseudo header
        .add_4bytes(source)
        .add_4bytes(destination)
        .add_2bytes([0, ip_number::UDP])
        .add_2bytes(udp_header.length.to_be_bytes())
        // udp header
        .add_2bytes(udp_header.source_port.to_be_bytes())
        .add_2bytes(udp_header.destination_port.to_be_bytes())
        .add_2bytes(udp_header.length.to_be_bytes())
        .add_2bytes([0, 0]) // checksum as zero (should have no effect)
        .add_slice(payload)
        .to_ones_complement_with_no_zero()
        .to_be()
    }

    proptest! {
        #[test]
        fn with_ipv4_checksum(
            source_port in any::<u16>(),
            destination_port in any::<u16>(),
            ipv4 in ipv4_any(),
            payload in proptest::collection::vec(any::<u8>(), 0..20),
            bad_len in ((std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1)..usize::MAX,
        ) {
            // normal case
            assert_eq!(
                UdpHeader::with_ipv4_checksum(
                    source_port,
                    destination_port,
                    &ipv4,
                    &payload
                ).unwrap(),
                {
                    let mut expected = UdpHeader {
                        source_port,
                        destination_port,
                        length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                        checksum: 0,
                    };
                    let checksum = expected_udp_ipv4_checksum(
                        ipv4.source,
                        ipv4.destination,
                        &expected,
                        &payload
                    );
                    expected.checksum = checksum;
                    expected
                }
            );

            // case where the 16 bit word results in a checksum of
            // 0, but gets converted to 0xffff as 0 is reserved.
            {
                let base = UdpHeader {
                    source_port: 0,
                    destination_port,
                    length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                    checksum: 0,
                };
                // use the source port to force 0 as a result value
                // for that first calculate the checksum with the source
                // set to 0
                let sourceless_checksum = !(expected_udp_ipv4_checksum(
                    ipv4.source,
                    ipv4.destination,
                    &base,
                    &payload
                ).to_le());

                assert_eq!(
                    UdpHeader::with_ipv4_checksum(
                        // we now need to add a value that results in the value
                        // 0xffff (which will become 0 via the ones complement rule).
                        0xffff - sourceless_checksum,
                        destination_port,
                        &ipv4,
                        &payload
                    ).unwrap(),
                    UdpHeader{
                        source_port: 0xffff - sourceless_checksum,
                        destination_port,
                        length: base.length,
                        checksum: 0xffff
                    }
                );
            }
            
            // length error case
            {
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_eq!(
                    ValueError::UdpPayloadLengthTooLarge(bad_len),
                    UdpHeader::with_ipv4_checksum(
                        source_port,
                        destination_port,
                        &ipv4,
                        &too_big_slice
                    ).unwrap_err()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn calc_checksum_ipv4_raw(
            source_port in any::<u16>(),
            destination_port in any::<u16>(),
            dummy_checksum in any::<u16>(),
            ipv4 in ipv4_any(),
            payload in proptest::collection::vec(any::<u8>(), 0..20),
            bad_len in ((std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1)..usize::MAX,
        ) {
            // normal case
            {
                let header = UdpHeader {
                    source_port,
                    destination_port,
                    length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                    checksum: dummy_checksum,
                };

                assert_eq!(
                    header.calc_checksum_ipv4_raw(
                        ipv4.source,
                        ipv4.destination,
                        &payload
                    ).unwrap(),
                    expected_udp_ipv4_checksum(
                        ipv4.source,
                        ipv4.destination,
                        &header,
                        &payload
                    )
                );
            }

            // case where the 16 bit word results in a checksum of
            // 0, but gets converted to 0xffff as 0 is reserved.
            {
                let base = UdpHeader {
                    source_port: 0,
                    destination_port,
                    length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                    checksum: dummy_checksum,
                };
                // use the source port to force 0 as a result value
                // for that first calculate the checksum with the source
                // set to 0
                let sourceless_checksum = !(expected_udp_ipv4_checksum(
                    ipv4.source,
                    ipv4.destination,
                    &base,
                    &payload
                ).to_le());

                // we now need to add a value that results in the value
                // 0xffff (which will become 0 via the ones complement rule).
                let header = {
                    let mut header = base.clone();
                    header.source_port = 0xffff - sourceless_checksum;
                    header
                };

                assert_eq!(
                    0xffff,
                    header.calc_checksum_ipv4_raw(
                        ipv4.source,
                        ipv4.destination,
                        &payload
                    ).unwrap()
                );
            }
            
            // length error case
            {
                let header = UdpHeader {
                    source_port,
                    destination_port,
                    // udp header length itself is ok, but the payload not
                    length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                    checksum: dummy_checksum,
                };
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_eq!(
                    ValueError::UdpPayloadLengthTooLarge(bad_len),
                    header.calc_checksum_ipv4_raw(
                        ipv4.source,
                        ipv4.destination,
                        too_big_slice
                    ).unwrap_err()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn with_ipv6_checksum(input in udp_any()) {
            // TODO
        }
    }

    proptest! {
        #[test]
        fn calc_checksum_ipv6(input in udp_any()) {
            // TODO
        }
    }

    proptest! {
        #[test]
        fn calc_checksum_ipv6_raw(input in udp_any()) {
            // TODO
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            input in udp_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let (result, rest) = UdpHeader::from_slice(&buffer[..]).unwrap();
                assert_eq!(result, input);
                assert_eq!(rest, &buffer[8..]);
            }
            #[allow(deprecated)]
            {
                let (result, rest) = UdpHeader::read_from_slice(&buffer[..]).unwrap();
                assert_eq!(result, input);
                assert_eq!(rest, &buffer[8..]);
            }

            // call with not enough data in the slice
            for len in 0..8 {
                assert_matches!(
                    UdpHeader::from_slice(&buffer[0..len]),
                    Err(ReadError::UnexpectedEndOfSlice(_))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_bytes(input in udp_any()) {
            assert_eq!(
                input,
                UdpHeader::from_bytes(
                    input.to_bytes()
                )
            );
        }
    }

    proptest! {
        #[test]
        fn read(
            input in udp_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len() + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // normal
            {
                let mut cursor = Cursor::new(&buffer);
                let result = UdpHeader::read(&mut cursor).unwrap();
                assert_eq!(result, input);
                assert_eq!(8, cursor.position());
            }

            // unexpexted eof
            for len in 0..8 {
                let mut cursor = Cursor::new(&buffer[0..len]);
                assert_eq!(
                    UdpHeader::read(&mut cursor)
                    .unwrap_err()
                    .kind(),
                    ErrorKind::UnexpectedEof
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write(input in udp_any()) {
            // normal write
            {
                let mut result = Vec::with_capacity(input.header_len());
                input.write(&mut result).unwrap();
                assert_eq!(
                    &result[..],
                    input.to_bytes()
                );
            }

            // unexpected eof
            for len in 0..8 {
                let mut writer = TestWriter::with_max_size(len);
                assert_eq!(
                    ErrorKind::UnexpectedEof,
                    input.write(&mut writer)
                        .unwrap_err()
                        .io_error()
                        .unwrap()
                        .kind()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn to_bytes(input in udp_any()) {
            let s_be = input.source_port.to_be_bytes();
            let d_be = input.destination_port.to_be_bytes();
            let l_be = input.length.to_be_bytes();
            let c_be = input.checksum.to_be_bytes();

            assert_eq!(
                input.to_bytes(),
                [
                    s_be[0],
                    s_be[1],
                    d_be[0],
                    d_be[1],
                    l_be[0],
                    l_be[1],
                    c_be[0],
                    c_be[1],
                ]
            );
        }
    }

    #[test]
    fn default() {
        let actual : UdpHeader = Default::default();
        assert_eq!(actual.source_port, 0);
        assert_eq!(actual.destination_port, 0);
        assert_eq!(actual.length, 0);
        assert_eq!(actual.checksum, 0);
    }

    proptest! {
        #[test]
        fn clone_eq(input in udp_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in udp_any()) {
            assert_eq!(
                &format!(
                    "UdpHeader {{ source_port: {}, destination_port: {}, length: {}, checksum: {} }}",
                    input.source_port,
                    input.destination_port,
                    input.length,
                    input.checksum,
                ),
                &format!("{:?}", input)
            );
        }
    }
}

mod udp_header_slice {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(
            input in udp_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(8 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let result = UdpHeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(&buffer[..8], result.slice());
            }

            // call with not enough data in the slice
            for len in 0..8 {
                assert_matches!(
                    UdpHeaderSlice::from_slice(&buffer[0..len]),
                    Err(ReadError::UnexpectedEndOfSlice(_))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in udp_any()) {
            let bytes = input.to_bytes();
            let slice = UdpHeaderSlice::from_slice(&bytes).unwrap();

            assert_eq!(slice.source_port(), input.source_port);
            assert_eq!(slice.destination_port(), input.destination_port);
            assert_eq!(slice.length(), input.length);
            assert_eq!(slice.checksum(), input.checksum);
        }
    }

    proptest! {
        #[test]
        fn to_header(input in udp_any()) {
            let bytes = input.to_bytes();
            let slice = UdpHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in udp_any()) {
            let bytes = input.to_bytes();
            let slice = UdpHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in udp_any()) {
            let bytes = input.to_bytes();
            let slice = UdpHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(
                &format!(
                    "UdpHeaderSlice {{ slice: {:?} }}",
                    slice.slice()
                ),
                &format!("{:?}", slice)
            );
        }
    }
}

#[test]
fn with_ipv4_checksum() {
    let payload = [9,10,11,12, 13,14,15,16];
    let ip_header = Ipv4Header::new(
        (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
        5,
        IpNumber::Udp, 
        [1,2,3,4], 
        [5,6,7,8]
    );

    let result = UdpHeader::with_ipv4_checksum(1234, 5678, &ip_header, &payload).unwrap();
    assert_eq!(UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
        checksum: 42118
    }, result);
}

#[test]
fn with_ipv4_checksum_flip() {
    let sum: u16 = u16::from(ip_number::UDP) +
                    (2*(UdpHeader::SERIALIZED_SIZE as u16 + 
                        4 as u16));
    let payload = {
        let sum_be = (0xffff - sum).to_be_bytes();
        [sum_be[0], sum_be[1], 0, 0]
    };

    let ip_header = Ipv4Header::new(
        (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
        5, 
        IpNumber::Udp, 
        [0,0,0,0],
        [0,0,0,0],
    );

    let result = UdpHeader::with_ipv4_checksum(0, 0, &ip_header, &payload).unwrap();
    assert_eq!(UdpHeader {
        source_port: 0,
        destination_port: 0,
        length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
        checksum: 0xffff
    }, result);
}

#[test]
fn with_ipv4_payload_size_check() {
    use std;
    //check that an error is produced when the payload size is too large
    let mut payload = Vec::with_capacity(std::u16::MAX as usize);

    //first try out the maximum size uint16 - udp header size
    payload.resize(std::u16::MAX as usize - UdpHeader::SERIALIZED_SIZE, 0);
    let ip_header = Ipv4Header::new(
        0,
        5, 
        IpNumber::Udp, 
        [1,2,3,4], 
        [5,6,7,8]
    );

    //with checksum
    assert_matches!(UdpHeader::with_ipv4_checksum(1234, 5678, &ip_header, &payload),
                    Ok(_));

    //without checksum
    assert_matches!(UdpHeader::without_ipv4_checksum(1234, 5678, payload.len()),
                    Ok(_));

    //check sum calculation methods
    {
        let header = UdpHeader::without_ipv4_checksum(1234, 5678, payload.len()).unwrap();
        //checksum calculation
        assert_matches!(header.calc_checksum_ipv4(&ip_header, &payload),
                        Ok(_));

        //checksum calculation raw
        assert_matches!(header.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &payload),
                        Ok(_));
    }

    //now check with a too large payload
    const TOO_LARGE: usize = std::u16::MAX as usize - UdpHeader::SERIALIZED_SIZE + 1;
    payload.resize(TOO_LARGE, 0);

    //with checksum
    assert_matches!(UdpHeader::with_ipv4_checksum(1234, 5678, &ip_header, &payload),
                    Err(ValueError::UdpPayloadLengthTooLarge(TOO_LARGE)));

    //without checksum
    assert_matches!(UdpHeader::without_ipv4_checksum(1234, 5678, payload.len()),
                    Err(ValueError::UdpPayloadLengthTooLarge(TOO_LARGE)));

    //check sum calculation methods
    {
        let header = UdpHeader::without_ipv4_checksum(1234, 5678, 1234).unwrap();
        //checksum calculation
        assert_matches!(header.calc_checksum_ipv4(&ip_header, &payload),
                        Err(ValueError::UdpPayloadLengthTooLarge(TOO_LARGE)));

        //checksum calculation raw
        assert_matches!(header.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &payload),
                        Err(ValueError::UdpPayloadLengthTooLarge(TOO_LARGE)));
    }
}

#[test]
fn udp_calc_checksum_ipv4() {
    //even sized payload
    let ipheader = Ipv4Header::new(4*3 + 8, 5, IpNumber::Udp, [1,2,3,4], [5,6,7,8]);
    let payload = [9,10,11,12, 13,14,15,16];
    let udp = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
        checksum: 0
    };

    assert_eq!(42118, udp.calc_checksum_ipv4(&ipheader, &payload).unwrap());
}

#[test]
fn udp_calc_checksum_ipv4_raw() {
    //even sized payload
    let udp = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 8,
        checksum: 0
    };
    let payload = [9,10,11,12, 13,14,15,16];

    assert_eq!(42134, udp.calc_checksum_ipv4_raw([1,2,3,4], [5,6,7,8], &payload).unwrap());
}

#[test]
fn udp_with_ipv6_checksum() {

    //simple packet (even payload)
    {
        let udp_payload = [39,40,41,42];

        let ip_header = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            next_header: ip_number::UDP,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };

        let result = UdpHeader::with_ipv6_checksum(37, 38, &ip_header, &udp_payload).unwrap();
        
        assert_eq!(37, result.source_port);
        assert_eq!(38, result.destination_port);
        assert_eq!((UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16, result.length);
        const EXPECTED_CHECKSUM: u16 = 0x8e08;
        assert_eq!(EXPECTED_CHECKSUM, result.checksum);

        //check seperate checksum calculation
        let udp_header = UdpHeader{
            source_port: 37,
            destination_port: 38,
            length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            checksum: 0
        };
        assert_matches!(udp_header.calc_checksum_ipv6(&ip_header,
                                                      &udp_payload),
                        Ok(EXPECTED_CHECKSUM));
        assert_matches!(udp_header.calc_checksum_ipv6_raw(ip_header.source,
                                                          ip_header.destination,
                                                          &udp_payload),
                        Ok(EXPECTED_CHECKSUM));
    }

    //simple packet (uneven payload)
    {
        let udp_payload = [39,40,41,42,43];

        let ip_header = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            next_header: ip_number::UDP,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8,
                     9,10,11,12,13,14,15,16],
            destination: [21,22,23,24,25,26,27,28,
                          29,30,31,32,33,34,35,36]
        };

        let result = UdpHeader::with_ipv6_checksum(37, 38, &ip_header, &udp_payload).unwrap();
        
        assert_eq!(37, result.source_port);
        assert_eq!(38, result.destination_port);
        assert_eq!((UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16, result.length);
        const EXPECTED_CHECKSUM: u16 = 0x6306;
        assert_eq!(EXPECTED_CHECKSUM, result.checksum);

        //check separate checksum calculation methods
        let udp_header = UdpHeader{
            source_port: 37,
            destination_port: 38,
            length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            checksum: 0
        };
        assert_matches!(udp_header.calc_checksum_ipv6(&ip_header,
                                                      &udp_payload),
                        Ok(EXPECTED_CHECKSUM));
        assert_matches!(udp_header.calc_checksum_ipv6_raw(ip_header.source,
                                                          ip_header.destination,
                                                          &udp_payload),
                        Ok(EXPECTED_CHECKSUM));
    }

    //maximum filled packet (does require a uint64 to calculate the checksum)
    {
        let udp_payload_len = 0xffff
                              - (Ipv4Header::SERIALIZED_SIZE as usize)
                              - (UdpHeader::SERIALIZED_SIZE as usize);
        let mut udp_payload = Vec::with_capacity(udp_payload_len);
        udp_payload.resize(udp_payload_len, 0xff);

        let ip_header = Ipv6Header {
            traffic_class: 1,
            flow_label: 0x81806,
            payload_length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            next_header: ip_number::UDP,
            hop_limit: 40,
            source: [0xff;16],
            destination: [0xff;16]
        };

        //check constructor
        let result = UdpHeader::with_ipv6_checksum(0xffff, 
                                                   0xffff, 
                                                   &ip_header,
                                                   &udp_payload).unwrap();

        assert_eq!(0xffff, result.source_port);
        assert_eq!(0xffff, result.destination_port);
        assert_eq!((UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16, result.length);
        const EXPECTED_CHECKSUM: u16 = 0x0116;
        assert_eq!(EXPECTED_CHECKSUM, result.checksum);

        //check separate checksum calculation methods
        let udp_header = UdpHeader{
            source_port: 0xffff,
            destination_port: 0xffff,
            length: (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
            checksum: 0
        };
        assert_matches!(udp_header.calc_checksum_ipv6(&ip_header,
                                                      &udp_payload),
                        Ok(EXPECTED_CHECKSUM));
        assert_matches!(udp_header.calc_checksum_ipv6_raw(ip_header.source,
                                                          ip_header.destination,
                                                          &udp_payload),
                        Ok(EXPECTED_CHECKSUM));
    }
}

#[test]
fn udp_ipv6_errors() {
    let ip_header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 1234,
        next_header: ip_number::UDP,
        hop_limit: 40,
        source: [0xff;16],
        destination: [0xff;16]
    };

    // too big payload (u32::MAX)
    {
        // SAFETY: In case the error is not triggered
        //         a nullptr exception will be triggered.
        const OVER_MAX: usize = (std::u32::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1;
        let too_big_slice = unsafe {
            //NOTE: The pointer must be initialized with a non null value
            //      otherwise a key constraint of slices is not fullfilled
            //      which can lead to crashes in release mode.
            use std::ptr::NonNull;
            std::slice::from_raw_parts(
                NonNull::<u8>::dangling().as_ptr(),
                OVER_MAX
            )
        };
        let udp_header = UdpHeader{
            source_port: 37,
            destination_port: 38,
            length: 0,
            checksum: 0
        };
        //assert_matches!(UdpHeader::with_ipv6_checksum(0, 0, &ip_header, &too_big_slice), 
        //                Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
        assert_matches!(udp_header.calc_checksum_ipv6(&ip_header, &too_big_slice), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
        assert_matches!(udp_header.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, &too_big_slice), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
    }

    // too big payload (u16::MAX)
    {
        // SAFETY: In case the error is not triggered
        //         a nullptr exception will be triggered.
        const OVER_MAX: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1;
        let too_big_slice = unsafe {
            //NOTE: The pointer must be initialized with a non null value
            //      otherwise a key constraint of slices is not fullfilled
            //      which can lead to crashes in release mode.
            use std::ptr::NonNull;
            std::slice::from_raw_parts(
                NonNull::<u8>::dangling().as_ptr(),
                OVER_MAX
            )
        };
        let udp_header = UdpHeader{
            source_port: 37,
            destination_port: 38,
            length: 0,
            checksum: 0
        };
        assert_matches!(UdpHeader::with_ipv6_checksum(0, 0, &ip_header, &too_big_slice), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
    }
}
