use etherparse::*;

use byteorder::{ByteOrder, BigEndian};
use super::super::*;
use std::io::Cursor;

proptest! {
    #[test]
    fn read_write(ref input in udp_any()) {
        //serialize
        let buffer = {
            let mut buffer: Vec<u8> = Vec::with_capacity(UdpHeader::SERIALIZED_SIZE + 1);
            input.write(&mut buffer).unwrap();
            //add some data to test the return slice
            buffer.push(1);
            buffer
        };

        //deserialize with read
        {
            let result = UdpHeader::read(&mut Cursor::new(&buffer)).unwrap();
            //check equivalence
            assert_eq!(input, &result);
        }
        //deserialize from slice
        {
            let result = UdpHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(input, &result.0);
            assert_eq!(&buffer[buffer.len()-1 .. ], result.1);
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
    let mut payload = [0,0,0,0];
    let sum: u16 = u16::from(ip_number::UDP) +
                    (2*(UdpHeader::SERIALIZED_SIZE as u16 + 
                        payload.len() as u16));
    BigEndian::write_u16(&mut payload, 0xffff - sum);
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
        assert_matches!(header.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, ip_header.protocol, &payload),
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
        assert_matches!(header.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, ip_header.protocol, &payload),
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

    assert_eq!(42134, udp.calc_checksum_ipv4_raw([1,2,3,4], [5,6,7,8], ip_number::UDP, &payload).unwrap());
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
    use std;

    let ip_header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 1234,
        next_header: ip_number::UDP,
        hop_limit: 40,
        source: [0xff;16],
        destination: [0xff;16]
    };

    //border still small enough
    const MAX: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
    {
        let mut payload = Vec::with_capacity(MAX);
        payload.resize(MAX, 0);

        let udp_header = UdpHeader{
            source_port: 37,
            destination_port: 38,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
            checksum: 0
        };
        assert_matches!(UdpHeader::with_ipv6_checksum(0, 0, &ip_header, &payload), 
                        Ok(_));
        assert_matches!(udp_header.calc_checksum_ipv6(&ip_header, &payload), 
                        Ok(_));
        assert_matches!(udp_header.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, &payload), 
                        Ok(_));
    }
    //border still small enough
    {
        const OVER_MAX: usize = MAX + 1;
        let mut payload = Vec::with_capacity(OVER_MAX);
        payload.resize(OVER_MAX, 0);
        let udp_header = UdpHeader{
            source_port: 37,
            destination_port: 38,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
            checksum: 0
        };
        assert_matches!(UdpHeader::with_ipv6_checksum(0, 0, &ip_header, &payload), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
        assert_matches!(udp_header.calc_checksum_ipv6(&ip_header, &payload), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
        assert_matches!(udp_header.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, &payload), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
    }
}

#[test]
fn from_slice() {
    let header = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 1356,
        checksum: 2467
    };
    let buffer = {
        let mut buffer = Vec::with_capacity(UdpHeader::SERIALIZED_SIZE);
        header.write(&mut buffer).unwrap();
        buffer
    };

    //get the slice
    let slice = UdpHeaderSlice::from_slice(&buffer).unwrap();

    assert_eq!(slice.slice(), &buffer);

    assert_eq!(slice.source_port(), header.source_port);
    assert_eq!(slice.destination_port(), header.destination_port);
    assert_eq!(slice.length(), header.length);
    assert_eq!(slice.checksum(), header.checksum);

    //check that the to_header method also results in the same header
    assert_eq!(slice.to_header(), header);
}

#[test]
fn read_write_length_error() {

    let header = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 1356,
        checksum: 2467
    };

    // write with an io error (not enough space)
    for len in 0..UdpHeader::SERIALIZED_SIZE {
        let mut writer = TestWriter::with_max_size(len);
        assert_eq!(
            writer.error_kind(),
            header.write(&mut writer).unwrap_err().io_error().unwrap().kind()
        );
    }

    // serialize
    let buffer = {
        let mut buffer: Vec<u8> = Vec::with_capacity(UdpHeader::SERIALIZED_SIZE);
        header.write(&mut buffer).unwrap();
        buffer
    };

    // read with an length error
    for len in 0..UdpHeader::SERIALIZED_SIZE {
        use ReadError::*;
        // read
        assert_matches!(
            UdpHeader::read(&mut Cursor::new(&buffer[..len])),
            Err(_)
        );

        // read_from_slice
        assert_matches!(
            UdpHeader::read_from_slice(&buffer[..len]),
            Err(UnexpectedEndOfSlice(UdpHeader::SERIALIZED_SIZE))
        );

        // from_slice
        assert_matches!(
            UdpHeaderSlice::from_slice(&buffer[..len]),
            Err(UnexpectedEndOfSlice(UdpHeader::SERIALIZED_SIZE))
        );
    }
}

#[test]
fn dbg_clone_eq() {
    let header = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 1356,
        checksum: 2467
    };

    println!("{:?}", header);
    assert_eq!(header.clone(), header);

    // write with an io error (not enough space)
    let buffer = {
        let mut buffer: Vec<u8> = Vec::with_capacity(UdpHeader::SERIALIZED_SIZE);
        header.write(&mut buffer).unwrap();
        buffer
    };

    let slice = UdpHeaderSlice::from_slice(&buffer).unwrap();
    println!("{:?}", slice);
    assert_eq!(slice.clone(), slice);
}
