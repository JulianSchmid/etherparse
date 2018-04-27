use etherparse::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian};

#[test]
fn read_write() {
    use std::io::Cursor;

    let input = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 1356,
        checksum: 2467
    };
    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(20);
    buffer.write_udp_header_raw(&input).unwrap();
    //deserialize
    let result = {
        let mut cursor = Cursor::new(&buffer);
        cursor.read_udp_header().unwrap()
    };
    //check equivalence
    assert_eq!(input, result);
}

#[test]
fn with_ipv4_checksum() {
    let payload = [9,10,11,12, 13,14,15,16];
    let ip_header = Ipv4Header::new(
        UdpHeader::SERIALIZED_SIZE + payload.len(), 
        5, 
        IpTrafficClass::Udp, 
        [1,2,3,4], 
        [5,6,7,8]).unwrap();

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
    let sum: u16 = IpTrafficClass::Udp as u16 +
                    (2*(UdpHeader::SERIALIZED_SIZE as u16 + 
                        payload.len() as u16));
    BigEndian::write_u16(&mut payload, 0xffff - sum);
    let ip_header = Ipv4Header::new(
        UdpHeader::SERIALIZED_SIZE + payload.len(), 
        5, 
        IpTrafficClass::Udp, 
        [0,0,0,0],
        [0,0,0,0]).unwrap();

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
        1234, //set the size here to something different, as otherwise the ip header size check will trigger 
        5, 
        IpTrafficClass::Udp, 
        [1,2,3,4], 
        [5,6,7,8]).unwrap();

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
        assert_matches!(header.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, ip_header.protocol, &payload),
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
        assert_matches!(header.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, ip_header.protocol, &payload),
                        Err(ValueError::UdpPayloadLengthTooLarge(TOO_LARGE)));
    }
}

#[test]
fn udp_calc_checksum_ipv4() {
    //even sized payload
    let ipheader = Ipv4Header::new(4*3 + 8, 5, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
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

    assert_eq!(42134, udp.calc_checksum_ipv4_raw(&[1,2,3,4], &[5,6,7,8], IpTrafficClass::Udp as u8, &payload).unwrap());
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
            next_header: IpTrafficClass::Udp as u8,
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
        assert_matches!(udp_header.calc_checksum_ipv6_raw(&ip_header.source,
                                                          &ip_header.destination,
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
            next_header: IpTrafficClass::Udp as u8,
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
        assert_matches!(udp_header.calc_checksum_ipv6_raw(&ip_header.source,
                                                          &ip_header.destination,
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
            next_header: IpTrafficClass::Udp as u8,
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
        assert_matches!(udp_header.calc_checksum_ipv6_raw(&ip_header.source,
                                                          &ip_header.destination,
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
        next_header: IpTrafficClass::Udp as u8,
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
        assert_matches!(udp_header.calc_checksum_ipv6_raw(&ip_header.source, &ip_header.destination, &payload), 
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
        assert_matches!(udp_header.calc_checksum_ipv6_raw(&ip_header.source, &ip_header.destination, &payload), 
                        Err(ValueError::UdpPayloadLengthTooLarge(OVER_MAX)));
    }
}

#[test]
fn udp_builder_eth_ipv4_udp() {
    //generate
    let in_payload = [24,25,26,27];
    let mut serialized = Vec::new();
    UdpPacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                     .ipv4([13,14,15,16], [17,18,19,20], 21)
                     .udp(22,23)
                     .write(&mut serialized, &in_payload)
                     .unwrap();

    //check the deserialized size
    let expected_ip_size: usize = Ipv4Header::SERIALIZED_SIZE + 
                                  UdpHeader::SERIALIZED_SIZE + 
                                  in_payload.len();
    assert_eq!(expected_ip_size + Ethernet2Header::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;
    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    {
        assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
                   Ethernet2Header{
                        source: [1,2,3,4,5,6],
                        destination: [7,8,9,10,11,12],
                        ether_type: EtherType::Ipv4 as u16
                   });
    }

    //ipv4 header
    let ip_actual = Ipv4Header::read(&mut cursor).unwrap();
    let mut ip_expected = Ipv4Header{
        header_length: 5,
        differentiated_services_code_point: 0,
        explicit_congestion_notification: 0,
        total_length: expected_ip_size as u16,
        identification: 0,
        dont_fragment: true,
        more_fragments: false,
        fragments_offset: 0,
        time_to_live: 21,
        protocol: IpTrafficClass::Udp as u8,
        header_checksum: 0,
        source: [13,14,15,16],
        destination: [17,18,19,20]
    };
    ip_expected.header_checksum = ip_expected.calc_header_checksum(&[]).unwrap();
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv4_checksum(22, 23, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_ipv6_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    UdpPacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                     .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                           [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                           47)
                     .udp(48,49)
                     .write(&mut serialized, &in_payload)
                     .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE + 
               in_payload.len(),

               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;
    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    {
        assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
                   Ethernet2Header{
                        source: [1,2,3,4,5,6],
                        destination: [7,8,9,10,11,12],
                        ether_type: EtherType::Ipv6 as u16
                   });
    }

    //ipv4 header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 0,
        flow_label: 0,
        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
        next_header: IpTrafficClass::Udp as u8,
        hop_limit: 47,
        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
    };
    assert_eq!(ip_actual,
               ip_expected);

    //udp header
    let udp_actual = UdpHeader::read(&mut cursor).unwrap();
    let udp_expected = UdpHeader::with_ipv6_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}