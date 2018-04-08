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
    println!("whatever = {:?}", sum);
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

    //uneven sized payload
    //TODO

    //check that zero checksum is converted to 0xffff
    //TODO
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

    //uneven sized payload
    //TODO

    //check that zero checksum is converted to 0xffff
    //TODO
}