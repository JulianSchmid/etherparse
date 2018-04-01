use etherparse::*;

#[test]
fn readwrite_udp_header_raw() {
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
fn udp_calc_checksum_ipv4() {
    //zero checksum should be inverted
    let ipheader = Ipv4Header::new(4*3 + 8, 5, IpTrafficClass::Udp, [1,2,3,4], [5,6,7,8]).unwrap();
    let udp = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 8,
        checksum: 0
    };
    let payload = [9,10,11,12, 13,14,15,16];

    assert_eq!(42134, udp.calc_checksum_ipv4(&ipheader, &payload).unwrap());
}

#[test]
fn udp_calc_checksum_ipv4_raw() {
    //zero checksum should be inverted
    let udp = UdpHeader {
        source_port: 1234,
        destination_port: 5678,
        length: 8,
        checksum: 0
    };
    let payload = [9,10,11,12, 13,14,15,16];

    assert_eq!(42134, udp.calc_checksum_ipv4_raw(&[1,2,3,4], &[5,6,7,8], IpTrafficClass::Udp as u8, &payload).unwrap());
}