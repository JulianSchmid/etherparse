use etherparse::*;

#[test]
fn eth_ipv4_udp() {
    //generate
    let in_payload = [24,25,26,27];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
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
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::Ipv4 as u16
               });

    //ip header
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
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
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
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
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

#[test]
fn udp_builder_eth_single_vlan_ipv4_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .single_vlan(0x123)
                  .ipv4([13,14,15,16], [17,18,19,20], 21)
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size

        //check the deserialized size
    let expected_ip_size: usize = Ipv4Header::SERIALIZED_SIZE + 
                                  UdpHeader::SERIALIZED_SIZE + 
                                  in_payload.len();
    assert_eq!(expected_ip_size + Ethernet2Header::SERIALIZED_SIZE
                                + SingleVlanHeader::SERIALIZED_SIZE, 
               serialized.len());

    //deserialize and check that everything is as expected
    use std::io::Cursor;
    use std::io::Read;
    //deserialize each part of the message and check it
    let mut cursor = Cursor::new(&serialized);

    //ethernet 2 header
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::VlanTaggedFrame as u16
               });

    //vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 0,
                    drop_eligible_indicator: false,
                    vlan_identifier: 0x123,
                    ether_type: EtherType::Ipv4 as u16
               });

    //ip header
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
    let udp_expected = UdpHeader::with_ipv4_checksum(48, 49, &ip_expected, &in_payload).unwrap();
    assert_eq!(udp_actual,
               udp_expected);

    //payload
    let mut actual_payload: [u8;4] = [0;4];
    cursor.read_exact(&mut actual_payload).unwrap();
    assert_eq!(actual_payload, in_payload);
}

#[test]
fn udp_builder_eth_double_vlan_ipv6_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .double_vlan(0x123, 0x234)
                  .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                         47)
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               DoubleVlanHeader::SERIALIZED_SIZE +
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
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::ProviderBridging as u16
               });

    //outer vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 0,
                    drop_eligible_indicator: false,
                    vlan_identifier: 0x123,
                    ether_type: EtherType::VlanTaggedFrame as u16
               });

    //inner vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 0,
                    drop_eligible_indicator: false,
                    vlan_identifier: 0x234,
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
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

#[test]
fn udp_builder_eth_ip_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .ip(IpHeader::Version6(Ipv6Header{
                        traffic_class: 1,
                        flow_label: 2,
                        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
                        next_header: IpTrafficClass::Udp as u8,
                        hop_limit: 47,
                        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
                    }))
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
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 1,
        flow_label: 2,
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

#[test]
fn udp_builder_eth_vlan_ip_udp() {
    //generate
    let in_payload = [50,51,52,53];
    let mut serialized = Vec::new();
    PacketBuilder::ethernet2([1,2,3,4,5,6], [7,8,9,10,11,12])
                  .vlan(VlanHeader::Single(SingleVlanHeader{
                      priority_code_point: 1,
                      drop_eligible_indicator: true,
                      vlan_identifier: 0x123,
                      ether_type: 0 //should be overwritten
                  }))
                  .ip(IpHeader::Version6(Ipv6Header{
                        traffic_class: 1,
                        flow_label: 2,
                        payload_length: (UdpHeader::SERIALIZED_SIZE + in_payload.len()) as u16,
                        next_header: IpTrafficClass::Udp as u8,
                        hop_limit: 47,
                        source: [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                        destination: [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46]
                    }))
                  .udp(48,49)
                  .write(&mut serialized, &in_payload)
                  .unwrap();

    //check the deserialized size
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               SingleVlanHeader::SERIALIZED_SIZE +
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
    assert_eq!(Ethernet2Header::read(&mut cursor).unwrap(), 
               Ethernet2Header{
                    source: [1,2,3,4,5,6],
                    destination: [7,8,9,10,11,12],
                    ether_type: EtherType::VlanTaggedFrame as u16
               });

    //outer vlan header
    assert_eq!(SingleVlanHeader::read(&mut cursor).unwrap(),
               SingleVlanHeader{
                    priority_code_point: 1,
                    drop_eligible_indicator: true,
                    vlan_identifier: 0x123,
                    ether_type: EtherType::Ipv6 as u16
               });

    //ip header
    let ip_actual = Ipv6Header::read(&mut cursor).unwrap();
    let ip_expected = Ipv6Header{
        traffic_class: 1,
        flow_label: 2,
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

#[test]
fn size() {
    //ipv4 no vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv4Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,

               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .ipv4([13,14,15,16], [17,18,19,20], 21)
                             .udp(22,23)
                             .size(123));

    //ipv6 no vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,
               
               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                                   [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                                   47)
                             .udp(22,23)
                             .size(123));

    //ipv4 single vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               SingleVlanHeader::SERIALIZED_SIZE +
               Ipv4Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,

               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .single_vlan(0x123)
                             .ipv4([13,14,15,16], [17,18,19,20], 21)
                             .udp(22,23)
                             .size(123));

    //ipv6 double vlan
    assert_eq!(Ethernet2Header::SERIALIZED_SIZE + 
               DoubleVlanHeader::SERIALIZED_SIZE +
               Ipv6Header::SERIALIZED_SIZE + 
               UdpHeader::SERIALIZED_SIZE +
               123,

               PacketBuilder::ethernet2([1,2,3,4,5,6],[7,8,9,10,11,12])
                             .double_vlan(0x123, 0x234)
                             .ipv6([11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
                                   [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
                                   47)
                             .udp(22,23)
                             .size(123));
}