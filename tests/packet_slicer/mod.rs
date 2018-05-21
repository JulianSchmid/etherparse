use etherparse::*;

#[test]
fn eth_ipv4_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let mut it = PacketSlicer::ethernet2(&buffer[..]);

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpHeader(
                    Slice::<UdpHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE + Ipv4Header::SERIALIZED_SIZE..]).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpPayload(
                    &buffer[Ethernet2Header::SERIALIZED_SIZE + Ipv4Header::SERIALIZED_SIZE + UdpHeader::SERIALIZED_SIZE..]
               ));
    assert_matches!(it.next(), None);
}


#[test]
fn eth_ipv6_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let mut it = PacketSlicer::ethernet2(&buffer[..]);

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ipv6Header(
                    Slice::<Ipv6Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpHeader(
                    Slice::<UdpHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE + Ipv6Header::SERIALIZED_SIZE..]).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpPayload(
                    &buffer[Ethernet2Header::SERIALIZED_SIZE + Ipv6Header::SERIALIZED_SIZE + UdpHeader::SERIALIZED_SIZE..]
               ));
    assert_matches!(it.next(), None);
}

#[test]
fn eth_single_vlan_ipv6_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .single_vlan(123)
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let mut it = PacketSlicer::ethernet2(&buffer[..]);

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::SingleVlanHeader(
                    Slice::<SingleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ipv6Header(
                    Slice::<Ipv6Header>::from_slice(
                        &buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE..]
                    ).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpHeader(
                    Slice::<UdpHeader>::from_slice(
                        &buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE + Ipv6Header::SERIALIZED_SIZE..]
                    ).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpPayload(
                    &buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE + Ipv6Header::SERIALIZED_SIZE + UdpHeader::SERIALIZED_SIZE..]
               ));
    assert_matches!(it.next(), None);
}

#[test]
fn eth_double_vlan_ipv4_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .double_vlan(123, 456)
                  .ipv4([0;4], [1;4], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let mut it = PacketSlicer::ethernet2(&buffer[..]);

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::DoubleVlanHeader(
                    Slice::<DoubleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(
                        &buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE..]
                    ).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpHeader(
                    Slice::<UdpHeader>::from_slice(
                        &buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE + Ipv4Header::SERIALIZED_SIZE..]
                    ).unwrap()
               ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpPayload(
                    &buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE + Ipv4Header::SERIALIZED_SIZE + UdpHeader::SERIALIZED_SIZE..]
               ));
    assert_matches!(it.next(), None);
}

#[test]
fn eth_error() {
    //check that an unexpected eof error is passed through
    let buffer = [1]; //too small for an ethernet II header
    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_matches!(it.next(),
                    Some(Err(_)));
    assert_matches!(it.next(), None);
}

#[test]
fn vlan() {
    const ETH_TYPES: [u16;3] = [
        EtherType::VlanTaggedFrame as u16,
        EtherType::ProviderBridging as u16,
        EtherType::VlanDoubleTaggedFrame as u16
    ];
    for id in ETH_TYPES.iter() {
        //single vlans
        {
            let mut buffer = Vec::new();
            Ethernet2Header{
                source: [0;6],
                destination: [0;6],
                ether_type: *id
            }.write(&mut buffer).unwrap();

            SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 123,
                ether_type: EtherType::WakeOnLan as u16
            }.write(&mut buffer).unwrap();

            let mut it = PacketSlicer::ethernet2(&buffer[..]);
            //normal parsing
            {
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::SingleVlanHeader(
                                Slice::<SingleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                           ));
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Payload(
                                EtherType::WakeOnLan as u16,
                                &buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE..]
                           ));
            }
            //length error
            {
                let mut it = PacketSlicer::ethernet2(&buffer[..buffer.len()-1]);
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_matches!(it.next(),
                                Some(Err(_)));
                assert_matches!(it.next(), None);
            }
        }
        //double vlans
        {
            let mut buffer = Vec::new();
            Ethernet2Header{
                source: [0;6],
                destination: [0;6],
                ether_type: *id
            }.write(&mut buffer).unwrap();

            SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 123,
                ether_type: *id
            }.write(&mut buffer).unwrap();

            SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 123,
                ether_type: *id
            }.write(&mut buffer).unwrap();

            //normal parsing
            {
                let mut it = PacketSlicer::ethernet2(&buffer[..]);

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::DoubleVlanHeader(
                                Slice::<DoubleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                           ));
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Payload(
                                *id,
                                &buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE..]
                           ));
            }
            //length error
            {
                let mut it = PacketSlicer::ethernet2(&buffer[..buffer.len()-1]);
                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_matches!(it.next(),
                                Some(Err(_)));
                assert_matches!(it.next(), None);
            }
        }
    }
}

#[test]
fn ipv4_error() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    //remove data to trigger an error during ipv4 parsing
    buffer.resize(Ethernet2Header::SERIALIZED_SIZE + 1, 0);

    //check that the ethernet II header is parsed and an error is provided during ipv4 parsing
    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_matches!(it.next(),
                    Some(Err(_)));
    assert_matches!(it.next(), None);
}

#[test]
fn ipv6_error() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    //remove data to trigger an error during ipv6 parsing
    buffer.resize(Ethernet2Header::SERIALIZED_SIZE + 1, 0);

    //check that the ethernet II header is parsed and an error is provided during ipv6 parsing
    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_matches!(it.next(),
                    Some(Err(_)));
    assert_matches!(it.next(), None);
}

#[test]
fn udp_error() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    //remove data to trigger an error during udp parsing
    buffer.resize(Ethernet2Header::SERIALIZED_SIZE + Ipv4Header::SERIALIZED_SIZE + 1, 0);

    //check that the ethernet II & ipv4 header is parsed and an error is provided during udp parsing
    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
               ));
    assert_matches!(it.next(),
                    Some(Err(_)));
    assert_matches!(it.next(), None);
}