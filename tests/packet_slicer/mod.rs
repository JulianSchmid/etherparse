use etherparse::*;

fn assert_udp(buffer: &[u8], expected: &[(usize, PacketSliceType)]) {
    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

    let mut size = 0;
    for (size_hint, e) in expected.iter() {
        assert_eq!(it.next().unwrap().unwrap(), 
                   *e);
        assert_eq!(it.size_hint(), (1, Some(*size_hint)));
        match e {
            PacketSliceType::Ethernet2Header(slice) => {
                size += slice.slice.len();
            },
            PacketSliceType::SingleVlanHeader(slice) => {
                size += slice.slice.len();
            },
            PacketSliceType::DoubleVlanHeader(slice) => {
                size += slice.slice.len();
            },
            PacketSliceType::Ipv4Header(slice) => {
                size += slice.slice.len();
            },
            PacketSliceType::Ipv6Header(slice) => {
                size += slice.slice.len();
            },
            _ => unreachable!()
        }
    }
    assert_eq!(it.next().unwrap().unwrap(),
               PacketSliceType::UdpHeader(
                    Slice::<UdpHeader>::from_slice(&buffer[size..]).unwrap()
                ));
    assert_eq!(it.size_hint(), (1, Some(1)));
    size += UdpHeader::SERIALIZED_SIZE;

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::UdpPayload(
                    &buffer[size..]
               ));
    assert_eq!(it.size_hint(), (0, Some(0)));

    assert_matches!(it.next(), None);
}

#[test]
#[should_panic]
fn assert_udp_panic() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
        &buffer,
        &[
            (   
                3,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ),
            ),
            (
                2,
                PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            ),
            (   
                1,
                PacketSliceType::UdpHeader(
                    Slice::<UdpHeader>::from_slice(&buffer).unwrap()
                ),
            ),
        ]);
}

#[test]
fn eth_ipv4_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
        &buffer,
        &[
            (   
                3,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ),
            ),
            (
                2,
                PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            )
    ]);
}

#[test]
fn eth_single_vlan_ipv4_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .single_vlan(123)
                  .ipv4([0;4], [1;4], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
        &buffer,
        &[
            (   
                2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ),
            ), (
                1 + 2,
                PacketSliceType::SingleVlanHeader(
                    Slice::<SingleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            ), (
                2,
                PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE..]).unwrap()
                )
            )
    ]);
}

#[test]
fn eth_double_vlan_ipv4_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .double_vlan(123, 456)
                  .ipv4([0;4], [1;4], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
        &buffer,
        &[
            (   
                2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ),
            ), (
                1 + 2,
                PacketSliceType::DoubleVlanHeader(
                    Slice::<DoubleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            ), (
                2,
                PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE..]).unwrap()
                )
            )
    ]);
}

#[test]
fn eth_ipv6_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
        &buffer,
        &[
            (   
                1 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ),
            ), (
                2,
                PacketSliceType::Ipv6Header(
                    Slice::<Ipv6Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            )
    ]);
}

#[test]
fn eth_single_vlan_ipv6_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .single_vlan(123)
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
       &buffer,
       &[
            (
                2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                )
            ), (
                1 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::SingleVlanHeader(
                    Slice::<SingleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            ), (
                2,
                PacketSliceType::Ipv6Header(
                    Slice::<Ipv6Header>::from_slice(
                        &buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE..]
                    ).unwrap()
                )
            )
    ]);
}

#[test]
fn eth_double_vlan_ipv6_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .double_vlan(123, 456)
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();
    assert_udp(
       &buffer,
       &[
            (
                2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                )
            ), (
                1 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2,
                PacketSliceType::DoubleVlanHeader(
                    Slice::<DoubleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                )
            ), (
                2,
                PacketSliceType::Ipv6Header(
                    Slice::<Ipv6Header>::from_slice(
                        &buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE..]
                    ).unwrap()
                )
            )
    ]);
}

#[test]
fn eth_payload() {
    let mut buffer = Vec::new();
    Ethernet2Header{
        source: [0;6],
        destination: [0;6],
        ether_type: EtherType::WakeOnLan as u16
    }.write(&mut buffer).unwrap();


    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.size_hint(), (1, Some(1)));

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Payload(
                    EtherType::WakeOnLan as u16,
                    &buffer[Ethernet2Header::SERIALIZED_SIZE..]
               ));
    assert_eq!(it.size_hint(), (0, Some(0)));

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

            //normal parsing
            {
                let mut it = PacketSlicer::ethernet2(&buffer[..]);
                assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_eq!(it.size_hint(), (1, Some(2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::SingleVlanHeader(
                                Slice::<SingleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                           ));
                assert_eq!(it.size_hint(), (1, Some(1)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Payload(
                                EtherType::WakeOnLan as u16,
                                &buffer[Ethernet2Header::SERIALIZED_SIZE + SingleVlanHeader::SERIALIZED_SIZE..]
                           ));
                assert_eq!(it.size_hint(), (0, Some(0)));

                assert_matches!(it.next(), None);
            }
            //length error
            {
                let mut it = PacketSlicer::ethernet2(&buffer[..buffer.len()-1]);
                assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_eq!(it.size_hint(), (1, Some(2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

                assert_matches!(it.next(),
                                Some(Err(_)));
                assert_eq!(it.size_hint(), (0, Some(0)));

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
                assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Header(
                                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                            ));
                assert_eq!(it.size_hint(), (1, Some(2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::DoubleVlanHeader(
                                Slice::<DoubleVlanHeader>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                           ));
                assert_eq!(it.size_hint(), (1, Some(1)));

                assert_eq!(it.next().unwrap().unwrap(), 
                           PacketSliceType::Ethernet2Payload(
                                *id,
                                &buffer[Ethernet2Header::SERIALIZED_SIZE + DoubleVlanHeader::SERIALIZED_SIZE..]
                           ));
                assert_eq!(it.size_hint(), (0, Some(0)));

                assert_matches!(it.next(), None);
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
fn ipv4_ip_payload() {
    let mut buffer = Vec::new();

    Ethernet2Header{
        source: [0;6],
        destination: [0;6],
        ether_type: EtherType::Ipv4 as u16
    }.write(&mut buffer).unwrap();

    Ipv4Header::new(
        8, 
        1, 
        IpTrafficClass::SccSp,
        [0;4], 
        [0;4]
    ).unwrap().write(&mut buffer, &[]).unwrap();

    use std::io::Write;
    buffer.write(&[1,2,3,4,5,6,7,8]).unwrap();

    let mut it = PacketSlicer::ethernet2(&buffer[..]);
    assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
    assert_eq!(it.size_hint(), (1, Some(1 + 2)));

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ipv4Header(
                    Slice::<Ipv4Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
               ));
    assert_eq!(it.size_hint(), (1, Some(1)));

    assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::IpPayload(
                    IpTrafficClass::SccSp as u8,
                    &buffer[Ethernet2Header::SERIALIZED_SIZE + Ipv4Header::SERIALIZED_SIZE..]
               ));
    assert_eq!(it.size_hint(), (0, Some(0)));

    assert_matches!(it.next(), None);
}

#[test]
fn ipv6_ip_payload() {
    let mut buffer = Vec::new();

    Ethernet2Header{
        source: [0;6],
        destination: [0;6],
        ether_type: EtherType::Ipv6 as u16
    }.write(&mut buffer).unwrap();

    Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: IpTrafficClass::SccSp as u8,
        hop_limit: 1,
        source: [0;16],
        destination: [0;16]
    }.write(&mut buffer).unwrap();

    use std::io::Write;
    buffer.write(&[1,2,3,4,5,6,7,8]).unwrap();

    let expected = [
        (
            PacketSliceType::Ethernet2Header(
                Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
            ),
            (1, Some(1 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2))
        ),
        (
            PacketSliceType::Ipv6Header(
                Slice::<Ipv6Header>::from_slice(
                    &buffer[Ethernet2Header::SERIALIZED_SIZE..]
                ).unwrap()
            ),
            (1, Some(1))
        ),
        (
            PacketSliceType::IpPayload(
                IpTrafficClass::SccSp as u8,
                &buffer[Ethernet2Header::SERIALIZED_SIZE + Ipv6Header::SERIALIZED_SIZE..]
            ),
            (0, Some(0))
        )
    ];

    let mut it = PacketSlicer::ethernet2(&buffer[..]);

    for (e, size_hint) in expected.iter() {
        assert_eq!(it.next().unwrap().unwrap(), 
                   *e);
        assert_eq!(it.size_hint(), *size_hint);
    }
    assert_matches!(it.next(), None);
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
fn ipv6_extension_headers() {
    use IpTrafficClass::*;
    use std::io::Write;
    const EXTENSION_IDS: [u8;7] = [
        IPv6HeaderHopByHop as u8,
        IPv6DestinationOptions as u8,
        IPv6RouteHeader as u8,
        IPv6FragmentationHeader as u8, //3
        IPv6AuthenticationHeader as u8,
        IPv6EncapSecurityPayload as u8,
        IPv6DestinationOptions as u8
    ];
    const SCCSP: u8 = IpTrafficClass::SccSp as u8;

    let setup = |buffer: &mut Vec<u8>, extensions: &[u8]| {
        Ethernet2Header{
            source: [0;6],
            destination: [0;6],
            ether_type: EtherType::Ipv6 as u16
        }.write(buffer).unwrap();

        Ipv6Header {
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
            next_header: EXTENSION_IDS[0],
            hop_limit: 1,
            source: [0;16],
            destination: [0;16]
        }.write(buffer).unwrap();

        buffer.write(extensions).unwrap();
    };

    let assert_setup = |it: &mut PacketSlicer, buffer: &Vec<u8>| -> usize {
        assert_eq!(it.size_hint(), (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

        assert_eq!(it.next().unwrap().unwrap(), 
               PacketSliceType::Ethernet2Header(
                    Slice::<Ethernet2Header>::from_slice(&buffer).unwrap()
                ));
        assert_eq!(it.size_hint(), (1, Some(1 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

        assert_eq!(it.next().unwrap().unwrap(), 
                   PacketSliceType::Ipv6Header(
                        Slice::<Ipv6Header>::from_slice(&buffer[Ethernet2Header::SERIALIZED_SIZE..]).unwrap()
                   ));
        assert_eq!(it.size_hint(), (1, Some(IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)));

        Ethernet2Header::SERIALIZED_SIZE + Ipv6Header::SERIALIZED_SIZE
    };

    //7 extensions (max)
    {
        let mut buffer = Vec::new();
        setup(&mut buffer, &[
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
            EXTENSION_IDS[2],1,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            EXTENSION_IDS[3],2,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            0,0,0,0,                0,0,0,0,
            //fragmentation header (fixed size 8 bytes)
            EXTENSION_IDS[4],5,0,0, 0,0,0,0,
            EXTENSION_IDS[5],0,0,0, 0,0,0,0,
            EXTENSION_IDS[6],0,0,0, 0,0,0,0,
            SCCSP,2,0,0, 0,0,0,0,

            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,0,
        ]);

        let mut it = PacketSlicer::ethernet2(&buffer[..]);
        let mut start = assert_setup(&mut it, &buffer);
        
        for (i, id) in EXTENSION_IDS.iter().enumerate() {
            let expected = Slice::<Ipv6ExtensionHeader>::from_slice(*id, &buffer[start..]).unwrap();
            start += expected.slice.len();

            assert_eq!(it.next().unwrap().unwrap(),
                       PacketSliceType::Ipv6ExtensionHeader(*id, expected));
            if i < IPV6_MAX_NUM_HEADER_EXTENSIONS - 1 {
                assert_eq!(it.size_hint(), (1, Some(IPV6_MAX_NUM_HEADER_EXTENSIONS - i - 1 + 2 )));
            } else {
                //at the last header the rest size becomes clear
                assert_eq!(it.size_hint(), (1, Some(1)));
            }
        }

        assert_eq!(it.next().unwrap().unwrap(), 
                   PacketSliceType::IpPayload(
                        IpTrafficClass::SccSp as u8,
                        &buffer[start..]
                   ));
        assert_eq!(it.size_hint(), (0, Some(0)));

        assert_matches!(it.next(), None);
    }

    //check the too many extension header error
    {
        let mut buffer = Vec::new();
        setup(&mut buffer, &[
            EXTENSION_IDS[1],0,0,0, 0,0,0,0,
            EXTENSION_IDS[2],1,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            EXTENSION_IDS[3],2,0,0, 0,0,0,0,
            0,0,0,0,                0,0,0,0,
            0,0,0,0,                0,0,0,0,
            //fragmentation header (fixed size 8 bytes)
            EXTENSION_IDS[4],5,0,0, 0,0,0,0,
            EXTENSION_IDS[5],0,0,0, 0,0,0,0,
            EXTENSION_IDS[6],0,0,0, 0,0,0,0,
            EXTENSION_IDS[1],2,0,0, 0,0,0,0,

            0,0,0,0,   0,0,0,0,
            0,0,0,0,   0,0,0,0,
        ]);

        let mut it = PacketSlicer::ethernet2(&buffer[..]);
        let mut start = assert_setup(&mut it, &buffer);

        for id in EXTENSION_IDS.iter() {
            let expected = Slice::<Ipv6ExtensionHeader>::from_slice(*id, &buffer[start..]).unwrap();
            start += expected.slice.len();

            assert_eq!(it.next().unwrap().unwrap(),
                       PacketSliceType::Ipv6ExtensionHeader(*id, expected));
        }

        //generate should generate a error
        assert_matches!(it.next(), Some(Err(ReadError::Ipv6TooManyHeaderExtensions)));
    }

    //check that errors are forwarded correctly
    {
        let mut buffer = Vec::new();
        setup(&mut buffer, &[
            EXTENSION_IDS[1],0,0,0, 0,0,0,
        ]);

        let mut it = PacketSlicer::ethernet2(&buffer[..]);
        assert_setup(&mut it, &buffer);
        assert_matches!(it.next(), Some(Err(_)));
    }
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