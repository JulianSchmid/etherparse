use super::*;

/*

#[derive(Clone, Debug, Eq, PartialEq)]
enum IpTest {
    Version4(Ipv4Header),
    Version6(Ipv6Header, Vec<(u8, Vec<u8>)>)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComponentTest {
    eth: Ethernet2Header,
    vlan: Option<VlanHeader>,
    ip: Option<IpTest>,
    transport: Option<TransportHeader>,
    payload: Vec<u8>
}

static VLAN_ETHER_TYPES: &'static [u16] = &[
    EtherType::VlanTaggedFrame as u16,
    EtherType::ProviderBridging as u16,
    EtherType::VlanDoubleTaggedFrame as u16
];

impl ComponentTest {

    fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::new();

        //fill all the elements
        self.eth.write(&mut buffer).unwrap();
        use crate::VlanHeader::*;
        match &self.vlan {
            Some(Single(header)) => header.write(&mut buffer).unwrap(),
            Some(Double(header)) => {
                header.write(&mut buffer).unwrap();
            },
            None => {}
        }
        match &self.ip {
            Some(IpTest::Version4(header)) => header.write_raw(&mut buffer).unwrap(),
            Some(IpTest::Version6(header, exts)) => {
                header.write(&mut buffer).unwrap();
                for ref ext in exts {
                    buffer.write(&ext.1).unwrap();
                }
            },
            None => {}
        }
        match &self.transport {
            Some(TransportHeader::Udp(header)) => header.write(&mut buffer).unwrap(),
            Some(TransportHeader::Tcp(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        use std::io::Write;
        buffer.write(&self.payload[..]).unwrap();
        buffer
    }

    ///Serialize a packet without ethernet & vlan headers.
    fn serialize_from_ip(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::new();
        match &self.ip {
            Some(IpTest::Version4(header)) => header.write_raw(&mut buffer).unwrap(),
            Some(IpTest::Version6(header, exts)) => {
                header.write(&mut buffer).unwrap();
                for ref ext in exts {
                    buffer.write(&ext.1).unwrap();
                }
            },
            None => {}
        }
        match &self.transport {
            Some(TransportHeader::Udp(header)) => header.write(&mut buffer).unwrap(),
            Some(TransportHeader::Tcp(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        use std::io::Write;
        buffer.write(&self.payload[..]).unwrap();
        buffer
    }

    fn run(&self) {
        //packet with ethernet2 & vlan headers
        {
            //serialize to buffer
            let buffer = self.serialize();

            //test the slicing & decoding of the packet
            self.assert_sliced_packet(SlicedPacket::from_ethernet(&buffer).unwrap());
            self.assert_decoded_packet(&buffer);

            //test that an error is generated when the data is too small
            {
                let too_short_slice = &buffer[..buffer.len() - 1 - self.payload.len()];
                assert_matches!(SlicedPacket::from_ethernet(too_short_slice), 
                                Err(ReadError::UnexpectedEndOfSlice(_)));
                assert_matches!(PacketHeaders::from_ethernet_slice(too_short_slice), 
                                Err(ReadError::UnexpectedEndOfSlice(_)));
            }
        }
        //packet from the internet layer down (without ethernet2 & vlan headers)
        if self.ip.is_some() {
            //serialize to buffer
            let buffer = self.serialize_from_ip();

            //test the decoding of the packet
            self.assert_from_ip_sliced_packet(SlicedPacket::from_ip(&buffer).unwrap());
            self.assert_from_ip_decoded_packet(&buffer);

            //test that an error is generated when the data is too small
            {
                let too_short_slice = &buffer[..buffer.len() - 1 - self.payload.len()];
                assert_matches!(SlicedPacket::from_ip(too_short_slice), 
                                Err(ReadError::UnexpectedEndOfSlice(_)));
                assert_matches!(PacketHeaders::from_ip_slice(too_short_slice), 
                                Err(ReadError::UnexpectedEndOfSlice(_)));
            }
        }
    }

    fn run_ipv6_ext_failure(&self) {
        //serialize to buffer
        let buffer = self.serialize();

        //slice & expect the error
        assert_matches!(SlicedPacket::from_ethernet(&buffer),
                        Err(ReadError::Ipv6TooManyHeaderExtensions));

        //same should happen for decoding
        assert_matches!(PacketHeaders::from_ethernet_slice(&buffer),
                        Err(ReadError::Ipv6TooManyHeaderExtensions));
    }

    fn assert_sliced_packet(&self, result: SlicedPacket) {
        //assert identity to touch the derives (code coverage hack)
        assert_eq!(result, result);

        //ethernet
        match &result.link {
            Some(LinkSlice::Ethernet2(actual)) => assert_eq!(self.eth, actual.to_header()),
            _ => panic!("missing or unexpected link")
        }

        //vlan
        assert_eq!(self.vlan,
            match result.vlan {
                Some(value) => Some(value.to_header()),
                None => None
            }
        );

        //ip
        assert_eq!(self.ip,
            {
                use crate::InternetSlice::*;
                use self::IpTest::*;
                match result.ip {
                    Some(Ipv4(actual)) => Some(Version4(actual.to_header())),
                    Some(Ipv6(actual_header, actual_extensions)) => 
                        Some(Version6(actual_header.to_header(),
                                      actual_extensions.iter()
                                                       .filter(|x| x.is_some() )
                                                       .map(|x| {
                                                            let r = x.as_ref().unwrap();
                                                            (r.0, r.1.slice().to_vec())
                                                       })
                                                       .collect()
                        )),
                    None => None
                }
            }
        );
        
        //transport
        assert_eq!(self.transport,
            match result.transport {
                Some(TransportSlice::Udp(actual)) => Some(TransportHeader::Udp(actual.to_header())),
                Some(TransportSlice::Tcp(actual)) => Some(TransportHeader::Tcp(actual.to_header())),
                None => None
            }
        );

        //payload
        assert_eq!(self.payload[..], result.payload[..]);
    }

    fn assert_from_ip_sliced_packet(&self, result: SlicedPacket) {
        //assert identity to touch the derives (code coverage hack)
        assert_eq!(result, result);

        //ethernet & vlan
        assert_eq!(None, result.link);
        assert_eq!(None, result.vlan);
        
        //ip
        assert_eq!(self.ip,
            {
                use crate::InternetSlice::*;
                use self::IpTest::*;
                match result.ip {
                    Some(Ipv4(actual)) => Some(Version4(actual.to_header())),
                    Some(Ipv6(actual_header, actual_extensions)) => 
                        Some(Version6(actual_header.to_header(),
                                      actual_extensions.iter()
                                                       .filter(|x| x.is_some() )
                                                       .map(|x| {
                                                            let r = x.as_ref().unwrap();
                                                            (r.0, r.1.slice().to_vec())
                                                       })
                                                       .collect()
                        )),
                    None => None
                }
            }
        );
        
        //transport
        assert_eq!(self.transport,
            match result.transport {
                Some(TransportSlice::Udp(actual)) => Some(TransportHeader::Udp(actual.to_header())),
                Some(TransportSlice::Tcp(actual)) => Some(TransportHeader::Tcp(actual.to_header())),
                None => None
            }
        );

        //payload
        assert_eq!(self.payload[..], result.payload[..]);
    }

    fn assert_decoded_packet(&self, buffer: &Vec<u8>) {
        //decode
        let actual = PacketHeaders::from_ethernet_slice(&buffer[..]).unwrap();

        //ethernet
        assert_eq!(self.eth, actual.link.unwrap());

        //vlan
        assert_eq!(self.vlan, actual.vlan);

        //ip
        assert_eq!(actual.ip,
            {
                use self::IpTest::*;
                match &self.ip {
                    Some(Version4(value)) => Some(IpHeader::Version4(value.clone())),
                    Some(Version6(value, _)) => Some(IpHeader::Version6(value.clone())),
                    None => None
                }
            }
        );

        //transport
        assert_eq!(self.transport, actual.transport);

        if self.payload[..] != actual.payload[..] {
            println!("foo");
        }

        //payload
        assert_eq!(self.payload[..], actual.payload[..]);
    }

    fn assert_from_ip_decoded_packet(&self, buffer: &Vec<u8>) {
        //decode
        let actual = PacketHeaders::from_ip_slice(&buffer[..]).unwrap();

        //ethernet
        assert_eq!(None, actual.link);

        //vlan
        assert_eq!(None, actual.vlan);

        //ip
        assert_eq!(actual.ip,
            {
                use self::IpTest::*;
                match &self.ip {
                    Some(Version4(value)) => Some(IpHeader::Version4(value.clone())),
                    Some(Version6(value, _)) => Some(IpHeader::Version6(value.clone())),
                    None => None
                }
            }
        );

        //transport
        assert_eq!(self.transport, actual.transport);

        //payload
        assert_eq!(self.payload[..], actual.payload[..]);
    }

    fn run_ipv4(&self, ip: &Ipv4Header, udp: &UdpHeader, tcp: &TcpHeader) {
        //ipv4 only
        {
            let mut test = self.clone();
            test.ip = Some(IpTest::Version4(ip.clone()));
            test.run();
        }

        //udp
        {
            let mut test = self.clone();
            test.ip = Some(IpTest::Version4({
                let mut header = ip.clone();
                header.protocol = IpTrafficClass::Udp as u8;
                header
            }));
            test.run_udp(udp);
        }
        //tcp
        {
            let mut test = self.clone();
            test.ip = Some(IpTest::Version4({
                let mut header = ip.clone();
                header.protocol = IpTrafficClass::Tcp as u8;
                header
            }));
            test.run_tcp(tcp);
        }
    }

    fn run_ipv6(&self, ip: &Ipv6Header, ipv6_ext: &Vec<(u8, Vec<u8>)>, udp: &UdpHeader, tcp: &TcpHeader) {
        
        let setup = | next_header: u8, exts: &Vec<(u8, Vec<u8>)>| -> ComponentTest {
            let mut result = self.clone();
            result.ip = Some(IpTest::Version6({
                let mut v = ip.clone();
                v.next_header = if exts.len() > 0 {
                    //set the next header of the ipv6 header to the first extension header
                    exts[0].0
                } else {
                    // no extension headers, straight up point to the next extension header
                    next_header
                };
                v
            }, {
                let mut ext_result = exts.clone();
                if ext_result.len() > 0 {
                    //set the last next_header to the given one
                    let last_index = ext_result.len()-1;
                    ext_result[last_index].1[0] = next_header;
                }
                ext_result
            }));
            result
        };

        //standalone & udp & extension headers
        setup(ip.next_header, &Vec::new()).run();
        setup(ip.next_header, ipv6_ext).run();
        setup(IpTrafficClass::Udp as u8, &Vec::new()).run_udp(udp);
        setup(IpTrafficClass::Udp as u8, ipv6_ext).run_udp(udp);
        setup(IpTrafficClass::Tcp as u8, &Vec::new()).run_tcp(tcp);
        setup(IpTrafficClass::Tcp as u8, ipv6_ext).run_tcp(tcp);

        //extensions
        const IPV6_EXT_IDS: [u8;6] = [
            IpTrafficClass::IPv6HeaderHopByHop as u8,
            IpTrafficClass::IPv6RouteHeader as u8,
            IpTrafficClass::IPv6FragmentationHeader as u8,
            IpTrafficClass::IPv6DestinationOptions as u8,
            IpTrafficClass::AuthenticationHeader as u8,
            IpTrafficClass::EncapsulatingSecurityPayload as u8
        ];

        //generate a too many ipv6 extensions error
        for id in IPV6_EXT_IDS.iter() {
            let mut exts = ipv6_ext.clone();

            //set the last entry of the extension header to the id
            if exts.len() > 0 {
                let len = exts.len();
                exts[len - 1].1[0] = *id;
            }

            //extend the vector to the maximum size
            exts.resize(IPV6_MAX_NUM_HEADER_EXTENSIONS, {
                (*id, vec![*id,0,0,0,  0,0,0,0])
            });

            //expect the failure
            setup(*id, &exts).run_ipv6_ext_failure();
        }
    }

    fn run_vlan(&self, 
                outer_vlan: &SingleVlanHeader, 
                inner_vlan: &SingleVlanHeader, 
                ipv4: &Ipv4Header, 
                ipv6: &Ipv6Header, 
                ipv6_ext: &Vec<(u8, Vec<u8>)>, 
                udp: &UdpHeader,
                tcp: &TcpHeader)
    {
        let setup_single = | ether_type: u16| -> ComponentTest {
            let mut result = self.clone();
            result.vlan = Some(VlanHeader::Single({
                let mut v = inner_vlan.clone();
                v.ether_type = ether_type;
                v
            }));
            result
        };
        let setup_double = |outer_ether_type: u16, inner_ether_type: u16| -> ComponentTest {
            let mut result = self.clone();
            result.vlan = Some(VlanHeader::Double(DoubleVlanHeader{
                outer: {
                    let mut v = outer_vlan.clone();
                    v.ether_type = outer_ether_type;
                    v
                },
                inner: {
                    let mut v = inner_vlan.clone();
                    v.ether_type = inner_ether_type;
                    v
                }}));
            result
        };

        //single
        setup_single(inner_vlan.ether_type).run();
        setup_single(EtherType::Ipv4 as u16).run_ipv4(ipv4, udp, tcp);
        setup_single(EtherType::Ipv6 as u16).run_ipv6(ipv6, ipv6_ext, udp, tcp);

        //double 
        for ether_type in VLAN_ETHER_TYPES {
            setup_double(*ether_type, inner_vlan.ether_type).run();
            setup_double(*ether_type, EtherType::Ipv4 as u16).run_ipv4(ipv4, udp, tcp);
            setup_double(*ether_type, EtherType::Ipv6 as u16).run_ipv6(ipv6, ipv6_ext, udp, tcp);
        }
    }

    fn run_udp(&self, udp: &UdpHeader) {
        let mut test = self.clone();
        test.transport = Some(TransportHeader::Udp(udp.clone()));
        test.run()
    }

    fn run_tcp(&self, tcp: &TcpHeader) {
        let mut test = self.clone();
        test.transport = Some(TransportHeader::Tcp(tcp.clone()));
        test.run()
    }
}

proptest! {
    ///Test that all known packet compositions are parsed correctly.
    #[test]
    fn test_compositions(ref eth in ethernet_2_unknown(),
                         ref vlan_outer in vlan_single_unknown(),
                         ref vlan_inner in vlan_single_unknown(),
                         ref ipv4 in ipv4_unknown(),
                         ref ipv6 in ipv6_unknown(),
                         ref ip6_ext in ipv6_extensions_unknown(),
                         ref udp in udp_any(),
                         ref tcp in tcp_any(),
                         ref payload in proptest::collection::vec(any::<u8>(), 0..1024))
    {
        let setup_eth = | ether_type: u16 | -> ComponentTest {
            ComponentTest {
                payload: payload.clone(),
                eth: {
                    let mut result = eth.clone();
                    result.ether_type = ether_type;
                    result
                },
                vlan: None,
                ip: None,
                transport: None
            }
        };

        //ethernet 2: standalone, ipv4, ipv6
        setup_eth(eth.ether_type).run();
        setup_eth(EtherType::Ipv4 as u16).run_ipv4(ipv4, udp, tcp);
        setup_eth(EtherType::Ipv6 as u16).run_ipv6(ipv6, ip6_ext, udp, tcp);

        //vlans
        for ether_type in VLAN_ETHER_TYPES {
            setup_eth(*ether_type).run_vlan(vlan_outer, vlan_inner, ipv4, ipv6, ip6_ext, udp, tcp);
        }
    }
}

///Test that assert_sliced_packet is panicing when the ethernet header is missing 
#[test]
#[should_panic]
fn test_packet_slicing_panics() {
    let v = Vec::new();
    let s = SlicedPacket {
        link: None,
        vlan: None,
        ip: None,
        transport: None,
        payload: &v[..]
    };
    ComponentTest {
        eth: Ethernet2Header {
            source: [0;6],
            destination: [0;6],
            ether_type: 0
        },
        vlan: None,
        ip: None,
        transport: None,
        payload: vec![]
    }.assert_sliced_packet(s);
}
*/