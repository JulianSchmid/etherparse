use etherparse::*;
use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
enum VlanTest {
    Single(SingleVlanHeader),
    Double(SingleVlanHeader, SingleVlanHeader),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IpTest {
    Version4(Ipv4Header, Vec<u8>),
    Version6(Ipv6Header, Vec<(u8, Vec<u8>)>)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TransportTest {
    Udp(UdpHeader)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComponentTest {
    eth: Ethernet2Header,
    vlan: Option<VlanTest>,
    ip: Option<IpTest>,
    transport: Option<TransportTest>,
    payload: Vec<u8>
}

static VLAN_ETHER_TYPES: &'static [u16] = &[
    EtherType::VlanTaggedFrame as u16,
    EtherType::ProviderBridging as u16,
    EtherType::VlanDoubleTaggedFrame as u16
];

impl ComponentTest {
    fn run(&self) {
        let mut buffer = Vec::<u8>::new();

        //fill all the elements
        self.eth.write(&mut buffer).unwrap();
        match &self.vlan {
            Some(VlanTest::Single(header)) => header.write(&mut buffer).unwrap(),
            Some(VlanTest::Double(outer, inner)) => {
                outer.write(&mut buffer).unwrap();
                inner.write(&mut buffer).unwrap();
            },
            None => {}
        }
        match &self.ip {
            Some(IpTest::Version4(header, options)) => header.write_raw(&mut buffer, options).unwrap(),
            Some(IpTest::Version6(header, exts)) => {
                header.write(&mut buffer).unwrap();
                for ref ext in exts {
                    buffer.write(&ext.1).unwrap();
                }
            },
            None => {}
        }
        match &self.transport {
            Some(TransportTest::Udp(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        use std::io::Write;
        buffer.write(&self.payload[..]).unwrap();

        //slice the packet & test the result
        self.assert_sliced_packet(SlicedPacket::from_ethernet(&buffer).unwrap());

        //test that an error is generated when the data is too small
        assert_matches!(SlicedPacket::from_ethernet(&buffer[..buffer.len() - 1 - self.payload.len()]), 
                        Err(ReadError::IoError(_)));
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
            {
                use VlanSlice::*;
                use self::VlanTest::*;
                match result.vlan {
                    Some(SingleVlan(actual)) => Some(Single(actual.to_header())),
                    Some(DoubleVlan(actual)) => Some(Double(actual.outer().to_header(),
                                                            actual.inner().to_header())),
                    None => None
                }
            }
        );

        //ip
        assert_eq!(self.ip,
            {
                use InternetSlice::*;
                use self::IpTest::*;
                match result.ip {
                    Some(Ipv4(actual)) => Some(Version4(actual.to_header(), 
                                                        actual.options().to_vec())),
                    Some(Ipv6(actual_header, actual_extensions)) => 
                        Some(Version6(actual_header.to_header(),
                                      actual_extensions.iter()
                                                       .filter(|x| x.is_some() )
                                                       .map(|x| {
                                                            let r = x.as_ref().unwrap();
                                                            (r.0, r.1.slice.to_vec())
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
                Some(TransportSlice::Udp(actual)) => Some(TransportTest::Udp(actual.to_header())),
                None => None
            }
        );

        //payload
        assert_eq!(self.payload[..], result.payload[..]);
    }

    fn run_ipv4(&self, ip: &(Ipv4Header, Vec<u8>), udp: &UdpHeader) {
        //ipv4 only
        {
            let mut test = self.clone();
            test.ip = Some(IpTest::Version4(ip.0.clone(), ip.1.clone()));
            test.run();
        }

        //udp
        {
            let mut test = self.clone();
            test.ip = Some(IpTest::Version4({
                let mut header = ip.0.clone();
                header.protocol = IpTrafficClass::Udp as u8;
                header
            }, ip.1.clone()));
            test.run_udp(udp);
        }
    }

    fn run_ipv6(&self, ip: &Ipv6Header, ipv6_ext: &Vec<(u8, Vec<u8>)>, udp: &UdpHeader) {
        
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

        //standalone & udp (without extension headers)
        setup(ip.next_header, &Vec::new()).run();
        setup(ip.next_header, ipv6_ext).run();
        setup(IpTrafficClass::Udp as u8, &Vec::new()).run_udp(udp);
        setup(IpTrafficClass::Udp as u8, ipv6_ext).run_udp(udp);
    }

    fn run_vlan(&self, 
                outer_vlan: &SingleVlanHeader, 
                inner_vlan: &SingleVlanHeader, 
                ipv4: &(Ipv4Header, Vec<u8>), 
                ipv6: &Ipv6Header, 
                ipv6_ext: &Vec<(u8, Vec<u8>)>, 
                udp: &UdpHeader)
    {
        let setup_single = | ether_type: u16| -> ComponentTest {
            let mut result = self.clone();
            result.vlan = Some(VlanTest::Single({
                let mut v = outer_vlan.clone();
                v.ether_type = ether_type;
                v
            }));
            result
        };
        let setup_double = |outer_ether_type: u16, inner_ether_type: u16| -> ComponentTest {
            let mut result = self.clone();
            result.vlan = Some(VlanTest::Double({
                let mut v = outer_vlan.clone();
                v.ether_type = outer_ether_type;
                v
            },{
                let mut v = inner_vlan.clone();
                v.ether_type = inner_ether_type;
                v
            }));
            result
        };

        //single
        setup_single(outer_vlan.ether_type).run();
        setup_single(EtherType::Ipv4 as u16).run_ipv4(ipv4, udp);
        setup_single(EtherType::Ipv6 as u16).run_ipv6(ipv6, ipv6_ext, udp);

        //double 
        for ether_type in VLAN_ETHER_TYPES {
            setup_double(*ether_type, inner_vlan.ether_type).run();
            setup_double(*ether_type, EtherType::Ipv4 as u16).run_ipv4(ipv4, udp);
            setup_double(*ether_type, EtherType::Ipv6 as u16).run_ipv6(ipv6, ipv6_ext, udp);
        }
    }

    fn run_udp(&self, udp: &UdpHeader) {
        let mut test = self.clone();
        test.transport = Some(TransportTest::Udp(udp.clone()));
        test.run()
    }
}

proptest! {
    ///Test that all known packet compositions are parsed correctly.
    #[test]
    fn test_packet_slicing(ref eth in ethernet_2_unknown(),
                           ref vlan_outer in vlan_single_unknown(),
                           ref vlan_inner in vlan_single_unknown(),
                           ref ipv4 in ipv4_unknown(),
                           ref ipv6 in ipv6_unknown(),
                           ref ip6_ext in ipv6_extensions_unknown(),
                           ref udp in udp_any(),
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
        setup_eth(EtherType::Ipv4 as u16).run_ipv4(ipv4, udp);
        setup_eth(EtherType::Ipv6 as u16).run_ipv6(ipv6, ip6_ext, udp);

        //vlans
        for ether_type in VLAN_ETHER_TYPES {
            setup_eth(*ether_type).run_vlan(vlan_outer, vlan_inner, ipv4, ipv6, ip6_ext, udp);
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