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
    Version6(Ipv6Header)
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
            Some(IpTest::Version6(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        match &self.transport {
            Some(TransportTest::Udp(header)) => header.write(&mut buffer).unwrap(),
            None => {}
        }
        use std::io::Write;
        buffer.write(&self.payload[..]).unwrap();

        //slice the packet
        let result = SlicedPacket::from_ethernet(&buffer).unwrap();

        //test the result
        match &result.link {
            Some(LinkSlice::Ethernet2(actual)) => assert_eq!(self.eth, actual.to_header()),
            _ => panic!("missing or unexpected link")
        }
        match &self.vlan {
            Some(VlanTest::Single(expected_header)) => {
                match result.vlan {
                    Some(VlanSlice::SingleVlan(actual)) => assert_eq!(expected_header, &actual.to_header()),
                    value => panic!("expected an single vlan header but found {:?}", value)
                }
            },
            Some(VlanTest::Double(expected_outer, expected_inner)) => {
                match result.vlan {
                    Some(VlanSlice::DoubleVlan(actual)) => {
                        assert_eq!(expected_outer, &actual.outer().to_header());
                        assert_eq!(expected_inner, &actual.inner().to_header());
                    },
                    value => panic!("expected an double vlan header but found {:?}", value)
                }
            },
            None => assert_eq!(None, result.vlan)
        }
        match &self.ip {
            Some(IpTest::Version4(expected_header, expect_options)) => {
                match &result.ip {
                    Some(InternetSlice::Ipv4(actual)) => {
                        assert_eq!(expected_header, &actual.to_header());
                        assert_eq!(&expect_options[..], actual.options());
                    },
                    value => panic!("expected an ipv4 header but found {:?}", value)
                }
            },
            Some(IpTest::Version6(expected)) => {
                match &result.ip {
                    Some(InternetSlice::Ipv6(actual_header, _actual_extensions)) => {
                        assert_eq!(expected, &actual_header.to_header());
                        // TODO ipv6 header extensions
                    },
                    value => panic!("expected an ipv6 header but found {:?}", value)
                }
            },
            None => assert_eq!(None, result.ip)
        }
        match &self.transport {
            Some(TransportTest::Udp(expected)) => {
                match &result.transport {
                    Some(TransportSlice::Udp(actual)) => assert_eq!(expected, &actual.to_header()),
                    value => panic!("expected an udp header but found {:?}", value)

                }
            },
            None => assert_eq!(None, result.transport)
        }
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

    fn run_ipv6(&self, ip: &Ipv6Header, udp: &UdpHeader) {
        // TODO header extensions
    }

    fn run_vlan(&self, outer_vlan: &SingleVlanHeader, inner_vlan: &SingleVlanHeader, ipv4: &(Ipv4Header, Vec<u8>), ipv6: &Ipv6Header, udp: &UdpHeader) {

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
        setup_single(EtherType::Ipv6 as u16).run_ipv6(ipv6, udp);

        //double 
        for ether_type in VLAN_ETHER_TYPES {
            setup_double(*ether_type, inner_vlan.ether_type).run();
            setup_double(*ether_type, EtherType::Ipv4 as u16).run_ipv4(ipv4, udp);
            setup_double(*ether_type, EtherType::Ipv6 as u16).run_ipv6(ipv6, udp);
        }
    }

    fn run_udp(&self, udp: &UdpHeader) {
        let mut test = self.clone();
        test.transport = Some(TransportTest::Udp(udp.clone()));
        test.run();
    }
}

proptest! {
    #[test]
    fn test_packet_slicing(ref eth in ethernet_2_unknown(),
                           ref vlan_outer in vlan_single_unknown(),
                           ref vlan_inner in vlan_single_unknown(),
                           ref ipv4 in ipv4_unknown(),
                           ref ipv6 in ipv6_unknown(),
                           ref udp in udp_any(),
                           ref payload in proptest::collection::vec(any::<u8>(), 0..1024))
    {
        let setup_eth = | ether_type: u16 | -> ComponentTest {
            ComponentTest {
                eth: {
                    let mut result = eth.clone();
                    result.ether_type = ether_type;
                    result
                },
                vlan: None,
                ip: None,
                transport: None,
                payload: payload.clone()
            }
        };

        //ethernet 2: standalone, ipv4, ipv6
        setup_eth(eth.ether_type).run();
        setup_eth(EtherType::Ipv4 as u16).run_ipv4(ipv4, udp);
        setup_eth(EtherType::Ipv6 as u16).run_ipv6(ipv6, udp);

        //vlans
        for ether_type in VLAN_ETHER_TYPES {
            setup_eth(*ether_type).run_vlan(vlan_outer, vlan_inner, ipv4, ipv6, udp);
        }
    }
}