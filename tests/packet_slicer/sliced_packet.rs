use etherparse::*;
use super::super::*;

trait PacketComponentTest {
    fn serialize(&self, target: &mut Vec<u8>);
    fn assert_in_sliced_packet(&self, pkt: &SlicedPacket);
}

struct Ethernet2ComponentTest {
    pub header: Option<Ethernet2Header>
}

impl Ethernet2ComponentTest {
    pub fn new(header: Ethernet2Header) -> Box<Ethernet2ComponentTest> {
        Box::new(Ethernet2ComponentTest {
            header: Some(header)
        })
    }
}

impl PacketComponentTest for Ethernet2ComponentTest {

    fn serialize(&self, target: &mut Vec<u8>) {
        match &self.header {
            Some(value) => value.write(target).unwrap(),
            None => {}
        }
    }

    fn assert_in_sliced_packet(&self, pkt: &SlicedPacket) {
        match &self.header {
            Some(expected) => {
                match &pkt.link {
                    Some(LinkSlice::Ethernet2(actual)) => {
                        assert_eq!(expected, &actual.to_header());
                    },
                    unexpected => panic!("unexpected link slice {:?}", unexpected)
                }
            },
            None => {
                assert!(pkt.link.is_none());
            }
        }
    }
}

struct Ipv4ComponentTest {
    pub header: Option<Ipv4Header>,
    pub options: Option<Vec<u8>>
}

impl Ipv4ComponentTest {
    pub fn new(header: Ipv4Header, options: Vec<u8>) -> Box<Ipv4ComponentTest> {
        Box::new(Ipv4ComponentTest {
            header: Some(header),
            options: Some(options)
        })
    }
    pub fn none() -> Box<Ipv4ComponentTest> {
        Box::new(Ipv4ComponentTest {
            header: None,
            options: None
        })
    }
}

impl PacketComponentTest for Ipv4ComponentTest {

    fn serialize(&self, target: &mut Vec<u8>) {
        match &self.header {
            Some(value) => value.write_raw(target, &self.options.as_ref().unwrap()).unwrap(),
            None => {}
        }
    }

    fn assert_in_sliced_packet(&self, pkt: &SlicedPacket) {
        match &self.header {
            Some(expected) => {
                match &pkt.ip {
                    Some(InternetSlice::Ipv4(actual)) => {
                        assert_eq!(expected, &actual.to_header());
                        assert_eq!(&self.options.as_ref().unwrap()[..], actual.options());
                    },
                    unexpected => panic!("unexpected link slice {:?}", unexpected)
                }
            },
            None => {
                assert!(pkt.ip.is_none());
            }
        }
    }
}

struct Ipv6ComponentTest {
    pub header: Option<Ipv6Header>
}

impl Ipv6ComponentTest {
    pub fn new(header: Ipv6Header) -> Box<Ipv6ComponentTest> {
        Box::new(Ipv6ComponentTest {
            header: Some(header)
        })
    }
    pub fn none() -> Box<Ipv6ComponentTest> {
        Box::new(Ipv6ComponentTest {
            header: None
        })
    }
}

impl PacketComponentTest for Ipv6ComponentTest {

    fn serialize(&self, target: &mut Vec<u8>) {
        match &self.header {
            Some(value) => value.write(target).unwrap(),
            None => {}
        }
    }

    fn assert_in_sliced_packet(&self, pkt: &SlicedPacket) {
        match &self.header {
            Some(expected) => {
                match &pkt.ip {
                    Some(InternetSlice::Ipv6(actual)) => {
                        assert_eq!(expected, &actual.to_header());
                    },
                    unexpected => panic!("unexpected link slice {:?}", unexpected)
                }
            },
            None => {
                assert!(pkt.ip.is_none());
            }
        }
    }
}

fn run_component_test(test_components: Vec<Box<PacketComponentTest>>) {
    let mut buffer = Vec::<u8>::new();

    //fill the elements
    for c in &test_components {
        c.serialize(&mut buffer);
    }

    //slice the packet
    let result = SlicedPacket::from_ethernet(&buffer).unwrap();
    println!("{:?}", result);

    //test the result
    for c in &test_components {
        c.assert_in_sliced_packet(&result);
    }
}

proptest! {
    #[test]
    fn ethernet2_only(ref eth in ethernet_2_unknown()) {
        run_component_test(vec![
            Ethernet2ComponentTest::new(eth.clone()),
            Ipv4ComponentTest::none()
        ]);
    }
}

proptest! {
    #[test]
    fn ethernet2_ipv4(ref eth in ethernet_2_with(EtherType::Ipv4),
                      ref ip in ipv4_unknown())
    {
        run_component_test(vec![
            Ethernet2ComponentTest::new(eth.clone()),
            Ipv4ComponentTest::new(ip.0.clone(), ip.1.clone())
        ]);
    }
}

proptest! {
    #[test]
    fn ethernet2_ipv6(ref eth in ethernet_2_with(EtherType::Ipv6),
                      ref ip in ipv6_unknown())
    {
        run_component_test(vec![
            Ethernet2ComponentTest::new(eth.clone()),
            Ipv6ComponentTest::new(ip.clone())
        ]);
    }
}