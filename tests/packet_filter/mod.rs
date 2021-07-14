use super::*;
#[allow(deprecated)]
use etherparse::packet_filter::*;
use proptest::*;


#[test]
#[allow(deprecated)]
fn default() {
    let value: ElementFilter<IpFilter> = Default::default();
    assert_eq!(ElementFilter::Any, value);
}

///The packet filter test generates all permutation of packet combinations & filter configurations
///and tests that all of them return the correct result.
#[allow(deprecated)]
#[derive(Debug, Clone, Default)]
struct PacketFilterTest {
    link: Option<Ethernet2Header>,
    vlan: Option<VlanHeader>,
    ip: Option<IpHeader>,
    transport: Option<TransportHeader>,

    filter: Filter
}

#[allow(deprecated)]
impl PacketFilterTest {

    ///Add all permutations of vlan data types to the test (none, single, double)
    ///and then proceeds calling "add_ip_data" with each permutations.
    fn add_vlan_data(&self, 
                     outer_vlan: &SingleVlanHeader, 
                     inner_vlan: &SingleVlanHeader, 
                     ipv4: &(Ipv4Header, Vec<u8>), 
                     ipv6: &Ipv6Header, 
                     udp: &UdpHeader,
                     tcp: &TcpHeader)
    {
        //none
        {
            let mut t = self.clone();
            t.vlan = None;
            t.add_transport_data(udp, tcp);
        }
        //single
        {
            let mut t = self.clone();
            t.vlan = Some(VlanHeader::Single(inner_vlan.clone()));
            t.add_ip_data(ipv4, ipv6, udp, tcp);
        }
        //double
        {
            let mut t = self.clone();
            t.vlan = Some(VlanHeader::Double(DoubleVlanHeader {
                outer: outer_vlan.clone(),
                inner: inner_vlan.clone()
            }));
            t.add_ip_data(ipv4, ipv6, udp, tcp);
        }
    }

    ///Add all permutations of ip data types to the test (none, v4, v6)
    ///and then proceeds calling "add_transport_data" with each permutations.
    fn add_ip_data(&self, 
                   ipv4: &(Ipv4Header, Vec<u8>), 
                   ipv6: &Ipv6Header, 
                   udp: &UdpHeader, 
                   tcp: &TcpHeader)
    {
        //none
        {
            let mut t = self.clone();
            t.ip = None;
            t.add_transport_data(udp, tcp);
        }
        //ipv4
        {
            let mut t = self.clone();
            t.ip = Some(IpHeader::Version4(ipv4.0.clone(), Default::default()));
            t.add_transport_data(udp, tcp);
        }

        //ipv6
        {
            let mut t = self.clone();
            t.ip = Some(IpHeader::Version6(ipv6.clone(), Default::default()));
            t.add_transport_data(udp, tcp);
        }
    }

    ///Add all permutations of transport data types to the test (none, udp, tcp)
    ///and then proceeds calling "add_link_filter" with each permutations.
    fn add_transport_data(&self, udp: &UdpHeader, tcp: &TcpHeader) {
        //none
        {
            let mut t = self.clone();
            t.transport = None;
            t.add_link_filter(true);
        }
        //tcp
        {
            let mut t = self.clone();
            t.transport = Some(TransportHeader::Tcp(tcp.clone()));
            t.add_link_filter(true);
        }
        //udp
        {
            let mut t = self.clone();
            t.transport = Some(TransportHeader::Udp(udp.clone()));
            t.add_link_filter(true);
        }
    }

    fn add_link_filter(&self, expected_result: bool) {
        //any
        {
            let mut t = self.clone();
            t.filter.link = ElementFilter::Any;
            t.add_vlan_filter(expected_result);
        }

        //none
        {
            let mut t = self.clone();
            t.filter.link = ElementFilter::No;
            t.add_vlan_filter(match &t.link {
                None => expected_result,
                _ => false
            });
        }
        //some
        match &self.link {
            Some(_) => {
                let mut t = self.clone();
                t.filter.link = ElementFilter::Some(
                    LinkFilter::Ethernet2 {
                        source: None,
                        destination: None
                    }
                );
                t.add_vlan_filter(expected_result);
            },
            _ => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.link = ElementFilter::Some(
                    LinkFilter::Ethernet2 {
                        source: None,
                        destination: None
                    }
                );
                t.add_vlan_filter(false);
            }
        }
    }

    fn add_vlan_filter(&self, expected_result: bool) {

        //any
        {
            let mut t = self.clone();
            t.filter.vlan = ElementFilter::Any;
            t.add_ip_filter(expected_result);
        }

        //none
        {
            let mut t = self.clone();
            t.filter.vlan = ElementFilter::No;
            t.add_ip_filter(match &t.vlan {
                None => expected_result,
                _ => false
            });
        }

        //single
        match &self.vlan {
            Some(VlanHeader::Single(_)) => {
                let mut t = self.clone();
                t.filter.vlan = ElementFilter::Some(
                    VlanFilter::Single(None)
                );
                t.add_ip_filter(expected_result);
            },
            Some(VlanHeader::Double(_)) => {
                let mut t = self.clone();
                t.filter.vlan = ElementFilter::Some(
                    VlanFilter::Double{
                        outer_identifier: None,
                        inner_identifier: None,
                    }
                );
                t.add_ip_filter(expected_result);
            },
            _ => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.vlan = ElementFilter::Some(
                    VlanFilter::Single(None)
                );
                t.add_ip_filter(false);
            }
        }
    }

    fn add_ip_filter(&self, expected_result: bool) {
        //any
        {
            let mut t = self.clone();
            t.filter.ip = ElementFilter::Any;
            t.add_transport_filter(expected_result);
        }

        //none
        {
            let mut t = self.clone();
            t.filter.ip = ElementFilter::No;
            t.add_transport_filter(match &t.ip {
                None => expected_result,
                _ => false
            });
        }

        //some
        match &self.ip {
            Some(IpHeader::Version4(_, _)) => {
                let mut t = self.clone();
                t.filter.ip = ElementFilter::Some(
                    IpFilter::Ipv4 {
                        source: None,
                        destination: None
                    }
                );
                t.add_transport_filter(expected_result);
            },
            Some(IpHeader::Version6(_,_)) => {
                let mut t = self.clone();
                t.filter.ip = ElementFilter::Some(
                    IpFilter::Ipv6 {
                        source: None,
                        destination: None
                    }
                );
                t.add_transport_filter(expected_result);
            },
            _ => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.ip = ElementFilter::Some(
                    IpFilter::Ipv4 {
                        source: None,
                        destination: None
                    }
                );
                t.add_transport_filter(false);
            }
        }
    }

    fn add_transport_filter(&self, expected_result: bool) {

        //any
        {
            let mut t = self.clone();
            t.filter.transport = ElementFilter::Any;
            t.run(expected_result);
        }

        //none
        {
            let mut t = self.clone();
            t.filter.transport = ElementFilter::No;
            t.run(match &t.transport {
                None => expected_result,
                _ => false
            });
        }
        //some
        match &self.transport {
            Some(TransportHeader::Udp(_)) => {
                let mut t = self.clone();
                t.filter.transport = ElementFilter::Some(
                    TransportFilter::Udp {
                        source_port: None,
                        destination_port: None
                    }
                );
                t.run(expected_result);
            },
            Some(TransportHeader::Tcp(_)) => {
                let mut t = self.clone();
                t.filter.transport = ElementFilter::Some(
                    TransportFilter::Tcp {
                        source_port: None,
                        destination_port: None
                    }
                );
                t.run(expected_result);
            },
            _ => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.transport = ElementFilter::Some(
                    TransportFilter::Udp {
                        source_port: None,
                        destination_port: None
                    }
                );
                t.run(false);
            }
        }
    }

    ///Gives self.filter the headers in self as input and assert the given parameter as a result.
    fn run(&self, expected_result: bool) {
        //generate a slice containing the headers
        let mut link_data = Vec::new();
        let mut vlan_data = Vec::new();
        let mut ip_data = Vec::new();
        let mut transport_data = Vec::new();
        let payload = Vec::new();

        let slice = SlicedPacket {
            link: match &self.link {
                Some(header) => {
                    header.write(&mut link_data).unwrap();
                    Some(LinkSlice::Ethernet2(Ethernet2HeaderSlice::from_slice(&link_data[..]).unwrap()))
                },
                None => None
            },
            vlan: match &self.vlan {
                Some(VlanHeader::Single(header)) => {
                    header.write(&mut vlan_data).unwrap();
                    Some(VlanSlice::SingleVlan(SingleVlanHeaderSlice::from_slice(&vlan_data[..]).unwrap()))
                },
                Some(VlanHeader::Double(header)) => {
                    header.write(&mut vlan_data).unwrap();
                    Some(VlanSlice::DoubleVlan(DoubleVlanHeaderSlice::from_slice(&vlan_data[..]).unwrap()))
                },
                None => None
            },
            ip: match &self.ip {
                Some(IpHeader::Version4(header, _)) => {
                    header.write(&mut ip_data).unwrap();
                    Some(
                         InternetSlice::Ipv4(
                            Ipv4HeaderSlice::from_slice(&ip_data[..]).unwrap(),
                            Default::default()
                        )
                    )
                },
                Some(IpHeader::Version6(header, _)) => {
                    header.write(&mut ip_data).unwrap();
                    Some(
                        InternetSlice::Ipv6(
                            Ipv6HeaderSlice::from_slice(&ip_data[..]).unwrap(),
                            Default::default()
                        )
                    )
                },

                None => None
            },
            transport: match &self.transport {
                Some(TransportHeader::Udp(header)) => {
                    header.write(&mut transport_data).unwrap();
                    Some(TransportSlice::Udp(UdpHeaderSlice::from_slice(&transport_data[..]).unwrap()))
                },
                Some(TransportHeader::Tcp(header)) => {
                    header.write(&mut transport_data).unwrap();
                    Some(TransportSlice::Tcp(TcpHeaderSlice::from_slice(&transport_data[..]).unwrap()))
                },
                None => None
            },
            payload: &payload[..]
        };

        assert_eq!(expected_result, self.filter.applies_to_slice(&slice));
    }
}
///Test that all known packet compositions are parsed correctly.
#[test]
fn test_compositions()
{
    //test without link
    {
        let test: PacketFilterTest = Default::default();
        test.add_vlan_data(
            &{
                //explicitly set the outer vlan ether_type id
                let mut re : SingleVlanHeader = Default::default();
                re.ether_type = EtherType::VlanTaggedFrame as u16;
                re
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default()
        );
    }

    //test with ethernet2 link
    {
        let mut test: PacketFilterTest = Default::default();
        test.link = Some(Default::default());
        test.add_vlan_data(
            &{
                //explicitly set the outer vlan ether_type id
                let mut re : SingleVlanHeader = Default::default();
                re.ether_type = EtherType::VlanTaggedFrame as u16;
                re
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default()
        );
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod link_filter {
    use super::*;
    proptest! {
        #[test]
        fn applies_to_slice(ref eth in ethernet_2_unknown())
        {
            use self::LinkFilter::*;
            //create the slice the filter can be checked against
            let eth_data = {
                let mut eth_data = Vec::new();
                eth.write(&mut eth_data).unwrap();
                eth_data };
            let eth_slice = LinkSlice::Ethernet2(
                Ethernet2HeaderSlice::from_slice(&eth_data[..]).unwrap()
            );

            //test ethernet 2 filter with wildcards
            {
                let wildcard = Ethernet2 {
                    source: Some(eth.source),
                    destination: Some(eth.destination)
                };
                assert_eq!(true, wildcard.applies_to_slice(&eth_slice));
            }
            //matching
            assert_eq!(true, Ethernet2 {
                source: Some(eth.source),
                destination: Some(eth.destination)
            }.applies_to_slice(&eth_slice));
            //non matching
            assert_eq!(false, Ethernet2 {
                source: Some({
                    let mut value = eth.source;
                    value[0] = !value[0];
                    value
                }),
                destination: Some(eth.destination)
            }.applies_to_slice(&eth_slice));
            assert_eq!(false, Ethernet2 {
                source: Some(eth.source),
                destination: Some({
                    let mut value = eth.destination;
                    value[0] = !value[0];
                    value
                })
            }.applies_to_slice(&eth_slice));
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod vlan_filter {
    use super::*;
    proptest! {
        #[test]
        fn applies_to_slice(ref vlan_outer in vlan_single_with(EtherType::VlanTaggedFrame as u16),
                            ref vlan_inner in vlan_single_unknown())
        {
            use self::VlanFilter::*;
            //create the slices the filters can be checked against
            let single_data = {
                let mut single_data = Vec::new();
                vlan_inner.write(&mut single_data).unwrap();
                single_data };
            let single_slice = VlanSlice::SingleVlan(
                SingleVlanHeaderSlice::from_slice(&single_data[..]).unwrap()
            );
            let double_data = {
                let mut double_data = Vec::new();
                DoubleVlanHeader {
                    outer: vlan_outer.clone(),
                    inner: vlan_inner.clone()
                }.write(&mut double_data).unwrap();
                double_data };
            let double_slice = VlanSlice::DoubleVlan(
                DoubleVlanHeaderSlice::from_slice(&double_data[..]).unwrap()
            );

            //test single vlan filter with wildcards
            {
                let wildcard = Single(None);
                assert_eq!(true, wildcard.applies_to_slice(&single_slice));
                assert_eq!(false, wildcard.applies_to_slice(&double_slice));
            }
            //matching
            assert_eq!(true, Single(
                Some(vlan_inner.vlan_identifier)
            ).applies_to_slice(&single_slice));
            //non matching
            assert_eq!(false, Single(
                Some(!vlan_inner.vlan_identifier)
            ).applies_to_slice(&single_slice));

            //test double vlan filter with wildcards
            {
                let wildcard = Double {
                    outer_identifier: None,
                    inner_identifier: None
                };
                assert_eq!(true, wildcard.applies_to_slice(&double_slice));
                assert_eq!(false, wildcard.applies_to_slice(&single_slice));
            }
            //matching
            assert_eq!(true, Double {
                outer_identifier: Some(vlan_outer.vlan_identifier),
                inner_identifier: Some(vlan_inner.vlan_identifier)
            }.applies_to_slice(&double_slice));
            //non matching
            assert_eq!(false, Double {
                outer_identifier: Some(!vlan_outer.vlan_identifier),
                inner_identifier: Some(vlan_inner.vlan_identifier)
            }.applies_to_slice(&double_slice));
            assert_eq!(false, Double {
                outer_identifier: Some(vlan_outer.vlan_identifier),
                inner_identifier: Some(!vlan_inner.vlan_identifier)
            }.applies_to_slice(&double_slice));
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod ip_filter {
    use super::*;
    proptest! {
        #[test]
        fn applies_to_slice(ref ipv4 in ipv4_unknown(),
                            ref ipv6 in ipv6_unknown())
        {
            use self::IpFilter::*;
            //create the slices the filters can be checked against
            let ipv4_data = {
                let mut ipv4_data = Vec::new();
                ipv4.write(&mut ipv4_data).unwrap();
                ipv4_data };
            let ipv4_slice = InternetSlice::Ipv4(
                Ipv4HeaderSlice::from_slice(&ipv4_data[..]).unwrap(),
                Default::default()
            );
            let ipv6_data = {
                let mut ipv6_data = Vec::new();
                ipv6.write(&mut ipv6_data).unwrap();
                ipv6_data };
            let ipv6_slice = InternetSlice::Ipv6(
                Ipv6HeaderSlice::from_slice(&ipv6_data[..]).unwrap(),
                Default::default()
            );

            //test ipv4 filter with wildcards
            {
                let wildcard = Ipv4 {
                    source: None,
                    destination:None
                };
                assert_eq!(true, wildcard.applies_to_slice(&ipv4_slice));
                assert_eq!(false, wildcard.applies_to_slice(&ipv6_slice));
            }
            //matching
            assert_eq!(true, Ipv4 {
                source: Some(ipv4.source),
                destination: Some(ipv4.destination)
            }.applies_to_slice(&ipv4_slice));
            //non matching
            assert_eq!(false, Ipv4 {
                source: Some({
                    let mut value = ipv4.source;
                    value[0] = !value[0];
                    value
                }),
                destination: Some(ipv4.destination)
            }.applies_to_slice(&ipv4_slice));
            assert_eq!(false, Ipv4 {
                source: Some(ipv4.source),
                destination: Some({
                    let mut value = ipv4.destination;
                    value[0] = !value[0];
                    value
                })
            }.applies_to_slice(&ipv4_slice));

            //test ipv6 filter with wildcards
            {
                let wildcard = Ipv6 {
                    source: None,
                    destination:None
                };
                assert_eq!(true, wildcard.applies_to_slice(&ipv6_slice));
                assert_eq!(false, wildcard.applies_to_slice(&ipv4_slice));
            }
            //matching
            assert_eq!(true, Ipv6 {
                source: Some(ipv6.source),
                destination: Some(ipv6.destination)
            }.applies_to_slice(&ipv6_slice));
            //non matching
            assert_eq!(false, Ipv6 {
                source: Some({
                    let mut value = ipv6.source;
                    value[0] = !value[0];
                    value }),
                destination: Some(ipv6.destination)
            }.applies_to_slice(&ipv6_slice));
            assert_eq!(false, Ipv6 {
                source: Some(ipv6.source),
                destination: Some({
                    let mut value = ipv6.destination;
                    value[0] = !value[0];
                    value })
            }.applies_to_slice(&ipv6_slice));
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod transport_filter {
    use super::*;
    proptest! {
        #[test]
        fn applies_to_slice(ref udp in udp_any(),
                            ref tcp in tcp_any())
        {
            use self::TransportFilter::*;
            //create the slices the filters can be checked against
            let udp_data = {
                let mut udp_data = Vec::new();
                udp.write(&mut udp_data).unwrap();
                udp_data };
            let udp_slice = TransportSlice::Udp(
                UdpHeaderSlice::from_slice(&udp_data[..]).unwrap()
            );
            let tcp_data = {
                let mut tcp_data = Vec::new();
                tcp.write(&mut tcp_data).unwrap();
                tcp_data };
            let tcp_slice = TransportSlice::Tcp(
                TcpHeaderSlice::from_slice(&tcp_data[..]).unwrap()
            );

            //test udp filter with wildcards
            {
                let wildcard = Udp {
                    source_port: None,
                    destination_port:None
                };
                assert_eq!(true, wildcard.applies_to_slice(&udp_slice));
                assert_eq!(false, wildcard.applies_to_slice(&tcp_slice));
            }
            //matching
            assert_eq!(true, Udp {
                source_port: Some(udp.source_port),
                destination_port: Some(udp.destination_port)
            }.applies_to_slice(&udp_slice));
            //non matching
            assert_eq!(false, Udp {
                source_port: Some(!udp.source_port), //inverted port
                destination_port: Some(udp.destination_port)
            }.applies_to_slice(&udp_slice));
            assert_eq!(false, Udp {
                source_port: Some(udp.source_port),
                destination_port: Some(!udp.destination_port) //inverted port
            }.applies_to_slice(&udp_slice));

            //test tcp filter with wildcards
            {
                let wildcard = Tcp {
                    source_port: None,
                    destination_port:None
                };
                assert_eq!(true, wildcard.applies_to_slice(&tcp_slice));
                assert_eq!(false, wildcard.applies_to_slice(&udp_slice));
            }
            //matching
            assert_eq!(true, Tcp {
                source_port: Some(tcp.source_port),
                destination_port: Some(tcp.destination_port)
            }.applies_to_slice(&tcp_slice));
            //non matching
            assert_eq!(false, Tcp {
                source_port: Some(!tcp.source_port), //inverted port
                destination_port: Some(tcp.destination_port)
            }.applies_to_slice(&tcp_slice));
            assert_eq!(false, Tcp {
                source_port: Some(tcp.source_port),
                destination_port: Some(!tcp.destination_port) //inverted port
            }.applies_to_slice(&tcp_slice));
        }
    }
}

#[test]
#[allow(deprecated)]
fn type_derives() {
    println!("{:?}", TransportFilter::Udp{
        source_port: None,
        destination_port: None
    });
    println!("{:?}", TransportFilter::Tcp{
        source_port: None,
        destination_port: None
    });
}
