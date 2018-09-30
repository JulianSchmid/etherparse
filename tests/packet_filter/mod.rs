use super::*;
use proptest::*;


#[test]
fn default() {
    let value: ElementFilter<IpFilter> = Default::default();
    assert_eq!(ElementFilter::Any, value);
}

///The packet filter test generates all permutation of packet combinations & filter configurations
///and tests that all of them return the correct result.
#[derive(Debug, Clone, Default)]
struct PacketFilterTest {
    link: Option<Ethernet2Header>,
    vlan: Option<VlanHeader>,
    ip: Option<IpHeader>,
    transport: Option<TransportHeader>,

    filter: Filter
}

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
            t.vlan = Some(VlanHeader::Single(outer_vlan.clone()));
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
            t.ip = Some(IpHeader::Version4(ipv4.0.clone()));
            t.add_transport_data(udp, tcp);
        }

        //ipv6
        {
            let mut t = self.clone();
            t.ip = Some(IpHeader::Version6(ipv6.clone()));
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
        //currently there is no link layer filter
        self.add_ip_filter(expected_result);
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

        //ipv4
        match &self.ip {
            //negative cases
            None | Some(IpHeader::Version6(_)) => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.ip = ElementFilter::Some(
                    IpFilter::Ipv4 {
                        source: None,
                        destination: None
                    }
                );
                t.add_transport_filter(false);
            },
            Some(IpHeader::Version4(header)) => {

                //positve test (non detailed)
                {
                    let mut t = self.clone();
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv4 {
                            source: None,
                            destination: None
                        }
                    );
                    t.add_transport_filter(expected_result);
                }

                //postive test: both matching
                {
                    let mut t = self.clone();
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv4 {
                            source: Some(header.source),
                            destination: Some(header.destination)
                        }
                    );
                    t.add_transport_filter(expected_result);
                }

                //negative test: source non matching
                {
                    let mut t = self.clone();
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv4 {
                            source: Some({
                                let mut source = header.source;
                                source[0] = !source[0];
                                source
                            }),
                            destination: Some(header.destination)
                        }
                    );
                    t.add_transport_filter(false);
                }

                //negative test: destination non matching
                {
                    let mut t = self.clone();
                    
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv4 {
                            source: Some(header.source),
                            destination: Some({
                                let mut dest = header.destination;
                                dest[0] = !dest[0];
                                dest
                            })
                        }
                    );
                    t.add_transport_filter(false);
                }
            }
        }

        //ipv6
        match &self.ip {
            //negative cases
            None | Some(IpHeader::Version4(_)) => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.ip = ElementFilter::Some(
                    IpFilter::Ipv6 {
                        source: None,
                        destination: None
                    }
                );
                t.add_transport_filter(false);
            },
            Some(IpHeader::Version6(header)) => {

                //positve test (non detailed)
                {
                    let mut t = self.clone();
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv6 {
                            source: None,
                            destination: None
                        }
                    );
                    t.add_transport_filter(expected_result);
                }

                //postive test: both matching
                {
                    let mut t = self.clone();
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv6 {
                            source: Some(header.source),
                            destination: Some(header.destination)
                        }
                    );
                    t.add_transport_filter(expected_result);
                }

                //negative test: source non matching
                {
                    let mut t = self.clone();
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv6 {
                            source: Some({
                                let mut source = header.source;
                                source[0] = !source[0];
                                source
                            }),
                            destination: Some(header.destination)
                        }
                    );
                    t.add_transport_filter(false);
                }

                //negative test: destination non matching
                {
                    let mut t = self.clone();
                    
                    t.filter.ip = ElementFilter::Some(
                        IpFilter::Ipv6 {
                            source: Some(header.source),
                            destination: Some({
                                let mut dest = header.destination;
                                dest[0] = !dest[0];
                                dest
                            })
                        }
                    );
                    t.add_transport_filter(false);
                }
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

        //udp
        match &self.transport {
            //negative cases
            None | Some(TransportHeader::Tcp(_)) => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.transport = ElementFilter::Some(
                    TransportFilter::Udp {
                        source_port: None,
                        destination_port: None
                    }
                );
                t.run(false);
            },
            Some(TransportHeader::Udp(header)) => {

                //positve test (non detailed)
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Udp {
                            source_port: None,
                            destination_port: None
                        }
                    );
                    t.run(expected_result);
                }

                //postive test: both matching
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Udp {
                            source_port: Some(header.source_port),
                            destination_port: Some(header.destination_port)
                        }
                    );
                    t.run(expected_result);
                }

                //negative test: source non matching
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Udp {
                            source_port: Some(!header.source_port), //invert to create a difference
                            destination_port: Some(header.destination_port)
                        }
                    );
                    t.run(false);
                }

                //negative test: destination non matching
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Udp {
                            source_port: Some(header.source_port), 
                            destination_port: Some(!header.destination_port) //invert to create a difference
                        }
                    );
                    t.run(false);
                }
            }
        }

        //tcp
        match &self.transport {
            //negative cases
            None | Some(TransportHeader::Udp(_)) => {
                //test that the filter results in a negative match
                let mut t = self.clone();
                t.filter.transport = ElementFilter::Some(
                    TransportFilter::Tcp {
                        source_port: None,
                        destination_port: None
                    }
                );
                t.run(false);
            },
            Some(TransportHeader::Tcp(header)) => {

                //positve test (non detailed)
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Tcp {
                            source_port: None,
                            destination_port: None
                        }
                    );
                    t.run(expected_result);
                }

                //postive test: both matching
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Tcp {
                            source_port: Some(header.source_port),
                            destination_port: Some(header.destination_port)
                        }
                    );
                    t.run(expected_result);
                }

                //negative test: source non matching
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Tcp {
                            source_port: Some(!header.source_port), //invert to create a difference
                            destination_port: Some(header.destination_port)
                        }
                    );
                    t.run(false);
                }

                //negative test: destination non matching
                {
                    let mut t = self.clone();
                    t.filter.transport = ElementFilter::Some(
                        TransportFilter::Tcp {
                            source_port: Some(header.source_port), 
                            destination_port: Some(!header.destination_port) //invert to create a difference
                        }
                    );
                    t.run(false);
                }
            }
        }
    }

    ///Gives self.filter the headers in self as input and assert the given parameter as a result.
    fn run(&self, expected_result: bool) {
        //generate a slice containing the headers
        let mut ip_data = Vec::new();
        let mut transport_data = Vec::new();
        let payload = Vec::new();

        let slice = SlicedPacket {
            link: None, //Option<LinkSlice<'a>>,
            vlan: None, //Option<VlanSlice<'a>>,
            ip: match &self.ip {
                Some(IpHeader::Version4(header)) => {
                    header.write(&mut ip_data, &[]).unwrap();
                    Some(InternetSlice::Ipv4(Ipv4HeaderSlice::from_slice(&ip_data[..]).unwrap()))
                },
                Some(IpHeader::Version6(header)) => {
                    header.write(&mut ip_data).unwrap();
                    Some(InternetSlice::Ipv6(Ipv6HeaderSlice::from_slice(&ip_data[..]).unwrap(), [None, None, None, None, None, None, None]))
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

proptest! {
    ///Test that all known packet compositions are parsed correctly.
    #[test]
    fn test_compositions(ref eth in ethernet_2_unknown(),
                         ref vlan_outer in vlan_single_unknown(),
                         ref vlan_inner in vlan_single_unknown(),
                         ref ipv4 in ipv4_unknown(),
                         ref ipv6 in ipv6_unknown(),
                         ref udp in udp_any(),
                         ref tcp in tcp_any())
    {
        //test without link
        {
            let test: PacketFilterTest = Default::default();
            test.add_vlan_data(
                vlan_outer,
                vlan_inner,
                ipv4,
                ipv6,
                udp,
                tcp
            );
        }

        //test with ethernet2 link
        {
            let mut test: PacketFilterTest = Default::default();
            test.link = Some(eth.clone());
            test.add_vlan_data(
                vlan_outer,
                vlan_inner,
                ipv4,
                ipv6,
                udp,
                tcp
            );
        }
    }
}
