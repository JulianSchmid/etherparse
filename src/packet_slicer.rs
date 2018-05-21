use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketSliceType<'a> {
    Ethernet2Header(Slice<'a, Ethernet2Header>),
    SingleVlanHeader(Slice<'a, SingleVlanHeader>),
    DoubleVlanHeader(Slice<'a, DoubleVlanHeader>),
    ///Payload after an ethernet II header if the ether_type is unknown to the slicer. The enum value contains unknown ether_type value & the slice containing the payload.
    Ethernet2Payload(u16, &'a [u8]),
    Ipv4Header(Slice<'a, Ipv4Header>),
    Ipv6Header(Slice<'a, Ipv6Header>),
    ///Ipv6 extension header. The first value is the type identifier of the header (see IpTrafficClass for a list of ids).
    Ipv6ExtensionHeader(u8, Slice<'a, Ipv6ExtensionHeader>),
    ///Payload after an ip header (and options or header extension if present) with an unknown protocol/next_header identifier. The enum value contains the unknown protocol/next_header value & the slice containing the payload.
    IpPayload(u8, &'a [u8]),
    UdpHeader(Slice<'a, UdpHeader>),
    UdpPayload(&'a [u8])
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LastParsed {
    Start,
    Ethernet2(u16),
    SingleVlan(u16),
    DoubleVlan(u16),
    Ipv4(u8),
    ///Ipv6 header or header extension. The first value is the next_header identifier & the other one is the count of extension headers already parsed.
    Ipv6(u8, usize),
    Udp,
    Payload,
    Error
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketSlicer<'a> {
    last: LastParsed,
    rest: &'a [u8]
}

impl<'a> PacketSlicer<'a> {
    pub fn ethernet2(slice: &'a[u8]) -> PacketSlicer<'a>{
        PacketSlicer {
            last: LastParsed::Start,
            rest: slice,
        }   
    }
}

const ETH_IPV4: u16 = EtherType::Ipv4 as u16;
const ETH_IPV6: u16 = EtherType::Ipv6 as u16;
const ETH_VLAN: u16 = EtherType::VlanTaggedFrame as u16;
const ETH_BRIDGE: u16 = EtherType::ProviderBridging as u16;
const ETH_VLAN_DOUBLE: u16 = EtherType::VlanDoubleTaggedFrame as u16;

const IP_UDP: u8 = IpTrafficClass::Udp as u8;

const IPV6_HOP_BY_HOP: u8 = IpTrafficClass::IPv6HeaderHopByHop as u8;
const IPV6_ROUTE: u8 = IpTrafficClass::IPv6RouteHeader as u8;
const IPV6_FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;
const IPV6_OPTIONS: u8 = IpTrafficClass::IPv6DestinationOptions as u8;
const IPV6_AUTH: u8 = IpTrafficClass::IPv6AuthenticationHeader as u8;
const IPV6_ENCAP_SEC: u8 = IpTrafficClass::IPv6EncapSecurityPayload as u8;

impl<'a> Iterator for PacketSlicer<'a> {
    type Item = Result<PacketSliceType<'a>, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {

        return match self.last {

            //ethernet header
            LastParsed::Start =>
            {
                let slice = Slice::<Ethernet2Header>::from_slice(self.rest);
                match slice {
                    Ok(value) => {
                        self.last = LastParsed::Ethernet2(value.ether_type());
                        self.rest = &self.rest[value.slice.len()..];
                        Some(Ok(PacketSliceType::Ethernet2Header(value)))
                    },
                    Err(value) => {
                        self.last = LastParsed::Error;
                        Some(Err(value))
                    }
                }
            },

            //vlan & double vlan header
            LastParsed::Ethernet2(ETH_VLAN) |
            LastParsed::Ethernet2(ETH_BRIDGE) |
            LastParsed::Ethernet2(ETH_VLAN_DOUBLE) =>
            {
                //check if there is a double vlan header
                let single = Slice::<SingleVlanHeader>::from_slice(self.rest);
                match single {
                    Ok(value) => {
                        match value.ether_type() {
                            ETH_VLAN | ETH_BRIDGE | ETH_VLAN_DOUBLE => {
                                //read a double
                                match Slice::<DoubleVlanHeader>::from_slice(self.rest) {
                                    Ok(value) => {
                                        self.last = LastParsed::DoubleVlan(value.inner().ether_type());
                                        self.rest = &self.rest[value.slice.len()..];
                                        Some(Ok(PacketSliceType::DoubleVlanHeader(value)))
                                    },
                                    Err(value) => {
                                        self.last = LastParsed::Error;
                                        Some(Err(value))
                                    }
                                }
                            },
                            _ => {
                                self.last = LastParsed::SingleVlan(value.ether_type());
                                self.rest = &self.rest[value.slice.len()..];
                                Some(Ok(PacketSliceType::SingleVlanHeader(value)))
                            }
                        }
                    },
                    Err(value) => {
                        self.last = LastParsed::Error;
                        Some(Err(value))
                    }
                }
            },

            //ipv4
            LastParsed::Ethernet2(ETH_IPV4) | 
            LastParsed::SingleVlan(ETH_IPV4) | 
            LastParsed::DoubleVlan(ETH_IPV4) => 
            {
                let slice = Slice::<Ipv4Header>::from_slice(self.rest);
                match slice {
                    Ok(value) => {
                        self.last = LastParsed::Ipv4(value.protocol());
                        self.rest = &self.rest[value.slice.len()..];
                        Some(Ok(PacketSliceType::Ipv4Header(value)))
                    },
                    Err(value) => {
                        self.last = LastParsed::Error;
                        Some(Err(value))
                    }
                }
            },

            //ipv6
            LastParsed::Ethernet2(ETH_IPV6) | 
            LastParsed::SingleVlan(ETH_IPV6) | 
            LastParsed::DoubleVlan(ETH_IPV6) => 
            {
                let slice = Slice::<Ipv6Header>::from_slice(self.rest);
                match slice {
                    Ok(value) => {
                        self.last = LastParsed::Ipv6(value.next_header(), 0);
                        self.rest = &self.rest[value.slice.len()..];
                        Some(Ok(PacketSliceType::Ipv6Header(value)))
                    },
                    Err(value) => {
                        self.last = LastParsed::Error;
                        Some(Err(value))
                    }
                }
            },

            //unknown ether_type payload
            LastParsed::Ethernet2(ether_type) | 
            LastParsed::SingleVlan(ether_type) | 
            LastParsed::DoubleVlan(ether_type) =>
            {
                self.last = LastParsed::Payload;
                Some(Ok(PacketSliceType::Ethernet2Payload(ether_type, &self.rest[..])))
            },

            //ipv6 extension headers
            LastParsed::Ipv6(header_type @ IPV6_HOP_BY_HOP, extension_header_count) | 
            LastParsed::Ipv6(header_type @ IPV6_ROUTE, extension_header_count) | 
            LastParsed::Ipv6(header_type @ IPV6_FRAG, extension_header_count) | 
            LastParsed::Ipv6(header_type @ IPV6_OPTIONS, extension_header_count) | 
            LastParsed::Ipv6(header_type @ IPV6_AUTH, extension_header_count) | 
            LastParsed::Ipv6(header_type @ IPV6_ENCAP_SEC, extension_header_count) => 
            {
                if extension_header_count + 1 > IPV6_MAX_NUM_HEADER_EXTENSIONS {
                    //raise an header extension error if the maximum
                    self.last = LastParsed::Error;
                    Some(Err(ReadError::Ipv6TooManyHeaderExtensions))
                } else  {
                    let slice = Slice::<Ipv6ExtensionHeader>::from_slice(header_type, self.rest);
                    match slice {
                        Ok(value) => {
                            self.last = LastParsed::Ipv6(value.next_header(), extension_header_count + 1);
                            self.rest = &self.rest[value.slice.len()..];
                            Some(Ok(PacketSliceType::Ipv6ExtensionHeader(header_type, value)))
                        },
                        Err(value) => {
                            self.last = LastParsed::Error;
                            Some(Err(value))
                        }
                    }
                }
            },

            //udp
            LastParsed::Ipv4(IP_UDP) | 
            LastParsed::Ipv6(IP_UDP, _) =>
            {
                let slice = Slice::<UdpHeader>::from_slice(self.rest);
                match slice {
                    Ok(value) => {
                        self.last = LastParsed::Udp;
                        self.rest = &self.rest[value.slice.len()..];
                        Some(Ok(PacketSliceType::UdpHeader(value)))
                    },
                    Err(value) => {
                        self.last = LastParsed::Error;
                        Some(Err(value))
                    }
                }
            },

            //unknown ip payload
            LastParsed::Ipv4(protocol) | 
            LastParsed::Ipv6(protocol, _) =>
            {
                self.last = LastParsed::Payload;
                Some(Ok(PacketSliceType::IpPayload(protocol, &self.rest[..])))
            },

            LastParsed::Udp => {
                self.last = LastParsed::Payload;
                Some(Ok(PacketSliceType::UdpPayload(&self.rest[..])))
            },

            LastParsed::Payload | LastParsed::Error => {
                None //done
            }
        };
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        return match self.last {
            //ethernet header
            LastParsed::Start =>
                //max path is: ethernet + vlan + ipv6 + ipv6 header extensions (max of 7) + udp + payload
                (1, Some(3 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)),

            //vlan & double vlan header
            LastParsed::Ethernet2(ETH_VLAN) |
            LastParsed::Ethernet2(ETH_BRIDGE) |
            LastParsed::Ethernet2(ETH_VLAN_DOUBLE) =>
                //max path is: vlan + ipv6 + ipv6 header extensions (max of 7) + udp + payload
                (1, Some(2 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)),

            //ipv4
            LastParsed::Ethernet2(ETH_IPV4) | 
            LastParsed::SingleVlan(ETH_IPV4) | 
            LastParsed::DoubleVlan(ETH_IPV4) => 
            //max path is: ipv4 + udp + payload
                (1, Some(3)),

            //ipv6
            LastParsed::Ethernet2(ETH_IPV6) | 
            LastParsed::SingleVlan(ETH_IPV6) | 
            LastParsed::DoubleVlan(ETH_IPV6) => 
            //max path is: ipv6 + ipv6 header extensions (max of 7) + udp + payload
                (1, Some(1 + IPV6_MAX_NUM_HEADER_EXTENSIONS + 2)),

            //ipv6 extension headers
            LastParsed::Ipv6(IPV6_HOP_BY_HOP, count) | 
            LastParsed::Ipv6(IPV6_ROUTE, count) | 
            LastParsed::Ipv6(IPV6_FRAG, count) | 
            LastParsed::Ipv6(IPV6_OPTIONS, count) | 
            LastParsed::Ipv6(IPV6_AUTH, count) | 
            LastParsed::Ipv6(IPV6_ENCAP_SEC, count) => 
            //max path is: ipv6 header extensions (max of 7) + udp + payload
            //TODO: use the number of already parsed header extensions
                (1, Some((IPV6_MAX_NUM_HEADER_EXTENSIONS - count) + 2)),

            //unknown ether_type payload
            LastParsed::Ethernet2(_) | 
            LastParsed::SingleVlan(_) | 
            LastParsed::DoubleVlan(_) =>
                //almost done
                (1, Some(1)),

            //udp
            LastParsed::Ipv4(IP_UDP) | 
            LastParsed::Ipv6(IP_UDP, _) =>
            //max path is: udp + payload
                (1, Some(2)),

            //unknown ip payload
            LastParsed::Ipv4(_) | 
            LastParsed::Ipv6(_, _) =>
                //almost done
                (1, Some(1)),

            LastParsed::Udp => 
                //almost done
                (1, Some(1)),

            LastParsed::Payload | 
            LastParsed::Error =>
                //done
                (0, Some(0)),
        };
    }

    //TODO add foreach implementation to avoid complex state handeling
}