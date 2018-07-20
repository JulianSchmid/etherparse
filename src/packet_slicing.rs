use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkSlice<'a> {
    Ethernet2(PacketSlice<'a, Ethernet2Header>)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanSlice<'a> {
    SingleVlan(PacketSlice<'a, SingleVlanHeader>),
    DoubleVlan(PacketSlice<'a, DoubleVlanHeader>),
}

impl<'a> VlanSlice<'a> {
    ///Decode all the fields and copy the results to a VlanHeader struct
    pub fn to_header(&self) -> VlanHeader {
        use VlanHeader::*;
        use VlanSlice::*;
        match self {
            SingleVlan(value) => Single(value.to_header()),
            DoubleVlan(value) => Double(value.to_header())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternetSlice<'a> {
    Ipv4(PacketSlice<'a, Ipv4Header>),
    ///First element is the Ipv6 header slice and second one are the Ipv6 extensions headers filled in order from 0 to the length of the array.
    Ipv6(PacketSlice<'a, Ipv6Header>, [Option<(u8, PacketSlice<'a, Ipv6ExtensionHeader>)>; IPV6_MAX_NUM_HEADER_EXTENSIONS]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportSlice<'a> {
    Udp(PacketSlice<'a, UdpHeader>),
    Tcp(PacketSlice<'a, TcpHeader>)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlicedPacket<'a> {
    pub link: Option<LinkSlice<'a>>,
    pub vlan: Option<VlanSlice<'a>>,
    pub ip: Option<InternetSlice<'a>>,
    pub transport: Option<TransportSlice<'a>>,
    /// The payload field points to the rest of the packet that could not be parsed by etherparse.
    ///
    /// Depending on what other fields contain a "Some" values the payload contains the corresponding 
    /// payload.
    ///
    /// For example if transport field contains Some(Udp(_)) then the payload field points to the udp payload.
    /// On the other hand if the transport field contains None then the payload contains the payload of
    /// next field containing a Some value (in order of transport, ip, vlan, link).
    pub payload: &'a [u8]
}

const ETH_IPV4: u16 = EtherType::Ipv4 as u16;
const ETH_IPV6: u16 = EtherType::Ipv6 as u16;
const ETH_VLAN: u16 = EtherType::VlanTaggedFrame as u16;
const ETH_BRIDGE: u16 = EtherType::ProviderBridging as u16;
const ETH_VLAN_DOUBLE: u16 = EtherType::VlanDoubleTaggedFrame as u16;

const IP_UDP: u8 = IpTrafficClass::Udp as u8;
const IP_TCP: u8 = IpTrafficClass::Tcp as u8;

const IPV6_HOP_BY_HOP: u8 = IpTrafficClass::IPv6HeaderHopByHop as u8;
const IPV6_ROUTE: u8 = IpTrafficClass::IPv6RouteHeader as u8;
const IPV6_FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;
const IPV6_OPTIONS: u8 = IpTrafficClass::IPv6DestinationOptions as u8;
const IPV6_AUTH: u8 = IpTrafficClass::IPv6AuthenticationHeader as u8;
const IPV6_ENCAP_SEC: u8 = IpTrafficClass::IPv6EncapSecurityPayload as u8;

impl<'a> SlicedPacket<'a> {
    pub fn from_ethernet(data: &'a [u8]) -> Result<SlicedPacket, ReadError> {

        //read link header
        let (rest, ether_type, link) = {
            use LinkSlice::*;

            let value = PacketSlice::<Ethernet2Header>::from_slice(data)?;
            (&data[value.slice.len()..], 
             value.ether_type(), 
             Some(Ethernet2(value)))
        };
        
        //read vlan header(s) if they exist
        let (rest, ether_type, vlan) = match ether_type {
            ETH_VLAN | ETH_BRIDGE | ETH_VLAN_DOUBLE => {
                use VlanSlice::*;

                //slice the first vlan header
                let single = PacketSlice::<SingleVlanHeader>::from_slice(rest)?;
                let ether_type = single.ether_type();
                match ether_type {

                    //check if it is a double vlan tagged packet based on the ether_type
                    ETH_VLAN | ETH_BRIDGE | ETH_VLAN_DOUBLE => {
                        let double = PacketSlice::<DoubleVlanHeader>::from_slice(rest)?;
                        (&rest[double.slice.len()..], 
                         double.inner().ether_type(), 
                         Some(DoubleVlan(double)))
                    },

                    //otherwise it is single tagged
                    _ => (&rest[single.slice.len()..], 
                          ether_type, 
                          Some(SingleVlan(single)))
                }
            },

            //no vlan header found
            _ => (rest, ether_type, None)
        };

        //read ip & transport
        let (rest, protocol, ip) = match ether_type {
            ETH_IPV4 => {
                use InternetSlice::*;

                let value = PacketSlice::<Ipv4Header>::from_slice(rest)?;
                (&rest[value.slice.len()..],
                 value.protocol(),
                 Some(Ipv4(value)))
            },
            //
            ETH_IPV6 => {
                use InternetSlice::*;

                let value = PacketSlice::<Ipv6Header>::from_slice(rest)?;

                let mut rest = &rest[value.slice.len()..];

                //extension headers
                let mut ip_extensions = [None, None, None, None, None, None, None];
                let mut next_header = value.next_header();
                for i in 0..IPV6_MAX_NUM_HEADER_EXTENSIONS {
                    match next_header {
                        IPV6_HOP_BY_HOP | 
                        IPV6_ROUTE | 
                        IPV6_FRAG | 
                        IPV6_OPTIONS | 
                        IPV6_AUTH | 
                        IPV6_ENCAP_SEC => {
                            let value = PacketSlice::<Ipv6ExtensionHeader>::from_slice(next_header, rest)?;
                            let this_header = next_header;
                            next_header = value.next_header();
                            rest = &rest[value.slice.len()..];
                            ip_extensions[i] = Some((this_header, value));
                        },
                        _ => break
                    }
                }

                //check that the next header is not an extension header
                match next_header {
                    IPV6_HOP_BY_HOP | 
                    IPV6_ROUTE | 
                    IPV6_FRAG | 
                    IPV6_OPTIONS | 
                    IPV6_AUTH | 
                    IPV6_ENCAP_SEC => {
                        return Err(ReadError::Ipv6TooManyHeaderExtensions)
                    },
                    _ => {}
                }

                //return ip header result
                (rest,
                 next_header,
                 Some(Ipv6(value, ip_extensions)))
            },
            _ => (rest, 0, None)
        };

        //read transport
        let (rest, transport) = if ip.is_some() {
            match protocol {
                IP_UDP => {
                    use TransportSlice::*;

                    let value = PacketSlice::<UdpHeader>::from_slice(rest)?;
                    (&rest[value.slice.len()..],
                     Some(Udp(value)))
                },
                IP_TCP => {
                    use TransportSlice::*;

                    let value = PacketSlice::<TcpHeader>::from_slice(rest)?;
                    (&rest[value.slice.len()..],
                     Some(Tcp(value)))
                },
                _ => (rest, None)
            }
        } else {
            (rest, None)
        };

        Ok(SlicedPacket{
            link: link,
            vlan: vlan,
            ip: ip,
            transport: transport,
            payload: rest
        })
    }
}
