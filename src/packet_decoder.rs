use super::*;

///Decoded packet headers. You can use PacketHeaders::decode_from_ethernet2 to decode packets and get this struct as a result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketHeaders<'a> {
    pub link: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
    ///Rest of the packet that could not be decoded as a header (usually the payload).
    pub payload: &'a [u8]
}

impl<'a> PacketHeaders<'a> {
    ///Tries to decode as much as possible of a packet.
    pub fn from_ethernet_slice(packet: &[u8]) -> Result<PacketHeaders, ReadError> {
        
        let (ethernet, mut rest) = Ethernet2Header::read_from_slice(&packet)?;
        let mut ether_type = ethernet.ether_type;

        let mut result = PacketHeaders{
            link: Some(ethernet),
            vlan: None,
            ip: None,
            transport: None,
            payload: &[]
        };

        //parse vlan header(s)
        use crate::EtherType::*;

        const VLAN_TAGGED_FRAME: u16 = VlanTaggedFrame as u16;
        const PROVIDER_BRIDGING: u16 = ProviderBridging as u16;
        const VLAN_DOUBLE_TAGGED_FRAME: u16 = VlanDoubleTaggedFrame as u16;

        result.vlan = match ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                use crate::VlanHeader::*;
                let (outer, outer_rest) = SingleVlanHeader::read_from_slice(rest)?;

                //set the rest & ether_type for the following operations
                rest = outer_rest;
                ether_type = outer.ether_type;

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {

                        let (inner, inner_rest) = SingleVlanHeader::read_from_slice(rest)?;

                        //set the rest & ether_type for the following operations
                        rest = inner_rest;
                        ether_type = inner.ether_type;

                        Some(Double(DoubleVlanHeader{
                            outer,
                            inner
                        }))
                    },
                    //no second vlan header detected -> single vlan header
                    _ => Some(Single(outer))
                }
            },
            //no vlan header
            _ => None
        };

        //parse ip (if present)
        const IPV4: u16 = Ipv4 as u16;
        const IPV6: u16 = Ipv6 as u16;

        fn read_transport(protocol: u8, rest: &[u8]) -> Result<(Option<TransportHeader>, &[u8]), ReadError> {
            use crate::IpTrafficClass::*;
            const UDP: u8 = Udp as u8;
            const TCP: u8 = Tcp as u8;
            match protocol {
                UDP => Ok(UdpHeader::read_from_slice(rest)
                          .map(|value| (Some(TransportHeader::Udp(value.0)), value.1))?),
                TCP => Ok(TcpHeader::read_from_slice(rest)
                          .map(|value| (Some(TransportHeader::Tcp(value.0)), value.1))?),
                _ => Ok((None, rest))
            }
        };

        match ether_type {
            IPV4 => {
                let (ip, ip_rest) = Ipv4Header::read_from_slice(rest)?;

                //cache the protocol for the next parsing layer
                let ip_protocol = ip.protocol;

                //set the ip result & rest
                rest = ip_rest;
                result.ip = Some(IpHeader::Version4(ip));

                //parse the transport layer
                let (transport, transport_rest) = read_transport(ip_protocol, rest)?;

                //assign to the output
                rest = transport_rest;
                result.transport = transport;
                
            },
            IPV6 => {
                let (ip, ip_rest) = Ipv6Header::read_from_slice(rest)?;

                //cache the protocol for the next parsing layer
                let next_header = ip.next_header;

                //set the ip result & rest
                rest = ip_rest;
                result.ip = Some(IpHeader::Version6(ip));

                //skip the header extensions
                let (next_header, ip_rest) = Ipv6Header::skip_all_header_extensions_in_slice(rest, next_header)?;
                
                //set the rest
                rest = ip_rest;

                //parse the transport layer
                let (transport, transport_rest) = read_transport(next_header, rest)?;
                
                rest = transport_rest;
                result.transport = transport;

            },
            _ => {}
        }

        //finally update the rest slice based on the cursor position
        result.payload = rest;

        Ok(result)
    }
}