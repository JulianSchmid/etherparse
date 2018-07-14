use super::*;

///Decoded packet headers. You can use PacketHeaders::decode_from_ethernet2 to decode packets and get this struct as a result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketHeaders<'a> {
    pub ethernet: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
    ///Rest of the packet that could not be decoded as a header (usually the payload).
    pub rest: &'a [u8]
}

impl<'a> PacketHeaders<'a> {
    ///Tries to decode as much as possible of a packet.
    pub fn from_ethernet_slice<'b>(packet: &'b [u8]) -> Result<PacketHeaders<'b>, ReadError> {
        
        use std::io::Cursor;
        let mut cursor = Cursor::new(&packet);

        let ethernet = Ethernet2Header::read(&mut cursor)?;
        let mut ether_type = ethernet.ether_type;

        let mut result = PacketHeaders{
            ethernet: Some(ethernet),
            vlan: None,
            ip: None,
            transport: None,
            rest: &[]
        };

        //parse vlan header(s)
        use EtherType::*;

        const VLAN_TAGGED_FRAME: u16 = VlanTaggedFrame as u16;
        const PROVIDER_BRIDGING: u16 = ProviderBridging as u16;
        const VLAN_DOUBLE_TAGGED_FRAME: u16 = VlanDoubleTaggedFrame as u16;

        result.vlan = match ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                use VlanHeader::*;
                let outer = SingleVlanHeader::read(&mut cursor)?;
                ether_type = outer.ether_type;

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {

                        let inner = SingleVlanHeader::read(&mut cursor)?;
                        ether_type = inner.ether_type;

                        Some(Double(DoubleVlanHeader{
                            outer: outer,
                            inner: inner
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

        let read_transport = |protocol: u8, cursor: &mut Cursor<&&[u8]>| -> Result<Option<TransportHeader>, ReadError> {
            use IpTrafficClass::*;
            const UDP: u8 = Udp as u8;
            match protocol {
                UDP => Ok(Some(TransportHeader::Udp(UdpHeader::read(cursor)?))),
                _ => Ok(None)
            }
        };

        match ether_type {
            IPV4 => {
                let ip = Ipv4Header::read(&mut cursor)?;
                //skip options
                ip.skip_options(&mut cursor)?;
                //parse the transport layer
                result.transport = read_transport(ip.protocol, &mut cursor)?;
                result.ip = Some(IpHeader::Version4(ip));
            },
            IPV6 => {
                let ip = Ipv6Header::read(&mut cursor)?;
                //skip the header extensions
                let next_header = Ipv6Header::skip_all_header_extensions(&mut cursor, ip.next_header)?;
                //parse the transport layer
                result.transport = read_transport(next_header, &mut cursor)?;
                //done
                result.ip = Some(IpHeader::Version6(ip));
            },
            _ => {}
        }

        //finally update the rest slice based on the cursor position
        result.rest = &packet[(cursor.position() as usize)..];

        Ok(result)
    }
}