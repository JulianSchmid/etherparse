use super::*;

/// Decoded packet headers (data link layer and higher).
/// You can use PacketHeaders::from_ethernet_slice or PacketHeader::from_ip_slice
/// to decode and get this struct as a result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketHeaders<'a> {
    pub link: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    /// IP Extension headers present after the ip header. 
    ///
    /// In case of IPV4 these can be ipsec authentication & encapsulated
    /// security headers. In case of IPv6 these are the ipv6 extension headers.
    /// The headers are in the same order as they are written to the packet.
    //pub ip_extensions: [Option<IpExtensionHeader<'a>>;IP_MAX_NUM_HEADER_EXTENSIONS],
    pub transport: Option<TransportHeader>,
    /// Rest of the packet that could not be decoded as a header (usually the payload).
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

        match ether_type {
            IPV4 => {
                let (ip, ip_rest) = Ipv4Header::read_from_slice(rest)?;
                let (ip_ext, ip_protocol, ip_ext_rest) = Ipv4Extensions::read_from_slice(ip.protocol, ip_rest)?;

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version4(ip, ip_ext));

                //parse the transport layer
                let (transport, transport_rest) = read_transport(ip_protocol, rest)?;

                //assign to the output
                rest = transport_rest;
                result.transport = transport;
                
            },
            IPV6 => {
                let (ip, ip_rest) = Ipv6Header::read_from_slice(rest)?;
                let (ip_ext, next_header, ip_ext_rest) = Ipv6Extensions::read_from_slice(ip.next_header, ip_rest)?;

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version6(ip, ip_ext));

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

    /// Tries to decode an ip packet and its transport headers.  
    /// Assumes the given slice starts with the first byte of the IP header
    /// # Example
    /// ```
    /// # use etherparse::*;
    /// // build a UDP packet
    /// let payload = [0u8;18];
    /// let builder = PacketBuilder::
    ///    ipv4([192,168,1,1], //source ip
    ///          [192,168,1,2], //desitionation ip
    ///          20)            //time to life
    ///    .udp(21,    //source port 
    ///         1234); //desitnation port
    ///
    /// // serialize the packet
    /// let packet = {
    ///     let mut packet = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///     builder.write(&mut packet, &payload).unwrap();
    ///     packet
    /// };
    /// # // should be 64 bytes long (including the ethernet FCS/CRC32) but since 
    /// # // this is not provided at the moment we're gonna be fine with 46
    /// # assert_eq!(packet.len(), 46);
    ///
    /// // parse the ip packet from a slice
    /// let p = PacketHeaders::from_ip_slice(&packet)
    ///     .expect("Failed to decode the packet");
    /// # assert_eq!(p.payload, payload);
    /// ```
    pub fn from_ip_slice(packet: &[u8]) -> Result<PacketHeaders, ReadError> {
        let mut result = PacketHeaders {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };

        let (transport_proto, rest) = {
            let (ip, transport_proto, rest) = IpHeader::read_from_slice(packet)?;
            // update output
            result.ip = Some(ip);
            (transport_proto, rest)
        };

        // try to parse the transport header
        let (transport, rest) = read_transport(transport_proto, rest)?;

        // update output
        result.transport = transport;
        result.payload = rest;

        Ok(result)
    }
}

/// helper function to process transport headers
fn read_transport(
    protocol: u8,
    rest: &[u8],
) -> Result<(Option<TransportHeader>, &[u8]), ReadError> {
    use crate::ip_number::*;
    match protocol {
        UDP => Ok(UdpHeader::read_from_slice(rest)
            .map(|value| (Some(TransportHeader::Udp(value.0)), value.1))?),
        TCP => Ok(TcpHeader::read_from_slice(rest)
            .map(|value| (Some(TransportHeader::Tcp(value.0)), value.1))?),
        _ => Ok((None, rest)),
    }
}