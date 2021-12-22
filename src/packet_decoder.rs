use super::*;

/// Decoded packet headers (data link layer and higher).
/// You can use PacketHeaders::from_ethernet_slice or PacketHeader::from_ip_slice
/// to decode and get this struct as a result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketHeaders<'a> {
    pub link: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
    /// Rest of the packet that could not be decoded as a header (usually the payload).
    pub payload: &'a [u8]
}

impl<'a> PacketHeaders<'a> {
    /// Tries to decode as much as possible of a packet.
    pub fn from_ethernet_slice(packet: &[u8]) -> Result<PacketHeaders, ReadError> {
        
        let (ethernet, mut rest) = Ethernet2Header::from_slice(packet)?;
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
                let (outer, outer_rest) = SingleVlanHeader::from_slice(rest)?;

                //set the rest & ether_type for the following operations
                rest = outer_rest;
                ether_type = outer.ether_type;

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {

                        let (inner, inner_rest) = SingleVlanHeader::from_slice(rest)?;

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
                let (ip, ip_rest) = Ipv4Header::from_slice(rest)?;
                let fragmented = ip.is_fragmenting_payload();
                let (ip_ext, ip_protocol, ip_ext_rest) = Ipv4Extensions::from_slice(ip.protocol, ip_rest)?;

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version4(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) = read_transport(ip_protocol, rest)?;

                    //assign to the output
                    rest = transport_rest;
                    result.transport = transport;
                }
            },
            IPV6 => {
                let (ip, ip_rest) = Ipv6Header::from_slice(rest)?;
                let (ip_ext, next_header, ip_ext_rest) = Ipv6Extensions::from_slice(ip.next_header, ip_rest)?;
                let fragmented = ip_ext.is_fragmenting_payload();

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version6(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) = read_transport(next_header, rest)?;

                    rest = transport_rest;
                    result.transport = transport;
                }

            },
            _ => {}
        }

        //finally update the rest slice based on the cursor position
        result.payload = rest;

        Ok(result)
    }

    /// Tries to decode a network packet into different headers using the
    /// given `ether_type` number to identify the first header.
    ///
    /// The result is returned as a `PacketHeaders` struct. Currently supported
    /// ether type numbers are:
    ///
    /// * `ether_type::IPV4`
    /// * `ether_type::IPV6`
    /// * `ether_type::VLAN_TAGGED_FRAME`
    /// * `ether_type::PROVIDER_BRIDGING`
    /// * `ether_type::VLAN_DOUBLE_TAGGED_FRAME`
    ///
    /// If an unsupported ether type is given the given slice will be set as payload
    /// and all other fields will be set to `None`.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{Ethernet2Header, SerializedSize, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ethernet2([1,2,3,4,5,6],     //source mac
    /// #               [7,8,9,10,11,12]) //destionation mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //desitionation ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); //desitnation port
    /// # // payload of the udp packet
    /// # let payload = [1,2,3,4,5,6,7,8];
    /// # // get some memory to store the serialized data
    /// # let mut complete_packet = Vec::<u8>::with_capacity(
    /// #     builder.size(payload.len())
    /// # );
    /// # builder.write(&mut complete_packet, &payload).unwrap();
    /// #
    /// # // skip ethernet 2 header so we can parse from there downwards
    /// # let packet = &complete_packet[Ethernet2Header::SERIALIZED_SIZE..];
    /// #
    /// use etherparse::{ether_type, PacketHeaders};
    ///
    /// match PacketHeaders::from_ether_type(ether_type::IPV4, packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ether_type(mut ether_type: u16, data: &'a [u8]) -> Result<PacketHeaders, ReadError> {
        let mut rest = data;
        let mut result = PacketHeaders{
            link: None,
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
                let (outer, outer_rest) = SingleVlanHeader::from_slice(rest)?;

                //set the rest & ether_type for the following operations
                rest = outer_rest;
                ether_type = outer.ether_type;

                //parse second vlan header if present
                match ether_type {
                    //second vlan tagging header
                    VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {

                        let (inner, inner_rest) = SingleVlanHeader::from_slice(rest)?;

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
                let (ip, ip_rest) = Ipv4Header::from_slice(rest)?;
                let fragmented = ip.is_fragmenting_payload();
                let (ip_ext, ip_protocol, ip_ext_rest) = Ipv4Extensions::from_slice(ip.protocol, ip_rest)?;

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version4(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) = read_transport(ip_protocol, rest)?;

                    //assign to the output
                    rest = transport_rest;
                    result.transport = transport;
                }
            },
            IPV6 => {
                let (ip, ip_rest) = Ipv6Header::from_slice(rest)?;
                let (ip_ext, next_header, ip_ext_rest) = Ipv6Extensions::from_slice(ip.next_header, ip_rest)?;
                let fragmented = ip_ext.is_fragmenting_payload();

                //set the ip result & rest
                rest = ip_ext_rest;
                result.ip = Some(IpHeader::Version6(ip, ip_ext));

                // only try to decode the transport layer if the payload
                // is not fragmented
                if false == fragmented {
                    //parse the transport layer
                    let (transport, transport_rest) = read_transport(next_header, rest)?;

                    rest = transport_rest;
                    result.transport = transport;
                }

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
            let (ip, transport_proto, rest) = IpHeader::from_slice(packet)?;
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
        UDP => Ok(UdpHeader::from_slice(rest)
            .map(|value| (Some(TransportHeader::Udp(value.0)), value.1))?),
        TCP => Ok(TcpHeader::from_slice(rest)
            .map(|value| (Some(TransportHeader::Tcp(value.0)), value.1))?),
        _ => Ok((None, rest)),
    }
}