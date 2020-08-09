use super::*;

extern crate byteorder;
use std::{io, marker};

/// Helper for building packets.
///
/// The packet builder allows the easy construction of a packet from the 
/// ethernet II layer downwards including ipv6, ipv4, the udp header and the 
/// actual payload. The packet builder automatically calculates lengths & checksums 
/// for ip & udp and set type identifiers for ethernetII and ip. This makes it 
/// easy and less error prone to construct custom packets.
///
/// # Example:
///
/// Generating a packet that starts with an Ethernet II header:
///
/// ```
/// use etherparse::PacketBuilder;
/// 
/// let builder = PacketBuilder::
///     ethernet2([1,2,3,4,5,6],     //source mac
///               [7,8,9,10,11,12]) //destionation mac
///    .ipv4([192,168,1,1], //source ip
///          [192,168,1,2], //desitionation ip
///          20)            //time to life
///    .udp(21,    //source port 
///         1234); //desitnation port
///
/// //payload of the udp packet
/// let payload = [1,2,3,4,5,6,7,8];
///     
/// //get some memory to store the result
/// let mut result = Vec::<u8>::with_capacity(
///                     builder.size(payload.len()));
///     
/// //serialize
/// builder.write(&mut result, &payload).unwrap();
/// println!("{:?}", result);
/// ```
pub struct PacketBuilder {}

impl PacketBuilder {
    /// Start an packet with an ethernetII header.
    ///
    /// # Example
    ///
    /// Basic usage: 
    ///
    /// ```
    /// # use etherparse::PacketBuilder;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     //source mac
    ///               [7,8,9,10,11,12]) //destionation mac
    ///    .ipv4([192,168,1,1], //source ip
    ///          [192,168,1,2], //desitionation ip
    ///          20)            //time to life
    ///    .udp(21,    //source port 
    ///         1234); //desitnation port
    ///
    /// //payload of the udp packet
    /// let payload = [1,2,3,4,5,6,7,8];
    ///     
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///     
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn ethernet2(source: [u8;6], destination: [u8;6]) -> PacketBuilderStep<Ethernet2Header> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: Some(Ethernet2Header{
                    source,
                    destination,
                    ether_type: 0 //the type identifier 
                }),
                vlan_header: None,
                ip_header: None,
                transport_header: None
            },
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }
    }

    ///Starts a packet with an IPv4 header.
    ///
    /// # Example
    ///
    /// Basic usage: 
    ///
    /// ```
    /// # use etherparse::PacketBuilder;
    /// #
    /// let builder = PacketBuilder::
    ///    ipv4([192,168,1,1],  //source ip
    ///          [192,168,1,2], //desitionation ip
    ///          20)            //time to life
    ///    .udp(21,    //source port 
    ///         1234); //desitnation port
    ///
    /// //payload of the udp packet
    /// let payload = [1,2,3,4,5,6,7,8];
    ///     
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///     
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn ipv4(source: [u8;4], destination: [u8;4], time_to_live: u8) -> PacketBuilderStep<IpHeader> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: None,
                vlan_header: None,
                ip_header: None,
                transport_header: None
            },
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ipv4(source, destination, time_to_live)
    }

    ///Start a packet with an IPv6 header.
    ///
    /// # Example
    ///
    /// Basic usage: 
    ///
    /// ```
    /// # use etherparse::PacketBuilder;
    /// #
    /// let builder = PacketBuilder::
    ///     ipv6(
    ///         //source
    ///         [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
    ///         //destination
    ///         [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
    ///         //hop_limit
    ///         47)
    ///    .udp(21,    //source port 
    ///         1234); //desitnation port
    ///
    /// //payload of the udp packet
    /// let payload = [1,2,3,4,5,6,7,8];
    ///     
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///     
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn ipv6(source: [u8;16], destination: [u8;16], hop_limit: u8) -> PacketBuilderStep<IpHeader> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: None,
                vlan_header: None,
                ip_header: None,
                transport_header: None
            },
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ipv6(source, destination, hop_limit)
    }

    ///Starts a packet with an arbitrary ip header (length, protocol/next_header & checksum fields will be overwritten based on the rest of the packet).
    ///
    /// # Examples
    ///
    /// With an IPv4 header:
    ///
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///    //payload_len, protocol & checksum will be replaced during write
    ///    ip(IpHeader::Version4(
    ///        Ipv4Header::new(
    ///            0, //payload_len will be replaced during write
    ///            12, //time_to_live
    ///            IpNumber::Udp, //will be replaced during write
    ///            [0,1,2,3], //source
    ///            [4,5,6,7] //destination
    ///        ), 
    ///        Default::default()))
    ///    .udp(21,    //source port 
    ///         1234); //desitnation port
    ///
    /// //payload of the udp packet
    /// let payload = [1,2,3,4,5,6,7,8];
    ///     
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///     
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    ///
    /// With an IPv6 header:
    ///
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///    ip(IpHeader::Version6(
    ///         Ipv6Header{
    ///             traffic_class: 0,
    ///             flow_label: 0,
    ///             payload_length: 0, //will be replaced during write
    ///             next_header: 0, //will be replaced during write
    ///             hop_limit: 4,
    ///             source: [0;16],
    ///             destination: [0;16]
    ///         },
    ///         Default::default()))
    ///    .udp(21,    //source port 
    ///         1234); //desitnation port
    ///
    /// //payload of the udp packet
    /// let payload = [1,2,3,4,5,6,7,8];
    ///     
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///     
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn ip(ip_header: IpHeader) -> PacketBuilderStep<IpHeader> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: None,
                vlan_header: None,
                ip_header: None,
                transport_header: None
            },
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ip(ip_header)
    }
}

struct PacketImpl {
    ethernet2_header: Option<Ethernet2Header>,
    ip_header: Option<IpHeader>,
    vlan_header: Option<VlanHeader>,
    transport_header: Option<TransportHeader>
}

///An unfinished packet that is build with the packet builder
pub struct PacketBuilderStep<LastStep> {
    state: PacketImpl,
    _marker: marker::PhantomData<LastStep>
}

impl PacketBuilderStep<Ethernet2Header> {
    ///Add an ip v4 header
    pub fn ipv4(mut self, source: [u8;4], destination: [u8;4], time_to_live: u8) -> PacketBuilderStep<IpHeader> {
        //add ip header
        self.state.ip_header = Some(IpHeader::Version4({
            let mut value: Ipv4Header = Default::default();
            value.source = source;
            value.destination = destination;
            value.time_to_live = time_to_live;
            value
        }, Default::default()));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Add an ip header (length, protocol/next_header & checksum fields will be overwritten based on the rest of the packet).
    ///
    /// # Examples
    ///
    /// With an IPv4 header:
    ///
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],
    ///               [7,8,9,10,11,12])
    ///    //payload_len, protocol & checksum will be replaced during write
    ///    .ip(IpHeader::Version4(
    ///        Ipv4Header::new(
    ///            0, //payload_len will be replaced during write
    ///            12, //time_to_live
    ///            IpNumber::Udp, //will be replaced during write
    ///            [0,1,2,3], //source
    ///            [4,5,6,7] //destination
    ///        ),
    ///        Default::default()));
    /// ```
    ///
    /// With an IPv6 header:
    ///
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],
    ///               [7,8,9,10,11,12])
    ///    .ip(IpHeader::Version6(
    ///         Ipv6Header{
    ///             traffic_class: 0,
    ///             flow_label: 0,
    ///             payload_length: 0, //will be replaced during write
    ///             next_header: 0, //will be replaced during write
    ///             hop_limit: 4,
    ///             source: [0;16],
    ///             destination: [0;16]
    ///         },
    ///         Default::default()));
    /// ```
    pub fn ip(mut self, ip_header: IpHeader) -> PacketBuilderStep<IpHeader> {
        //add ip header
        self.state.ip_header = Some(ip_header);
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Add an ip v6 header
    pub fn ipv6(mut self, source: [u8;16], destination: [u8;16], hop_limit: u8) -> PacketBuilderStep<IpHeader> {
        self.state.ip_header = Some(IpHeader::Version6(Ipv6Header{
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0, //filled in on write
            next_header: 0, //filled in on write
            hop_limit,
            source,
            destination
        }, Default::default()));
        
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Adds a vlan tagging header with the given vlan identifier
    pub fn vlan(mut self, vlan: VlanHeader) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(vlan);
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader>{}
        }
    }

    ///Adds a vlan tagging header with the given vlan identifier
    pub fn single_vlan(mut self, vlan_identifier: u16) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(VlanHeader::Single(SingleVlanHeader {
            priority_code_point: 0,
            drop_eligible_indicator: false,
            vlan_identifier,
            ether_type: 0, //will be set automatically during write
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader>{}
        }
    }

    ///Adds two vlan tagging header with the given vlan identifiers (also known as double vlan tagging).
    pub fn double_vlan(mut self, outer_vlan_identifier: u16, inner_vlan_identifier: u16) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(VlanHeader::Double(DoubleVlanHeader {
            outer: SingleVlanHeader {
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: outer_vlan_identifier,
                ether_type: 0, //will be set automatically during write
            },
            inner: SingleVlanHeader {
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: inner_vlan_identifier,
                ether_type: 0, //will be set automatically during write
            }
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader>{}
        }
    }
}

impl PacketBuilderStep<VlanHeader> {

    ///Add an ip header (length, protocol/next_header & checksum fields will be overwritten based on the rest of the packet).
    ///
    /// # Example IPv4
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],
    ///               [7,8,9,10,11,12])
    ///    //payload_len, protocol & checksum will be replaced during write
    ///    .ip(IpHeader::Version4(
    ///         Ipv4Header::new(
    ///             0, //payload_len will be replaced during write
    ///             12, //time_to_live
    ///             IpNumber::Udp, //will be replaced during write
    ///             [0,1,2,3], //source
    ///             [4,5,6,7] //destination
    ///         ),
    ///         Default::default()));
    /// ```
    ///
    /// # Example IPv6
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],
    ///               [7,8,9,10,11,12])
    ///    .ip(IpHeader::Version6(
    ///         Ipv6Header{
    ///             traffic_class: 0,
    ///             flow_label: 0,
    ///             payload_length: 0, //will be replaced during write
    ///             next_header: 0, //will be replaced during write
    ///             hop_limit: 4,
    ///             source: [0;16],
    ///             destination: [0;16]
    ///         },
    ///         Default::default()));
    /// ```
    pub fn ip(self, ip_header: IpHeader) -> PacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ip(ip_header)
    }

    ///Add a ip v6 header
    pub fn ipv6(self, source: [u8;16], destination: [u8;16], hop_limit: u8) -> PacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ipv6(source, destination, hop_limit)
    }

    ///Add a ip v4 header
    pub fn ipv4(self, source: [u8;4], destination: [u8;4], time_to_live: u8) -> PacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ipv4(source, destination, time_to_live)
    }
}

impl PacketBuilderStep<IpHeader> {
    pub fn udp(mut self, source_port: u16, destination_port: u16) -> PacketBuilderStep<UdpHeader> {
        self.state.transport_header = Some(TransportHeader::Udp(UdpHeader{
            source_port,
            destination_port,
            length: 0, //calculated later
            checksum: 0 //calculated later
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<UdpHeader>{}
        }
    }

    pub fn tcp(mut self, source_port: u16, destination_port: u16, sequence_number: u32, window_size: u16) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header = Some(TransportHeader::Tcp(
            TcpHeader::new(source_port, destination_port, sequence_number, window_size)
        ));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<TcpHeader>{}
        }
    }
}

impl PacketBuilderStep<UdpHeader> {
    ///Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(self, writer: &mut T, payload: &[u8]) -> Result<(),WriteError> {
        final_write(self, writer, payload)
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(&self, payload_size)
    }
}

impl PacketBuilderStep<TcpHeader> {

    ///Set ns flag (ECN-nonce - concealment protection; experimental: see RFC 3540)
    pub fn ns(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().ns = true;
        self
    }
    ///Set fin flag (No more data from sender)
    pub fn fin(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().fin = true;
        self
    }
    ///Set the syn flag (synchronize sequence numbers)
    pub fn syn(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().syn = true;
        self
    }
    ///Sets the rst flag (reset the connection)
    pub fn rst(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().rst = true;
        self
    }
    ///Sets the psh flag (push function)
    pub fn psh(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().psh = true;
        self
    }
    ///Sets the ack flag and the acknowledgment_number.
    pub fn ack(mut self, acknowledgment_number: u32) -> PacketBuilderStep<TcpHeader> {
        {
            let header = self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap();
            header.ack = true;
            header.acknowledgment_number = acknowledgment_number;
        }
        self
    }
    ///Set the urg flag & the urgent pointer field.
    ///
    ///The urgent pointer points to the sequence number of the octet following
    ///the urgent data.
    pub fn urg(mut self, urgent_pointer: u16) -> PacketBuilderStep<TcpHeader> {
        {
            let header = self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap();
            header.urg = true;
            header.urgent_pointer = urgent_pointer;
        }
        self
    }
    ///Sets ece flag (ECN-Echo, RFC 3168)
    pub fn ece(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().ece = true;
        self
    }

    ///Set cwr flag (Congestion Window Reduced)
    ///
    ///This flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    pub fn cwr(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().cwr = true;
        self
    }

    ///Set the tcp options of the header.
    pub fn options(mut self, options: &[TcpOptionElement]) -> Result<PacketBuilderStep<TcpHeader>, TcpOptionWriteError> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().set_options(options)?;
        Ok(self)
    }

    ///Set the tcp options of the header (setting the bytes directly).
    pub fn options_raw(mut self, options: &[u8]) -> Result<PacketBuilderStep<TcpHeader>, TcpOptionWriteError> {
        self.state.transport_header.as_mut().unwrap().mut_tcp().unwrap().set_options_raw(options)?;
        Ok(self)
    }

    ///Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(self, writer: &mut T, payload: &[u8]) -> Result<(),WriteError> {
        final_write(self, writer, payload)
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(&self, payload_size)
    }
}

///Write all the headers and the payload.
fn final_write<T: io::Write + Sized, B>(builder: PacketBuilderStep<B>, writer: &mut T, payload: &[u8]) -> Result<(),WriteError> {
    
    let ip_ether_type = {
        use crate::IpHeader::*;
        match builder.state.ip_header {
            Some(Version4(_,_)) => EtherType::Ipv4 as u16,
            Some(Version6(_,_)) => EtherType::Ipv6 as u16,
            None => panic!("Missing ip header")
        }
    };

    //ethernetII header
    if let Some(mut eth) = builder.state.ethernet2_header {
        eth.ether_type = {
            
            use crate::VlanHeader::*;
            //determine the ether type depending on if there is a vlan tagging header
            match builder.state.vlan_header {
                Some(Single(_)) => EtherType::VlanTaggedFrame as u16,
                Some(Double(_)) => EtherType::ProviderBridging as u16,
                //if no vlan header exists, the id is purely defined by the ip type
                None => ip_ether_type
            }
        };
        eth.write(writer)?;
    }

    //write the vlan header if it exists
    use crate::VlanHeader::*;
    match builder.state.vlan_header {
        Some(Single(mut value)) => {
            //set ether types
            value.ether_type = ip_ether_type;
            //serialize
            value.write(writer)?;
        },
        Some(Double(mut value)) => {
            //set ether types
            value.outer.ether_type = EtherType::VlanTaggedFrame as u16;
            value.inner.ether_type = ip_ether_type;
            //serialize
            value.write(writer)?;
        },
        None => {}
    }

    //unpack the transport header
    let mut transport = builder.state.transport_header.unwrap();

    //ip header
    use crate::IpHeader::*;
    let ip_header = builder.state.ip_header.unwrap();
    match ip_header {
        Version4(mut ip, mut ext) => {
            //set total length & udp payload length (ip checks that the payload length is ok)
            let transport_size = transport.header_len() + payload.len();
            ip.set_payload_len(ext.header_len() + transport_size)?;
            use crate::TransportHeader::*;
            match transport {
                Udp(ref mut udp) => { udp.length = transport_size as u16; }
                Tcp(_) => {}
            }

            //ip protocol number & next header values of the extension header
            ip.protocol = ext.set_next_headers(
                match transport {
                    Udp(_) => ip_number::UDP,
                    Tcp(_) => ip_number::TCP
                }
            );

            //calculate the udp checksum
            transport.update_checksum_ipv4(&ip, payload)?;

            //write (will automatically calculate the checksum)
            ip.write(writer)?;
            ext.write(writer, ip.protocol)?
        },
        Version6(mut ip, mut ext) => {
            //set total length
            let transport_size = transport.header_len() + payload.len();
            ip.set_payload_length(ext.header_len() + transport_size)?;
            use crate::TransportHeader::*;
            match transport {
                Udp(ref mut udp) => { udp.length = transport_size as u16; }
                Tcp(_) => {}
            }

            //set the protocol
            ip.next_header = ext.set_next_headers(
                match transport {
                    Udp(_) => ip_number::UDP as u8,
                    Tcp(_) => ip_number::TCP as u8
                }
            );

            //calculate the udp checksum
            transport.update_checksum_ipv6(&ip, payload)?;

            //write (will automatically calculate the checksum)
            ip.write(writer)?;
            ext.write(writer, ip.next_header)?
        }
    }

    //finaly write the udp header & payload
    transport.write(writer)?;
    writer.write_all(payload)?;
    Ok(())
}

///Returns the size of the packet when it is serialized
fn final_size<B>(builder: &PacketBuilderStep<B>, payload_size: usize) -> usize {
    use crate::IpHeader::*;
    use crate::VlanHeader::*;
    use crate::TransportHeader::*;
    (match builder.state.ethernet2_header {
        Some(_) => Ethernet2Header::SERIALIZED_SIZE,
        None => 0
    }) + match builder.state.vlan_header {
        Some(Single(_)) => SingleVlanHeader::SERIALIZED_SIZE,
        Some(Double(_)) => DoubleVlanHeader::SERIALIZED_SIZE,
        None => 0 
    } + match builder.state.ip_header {
        Some(Version4(ref value, ref ext)) => value.header_len() + ext.header_len(),
        Some(Version6(_, ref ext)) => Ipv6Header::SERIALIZED_SIZE + ext.header_len(),
        None => 0
    } + match builder.state.transport_header {
        Some(Udp(_)) => UdpHeader::SERIALIZED_SIZE,
        Some(Tcp(ref value)) => value.header_len() as usize,
        None => 0
    } + payload_size
}

#[cfg(test)]
mod whitebox_tests {
    //whitebox tests that need internal access
    #[test]
    fn size() {
        use super::*;

        assert_eq!(0,
        PacketBuilderStep::<UdpHeader> {
            state: PacketImpl {
                ethernet2_header: None,
                ip_header: None,
                vlan_header: None,
                transport_header: None
            },
            _marker: marker::PhantomData::<UdpHeader>{}
        }.size(0));
    }
}

