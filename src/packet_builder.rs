use super::*;

extern crate byteorder;
use std::marker;

/// Helper for building packets.
///
/// The packet builder allows the easy construction of a packet from the 
/// ethernet II layer downwards including ipv6, ipv4, the udp header and the 
/// actual payload. The packet builder automatically calculates lengths & checksums 
/// for ip & udp and set type identifiers for ethernetII and ip. This makes it 
/// easy and less error prone to construct custom packets.
///
/// # Example
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
/// println!("{:?}", result);
/// ```
pub struct PacketBuilder {}

impl PacketBuilder {
    ///Start an packet with an ethernetII header.
    pub fn ethernet2(source: [u8;6], destination: [u8;6]) -> PacketBuilderStep<Ethernet2Header> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: Some(Ethernet2Header{
                    source: source,
                    destination: destination,
                    ether_type: 0 //the type identifier 
                }),
                vlan_header: None,
                ip_header: None,
                udp_header: None
            },
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }
    }
}

struct PacketImpl {
    ethernet2_header: Option<Ethernet2Header>,
    ip_header: Option<IpHeader>,
    vlan_header: Option<VlanHeader>,
    udp_header: Option<UdpHeader>
}

///An unfinished packet that is build with the packet builder
pub struct PacketBuilderStep<LastStep> {
    state: PacketImpl,
    _marker: marker::PhantomData<LastStep>
}

impl PacketBuilderStep<Ethernet2Header> {
    ///Add a ip v4 header
    pub fn ipv4(mut self, source: [u8;4], destination: [u8;4], time_to_live: u8) -> PacketBuilderStep<IpHeader> {
        //add ip header
        self.state.ip_header = Some(IpHeader::Version4(Ipv4Header{
            header_length: 5,
            differentiated_services_code_point: 0,
            explicit_congestion_notification: 0,
            total_length: 0, //filled in later
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragments_offset: 0,
            time_to_live: time_to_live,
            protocol: 0, //filled in later as soon as the content is clear
            header_checksum: 0, //calculated later
            source: source,
            destination: destination
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Add a ip v6 header
    pub fn ipv6(mut self, source: [u8;16], destination: [u8;16], hop_limit: u8) -> PacketBuilderStep<IpHeader> {
        self.state.ip_header = Some(IpHeader::Version6(Ipv6Header{
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0, //filled in on write
            next_header: 0, //filled in on write
            hop_limit: hop_limit,
            source: source,
            destination: destination
        }));
        
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Adds a vlan tagging header with the given vlan identifier
    pub fn single_vlan(mut self, vlan_identifier: u16) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(VlanHeader::Single(SingleVlanHeader {
            priority_code_point: 0,
            drop_eligible_indicator: false,
            vlan_identifier: vlan_identifier,
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
        self.state.udp_header = Some(UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: 0, //calculated later
            checksum: 0 //calculated later
        });
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<UdpHeader>{}
        }
    }
}

impl PacketBuilderStep<UdpHeader> {
    ///Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(self, writer: &mut T, payload: &[u8]) -> Result<(),WriteError> {
        
        let ip_ether_type = {
            use IpHeader::*;
            match self.state.ip_header {
                Some(Version4(_)) => EtherType::Ipv4 as u16,
                Some(Version6(_)) => EtherType::Ipv6 as u16,
                None => panic!("Missing ip header")
            }
        };

        //ethernetII header
        match self.state.ethernet2_header {
            Some(mut eth) => {
                eth.ether_type = {
                    
                    use VlanHeader::*;
                    //determine the ether type depending on if there is a vlan tagging header
                    match self.state.vlan_header {
                        Some(Single(_)) => EtherType::VlanTaggedFrame as u16,
                        Some(Double(_)) => EtherType::ProviderBridging as u16,
                        //if no vlan header exists, the id is purely defined by the ip type
                        None => ip_ether_type
                    }
                };
                eth.write(writer)?;
            },
            None => {}
        }

        //write the vlan header if it exists
        use VlanHeader::*;
        match self.state.vlan_header {
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

        //unpack the udp header
        let mut udp = self.state.udp_header.unwrap();

        //ip header
        use IpHeader::*;
        let ip_header = self.state.ip_header.unwrap();
        match ip_header {
            Version4(mut ip) => {
                //set total length & udp payload length (ip checks that the payload length is ok)
                let size = UdpHeader::SERIALIZED_SIZE + payload.len();
                ip.set_payload_and_options_length(size)?;
                udp.length = size as u16;

                //traffic class
                ip.protocol = IpTrafficClass::Udp as u8;

                //calculate the udp checksum
                udp.checksum = udp.calc_checksum_ipv4(&ip, payload)?;

                //write (will automatically calculate the checksum)
                ip.write(writer, &[])?
            },
            Version6(mut ip) => {
                //set total length
                let size = UdpHeader::SERIALIZED_SIZE + payload.len();
                ip.set_payload_length(size)?;
                udp.length = size as u16;

                //set the protocol
                ip.next_header = IpTrafficClass::Udp as u8;

                //calculate the udp checksum
                udp.checksum = udp.calc_checksum_ipv6(&ip, payload)?;

                //write (will automatically calculate the checksum)
                ip.write(writer)?

            }
        }

        //finaly write the udp header & payload
        udp.write(writer)?;
        writer.write_all(payload)?;
        Ok(())
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        use IpHeader::*;
        let result = match self.state.ethernet2_header {
            Some(_) => Ethernet2Header::SERIALIZED_SIZE,
            None => 0
        } + match self.state.ip_header {
            Some(Version4(_)) => Ipv4Header::SERIALIZED_SIZE,
            Some(Version6(_)) => Ipv6Header::SERIALIZED_SIZE,
            None => 0
        } + match self.state.udp_header {
            Some(_) => UdpHeader::SERIALIZED_SIZE,
            None => 0
        } + payload_size;
        result
    }
}