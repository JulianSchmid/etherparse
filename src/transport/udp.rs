use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
use std::marker;

///Udp header according to rfc768.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpHeader {
    ///Source port of the packet (optional).
    pub source_port: u16,
    ///Destination port of the packet.
    pub destination_port: u16,
    ///Length of the packet (includes the udp header length of 8 bytes).
    pub length: u16,
    ///The checksum of the packet. The checksum is calculated from a pseudo header, the udp header and the payload. The pseudo header is composed of source and destination address, protocol number 
    pub checksum: u16
}

impl UdpHeader {

    ///Returns an udp header for the given parameters
    pub fn without_ipv4_checksum(source_port: u16, destination_port: u16, payload_length: usize) -> Result<UdpHeader, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload_length {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload_length));
        }

        Ok(UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload_length) as u16, //payload plus udp header
            checksum: 0
        })
    }

    ///Calculate an udp header given an ipv4 header and the payload
    pub fn with_ipv4_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv4Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {

        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        let mut result = UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv4_internal(&ip_header.source, &ip_header.destination, ip_header.protocol, payload);
        Ok(result)
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4(&self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, ip_header.protocol, payload)
    }

    ///Calculates the upd header checksum based on a ipv4 header.
    pub fn calc_checksum_ipv4_raw(&self, source: &[u8;4], destination: &[u8;4], protocol: u8, payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv4_internal(source, destination, protocol, payload))
    }
    
    ///Calculates the upd header checksum based on a ipv4 header.
    fn calc_checksum_ipv4_internal(&self, source: &[u8;4], destination: &[u8;4], protocol: u8, payload: &[u8]) -> u16 {
        self.calc_checksum_post_ip(BigEndian::read_u16(&source[0..2]) as u64 + //pseudo header
                                   BigEndian::read_u16(&source[2..4]) as u64 +
                                   BigEndian::read_u16(&destination[0..2]) as u64 +
                                   BigEndian::read_u16(&destination[2..4]) as u64 +
                                   protocol as u64 +
                                   self.length as u64, 
                                   payload)
    }

    ///Calculate an udp header given an ipv6 header and the payload
    pub fn with_ipv6_checksum(source_port: u16, destination_port: u16, ip_header: &Ipv6Header, payload: &[u8]) -> Result<UdpHeader, ValueError> {

        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        let mut result = UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16, //payload plus udp header
            checksum: 0
        };
        result.checksum = result.calc_checksum_ipv6_internal(&ip_header.source, &ip_header.destination, payload);
        Ok(result)
    }

    ///Calculates the checksum of the current udp header given an ipv6 header and the payload.
    pub fn calc_checksum_ipv6(&self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<u16, ValueError> {
        self.calc_checksum_ipv6_raw(&ip_header.source, &ip_header.destination, payload)
    }

    ///Calculates the checksum of the current udp header given an ipv6 source & destination address plus the payload.
    pub fn calc_checksum_ipv6_raw(&self, source: &[u8;16], destination: &[u8;16], payload: &[u8]) -> Result<u16, ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE;
        if MAX_PAYLOAD_LENGTH < payload.len() {
            return Err(ValueError::UdpPayloadLengthTooLarge(payload.len()));
        }

        Ok(self.calc_checksum_ipv6_internal(source, destination, payload))
    }

    fn calc_checksum_ipv6_internal(&self, source: &[u8;16], destination: &[u8;16], payload: &[u8]) -> u16 {
        fn calc_sum(value: &[u8;16]) -> u64 {
            let mut result = 0;
            for i in 0..8 {
                let index = i*2;
                result += BigEndian::read_u16(&value[index..(index + 2)]) as u64;
            }
            result
        }
        self.calc_checksum_post_ip(calc_sum(source) +
                                   calc_sum(destination) +
                                   IpTrafficClass::Udp as u64 +
                                   self.length as u64,
                                   payload)
    }

    ///This method takes the sum of the preudo ip header and calculates the rest of the checksum.
    fn calc_checksum_post_ip(&self, ip_pseudo_header_sum: u64, payload: &[u8]) -> u16 {
        let mut sum = ip_pseudo_header_sum +
                      self.source_port as u64 + //udp header start
                      self.destination_port as u64 +
                      self.length as u64;

        for i in 0..(payload.len()/2) {
            sum += BigEndian::read_u16(&payload[i*2..i*2 + 2]) as u64;
        }
        //pad the last byte with 0
        if payload.len() % 2 == 1 {
            sum += BigEndian::read_u16(&[*payload.last().unwrap(), 0]) as u64;
        }
        let carry_add = (sum & 0xffff) + 
                        ((sum >> 16) & 0xffff) +
                        ((sum >> 32) & 0xffff) +
                        ((sum >> 48) & 0xffff);
        let result = ((carry_add & 0xffff) + (carry_add >> 16)) as u16;
        if 0xffff == result {
            result //avoid the transmition of an all 0 checksum as this value is reserved by "checksum disabled" (see rfc)
        } else {
            !result
        }
    }

    ///Tries to read an udp header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<UdpHeader, io::Error> {
        Ok(UdpHeader{
            source_port: reader.read_u16::<BigEndian>()?,
            destination_port: reader.read_u16::<BigEndian>()?,
            length: reader.read_u16::<BigEndian>()?,
            checksum: reader.read_u16::<BigEndian>()?
        })
    }

    ///Write the udp header without recalculating the checksum or length.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_u16::<BigEndian>(self.source_port)?;
        writer.write_u16::<BigEndian>(self.destination_port)?;
        writer.write_u16::<BigEndian>(self.length)?;
        writer.write_u16::<BigEndian>(self.checksum)?;
        Ok(())
    }
}

impl SerializedSize for UdpHeader {
    ///Size of the header itself
    const SERIALIZED_SIZE: usize = 8;
}

/// Helper for building udp packets.
///
/// The upd packet builder allows the easy construction of a packet from the 
/// ethernet II layer downwards including ipv6, ipv4, the udp header and the 
/// actual payload. The packet builder automatically calculates lengths & checksums 
/// for ip & udp and set type identifiers for ethernetII and ip. This makes it 
/// easy and less error prone to construct custom packets.
///
/// # Example
/// ```
/// # use etherparse::UdpPacketBuilder;
/// #
/// let builder = UdpPacketBuilder::
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
pub struct UdpPacketBuilder {}

impl UdpPacketBuilder {
    ///Start an udp packet with an ethernetII header.
    pub fn ethernet2(source: [u8;6], destination: [u8;6]) -> UdpPacketBuilderStep<Ethernet2Header> {
        UdpPacketBuilderStep {
            state: UdpPacketImpl {
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

struct UdpPacketImpl {
    ethernet2_header: Option<Ethernet2Header>,
    ip_header: Option<IpHeader>,
    vlan_header: Option<VlanHeader>,
    udp_header: Option<UdpHeader>
}

///An unfinished udp packet that is build with the udp packet builder
pub struct UdpPacketBuilderStep<LastStep> {
    state: UdpPacketImpl,
    _marker: marker::PhantomData<LastStep>
}

impl UdpPacketBuilderStep<Ethernet2Header> {
    ///Add a ip v4 header
    pub fn ipv4(mut self, source: [u8;4], destination: [u8;4], time_to_live: u8) -> UdpPacketBuilderStep<IpHeader> {
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
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Add a ip v6 header
    pub fn ipv6(mut self, source: [u8;16], destination: [u8;16], hop_limit: u8) -> UdpPacketBuilderStep<IpHeader> {
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
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader>{}
        }
    }

    ///Adds a vlan tagging header with the given vlan identifier
    pub fn single_vlan(mut self, vlan_identifier: u16) -> UdpPacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(VlanHeader::Single(SingleVlanHeader {
            priority_code_point: 0,
            drop_eligible_indicator: false,
            vlan_identifier: vlan_identifier,
            ether_type: 0, //will be set automatically during write
        }));
        //return for next step
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader>{}
        }
    }

    ///Adds two vlan tagging header with the given vlan identifiers (also known as double vlan tagging).
    pub fn double_vlan(mut self, outer_vlan_identifier: u16, inner_vlan_identifier: u16) -> UdpPacketBuilderStep<VlanHeader> {
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
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader>{}
        }
    }
}

impl UdpPacketBuilderStep<VlanHeader> {
    ///Add a ip v6 header
    pub fn ipv6(self, source: [u8;16], destination: [u8;16], hop_limit: u8) -> UdpPacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ipv6(source, destination, hop_limit)
    }

    ///Add a ip v4 header
    pub fn ipv4(self, source: [u8;4], destination: [u8;4], time_to_live: u8) -> UdpPacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header>{}
        }.ipv4(source, destination, time_to_live)
    }
}

impl UdpPacketBuilderStep<IpHeader> {
    pub fn udp(mut self, source_port: u16, destination_port: u16) -> UdpPacketBuilderStep<UdpHeader> {
        self.state.udp_header = Some(UdpHeader{
            source_port: source_port,
            destination_port: destination_port,
            length: 0, //calculated later
            checksum: 0 //calculated later
        });
        //return for next step
        UdpPacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<UdpHeader>{}
        }
    }
}

impl UdpPacketBuilderStep<UdpHeader> {
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
