use super::*;

///A slice containing the link layer header (currently only Ethernet II is supported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkSlice<'a> {
    ///A slice containing an Ethernet II header.
    Ethernet2(Ethernet2HeaderSlice<'a>)
}

///A slice containing a single or double vlan header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanSlice<'a> {
    SingleVlan(SingleVlanHeaderSlice<'a>),
    DoubleVlan(DoubleVlanHeaderSlice<'a>),
}

impl<'a> VlanSlice<'a> {
    ///Decode all the fields and copy the results to a VlanHeader struct
    pub fn to_header(&self) -> VlanHeader {
        use crate::VlanHeader::*;
        use crate::VlanSlice::*;
        match self {
            SingleVlan(value) => Single(value.to_header()),
            DoubleVlan(value) => Double(value.to_header())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternetSlice<'a> {
    /// The ipv6 header & the decoded extension headers.
    Ipv4(Ipv4HeaderSlice<'a>, Ipv4ExtensionSlices<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(Ipv6HeaderSlice<'a>, Ipv6ExtensionSlices<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportSlice<'a> {
    ///A slice containing an UDP header.
    Udp(UdpHeaderSlice<'a>),
    ///A slice containing a TCP header.
    Tcp(TcpHeaderSlice<'a>),
    ///Unknonwn transport layer protocol. The value is the last parsed ip protocol number.
    Unknown(u8),
}

///A sliced into its component headers. Everything that could not be parsed is stored in a slice in the field "payload".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlicedPacket<'a> {
    pub link: Option<LinkSlice<'a>>,
    pub vlan: Option<VlanSlice<'a>>,
    pub ip: Option<InternetSlice<'a>>,
    /// IP Extension headers present after the ip header. 
    ///
    /// In case of IPV4 these can be ipsec authentication & encapsulated
    /// security headers. In case of IPv6 these are the ipv6 extension headers.
    /// The headers are in the same order as they are written to the packet.
    //pub ip_extensions: [Option<IpExtensionHeaderSlice<'a>>;IP_MAX_NUM_HEADER_EXTENSIONS],
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

impl<'a> SlicedPacket<'a> {
    /// Seperates a network packet slice into different slices containing the headers from the ethernet header downwards. 
    ///
    /// The result is returned as a SlicerPacket struct. This function assumes the given data starts 
    /// with an ethernet II header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{SlicedPacket, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ethernet2([1,2,3,4,5,6],     //source mac
    /// #               [7,8,9,10,11,12]) //destionation mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //desitionation ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port 
    /// #         1234); //desitnation port
    /// #    //payload of the udp packet
    /// #    let payload = [1,2,3,4,5,6,7,8];
    /// #    //get some memory to store the serialized data
    /// #    let mut packet = Vec::<u8>::with_capacity(
    /// #                            builder.size(payload.len()));
    /// #    builder.write(&mut packet, &payload).unwrap();
    /// match SlicedPacket::from_ethernet(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ethernet(data: &'a [u8]) -> Result<SlicedPacket, ReadError> {
        CursorSlice::new(data).slice_ethernet2()
    }

    /// Seperates a network packet slice into different slices containing the headers from the ip header downwards. 
    ///
    /// The result is returned as a SlicerPacket struct. This function assumes the given data starts 
    /// with an IPv4 or IPv6 header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{SlicedPacket, PacketBuilder};
    /// # let builder = PacketBuilder::
    /// #    ipv4([192,168,1,1], //source ip
    /// #         [192,168,1,2], //desitionation ip
    /// #         20)            //time to life
    /// #    .udp(21,    //source port 
    /// #         1234); //desitnation port
    /// #    //payload of the udp packet
    /// #    let payload = [1,2,3,4,5,6,7,8];
    /// #    //get some memory to store the serialized data
    /// #    let mut packet = Vec::<u8>::with_capacity(
    /// #                            builder.size(payload.len()));
    /// #    builder.write(&mut packet, &payload).unwrap();
    /// match SlicedPacket::from_ip(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         //link & vlan fields are empty when parsing from ip downwards
    ///         assert_eq!(None, value.link);
    ///         assert_eq!(None, value.vlan);
    ///
    ///         //ip & transport (udp or tcp)
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ip(data: &'a [u8]) -> Result<SlicedPacket, ReadError> {
        CursorSlice::new(data).slice_ip()
    }
}

///Helper class for slicing packets
struct CursorSlice<'a> {
    pub slice: &'a [u8],
    pub offset: usize,
    pub result: SlicedPacket<'a>
}

impl<'a> CursorSlice<'a> {

    pub fn new(slice: &'a [u8]) -> CursorSlice<'a> {
        CursorSlice {
            offset: 0,
            slice,
            result: SlicedPacket {
                link: None,
                vlan: None,
                ip: None,
                //ip_extensions: [None;IP_MAX_NUM_HEADER_EXTENSIONS],
                transport: None,
                payload: slice
            }
        }
    }

    fn move_by_slice(&mut self, other: &'a[u8]) {
        self.slice = &self.slice[other.len()..];
        self.offset += other.len();
    }

    fn move_to_slice(&mut self, other: &'a[u8]) {
        self.offset += self.slice.len() - other.len();
        self.slice = other;
    }

    pub fn slice_ethernet2(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::LinkSlice::*;

        let result = Ethernet2HeaderSlice::from_slice(self.slice)
                     .map_err(|err| 
                        err.add_slice_offset(self.offset)
                     )?;

        //cache the ether_type for later
        let ether_type = result.ether_type();

        //set the new data
        self.move_by_slice(result.slice());
        self.result.link = Some(Ethernet2(result));

        //continue parsing (if required)
        match ether_type {
            ETH_IPV4 => self.slice_ipv4(),
            ETH_IPV6 => self.slice_ipv6(),
            ETH_VLAN | ETH_BRIDGE | ETH_VLAN_DOUBLE => self.slice_vlan(),
            _ => self.slice_payload()
        }
    }

    pub fn slice_vlan(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::VlanSlice::*;

        let single = SingleVlanHeaderSlice::from_slice(self.slice)
                     .map_err(|err| 
                        err.add_slice_offset(self.offset)
                     )?;

        //check if it is a double vlan header
        let ether_type = single.ether_type();
        match ether_type {
            //in case of a double vlan header continue with the inner
            ETH_VLAN | ETH_BRIDGE | ETH_VLAN_DOUBLE => self.slice_double_vlan(),
            value => {
                //set the vlan header and continue the normal parsing
                self.move_by_slice(single.slice());
                self.result.vlan = Some(SingleVlan(single));

                match value {
                    ETH_IPV4 => self.slice_ipv4(),
                    ETH_IPV6 => self.slice_ipv6(),
                    _ => self.slice_payload()
                }
            }
        }
    }

    pub fn slice_double_vlan(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::VlanSlice::*;

        let result = DoubleVlanHeaderSlice::from_slice(self.slice)
                     .map_err(|err| 
                        err.add_slice_offset(self.offset)
                     )?;

        //cache ether_type for later
        let ether_type = result.inner().ether_type();

        //set the new data
        self.move_by_slice(result.slice());
        self.result.vlan = Some(DoubleVlan(result));

        //continue parsing (if required)
        match ether_type {
            ETH_IPV4 => self.slice_ipv4(),
            ETH_IPV6 => self.slice_ipv6(),
            _ => self.slice_payload()
        }
    }

    pub fn slice_ip(self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::ReadError::*;
        if self.slice.is_empty() {
            Err(UnexpectedEndOfSlice(self.offset + 1))
        } else {
            match self.slice[0] >> 4 {
                4 => self.slice_ipv4(),
                6 => self.slice_ipv6(),
                version => Err(IpUnsupportedVersion(version))
            }
        }
    }

    pub fn slice_ipv4(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::InternetSlice::*;

        let ip_header = Ipv4HeaderSlice::from_slice(self.slice)
                        .map_err(|err| 
                            err.add_slice_offset(self.offset)
                        )?;
        // move the slice
        self.move_by_slice(ip_header.slice());

        // slice extensions
        let (ip_ext, protocol, rest) = Ipv4ExtensionSlices::from_slice(ip_header.protocol(), self.slice)
                                       .map_err(|err| 
                                            err.add_slice_offset(self.offset)
                                       )?;

        // set the new data 
        self.move_to_slice(rest);
        self.result.ip = Some(Ipv4(ip_header, ip_ext));

        match protocol {
            ip_number::UDP => self.slice_udp(),
            ip_number::TCP => self.slice_tcp(),
            value => {
                use TransportSlice::*;
                self.result.transport = Some(Unknown(value));
                self.slice_payload()
            }
        }
    }

    pub fn slice_ipv6(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::InternetSlice::*;

        let ip = Ipv6HeaderSlice::from_slice(self.slice)
                 .map_err(|err| 
                    err.add_slice_offset(self.offset)
                 )?;

        //move the slice
        self.move_by_slice(ip.slice());

        //extension headers
        let (ip_ext, next_header, rest) = Ipv6ExtensionSlices::from_slice(ip.next_header(), self.slice)
                                          .map_err(|err| 
                                              err.add_slice_offset(self.offset)
                                          )?;

        // set the new data 
        self.move_to_slice(rest);
        self.result.ip = Some(Ipv6(ip, ip_ext));

        //parse the data bellow
        match next_header {
            ip_number::UDP => self.slice_udp(),
            ip_number::TCP => self.slice_tcp(),
            value => {
                use TransportSlice::*;
                self.result.transport = Some(Unknown(value));
                self.slice_payload()
            }
        }
    }

    pub fn slice_udp(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::TransportSlice::*;

        let result = UdpHeaderSlice::from_slice(self.slice)
                     .map_err(|err| 
                        err.add_slice_offset(self.offset)
                     )?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Udp(result));

        //done
        self.slice_payload()
    }

    pub fn slice_tcp(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        use crate::TransportSlice::*;

        let result = TcpHeaderSlice::from_slice(self.slice)
                     .map_err(|err| 
                        err.add_slice_offset(self.offset)
                     )?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Tcp(result));

        //done
        self.slice_payload()
    }

    pub fn slice_payload(mut self) -> Result<SlicedPacket<'a>, ReadError> {
        self.result.payload = self.slice;
        Ok(self.result)
    }

}
