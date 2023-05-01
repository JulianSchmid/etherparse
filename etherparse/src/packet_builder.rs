use crate::err::packet::BuildWriteError;

use super::*;

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
///
/// # Options
///
/// * Starting Options:
///     * [`PacketBuilder::ethernet2`]
///     * [`PacketBuilder::ip`]
///     * [`PacketBuilder::ipv4`]
///     * [`PacketBuilder::ipv6`]
/// * Options after an Ethernet2 header was added:
///     * [`PacketBuilderStep<Ethernet2Header>::vlan`]
///     * [`PacketBuilderStep<Ethernet2Header>::single_vlan`]
///     * [`PacketBuilderStep<Ethernet2Header>::double_vlan`]
///     * [`PacketBuilderStep<Ethernet2Header>::ip`]
///     * [`PacketBuilderStep<Ethernet2Header>::ipv4`]
///     * [`PacketBuilderStep<Ethernet2Header>::ipv6`]
/// * Options after an Vlan header was added:
///     * [`PacketBuilderStep<VlanHeader>::ip`]
///     * [`PacketBuilderStep<VlanHeader>::ipv4`]
///     * [`PacketBuilderStep<VlanHeader>::ipv6`]
/// * Options after an IP header was added:
///     * [`PacketBuilderStep<IpHeader>::write`]
///     * [`PacketBuilderStep<IpHeader>::tcp`]
///     * [`PacketBuilderStep<IpHeader>::udp`]
///     * [`PacketBuilderStep<IpHeader>::icmpv4`]
///     * [`PacketBuilderStep<IpHeader>::icmpv4_raw`]
///     * [`PacketBuilderStep<IpHeader>::icmpv4_echo_request`]
///     * [`PacketBuilderStep<IpHeader>::icmpv4_echo_reply`]
///     * [`PacketBuilderStep<IpHeader>::icmpv6`]
///     * [`PacketBuilderStep<IpHeader>::icmpv6_raw`]
///     * [`PacketBuilderStep<IpHeader>::icmpv6_echo_request`]
///     * [`PacketBuilderStep<IpHeader>::icmpv6_echo_reply`]
/// * Options after an TCP header was added:
///     * [`PacketBuilderStep<TcpHeader>::write`]
///     * [`PacketBuilderStep<TcpHeader>::size`]
///     * [`PacketBuilderStep<TcpHeader>::ns`]
///     * [`PacketBuilderStep<TcpHeader>::fin`]
///     * [`PacketBuilderStep<TcpHeader>::syn`]
///     * [`PacketBuilderStep<TcpHeader>::rst`]
///     * [`PacketBuilderStep<TcpHeader>::psh`]
///     * [`PacketBuilderStep<TcpHeader>::ack`]
///     * [`PacketBuilderStep<TcpHeader>::urg`]
///     * [`PacketBuilderStep<TcpHeader>::ece`]
///     * [`PacketBuilderStep<TcpHeader>::cwr`]
///     * [`PacketBuilderStep<TcpHeader>::options`]
///     * [`PacketBuilderStep<TcpHeader>::options_raw`]
/// * Options after an UDP header was added:
///     * [`PacketBuilderStep<UdpHeader>::write`]
///     * [`PacketBuilderStep<UdpHeader>::size`]
/// * Options after an ICMPv4 header was added:
///     * [`PacketBuilderStep<Icmpv4Header>::write`]
///     * [`PacketBuilderStep<Icmpv4Header>::size`]
/// * Options after an ICMPv6 header was added:
///     * [`PacketBuilderStep<Icmpv6Header>::write`]
///     * [`PacketBuilderStep<Icmpv6Header>::size`]
///
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
    pub fn ethernet2(source: [u8; 6], destination: [u8; 6]) -> PacketBuilderStep<Ethernet2Header> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: Some(Ethernet2Header {
                    source,
                    destination,
                    ether_type: EtherType(0), //the type identifier
                }),
                vlan_header: None,
                ip_header: None,
                transport_header: None,
            },
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
    }

    /// Starts a packet with an IPv4 header.
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
    pub fn ipv4(
        source: [u8; 4],
        destination: [u8; 4],
        time_to_live: u8,
    ) -> PacketBuilderStep<IpHeader> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: None,
                vlan_header: None,
                ip_header: None,
                transport_header: None,
            },
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
        .ipv4(source, destination, time_to_live)
    }

    /// Start a packet with an IPv6 header.
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
    pub fn ipv6(
        source: [u8; 16],
        destination: [u8; 16],
        hop_limit: u8,
    ) -> PacketBuilderStep<IpHeader> {
        PacketBuilderStep {
            state: PacketImpl {
                ethernet2_header: None,
                vlan_header: None,
                ip_header: None,
                transport_header: None,
            },
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
        .ipv6(source, destination, hop_limit)
    }

    /// Starts a packet with an arbitrary IP header (length, protocol/next_header & checksum fields will be overwritten based on the rest of the packet).
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
    ///            ip_number::UDP, //will be replaced during write
    ///            [0,1,2,3], //source
    ///            [4,5,6,7] //destination
    ///        ).unwrap(),
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
    ///             flow_label: 0.try_into().unwrap(),
    ///             hop_limit: 4.try_into().unwrap(),
    ///             source: [0;16],
    ///             destination: [0;16],
    ///             // payload_length & next_header will be replaced during write
    ///             ..Default::default()
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
                transport_header: None,
            },
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
        .ip(ip_header)
    }
}

struct PacketImpl {
    ethernet2_header: Option<Ethernet2Header>,
    ip_header: Option<IpHeader>,
    vlan_header: Option<VlanHeader>,
    transport_header: Option<TransportHeader>,
}

///An unfinished packet that is build with the packet builder
pub struct PacketBuilderStep<LastStep> {
    state: PacketImpl,
    _marker: marker::PhantomData<LastStep>,
}

impl PacketBuilderStep<Ethernet2Header> {
    /// Add an IPv4 header
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
    pub fn ipv4(
        mut self,
        source: [u8; 4],
        destination: [u8; 4],
        time_to_live: u8,
    ) -> PacketBuilderStep<IpHeader> {
        //add ip header
        self.state.ip_header = Some(IpHeader::Version4(
            Ipv4Header {
                source,
                destination,
                time_to_live,
                ..Default::default()
            },
            Default::default(),
        ));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader> {},
        }
    }

    /// Add an IP header (length, protocol/next_header & checksum fields will be overwritten based on the rest of the packet).
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
    ///            ip_number::UDP, //will be replaced during write
    ///            [0,1,2,3], //source
    ///            [4,5,6,7] //destination
    ///        ).unwrap(),
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
    ///             flow_label: 0.try_into().unwrap(),
    ///             hop_limit: 4,
    ///             source: [0;16],
    ///             destination: [0;16],
    ///             // payload_length & next_header will be replaced during write
    ///             ..Default::default()
    ///         },
    ///         Default::default()));
    /// ```
    pub fn ip(mut self, ip_header: IpHeader) -> PacketBuilderStep<IpHeader> {
        //add ip header
        self.state.ip_header = Some(ip_header);
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader> {},
        }
    }

    /// Add an IPv6 header
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::PacketBuilder;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],
    ///               [7,8,9,10,11,12])
    ///     .ipv6(
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
    pub fn ipv6(
        mut self,
        source: [u8; 16],
        destination: [u8; 16],
        hop_limit: u8,
    ) -> PacketBuilderStep<IpHeader> {
        self.state.ip_header = Some(IpHeader::Version6(
            Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,          //filled in on write
                next_header: IpNumber(255), //filled in on write
                hop_limit,
                source,
                destination,
            },
            Default::default(),
        ));

        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<IpHeader> {},
        }
    }

    /// Adds a vlan tagging header with the given vlan identifier
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, SingleVlanHeader, VlanHeader};
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     //source mac
    ///               [7,8,9,10,11,12]) //destionation mac
    ///     .vlan(VlanHeader::Single(
    ///         SingleVlanHeader{
    ///             pcp: 1.try_into().unwrap(),
    ///             drop_eligible_indicator: false,
    ///             vlan_id: 0x123.try_into().unwrap(),
    ///             ether_type: 0.into() // will be overwritten during write
    ///         }))
    ///     .ipv4([192,168,1,1], //source ip
    ///           [192,168,1,2], //desitionation ip
    ///           20)            //time to life
    ///     .udp(21,    //source port
    ///          1234); //desitnation port
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
    pub fn vlan(mut self, vlan: VlanHeader) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(vlan);
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader> {},
        }
    }

    /// Adds a vlan tagging header with the given vlan identifier
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, SingleVlanHeader, VlanHeader};
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     //source mac
    ///               [7,8,9,10,11,12]) //destionation mac
    ///     .single_vlan(0x123.try_into().unwrap()) // vlan identifier
    ///     .ipv4([192,168,1,1], //source ip
    ///           [192,168,1,2], //desitionation ip
    ///           20)            //time to life
    ///     .udp(21,    //source port
    ///          1234); //desitnation port
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
    pub fn single_vlan(mut self, vlan_identifier: VlanId) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(VlanHeader::Single(SingleVlanHeader {
            pcp: VlanPcp::ZERO,
            drop_eligible_indicator: false,
            vlan_id: vlan_identifier,
            ether_type: EtherType(0), //will be set automatically during write
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader> {},
        }
    }

    /// Adds two vlan tagging header with the given vlan identifiers (also known as double vlan tagging).
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, SingleVlanHeader, VlanHeader};
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     //source mac
    ///               [7,8,9,10,11,12]) //destionation mac
    ///     .double_vlan(0x123.try_into().unwrap(), // outer vlan identifier
    ///                  0x234.try_into().unwrap()) // inner vlan identifier
    ///     .ipv4([192,168,1,1], //source ip
    ///           [192,168,1,2], //desitionation ip
    ///           20)            //time to life
    ///     .udp(21,    //source port
    ///          1234); //desitnation port
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
    pub fn double_vlan(
        mut self,
        outer_vlan_identifier: VlanId,
        inner_vlan_identifier: VlanId,
    ) -> PacketBuilderStep<VlanHeader> {
        self.state.vlan_header = Some(VlanHeader::Double(DoubleVlanHeader {
            outer: SingleVlanHeader {
                pcp: VlanPcp::ZERO,
                drop_eligible_indicator: false,
                vlan_id: outer_vlan_identifier,
                ether_type: EtherType(0), //will be set automatically during write
            },
            inner: SingleVlanHeader {
                pcp: VlanPcp::ZERO,
                drop_eligible_indicator: false,
                vlan_id: inner_vlan_identifier,
                ether_type: EtherType(0), //will be set automatically during write
            },
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<VlanHeader> {},
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
    ///    .single_vlan(0x132.try_into().unwrap())
    ///    //payload_len, protocol & checksum will be replaced during write
    ///    .ip(IpHeader::Version4(
    ///         Ipv4Header::new(
    ///             0, //payload_len will be replaced during write
    ///             12, //time_to_live
    ///             ip_number::UDP, //will be replaced during write
    ///             [0,1,2,3], //source
    ///             [4,5,6,7] //destination
    ///         ).unwrap(),
    ///         Default::default() // IPv4 extension headers (default is none)
    ///     ));
    /// ```
    ///
    /// # Example IPv6
    /// ```
    /// # use etherparse::*;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],
    ///               [7,8,9,10,11,12])
    ///    .single_vlan(0x132.try_into().unwrap())
    ///    .ip(IpHeader::Version6(
    ///         Ipv6Header{
    ///             traffic_class: 0,
    ///             flow_label: 0.try_into().unwrap(),
    ///             hop_limit: 4,
    ///             source: [0;16],
    ///             destination: [0;16],
    ///             // payload_length & next_header will be replaced during write
    ///             ..Default::default()
    ///         },
    ///         Default::default() // IPv6 extension headers (default is none)
    ///     ));
    /// ```
    pub fn ip(self, ip_header: IpHeader) -> PacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
        .ip(ip_header)
    }

    /// Add an IPv6 header
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, SingleVlanHeader, VlanHeader};
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     //source mac
    ///               [7,8,9,10,11,12]) //destionation mac
    ///     .single_vlan(0x123.try_into().unwrap()) // vlan identifier
    ///     .ipv6(
    ///         //source
    ///         [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
    ///         //destination
    ///         [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
    ///         //hop_limit
    ///         47)
    ///     .udp(21,    //source port
    ///          1234); //desitnation port
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
    pub fn ipv6(
        self,
        source: [u8; 16],
        destination: [u8; 16],
        hop_limit: u8,
    ) -> PacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
        .ipv6(source, destination, hop_limit)
    }

    /// Add an IPv4 header
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, SingleVlanHeader, VlanHeader};
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     //source mac
    ///               [7,8,9,10,11,12]) //destionation mac
    ///     .single_vlan(0x123.try_into().unwrap()) // vlan identifier
    ///     .ipv4([192,168,1,1], //source ip
    ///           [192,168,1,2], //desitionation ip
    ///           20)            //time to life
    ///     .udp(21,    //source port
    ///          1234); //desitnation port
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
    pub fn ipv4(
        self,
        source: [u8; 4],
        destination: [u8; 4],
        time_to_live: u8,
    ) -> PacketBuilderStep<IpHeader> {
        //use the method from the Ethernet2Header implementation
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Ethernet2Header> {},
        }
        .ipv4(source, destination, time_to_live)
    }
}

impl PacketBuilderStep<IpHeader> {
    /// Adds an ICMPv4 header of the given [`Icmpv4Type`] to the packet.
    ///
    /// If an ICMPv4 header gets added the payload used during the builders `write`
    /// call contains the bytes after the header and has different meanings
    /// and contents based on the type. Ususally all statically sized values
    /// known based on the ICMPv4 type & code are part of the header and the
    /// payload is used to store contains the dynamic parts of the ICMPv4 packet.
    ///
    /// Check [`Icmpv4Type`] for a documentation which values are part of the
    /// header and what is stored as part of the payload.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, Icmpv4Type, icmpv4};
    /// #
    /// let builder = PacketBuilder::
    ///    ipv4([192,168,1,1],  //source ip
    ///          [192,168,1,2], //desitionation ip
    ///          20)            //time to life
    ///    .icmpv4(
    ///         Icmpv4Type::TimeExceeded(
    ///             icmpv4::TimeExceededCode::TtlExceededInTransit
    ///         )
    ///     );
    ///
    /// // what is part of the payload depends on the Icmpv4Type
    /// //
    /// // In case of `Icmpv4Type::TimeExceeded` the "internet header
    /// // + 64 bits of the original data datagram" should be given as
    /// // the payload
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv4(mut self, icmp_type: Icmpv4Type) -> PacketBuilderStep<Icmpv4Header> {
        self.state.transport_header = Some(TransportHeader::Icmpv4(Icmpv4Header {
            icmp_type,
            checksum: 0, // calculated later
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv4Header> {},
        }
    }

    /// Adds an ICMPv4 header based on raw numbers.
    ///
    /// This can be usefull when trying to build an ICMPv4 packet
    /// which is not fully supported by etherparse and is the equivalent
    /// of using [`Icmpv4Type::Unknown`] together with
    /// [`PacketBuilderStep<IpHeader>::icmpv4`].
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
    ///    .icmpv4_raw(
    ///         253, // ICMPv4 type (e.g. 253 is RFC3692-style Experiment 1)
    ///         0, // ICMPv4 code
    ///         [1,2,3,4]  // bytes 5-8 in the ICMPv4 header
    ///     );
    ///
    /// // the payload is written after the 8 byte raw ICMPv4 header
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// // get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// // serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv4_raw(
        mut self,
        type_u8: u8,
        code_u8: u8,
        bytes5to8: [u8; 4],
    ) -> PacketBuilderStep<Icmpv4Header> {
        let icmp_type = Icmpv4Type::Unknown {
            type_u8,
            code_u8,
            bytes5to8,
        };
        self.state.transport_header = Some(TransportHeader::Icmpv4(Icmpv4Header {
            icmp_type,
            checksum: 0, // calculated later
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv4Header> {},
        }
    }

    /// Adds an ICMPv4 echo request packet.
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
    ///    .icmpv4_echo_request(
    ///         123, // identifier
    ///         456, // sequence number
    ///     );
    ///
    /// // payload of the echo request
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// // get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// // serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv4_echo_request(mut self, id: u16, seq: u16) -> PacketBuilderStep<Icmpv4Header> {
        let echo_header = IcmpEchoHeader { id, seq };
        let icmpv4_echo = Icmpv4Header::new(Icmpv4Type::EchoRequest(echo_header));
        self.state.transport_header = Some(TransportHeader::Icmpv4(icmpv4_echo));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv4Header> {},
        }
    }

    /// Adds an ICMPv4 echo reply packet.
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
    ///    .icmpv4_echo_reply(
    ///         123, // identifier
    ///         456, // sequence number
    ///     );
    ///
    /// // payload of the echo reply
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// // get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// // serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv4_echo_reply(mut self, id: u16, seq: u16) -> PacketBuilderStep<Icmpv4Header> {
        let echo_header = IcmpEchoHeader { id, seq };
        let icmpv4_echo = Icmpv4Header::new(Icmpv4Type::EchoReply(echo_header));
        self.state.transport_header = Some(TransportHeader::Icmpv4(icmpv4_echo));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv4Header> {},
        }
    }

    /// Adds an ICMPv6 header of the given [`Icmpv6Type`] to the packet.
    ///
    /// If an ICMPv6 header gets added the payload used during the builders `write`
    /// call contains the bytes after the header and has different meanings
    /// and contents based on the type. Ususally all statically sized values
    /// known based on the ICMPv6 type & code are part of the header and the
    /// payload is used to store contains the dynamic parts of the ICMPv6 packet.
    ///
    /// Check [`Icmpv6Type`] for a documentation which values are part of the
    /// header and what is stored as part of the payload.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::{PacketBuilder, Icmpv6Type, icmpv6};
    /// #
    /// let builder = PacketBuilder::
    ///     ipv6(
    ///         //source
    ///         [11,12,13,14,15,16,17,18,19,10,21,22,23,24,25,26],
    ///         //destination
    ///         [31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46],
    ///         //hop_limit
    ///         47)
    ///    .icmpv6(
    ///         Icmpv6Type::TimeExceeded(
    ///             icmpv6::TimeExceededCode::HopLimitExceeded
    ///         )
    ///     );
    ///
    /// // what is part of the payload depends on the Icmpv6Type
    /// //
    /// // In case of `Icmpv6Type::TimeExceeded` "As much of invoking packet
    /// // as possible without the ICMPv6 packet exceeding the minimum IPv6 MTU"
    /// // should be given as the payload.
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv6(mut self, icmp_type: Icmpv6Type) -> PacketBuilderStep<Icmpv6Header> {
        self.state.transport_header = Some(TransportHeader::Icmpv6(Icmpv6Header {
            icmp_type,
            checksum: 0, // calculated later
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv6Header> {},
        }
    }

    /// Adds an ICMPv6 header based on raw values.
    ///
    /// This can be usefull when trying to build an ICMPv6 packet
    /// which is not fully supported by etherparse and is the equivalent
    /// of using [`Icmpv6Type::Unknown`] together with
    /// [`PacketBuilderStep<IpHeader>::icmpv6`].
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
    ///    .icmpv4_raw(
    ///         200, // ICMPv6 type (e.g. 200 is for "private experimentation")
    ///         0, // ICMPv6 code
    ///         [1,2,3,4]  // bytes 5-8 in the ICMPv6 header
    ///     );
    ///
    /// // the payload is written after the 8 byte raw ICMPv6 header
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv6_raw(
        mut self,
        type_u8: u8,
        code_u8: u8,
        bytes5to8: [u8; 4],
    ) -> PacketBuilderStep<Icmpv6Header> {
        let icmp_type = Icmpv6Type::Unknown {
            type_u8,
            code_u8,
            bytes5to8,
        };
        self.state.transport_header = Some(TransportHeader::Icmpv6(Icmpv6Header {
            icmp_type,
            checksum: 0, // calculated later
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv6Header> {},
        }
    }

    /// Adds an ICMPv6 echo reply packet.
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
    ///    .icmpv6_echo_request(
    ///         123, // identifier
    ///         456, // sequence number
    ///     );
    ///
    /// // payload of the echo request
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv6_echo_request(mut self, id: u16, seq: u16) -> PacketBuilderStep<Icmpv6Header> {
        let echo_header = IcmpEchoHeader { id, seq };
        let icmpv6_echo = Icmpv6Header::new(Icmpv6Type::EchoRequest(echo_header));
        self.state.transport_header = Some(TransportHeader::Icmpv6(icmpv6_echo));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv6Header> {},
        }
    }

    /// Adds an ICMPv6 echo request packet.
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
    ///    .icmpv6_echo_reply(
    ///         123, // identifier
    ///         456, // sequence number
    ///     );
    ///
    /// // payload of the echo reply
    /// let payload = [1,2,3,4,5,6,7,8];
    ///
    /// //get some memory to store the result
    /// let mut result = Vec::<u8>::with_capacity(
    ///                     builder.size(payload.len()));
    ///
    /// //serialize
    /// builder.write(&mut result, &payload).unwrap();
    /// ```
    pub fn icmpv6_echo_reply(mut self, id: u16, seq: u16) -> PacketBuilderStep<Icmpv6Header> {
        let echo_header = IcmpEchoHeader { seq, id };
        let icmpv6_echo = Icmpv6Header::new(Icmpv6Type::EchoReply(echo_header));
        self.state.transport_header = Some(TransportHeader::Icmpv6(icmpv6_echo));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<Icmpv6Header> {},
        }
    }

    /// Adds an UDP header.
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
    pub fn udp(mut self, source_port: u16, destination_port: u16) -> PacketBuilderStep<UdpHeader> {
        self.state.transport_header = Some(TransportHeader::Udp(UdpHeader {
            source_port,
            destination_port,
            length: 0,   //calculated later
            checksum: 0, //calculated later
        }));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<UdpHeader> {},
        }
    }

    /// Adds an TCP header.
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use etherparse::PacketBuilder;
    /// #
    /// let builder = PacketBuilder::
    ///     ethernet2([1,2,3,4,5,6],     // source mac
    ///               [7,8,9,10,11,12]) // destionation mac
    ///    .ipv4([192,168,1,1], // source ip
    ///          [192,168,1,2], // desitionation ip
    ///          20)            // time to life
    ///    .tcp(21,    // source port
    ///         12,    // destination port
    ///         12345, // sequence number
    ///         4000); // window size
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
    pub fn tcp(
        mut self,
        source_port: u16,
        destination_port: u16,
        sequence_number: u32,
        window_size: u16,
    ) -> PacketBuilderStep<TcpHeader> {
        self.state.transport_header = Some(TransportHeader::Tcp(TcpHeader::new(
            source_port,
            destination_port,
            sequence_number,
            window_size,
        )));
        //return for next step
        PacketBuilderStep {
            state: self.state,
            _marker: marker::PhantomData::<TcpHeader> {},
        }
    }

    /// Write all the headers and the payload with the given ip number.
    ///
    /// `last_next_header_ip_number` will be set in the last extension header
    /// or if no extension header exists the ip header as the "next header" or
    /// "protocol number".
    pub fn write<T: io::Write + Sized>(
        mut self,
        writer: &mut T,
        last_next_header_ip_number: IpNumber,
        payload: &[u8],
    ) -> Result<(), BuildWriteError> {
        self.state
            .ip_header
            .as_mut()
            .unwrap()
            .set_next_headers(last_next_header_ip_number);
        final_write(self, writer, payload)
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(self, payload_size)
    }
}

impl PacketBuilderStep<Icmpv4Header> {
    /// Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(
        self,
        writer: &mut T,
        payload: &[u8],
    ) -> Result<(), BuildWriteError> {
        final_write(self, writer, payload)
    }

    /// Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(self, payload_size)
    }
}

impl PacketBuilderStep<Icmpv6Header> {
    ///Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(
        self,
        writer: &mut T,
        payload: &[u8],
    ) -> Result<(), BuildWriteError> {
        final_write(self, writer, payload)
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(self, payload_size)
    }
}

impl PacketBuilderStep<UdpHeader> {
    ///Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(
        self,
        writer: &mut T,
        payload: &[u8],
    ) -> Result<(), BuildWriteError> {
        final_write(self, writer, payload)
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(self, payload_size)
    }
}

impl PacketBuilderStep<TcpHeader> {
    ///Set ns flag (ECN-nonce - concealment protection; experimental: see RFC 3540)
    pub fn ns(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .ns = true;
        self
    }
    ///Set fin flag (No more data from sender)
    pub fn fin(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .fin = true;
        self
    }
    ///Set the syn flag (synchronize sequence numbers)
    pub fn syn(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .syn = true;
        self
    }
    ///Sets the rst flag (reset the connection)
    pub fn rst(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .rst = true;
        self
    }
    ///Sets the psh flag (push function)
    pub fn psh(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .psh = true;
        self
    }
    ///Sets the ack flag and the acknowledgment_number.
    pub fn ack(mut self, acknowledgment_number: u32) -> PacketBuilderStep<TcpHeader> {
        {
            let header = self
                .state
                .transport_header
                .as_mut()
                .unwrap()
                .mut_tcp()
                .unwrap();
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
            let header = self
                .state
                .transport_header
                .as_mut()
                .unwrap()
                .mut_tcp()
                .unwrap();
            header.urg = true;
            header.urgent_pointer = urgent_pointer;
        }
        self
    }
    ///Sets ece flag (ECN-Echo, RFC 3168)
    pub fn ece(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .ece = true;
        self
    }

    ///Set cwr flag (Congestion Window Reduced)
    ///
    ///This flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    pub fn cwr(mut self) -> PacketBuilderStep<TcpHeader> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .cwr = true;
        self
    }

    ///Set the tcp options of the header.
    pub fn options(
        mut self,
        options: &[TcpOptionElement],
    ) -> Result<PacketBuilderStep<TcpHeader>, TcpOptionWriteError> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .set_options(options)?;
        Ok(self)
    }

    ///Set the tcp options of the header (setting the bytes directly).
    pub fn options_raw(
        mut self,
        options: &[u8],
    ) -> Result<PacketBuilderStep<TcpHeader>, TcpOptionWriteError> {
        self.state
            .transport_header
            .as_mut()
            .unwrap()
            .mut_tcp()
            .unwrap()
            .set_options_raw(options)?;
        Ok(self)
    }

    ///Write all the headers and the payload.
    pub fn write<T: io::Write + Sized>(
        self,
        writer: &mut T,
        payload: &[u8],
    ) -> Result<(), BuildWriteError> {
        final_write(self, writer, payload)
    }

    ///Returns the size of the packet when it is serialized
    pub fn size(&self, payload_size: usize) -> usize {
        final_size(self, payload_size)
    }
}

/// Write all the headers and the payload.
fn final_write<T: io::Write + Sized, B>(
    builder: PacketBuilderStep<B>,
    writer: &mut T,
    payload: &[u8],
) -> Result<(), BuildWriteError> {
    use BuildWriteError::*;

    let ip_ether_type = {
        use crate::IpHeader::*;
        match builder.state.ip_header {
            Some(Version4(_, _)) => ether_type::IPV4,
            Some(Version6(_, _)) => ether_type::IPV6,
            None => panic!("Missing ip header"),
        }
    };

    //ethernetII header
    if let Some(mut eth) = builder.state.ethernet2_header {
        eth.ether_type = {
            use crate::VlanHeader::*;
            //determine the ether type depending on if there is a vlan tagging header
            match builder.state.vlan_header {
                Some(Single(_)) => ether_type::VLAN_TAGGED_FRAME,
                Some(Double(_)) => ether_type::PROVIDER_BRIDGING,
                //if no vlan header exists, the id is purely defined by the ip type
                None => ip_ether_type,
            }
        };
        eth.write(writer).map_err(Io)?;
    }

    //write the vlan header if it exists
    use crate::VlanHeader::*;
    match builder.state.vlan_header {
        Some(Single(mut value)) => {
            //set ether types
            value.ether_type = ip_ether_type;
            //serialize
            value.write(writer).map_err(Io)?;
        }
        Some(Double(mut value)) => {
            //set ether types
            value.outer.ether_type = ether_type::VLAN_TAGGED_FRAME;
            value.inner.ether_type = ip_ether_type;
            //serialize
            value.write(writer).map_err(Io)?;
        }
        None => {}
    }

    //ip header
    use crate::IpHeader::*;
    let ip_header = builder.state.ip_header.unwrap();

    //transport header
    let transport = builder.state.transport_header;
    match transport {
        None => {
            // in case no transport header is present the protocol
            // number and next_header fields are set in the write call
            // directly and don't need to be set here again.
            match ip_header {
                Version4(mut ip, ext) => {
                    ip.set_payload_len(ext.header_len() + payload.len()).map_err(PayloadLen)?;
                    ip.write(writer).map_err(Io)?;
                    ext.write(writer, ip.protocol).map_err(|err| {
                        use err::ipv4_exts::HeaderWriteError as I;
                        match err {
                            I::Io(err) => Io(err),
                            I::Content(err) => Ipv4Exts(err),
                        }
                    })?;
                }
                Version6(mut ip, ext) => {
                    ip.set_payload_length(ext.header_len() + payload.len()).map_err(PayloadLen)?;
                    ip.write(writer).map_err(Io)?;
                    ext.write(writer, ip.next_header).map_err(|err| {
                        use err::ipv6_exts::HeaderWriteError as I;
                        match err {
                            I::Io(err) => Io(err),
                            I::Content(err) => Ipv6Exts(err),
                        }
                    })?;
                }
            }
        }
        Some(mut transport) => {
            match ip_header {
                Version4(mut ip, mut ext) => {
                    //set total length & udp payload length (ip checks that the payload length is ok)
                    let transport_size = transport.header_len() + payload.len();
                    ip.set_payload_len(ext.header_len() + transport_size).map_err(PayloadLen)?;
                    use crate::TransportHeader::*;
                    match transport {
                        Icmpv4(_) => {}
                        Icmpv6(_) => {}
                        Udp(ref mut udp) => {
                            udp.length = transport_size as u16;
                        }
                        Tcp(_) => {}
                    }

                    //ip protocol number & next header values of the extension header
                    ip.protocol = ext.set_next_headers(match transport {
                        Icmpv4(_) => ip_number::ICMP,
                        Icmpv6(_) => ip_number::IPV6_ICMP,
                        Udp(_) => ip_number::UDP,
                        Tcp(_) => ip_number::TCP,
                    });

                    //calculate the udp checksum
                    transport.update_checksum_ipv4(&ip, payload).map_err(|err| {
                        use err::packet::TransportChecksumError as I;
                        match err {
                            I::PayloadLen(err) => PayloadLen(err),
                            I::Icmpv6InIpv4 => Icmpv6InIpv4,
                        }
                    })?;

                    //write (will automatically calculate the checksum)
                    ip.write(writer).map_err(Io)?;
                    ext.write(writer, ip.protocol).map_err(|err| {
                        use err::ipv4_exts::HeaderWriteError as I;
                        match err {
                            I::Io(err) => Io(err),
                            I::Content(err) => Ipv4Exts(err),
                        }
                    })?;
                }
                Version6(mut ip, mut ext) => {
                    //set total length
                    let transport_size = transport.header_len() + payload.len();
                    ip.set_payload_length(ext.header_len() + transport_size).map_err(PayloadLen)?;
                    use crate::TransportHeader::*;
                    match transport {
                        Icmpv4(_) => {}
                        Icmpv6(_) => {}
                        Udp(ref mut udp) => {
                            udp.length = transport_size as u16;
                        }
                        Tcp(_) => {}
                    }

                    //set the protocol
                    ip.next_header = ext.set_next_headers(match transport {
                        Icmpv4(_) => ip_number::ICMP,
                        Icmpv6(_) => ip_number::IPV6_ICMP,
                        Udp(_) => ip_number::UDP,
                        Tcp(_) => ip_number::TCP,
                    });

                    //calculate the udp checksum
                    transport.update_checksum_ipv6(&ip, payload).map_err(PayloadLen)?;

                    //write (will automatically calculate the checksum)
                    ip.write(writer).map_err(Io)?;
                    ext.write(writer, ip.next_header).map_err(|err| {
                        use err::ipv6_exts::HeaderWriteError as I;
                        match err {
                            I::Io(err) => Io(err),
                            I::Content(err) => Ipv6Exts(err),
                        }
                    })?;
                }
            }

            //finaly write the udp header & payload
            transport.write(writer).map_err(Io)?;
        }
    }
    writer.write_all(payload).map_err(Io)?;
    Ok(())
}

///Returns the size of the packet when it is serialized
fn final_size<B>(builder: &PacketBuilderStep<B>, payload_size: usize) -> usize {
    use crate::IpHeader::*;
    use crate::TransportHeader::*;
    use crate::VlanHeader::*;
    (match builder.state.ethernet2_header {
        Some(_) => Ethernet2Header::LEN,
        None => 0,
    }) + match builder.state.vlan_header {
        Some(Single(_)) => SingleVlanHeader::LEN,
        Some(Double(_)) => DoubleVlanHeader::LEN,
        None => 0,
    } + match builder.state.ip_header {
        Some(Version4(ref value, ref ext)) => value.header_len() + ext.header_len(),
        Some(Version6(_, ref ext)) => Ipv6Header::LEN + ext.header_len(),
        None => 0,
    } + match builder.state.transport_header {
        Some(Icmpv4(ref value)) => value.header_len(),
        Some(Icmpv6(ref value)) => value.header_len(),
        Some(Udp(_)) => UdpHeader::LEN,
        Some(Tcp(ref value)) => value.header_len() as usize,
        None => 0,
    } + payload_size
}

#[cfg(test)]
mod whitebox_tests {
    use super::*;
    use alloc::vec::Vec;

    //whitebox tests that need internal access
    #[test]
    fn size() {
        assert_eq!(
            0,
            PacketBuilderStep::<UdpHeader> {
                state: PacketImpl {
                    ethernet2_header: None,
                    ip_header: None,
                    vlan_header: None,
                    transport_header: None
                },
                _marker: marker::PhantomData::<UdpHeader> {}
            }
            .size(0)
        );
    }

    #[test]
    #[should_panic]
    fn final_write_panic_missing_ip() {
        let mut writer = Vec::new();
        final_write(
            PacketBuilderStep::<UdpHeader> {
                state: PacketImpl {
                    ethernet2_header: None,
                    ip_header: None,
                    vlan_header: None,
                    transport_header: None,
                },
                _marker: marker::PhantomData::<UdpHeader> {},
            },
            &mut writer,
            &[],
        )
        .unwrap();
    }
}
