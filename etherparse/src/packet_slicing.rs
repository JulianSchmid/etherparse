use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternetSlice<'a> {
    /// The ipv4 header & the decoded extension headers.
    Ipv4(Ipv4HeaderSlice<'a>, Ipv4ExtensionsSlice<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(Ipv6HeaderSlice<'a>, Ipv6ExtensionsSlice<'a>),
}

impl<'a> InternetSlice<'a> {
    /// Returns true if the payload is fragmented.
    pub fn is_fragmenting_payload(&self) -> bool {
        match self {
            InternetSlice::Ipv4(v4_hdr, _) => v4_hdr.is_fragmenting_payload(),
            InternetSlice::Ipv6(_, v6_ext) => v6_ext.is_fragmenting_payload(),
        }
    }

    /// Return the source address as an std::net::Ipvddr
    pub fn source_addr(&self) -> std::net::IpAddr {
        match self {
            InternetSlice::Ipv4(v4_hdr, _) => v4_hdr.source_addr().into(),
            InternetSlice::Ipv6(v6_hdr, _) => v6_hdr.source_addr().into(),
        }
    }

    /// Return the destination address as an std::net::IpAddr
    pub fn destination_addr(&self) -> std::net::IpAddr {
        match self {
            InternetSlice::Ipv4(v4_hdr, _) => v4_hdr.destination_addr().into(),
            InternetSlice::Ipv6(v6_hdr, _) => v6_hdr.destination_addr().into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportSlice<'a> {
    /// A slice containing an Icmp4 header
    Icmpv4(Icmpv4Slice<'a>),
    /// A slice containing an Icmp6 header
    Icmpv6(Icmpv6Slice<'a>),
    /// A slice containing an UDP header.
    Udp(UdpHeaderSlice<'a>),
    /// A slice containing a TCP header.
    Tcp(TcpHeaderSlice<'a>),
    /// Unknonwn transport layer protocol. The value is the last parsed ip protocol number.
    Unknown(u8),
}

/// Packet slice split into multiple slices containing the different headers & payload.
///
/// Everything that could not be parsed is stored in a slice in the field "payload".
///
/// You can use
///
/// * [`SlicedPacket::from_ethernet`]
/// * [`SlicedPacket::from_ether_type`]
/// * [`SlicedPacket::from_ip`]
///
/// depending on your starting header to slice a packet.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlicedPacket<'a> {
    /// Ethernet II header if present.
    pub link: Option<LinkSlice<'a>>,
    /// Single or double vlan headers if present.
    pub vlan: Option<VlanSlice<'a>>,
    /// IPv4 or IPv6 header and IP extension headers if present.
    pub ip: Option<InternetSlice<'a>>,
    /// TCP or UDP header if present.
    pub transport: Option<TransportSlice<'a>>,
    /// The payload field points to the rest of the packet that could not be parsed by etherparse.
    ///
    /// Depending on what other fields contain a "Some" values the payload contains the corresponding
    /// payload.
    ///
    /// For example if transport field contains Some(Udp(_)) then the payload field points to the udp payload.
    /// On the other hand if the transport field contains None then the payload contains the payload of
    /// next field containing a Some value (in order of transport, ip, vlan, link).
    pub payload: &'a [u8],
}

impl<'a> SlicedPacket<'a> {
    /// Seperates a network packet slice into different slices containing the headers from the ethernet header downwards.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function assumes the given data starts
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
    pub fn from_ethernet(data: &'a [u8]) -> Result<SlicedPacket, err::packet::EthSliceError> {
        CursorSlice::new(data).slice_ethernet2()
    }

    /// Seperates a network packet slice into different slices containing the headers using
    /// the given `ether_type` number to identify the first header.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. Currently supported
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
    /// # use etherparse::{Ethernet2Header, PacketBuilder};
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
    /// # let packet = &complete_packet[Ethernet2Header::LEN..];
    /// #
    /// use etherparse::{ether_type, SlicedPacket};
    ///
    /// match SlicedPacket::from_ether_type(ether_type::IPV4, packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("ip: {:?}", value.ip);
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ether_type(ether_type: u16, data: &'a [u8]) -> Result<SlicedPacket, err::packet::EthSliceError> {
        use ether_type::*;
        match ether_type {
            IPV4 => CursorSlice::new(data).slice_ipv4(),
            IPV6 => CursorSlice::new(data).slice_ipv6(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                CursorSlice::new(data).slice_vlan()
            }
            _ => Ok(SlicedPacket {
                link: None,
                vlan: None,
                ip: None,
                transport: None,
                payload: data,
            }),
        }
    }

    /// Seperates a network packet slice into different slices containing the headers from the ip header downwards.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function assumes the given data starts
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
    pub fn from_ip(data: &'a [u8]) -> Result<SlicedPacket, err::packet::IpSliceError> {
        CursorSlice::new(data).slice_ip()
    }

    /// If the slice in the `payload` field contains an ethernet payload
    /// this method returns the ether type number describing the payload type.
    ///
    /// The ether type number can come from an ethernet II header or a
    /// VLAN header depending on which headers are present.
    ///
    /// In case that `ip` and/or `transport` fields are the filled None
    /// is returned, as the payload contents then are defined by a
    /// lower layer protocol described in these fields.
    pub fn payload_ether_type(&self) -> Option<u16> {
        if self.ip.is_some() || self.transport.is_some() {
            None
        } else {
            if let Some(vlan) = &self.vlan {
                use VlanSlice::*;
                match vlan {
                    SingleVlan(s) => Some(s.ether_type()),
                    DoubleVlan(d) => Some(d.inner().ether_type()),
                }
            } else {
                if let Some(link) = &self.link {
                    use LinkSlice::*;
                    match link {
                        Ethernet2(eth) => Some(eth.ether_type()),
                    }
                } else {
                    None
                }
            }
        }
    }
}

///Helper class for slicing packets
struct CursorSlice<'a> {
    pub slice: &'a [u8],
    pub offset: usize,
    pub result: SlicedPacket<'a>,
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
                transport: None,
                payload: slice,
            },
        }
    }

    fn move_by_slice(&mut self, other: &'a [u8]) {
        unsafe {
            use std::slice::from_raw_parts;
            self.slice = from_raw_parts(
                self.slice.as_ptr().add(other.len()),
                self.slice.len() - other.len(),
            );
        }
        self.offset += other.len();
    }

    fn move_to_slice(&mut self, other: &'a [u8]) {
        self.offset += self.slice.len() - other.len();
        self.slice = other;
    }

    pub fn slice_ethernet2(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use ether_type::*;
        use LinkSlice::*;
        use err::packet::EthSliceError::*;

        let result = Ethernet2HeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //cache the ether_type for later
        let ether_type = result.ether_type();

        //set the new data
        self.move_by_slice(result.slice());
        self.result.link = Some(Ethernet2(result));

        //continue parsing (if required)
        match ether_type {
            IPV4 => self.slice_ipv4(),
            IPV6 => self.slice_ipv6(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => self.slice_vlan(),
            _ => Ok(self.slice_payload()),
        }
    }

    pub fn slice_vlan(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use ether_type::*;
        use VlanSlice::*;
        use err::packet::EthSliceError::*;

        let outer = SingleVlanHeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //check if it is a double vlan header
        match outer.ether_type() {
            //in case of a double vlan header continue with the inner
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                self.move_by_slice(outer.slice());
                let inner = SingleVlanHeaderSlice::from_slice(self.slice)
                    .map_err(|err| Len(err.add_offset(self.offset)))?;
                self.move_by_slice(inner.slice());

                let inner_ether_type = inner.ether_type();
                self.result.vlan = Some(DoubleVlan(DoubleVlanHeaderSlice {
                    // SAFETY: Safe as the lenght of the slice was previously verified.
                    slice: unsafe {
                        core::slice::from_raw_parts(
                            outer.slice().as_ptr(),
                            outer.slice().len() + inner.slice().len(),
                        )
                    },
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ipv4(),
                    IPV6 => self.slice_ipv6(),
                    _ => Ok(self.slice_payload()),
                }
            }
            value => {
                //set the vlan header and continue the normal parsing
                self.move_by_slice(outer.slice());
                self.result.vlan = Some(SingleVlan(outer));

                match value {
                    IPV4 => self.slice_ipv4(),
                    IPV6 => self.slice_ipv6(),
                    _ => Ok(self.slice_payload()),
                }
            }
        }
    }

    pub fn slice_ip(mut self) -> Result<SlicedPacket<'a>, err::packet::IpSliceError> {
        use err::packet::IpSliceError::*;

        if self.slice.is_empty() {
            Err(Len(err::LenError {
                required_len: 1,
                len: self.slice.len(),
                len_source: err::LenSource::Slice,
                layer: err::Layer::IpHeader,
                layer_start_offset: self.offset,
            }))
        } else {
            // SAFETY: Safe as slice is not empty.
            let first_byte = unsafe { self.slice.get_unchecked(0) };
            match first_byte >> 4 {
                4 => {
                    let ihl = first_byte & 0xf;
                    
                    // check that the ihl has at least the lenght of the base IPv4 header
                    if ihl < 5 {
                        use err::ip::HeaderError::Ipv4HeaderLengthSmallerThanHeader;
                        return Err(IpHeader(Ipv4HeaderLengthSmallerThanHeader { ihl }));
                    }

                    // check there is enough data for the header
                    let header_len = (usize::from(ihl)) * 4;
                    if self.slice.len() < header_len {
                        return Err(Len(err::LenError {
                            required_len: header_len,
                            len: self.slice.len(),
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv4Header,
                            layer_start_offset: self.offset,
                        }));
                    }

                    // check the total_length can contain the header
                    //
                    // SAFETY:
                    // Safe as the slice length is checked to be at least
                    // 5*4 (5 for the minimum of the ihl) just before.
                    let total_length = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) };
                    if total_length < header_len as u16 {
                        use err::ip::HeaderError::Ipv4TotalLengthSmallerThanHeader;
                        return Err(IpHeader(Ipv4TotalLengthSmallerThanHeader {
                            total_length,
                            min_expected_length: header_len as u16,
                        }));
                    }

                    // SAFETY:
                    // Safe as the slice length is checked to be at least
                    // header_len or greater above.
                    let ipv4_header = unsafe {
                        Ipv4HeaderSlice::from_slice_unchecked(
                            core::slice::from_raw_parts(self.slice.as_ptr(), header_len)
                        )
                    };

                    let fragmented = ipv4_header.is_fragmenting_payload();

                    // move the slice
                    self.move_by_slice(ipv4_header.slice());

                    // slice extensions
                    let (ip_ext, protocol, rest) =
                        Ipv4ExtensionsSlice::from_slice(ipv4_header.protocol(), self.slice).map_err(|err| {
                            use err::ip_auth::HeaderSliceError as I;
                            match err {
                                I::Len(err) => Len(err.add_offset(self.offset)),
                                I::Content(err) => IpHeader(err::ip::HeaderError::Ipv4Exts(err)),
                            }
                        })?;

                     // set the new data
                    self.move_to_slice(rest);
                    self.result.ip = Some(InternetSlice::Ipv4(ipv4_header, ip_ext));

                    if fragmented {
                        Ok(self.slice_payload())
                    } else {
                        match protocol {
                            ip_number::UDP => self.slice_udp().map_err(Len),
                            ip_number::TCP => self.slice_tcp().map_err(|err| {
                                use err::tcp::HeaderSliceError as I;
                                match err {
                                    I::Len(err) => Len(err),
                                    I::Content(err) => TcpHeader(err),
                                }
                            }),
                            ip_number::ICMP => self.slice_icmp4().map_err(Len),
                            ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                            value => {
                                use TransportSlice::*;
                                self.result.transport = Some(Unknown(value));
                                Ok(self.slice_payload())
                            }
                        }
                    }
                },
                6 => {
                    // check length
                    if self.slice.len() < Ipv6Header::LEN {
                        return Err(Len(err::LenError {
                            required_len: Ipv6Header::LEN,
                            len: self.slice.len(),
                            len_source: err::LenSource::Slice,
                            layer: err::Layer::Ipv6Header,
                            layer_start_offset: self.offset,
                        }));
                    }

                    let ipv6_header = unsafe {
                        Ipv6HeaderSlice::from_slice_unchecked(
                            core::slice::from_raw_parts(self.slice.as_ptr(), Ipv6Header::LEN)
                        )
                    };
                    
                    //move the slice
                    self.move_by_slice(ipv6_header.slice());

                    //extension headers
                    let (ip_ext, next_header, rest) =
                        Ipv6ExtensionsSlice::from_slice(ipv6_header.next_header(), self.slice)
                            .map_err(|err| {
                                use err::ipv6_exts::HeaderSliceError as I;
                                match err {
                                    I::Len(err) => Len(err.add_offset(self.offset)),
                                    I::Content(err) => IpHeader(err::ip::HeaderError::Ipv6Exts(err)),
                                }
                            })?;
                    let fragmented = ip_ext.is_fragmenting_payload();

                    // set the new data
                    self.move_to_slice(rest);
                    self.result.ip = Some(InternetSlice::Ipv6(ipv6_header, ip_ext));

                    if fragmented {
                        Ok(self.slice_payload())
                    } else {
                        //parse the data bellow
                        match next_header {
                            ip_number::ICMP => self.slice_icmp4().map_err(Len),
                            ip_number::UDP => self.slice_udp().map_err(Len),
                            ip_number::TCP => self.slice_tcp().map_err(|err| {
                                use err::tcp::HeaderSliceError as I;
                                match err {
                                    I::Len(err) => Len(err),
                                    I::Content(err) => TcpHeader(err),
                                }
                            }),
                            ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                            value => {
                                use TransportSlice::*;
                                self.result.transport = Some(Unknown(value));
                                Ok(self.slice_payload())
                            }
                        }
                    }
                },
                version_number => Err(IpHeader(err::ip::HeaderError::UnsupportedIpVersion { version_number })),
            }
        }
    }

    pub fn slice_ipv4(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use InternetSlice::*;
        use err::packet::EthSliceError::*;

        let ip_header = Ipv4HeaderSlice::from_slice(self.slice).map_err(|err| {
            use err::ipv4::HeaderSliceError as I;
            match err {
                I::Len(err) => Len(err.add_offset(self.offset)),
                I::Content(err) => Ipv4Header(err),
            }
        })?;
        let fragmented = ip_header.is_fragmenting_payload();

        // move the slice
        self.move_by_slice(ip_header.slice());

        // slice extensions
        let (ip_ext, protocol, rest) =
            Ipv4ExtensionsSlice::from_slice(ip_header.protocol(), self.slice).map_err(|err| {
                use err::ip_auth::HeaderSliceError as I;
                match err {
                    I::Len(err) => Len(err.add_offset(self.offset)),
                    I::Content(err) => IpAuthHeader(err),
                }
            })?;

        // set the new data
        self.move_to_slice(rest);
        self.result.ip = Some(Ipv4(ip_header, ip_ext));

        if fragmented {
            Ok(self.slice_payload())
        } else {
            match protocol {
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => TcpHeader(err),
                    }
                }),
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                value => {
                    use TransportSlice::*;
                    self.result.transport = Some(Unknown(value));
                    Ok(self.slice_payload())
                }
            }
        }
    }

    pub fn slice_ipv6(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use crate::InternetSlice::*;
        use err::packet::EthSliceError::*;

        let ip = Ipv6HeaderSlice::from_slice(self.slice).map_err(|err| {
            use err::ipv6::HeaderSliceError as I;
            match err {
                I::Content(err) => Ipv6Header(err),
                I::Len(err) => Len(err.add_offset(self.offset)),
            }
        })?;

        //move the slice
        self.move_by_slice(ip.slice());

        //extension headers
        let (ip_ext, next_header, rest) =
            Ipv6ExtensionsSlice::from_slice(ip.next_header(), self.slice)
                .map_err(|err| {
                    use err::ipv6_exts::HeaderSliceError as I;
                    use err::ipv6_exts::HeaderError as E;
                    match err {
                        I::Len(err) => Len(err.add_offset(self.offset)),
                        I::Content(E::HopByHopNotAtStart) => Ipv6HopByHopNotAtStart,
                        I::Content(E::IpAuth(err)) => IpAuthHeader(err),
                    }
                })?;
        let fragmented = ip_ext.is_fragmenting_payload();

        // set the new data
        self.move_to_slice(rest);
        self.result.ip = Some(Ipv6(ip, ip_ext));

        // only try to decode the transport layer if the payload
        // is not fragmented
        if fragmented {
            Ok(self.slice_payload())
        } else {
            //parse the data bellow
            match next_header {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => TcpHeader(err),
                    }
                }),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                value => {
                    use TransportSlice::*;
                    self.result.transport = Some(Unknown(value));
                    Ok(self.slice_payload())
                }
            }
        }
    }

    pub fn slice_icmp4(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = Icmpv4Slice::from_slice(self.slice)
            .map_err(|err| err.add_offset(self.offset))?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Icmpv4(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_icmp6(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = Icmpv6Slice::from_slice(self.slice)
            .map_err(|err| err.add_offset(self.offset))?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Icmpv6(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_udp(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = UdpHeaderSlice::from_slice(self.slice)
            .map_err(|err| err.add_offset(self.offset))?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Udp(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_tcp(mut self) -> Result<SlicedPacket<'a>, err::tcp::HeaderSliceError> {
        use crate::TransportSlice::*;

        let result = TcpHeaderSlice::from_slice(self.slice)
            .map_err(|err| err.add_slice_offset(self.offset))?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Tcp(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_payload(mut self) -> SlicedPacket<'a> {
        self.result.payload = self.slice;
        self.result
    }
}
