use crate::err::LenSource;

use super::*;

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
/// #               [7,8,9,10,11,12]) //destination mac
/// #    .ipv4([192,168,1,1], //source ip
/// #          [192,168,1,2], //destination ip
/// #          20)            //time to life
/// #    .udp(21,    //source port
/// #         1234); // destination port
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
    pub ip: Option<IpSlice<'a>>,
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
    /// Separates a network packet slice into different slices containing the headers from the ethernet header downwards.
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
    /// #               [7,8,9,10,11,12]) //destination mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //destination ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
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

    /// Separates a network packet slice into different slices containing the headers using
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
    /// #               [7,8,9,10,11,12]) //destination mac
    /// #    .ipv4([192,168,1,1], //source ip
    /// #          [192,168,1,2], //destination ip
    /// #          20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
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
    pub fn from_ether_type(
        ether_type: EtherType,
        data: &'a [u8],
    ) -> Result<SlicedPacket, err::packet::EthSliceError> {
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

    /// Separates a network packet slice into different slices containing the headers using
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
    /// #          [192,168,1,2], //destination ip
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
    pub fn from_ether_type_lax(
        ether_type: EtherType,
        data: &'a [u8],
    ) -> Result<SlicedPacket, err::packet::EthSliceError> {
        use ether_type::*;
        match ether_type {
            IPV4 => CursorSlice::new(data).slice_ipv4_lax(),
            IPV6 => CursorSlice::new(data).slice_ipv6_lax(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                CursorSlice::new(data).slice_vlan_lax()
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

    /// Separates a network packet slice into different slices containing the headers from the ip header downwards.
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
    /// #         [192,168,1,2], //destination ip
    /// #         20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); // destination port
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

    /// Separates a network packet slice into different slices containing
    /// the headers from the ip header downwards with lax length checks.
    ///
    /// This function allows the length in the IP header to be inconsistent
    /// (e.g. data is missing from the slice) and falls back to the length of
    /// slice. See [`IpSlice::from_ip_slice_lax`] for a detailed description
    /// of when the slice length is used as a fallback.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function
    /// assumes the given data starts with an IPv4 or IPv6 header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{SlicedPacket, PacketBuilder, IpSlice, err::LenSource};
    /// # let builder = PacketBuilder::
    /// #    ipv4([192,168,1,1], //source ip
    /// #         [192,168,1,2], //destination ip
    /// #         20)            //time to life
    /// #    .udp(21,    //source port
    /// #         1234); //desitnation port
    /// #    //payload of the udp packet
    /// #    let payload = [1,2,3,4,5,6,7,8];
    /// #    //get some memory to store the serialized data
    /// #    let mut packet = Vec::<u8>::with_capacity(
    /// #                            builder.size(payload.len()));
    /// #    builder.write(&mut packet, &payload).unwrap();
    /// match SlicedPacket::from_ip_lax(&packet) {
    ///     Err(value) => println!("Err {:?}", value),
    ///     Ok(value) => {
    ///         // link & vlan fields are empty when parsing from ip downwards
    ///         assert_eq!(None, value.link);
    ///         assert_eq!(None, value.vlan);
    ///
    ///         // ip & transport (udp or tcp)
    ///         println!("ip: {:?}", value.ip);
    ///         if let Some(ip_payload) = value.ip.as_ref().map(|ip| ip.payload()) {
    ///             // the ip payload len_source field can be used to check
    ///             // if the slice length was used as a fallback value
    ///             if ip_payload.len_source == LenSource::Slice {
    ///                 println!("  Used slice length as fallback to identify the IP payload");
    ///             } else {
    ///                 println!("  IP payload could correctly be identfied via the length field in the header");
    ///             }
    ///         }
    ///         println!("transport: {:?}", value.transport);
    ///     }
    /// }
    /// ```
    pub fn from_ip_lax(data: &'a [u8]) -> Result<SlicedPacket, err::packet::IpSliceError> {
        CursorSlice::new(data).slice_ip_lax()
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
    pub fn payload_ether_type(&self) -> Option<EtherType> {
        if self.ip.is_some() || self.transport.is_some() {
            None
        } else if let Some(vlan) = &self.vlan {
            use VlanSlice::*;
            match vlan {
                SingleVlan(s) => Some(s.ether_type()),
                DoubleVlan(d) => Some(d.inner().ether_type()),
            }
        } else if let Some(link) = &self.link {
            use LinkSlice::*;
            match link {
                Ethernet2(eth) => Some(eth.ether_type()),
            }
        } else {
            None
        }
    }
}

///Helper class for slicing packets
struct CursorSlice<'a> {
    pub slice: &'a [u8],
    pub offset: usize,
    pub len_source: LenSource,
    pub result: SlicedPacket<'a>,
}

impl<'a> CursorSlice<'a> {
    pub fn new(slice: &'a [u8]) -> CursorSlice<'a> {
        CursorSlice {
            slice,
            offset: 0,
            len_source: LenSource::Slice,
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
            use core::slice::from_raw_parts;
            self.slice = from_raw_parts(
                self.slice.as_ptr().add(other.len()),
                self.slice.len() - other.len(),
            );
        }
        self.offset += other.len();
    }

    pub fn slice_ethernet2(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use LinkSlice::*;

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

    pub fn slice_ethernet2_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use LinkSlice::*;

        let result = Ethernet2HeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //cache the ether_type for later
        let ether_type = result.ether_type();

        //set the new data
        self.move_by_slice(result.slice());
        self.result.link = Some(Ethernet2(result));

        //continue parsing (if required)
        match ether_type {
            IPV4 => self.slice_ipv4_lax(),
            IPV6 => self.slice_ipv6_lax(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => self.slice_vlan_lax(),
            _ => Ok(self.slice_payload()),
        }
    }

    pub fn slice_vlan(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use VlanSlice::*;

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
                    // SAFETY: Safe as the length of the slice was previously verified.
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


    pub fn slice_vlan_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use VlanSlice::*;

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
                    // SAFETY: Safe as the length of the slice was previously verified.
                    slice: unsafe {
                        core::slice::from_raw_parts(
                            outer.slice().as_ptr(),
                            outer.slice().len() + inner.slice().len(),
                        )
                    },
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ipv4_lax(),
                    IPV6 => self.slice_ipv6_lax(),
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

        // slice header, extension headers and identify payload range
        let ip = IpSlice::from_ip_slice(self.slice).map_err(|err| {
            use err::ip::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::IpHeader(err) => Ip(err),
            }
        })?;

        // safe data needed
        let payload = ip.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(ip);

        // continue to the lower layers
        if payload.fragmented {
            Ok(self.slice_payload())
        } else {
            match payload.ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
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

    pub fn slice_ip_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::IpSliceError> {
        use err::packet::IpSliceError::*;

        // slice header, extension headers and identify payload range
        let ip = IpSlice::from_ip_slice_lax(self.slice).map_err(|err| {
            use err::ip::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::IpHeader(err) => Ip(err),
            }
        })?;

        // safe data needed
        let payload = ip.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(ip);

        // continue to the lower layers
        if payload.fragmented {
            Ok(self.slice_payload())
        } else {
            match payload.ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
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

    pub fn slice_ipv4(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        // slice ipv4 header & extension headers
        let ipv4 = Ipv4Slice::from_slice(self.slice).map_err(|err| {
            use err::ipv4::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv4(err),
                I::Exts(err) => Ipv4Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload = ipv4.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(IpSlice::Ipv4(ipv4));

        if payload.fragmented {
            Ok(self.slice_payload())
        } else {
            match payload.ip_number {
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
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

    pub fn slice_ipv4_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        // slice ipv4 header & extension headers
        let ipv4 = Ipv4Slice::from_slice_lax(self.slice).map_err(|err| {
            use err::ipv4::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv4(err),
                I::Exts(err) => Ipv4Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload = ipv4.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(IpSlice::Ipv4(ipv4));

        if payload.fragmented {
            Ok(self.slice_payload())
        } else {
            match payload.ip_number {
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
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
        use err::packet::EthSliceError::*;

        let ipv6 = Ipv6Slice::from_slice(self.slice).map_err(|err| {
            use err::ipv6::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv6(err),
                I::Exts(err) => Ipv6Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload_ip_number = ipv6.payload().ip_number;
        let fragmented = ipv6.payload().fragmented;

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            ipv6.payload()
                .payload
                .as_ptr()
                .offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = ipv6.payload().len_source;
        self.slice = ipv6.payload().payload;
        self.result.ip = Some(IpSlice::Ipv6(ipv6));

        // only try to decode the transport layer if the payload
        // is not fragmented
        if fragmented {
            Ok(self.slice_payload())
        } else {
            //parse the data bellow
            match payload_ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
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

    pub fn slice_ipv6_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        let ipv6 = Ipv6Slice::from_slice_lax(self.slice).map_err(|err| {
            use err::ipv6::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv6(err),
                I::Exts(err) => Ipv6Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload_ip_number = ipv6.payload().ip_number;
        let fragmented = ipv6.payload().fragmented;

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            ipv6.payload()
                .payload
                .as_ptr()
                .offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = ipv6.payload().len_source;
        self.slice = ipv6.payload().payload;
        self.result.ip = Some(IpSlice::Ipv6(ipv6));

        // only try to decode the transport layer if the payload
        // is not fragmented
        if fragmented {
            Ok(self.slice_payload())
        } else {
            //parse the data bellow
            match payload_ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
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

        let result = Icmpv4Slice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Icmpv4(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_icmp6(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = Icmpv6Slice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Icmpv6(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_udp(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = UdpHeaderSlice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Udp(result));

        //done
        Ok(self.slice_payload())
    }

    pub fn slice_tcp(mut self) -> Result<SlicedPacket<'a>, err::tcp::HeaderSliceError> {
        use crate::TransportSlice::*;

        let result = TcpHeaderSlice::from_slice(self.slice).map_err(|mut err| {
            use err::tcp::HeaderSliceError::Len;
            if let Len(err) = &mut err {
                err.layer_start_offset += self.offset;
                if LenSource::Slice == err.len_source {
                    err.len_source = self.len_source;
                }
            }
            err
        })?;

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::{
        packet::{EthSliceError, IpSliceError},
        Layer, LenError,
    };
    use crate::test_gens::*;
    use crate::test_packet::TestPacket;
    use proptest::prelude::*;

    const VLAN_ETHER_TYPES: [EtherType; 3] = [
        ether_type::VLAN_TAGGED_FRAME,
        ether_type::PROVIDER_BRIDGING,
        ether_type::VLAN_DOUBLE_TAGGED_FRAME,
    ];

    #[test]
    fn clone_eq() {
        let header = SlicedPacket {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn debug() {
        use alloc::format;
        let header = SlicedPacket {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &[],
        };
        assert_eq!(
            format!("{:?}", header),
            format!(
                "SlicedPacket {{ link: {:?}, vlan: {:?}, ip: {:?}, transport: {:?}, payload: {:?} }}",
                header.link,
                header.vlan,
                header.ip,
                header.transport,
                header.payload
            )
        );
    }

    #[test]
    fn from_x_slice() {
        // no eth
        from_x_slice_vlan_variants(&TestPacket {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
        });

        // eth
        {
            let eth = Ethernet2Header {
                source: [1, 2, 3, 4, 5, 6],
                destination: [1, 2, 3, 4, 5, 6],
                ether_type: 0.into(),
            };
            let test = TestPacket {
                link: Some(eth.clone()),
                vlan: None,
                ip: None,
                transport: None,
            };

            // ok ethernet header (with unknown next)
            from_x_slice_vlan_variants(&test);

            // eth len error
            {
                let data = test.to_vec(&[]);
                for len in 0..data.len() {
                    let err = LenError {
                        required_len: eth.header_len(),
                        len,
                        len_source: LenSource::Slice,
                        layer: Layer::Ethernet2Header,
                        layer_start_offset: 0,
                    };

                    from_slice_assert_err(
                        &test,
                        &data[..len],
                        EthSliceError::Len(err.clone()),
                        IpSliceError::Len(err.clone()),
                    );
                }
            }
        }
    }

    fn from_x_slice_vlan_variants(base: &TestPacket) {
        // none
        from_x_slice_ip_variants(base);

        // single vlan header
        {
            let single = SingleVlanHeader {
                pcp: 1.try_into().unwrap(),
                drop_eligible_indicator: false,
                vlan_id: 2.try_into().unwrap(),
                ether_type: 3.into(),
            };

            for vlan_ether_type in VLAN_ETHER_TYPES {
                let mut test = base.clone();
                test.set_ether_type(vlan_ether_type);
                test.vlan = Some(VlanHeader::Single(single.clone()));

                // ok vlan header
                from_x_slice_ip_variants(&test);

                // len error
                {
                    let data = test.to_vec(&[]);
                    for len in 0..single.header_len() {
                        let base_len = test.len(&[]) - single.header_len();

                        let err = LenError {
                            required_len: single.header_len(),
                            len,
                            len_source: LenSource::Slice,
                            layer: Layer::VlanHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len(err.clone()),
                        );
                    }
                }
            }
        }

        // double vlan header
        for outer_vlan_ether_type in VLAN_ETHER_TYPES {
            for inner_vlan_ether_type in VLAN_ETHER_TYPES {
                let double = DoubleVlanHeader {
                    outer: SingleVlanHeader {
                        pcp: 1.try_into().unwrap(),
                        drop_eligible_indicator: false,
                        vlan_id: 2.try_into().unwrap(),
                        ether_type: inner_vlan_ether_type,
                    },
                    inner: SingleVlanHeader {
                        pcp: 1.try_into().unwrap(),
                        drop_eligible_indicator: false,
                        vlan_id: 2.try_into().unwrap(),
                        ether_type: 3.into(),
                    },
                };
                let mut test = base.clone();
                test.set_ether_type(outer_vlan_ether_type);
                test.vlan = Some(VlanHeader::Double(double.clone()));

                // ok double vlan header
                from_x_slice_ip_variants(&test);

                // len error
                {
                    let data = test.to_vec(&[]);
                    for len in 0..SingleVlanHeader::LEN {
                        let base_len = test.len(&[]) - SingleVlanHeader::LEN;

                        let err = LenError {
                            required_len: SingleVlanHeader::LEN,
                            len,
                            len_source: LenSource::Slice,
                            layer: Layer::VlanHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len(err.clone()),
                        );
                    }
                }
            }
        }
    }

    fn from_x_slice_ip_variants(base: &TestPacket) {
        // none
        from_x_slice_transport_variants(base);

        // ipv4
        for fragmented in [false, true] {
            let ipv4 = {
                let mut ipv4 =
                    Ipv4Header::new(0, 1, 2.into(), [3, 4, 5, 6], [7, 8, 9, 10]).unwrap();
                ipv4.more_fragments = fragmented;
                ipv4
            };

            {
                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV4);
                test.ip = Some(IpHeader::Version4(ipv4.clone(), Default::default()));
                test.set_payload_len(0);

                // ok ipv4
                from_x_slice_transport_variants(&test);

                // ipv4 len error
                {
                    let data = test.to_vec(&[]);
                    for len in 0..ipv4.header_len() {
                        let base_len = test.len(&[]) - ipv4.header_len();

                        let err = LenError {
                            required_len: ipv4.header_len(),
                            len,
                            len_source: LenSource::Slice,
                            layer: Layer::Ipv4Header,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len({
                                if len < 1 {
                                    let mut err = err.clone();
                                    err.required_len = 1;
                                    err.layer = Layer::IpHeader;
                                    err
                                } else {
                                    err.clone()
                                }
                            }),
                        );
                    }
                }

                // ipv4 content error (ihl length too small)
                {
                    let mut data = test.to_vec(&[]);
                    let ipv4_offset = data.len() - ipv4.header_len();

                    // set the ihl to 0 to trigger a content error
                    data[ipv4_offset] = 0b1111_0000 & data[ipv4_offset];

                    from_slice_assert_err(
                        &test,
                        &data,
                        EthSliceError::Ipv4(
                            err::ipv4::HeaderError::HeaderLengthSmallerThanHeader { ihl: 0 },
                        ),
                        IpSliceError::Ip(err::ip::HeaderError::Ipv4HeaderLengthSmallerThanHeader {
                            ihl: 0,
                        }),
                    );
                }

                // ipv4 content error (total length too small)
                {
                    let mut data = test.to_vec(&[]);
                    let ipv4_offset = data.len() - ipv4.header_len();

                    // set the total length to 0 to trigger a content error
                    data[ipv4_offset + 2] = 0;
                    data[ipv4_offset + 3] = 0;

                    let err = LenError {
                        required_len: ipv4.header_len(),
                        len: 0,
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        layer: Layer::Ipv4Packet,
                        layer_start_offset: {
                            test.link.as_ref().map(|h| h.header_len()).unwrap_or(0)
                                + test.vlan.as_ref().map(|h| h.header_len()).unwrap_or(0)
                        },
                    };

                    from_slice_assert_err(
                        &test,
                        &data,
                        EthSliceError::Len(err.clone()),
                        IpSliceError::Len(err.clone()),
                    );
                }
            }

            // ipv4 extension content error
            {
                let auth = IpAuthHeader::new(0.into(), 1, 2, &[]).unwrap();

                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV4);
                test.ip = Some(IpHeader::Version4(
                    {
                        let mut ipv4 = ipv4.clone();
                        ipv4.protocol = ip_number::AUTH;
                        ipv4
                    },
                    Ipv4Extensions {
                        auth: Some(auth.clone()),
                    },
                ));
                test.set_payload_len(0);

                // ok ipv4 & extension
                from_x_slice_transport_variants(&test);

                // ipv4 extension len error
                for len in 0..auth.header_len() {
                    // set payload length
                    let mut test = test.clone();
                    test.set_payload_le_from_ip_on(
                        -1 * (auth.header_len() as isize) + (len as isize),
                    );

                    let data = test.to_vec(&[]);
                    let base_len = test.len(&[]) - auth.header_len();

                    let err = LenError {
                        required_len: auth.header_len(),
                        len,
                        len_source: LenSource::Ipv4HeaderTotalLen,
                        layer: Layer::IpAuthHeader,
                        layer_start_offset: base_len,
                    };

                    from_slice_assert_err(
                        &test,
                        &data[..base_len + len],
                        EthSliceError::Len(err.clone()),
                        IpSliceError::Len(err.clone()),
                    );
                }

                // ipv4 extension content error
                {
                    let mut data = test.to_vec(&[]);
                    let auth_offset = data.len() - auth.header_len();

                    // set the icv len too smaller then allowed
                    data[auth_offset + 1] = 0;

                    // expect an error
                    let err = err::ip_auth::HeaderError::ZeroPayloadLen;
                    from_slice_assert_err(
                        &test,
                        &data,
                        EthSliceError::Ipv4Exts(err.clone()),
                        IpSliceError::Ip(err::ip::HeaderError::Ipv4Ext(err.clone())),
                    );
                }
            }
        }

        // ipv6
        {
            let ipv6 = Ipv6Header {
                traffic_class: 0,
                flow_label: 1.try_into().unwrap(),
                payload_length: 2,
                next_header: 3.into(),
                hop_limit: 4,
                source: [0; 16],
                destination: [0; 16],
            };

            // ipv6 header only
            {
                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV6);
                test.ip = Some(IpHeader::Version6(ipv6.clone(), Default::default()));
                test.set_payload_len(0);

                // ok ipv6
                from_x_slice_transport_variants(&test);

                // header len ipv6
                {
                    let data = test.to_vec(&[]);
                    for len in 0..ipv6.header_len() {
                        let base_len = test.len(&[]) - ipv6.header_len();

                        let err = err::LenError {
                            required_len: ipv6.header_len(),
                            len,
                            len_source: LenSource::Slice,
                            layer: Layer::Ipv6Header,
                            layer_start_offset: base_len,
                        };

                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len({
                                if len < 1 {
                                    let mut err = err.clone();
                                    err.required_len = 1;
                                    err.layer = Layer::IpHeader;
                                    err
                                } else {
                                    err.clone()
                                }
                            }),
                        );
                    }
                }

                // content error ipv6
                {
                    let mut data = test.to_vec(&[]);

                    // inject an invalid ip version
                    let base_len = data.len() - ipv6.header_len();
                    data[base_len] = data[base_len] & 0b0000_1111;

                    from_slice_assert_err(
                        &test,
                        &data,
                        EthSliceError::Ipv6(err::ipv6::HeaderError::UnexpectedVersion {
                            version_number: 0,
                        }),
                        IpSliceError::Ip(err::ip::HeaderError::UnsupportedIpVersion {
                            version_number: 0,
                        }),
                    );
                }
            }

            // ipv6 + extension
            for fragment in [false, true] {
                let auth = IpAuthHeader::new(ip_number::GGP, 1, 2, &[]).unwrap();
                let frag = Ipv6FragmentHeader {
                    next_header: ip_number::AUTH,
                    fragment_offset: 0.try_into().unwrap(),
                    more_fragments: fragment,
                    identification: 3,
                };

                let mut test = base.clone();
                test.set_ether_type(ether_type::IPV6);
                test.ip = Some(IpHeader::Version6(
                    {
                        let mut ipv6 = ipv6.clone();
                        ipv6.next_header = ip_number::IPV6_FRAG;
                        ipv6
                    },
                    {
                        let mut exts: Ipv6Extensions = Default::default();
                        exts.fragment = Some(frag.clone());
                        exts.auth = Some(auth.clone());
                        exts
                    },
                ));
                test.set_payload_len(0);

                // ok ipv6 & extensions
                from_x_slice_transport_variants(&test);

                // ipv6 extension len error
                for len in 0..auth.header_len() {
                    // set payload length
                    let mut test = test.clone();
                    test.set_payload_le_from_ip_on(
                        -1 * (auth.header_len() as isize) + (len as isize),
                    );

                    let data = test.to_vec(&[]);
                    let base_len = test.len(&[]) - auth.header_len();

                    let err = LenError {
                        required_len: auth.header_len(),
                        len,
                        len_source: LenSource::Ipv6HeaderPayloadLen,
                        layer: Layer::IpAuthHeader,
                        layer_start_offset: base_len,
                    };
                    from_slice_assert_err(
                        &test,
                        &data[..base_len + len],
                        EthSliceError::Len(err.clone()),
                        IpSliceError::Len(err.clone()),
                    );
                }

                // ipv6 extension content error (auth)
                {
                    let mut data = test.to_vec(&[]);
                    let auth_offset = data.len() - auth.header_len();
                    // set the icv len too smaller then allowed
                    data[auth_offset + 1] = 0;

                    let err = err::ip_auth::HeaderError::ZeroPayloadLen;
                    from_slice_assert_err(
                        &test,
                        &data,
                        EthSliceError::Ipv6Exts(err::ipv6_exts::HeaderError::IpAuth(err.clone())),
                        IpSliceError::Ip(err::ip::HeaderError::Ipv6Ext(
                            err::ipv6_exts::HeaderError::IpAuth(err.clone()),
                        )),
                    );
                }

                // ipv6 extension content error (hop by hop not at start)
                {
                    let mut data = test.to_vec(&[]);
                    let auth_offset = data.len() - auth.header_len();

                    // set the next header to be a hop-by-hop header to trigger a "not at start error"
                    data[auth_offset] = 0;

                    from_slice_assert_err(
                        &test,
                        &data,
                        EthSliceError::Ipv6Exts(err::ipv6_exts::HeaderError::HopByHopNotAtStart),
                        IpSliceError::Ip(err::ip::HeaderError::Ipv6Ext(
                            err::ipv6_exts::HeaderError::HopByHopNotAtStart,
                        )),
                    );
                }
            }
        }
    }

    fn from_x_slice_transport_variants(base: &TestPacket) {
        // none
        from_x_slice_assert_ok(base);

        // transport can only be set if ip is present
        if let Some(ip) = &base.ip {
            // udp
            {
                let udp = UdpHeader {
                    source_port: 1,
                    destination_port: 2,
                    length: 3,
                    checksum: 4,
                };
                let mut test = base.clone();
                test.ip = Some({
                    let mut ip = ip.clone();
                    ip.set_next_headers(ip_number::UDP);
                    ip
                });
                test.transport = Some(TransportHeader::Udp(udp.clone()));
                test.set_payload_len(0);

                // ok decode
                from_x_slice_assert_ok(&test);

                // length error
                if false == test.is_ip_payload_fragmented() {
                    for len in 0..udp.header_len() {
                        // build new test packet
                        let mut test = test.clone();

                        // set payload length
                        test.set_payload_le_from_ip_on(len as isize);

                        // generate data
                        let data = test.to_vec(&[]);

                        let base_len = test.len(&[]) - udp.header_len();
                        let err = LenError {
                            required_len: udp.header_len(),
                            len,
                            len_source: match test.ip.as_ref().unwrap() {
                                IpHeader::Version4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                IpHeader::Version6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: Layer::UdpHeader,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len(err.clone()),
                        );
                    }
                }
            }

            // tcp
            {
                let tcp = TcpHeader::new(1, 2, 3, 4);
                let mut test = base.clone();
                test.ip = Some({
                    let mut ip = ip.clone();
                    ip.set_next_headers(ip_number::TCP);
                    ip
                });
                test.transport = Some(TransportHeader::Tcp(tcp.clone()));
                test.set_payload_len(0);

                // ok decode
                from_x_slice_assert_ok(&test);

                // error can only occur if ip does not fragment the packet
                if false == test.is_ip_payload_fragmented() {
                    // length error
                    {
                        for len in 0..(tcp.header_len() as usize) {
                            // set payload length
                            let mut test = test.clone();
                            test.set_payload_le_from_ip_on(len as isize);

                            let data = test.to_vec(&[]);
                            let base_len = test.len(&[]) - (tcp.header_len() as usize);

                            let err = LenError {
                                required_len: tcp.header_len() as usize,
                                len,
                                len_source: match test.ip.as_ref().unwrap() {
                                    IpHeader::Version4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                    IpHeader::Version6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                                },
                                layer: Layer::TcpHeader,
                                layer_start_offset: base_len,
                            };
                            from_slice_assert_err(
                                &test,
                                &data[..base_len + len],
                                EthSliceError::Len(err.clone()),
                                IpSliceError::Len(err.clone()),
                            );
                        }
                    }

                    // content error
                    {
                        let mut data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - (tcp.header_len() as usize);

                        // set data offset to 0 to trigger an error
                        data[base_len + 12] = data[base_len + 12] & 0b0000_1111;

                        let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 0 };
                        from_slice_assert_err(
                            &test,
                            &data,
                            EthSliceError::Tcp(err.clone()),
                            IpSliceError::Tcp(err.clone()),
                        );
                    }
                }
            }

            // icmpv4
            {
                let icmpv4 =
                    Icmpv4Header::new(Icmpv4Type::EchoReply(IcmpEchoHeader { id: 1, seq: 2 }));
                let mut test = base.clone();
                test.ip = Some({
                    let mut ip = ip.clone();
                    ip.set_next_headers(ip_number::ICMP);
                    ip
                });
                test.transport = Some(TransportHeader::Icmpv4(icmpv4.clone()));
                test.set_payload_len(0);

                // ok decode
                from_x_slice_assert_ok(&test);

                // length error
                if false == test.is_ip_payload_fragmented() {
                    for len in 0..icmpv4.header_len() {
                        // set payload length
                        let mut test = test.clone();
                        test.set_payload_le_from_ip_on(len as isize);

                        let data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - icmpv4.header_len();

                        let err = LenError {
                            required_len: icmpv4.header_len(),
                            len,
                            len_source: match test.ip.as_ref().unwrap() {
                                IpHeader::Version4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                IpHeader::Version6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: Layer::Icmpv4,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len(err.clone()),
                        );
                    }
                }
            }

            // icmpv6
            {
                let icmpv6 =
                    Icmpv6Header::new(Icmpv6Type::EchoReply(IcmpEchoHeader { id: 1, seq: 2 }));
                let mut test = base.clone();
                test.ip = Some({
                    let mut ip = ip.clone();
                    ip.set_next_headers(ip_number::IPV6_ICMP);
                    ip
                });
                test.transport = Some(TransportHeader::Icmpv6(icmpv6.clone()));
                test.set_payload_len(0);

                // ok decode
                from_x_slice_assert_ok(&test);

                // length error
                if false == test.is_ip_payload_fragmented() {
                    for len in 0..icmpv6.header_len() {
                        // set payload length
                        let mut test = test.clone();
                        test.set_payload_le_from_ip_on(len as isize);

                        let data = test.to_vec(&[]);
                        let base_len = test.len(&[]) - icmpv6.header_len();

                        let err = LenError {
                            required_len: icmpv6.header_len(),
                            len,
                            len_source: match test.ip.as_ref().unwrap() {
                                IpHeader::Version4(_, _) => LenSource::Ipv4HeaderTotalLen,
                                IpHeader::Version6(_, _) => LenSource::Ipv6HeaderPayloadLen,
                            },
                            layer: Layer::Icmpv6,
                            layer_start_offset: base_len,
                        };
                        from_slice_assert_err(
                            &test,
                            &data[..base_len + len],
                            EthSliceError::Len(err.clone()),
                            IpSliceError::Len(err.clone()),
                        );
                    }
                }
            }
        }
    }

    fn from_x_slice_assert_ok(test_base: &TestPacket) {
        fn assert_test_result(
            test: &TestPacket,
            expected_payload: &[u8],
            data: &[u8],
            result: &SlicedPacket,
        ) {
            // check if fragmenting
            let is_fragmented = test.is_ip_payload_fragmented();

            // check headers
            assert_eq!(test.link, result.link.as_ref().map(|e| e.to_header()));
            assert_eq!(test.vlan, result.vlan.as_ref().map(|e| e.to_header()));
            assert_eq!(
                test.ip,
                result.ip.as_ref().map(|s: &IpSlice| -> IpHeader {
                    match s {
                        IpSlice::Ipv4(ipv4) => IpHeader::Version4(
                            ipv4.header().to_header(),
                            ipv4.extensions().to_header(),
                        ),
                        IpSlice::Ipv6(ipv6) => IpHeader::Version6(
                            ipv6.header().to_header(),
                            Ipv6Extensions::from_slice(
                                ipv6.header().next_header(),
                                ipv6.extensions().slice(),
                            )
                            .unwrap()
                            .0,
                        ),
                    }
                })
            );

            // check transport header & payload
            if is_fragmented {
                assert_eq!(result.transport, None);
                let transport_len = test.transport.as_ref().map_or(0, |t| t.header_len());
                assert_eq!(
                    result.payload,
                    &data[data.len() - expected_payload.len() - transport_len..]
                );
            } else {
                use TransportHeader as H;
                use TransportSlice as S;
                match &result.transport {
                    Some(S::Icmpv4(icmpv4)) => {
                        assert_eq!(&test.transport, &Some(H::Icmpv4(icmpv4.header())));
                        assert_eq!(icmpv4.payload(), expected_payload);
                        assert_eq!(result.payload, &[]);
                    }
                    Some(S::Icmpv6(icmpv6)) => {
                        assert_eq!(&test.transport, &Some(H::Icmpv6(icmpv6.header())));
                        assert_eq!(icmpv6.payload(), expected_payload);
                        assert_eq!(result.payload, &[]);
                    }
                    Some(S::Udp(s)) => {
                        assert_eq!(&test.transport, &Some(H::Udp(s.to_header())));
                        assert_eq!(result.payload, expected_payload);
                    }
                    Some(S::Tcp(s)) => {
                        assert_eq!(&test.transport, &Some(H::Tcp(s.to_header())));
                        assert_eq!(result.payload, expected_payload);
                    }
                    Some(S::Unknown(next_ip_number)) => {
                        assert_eq!(&test.transport, &None);
                        assert_eq!(
                            *next_ip_number,
                            test.ip.as_ref().unwrap().next_header().unwrap()
                        );
                        assert_eq!(result.payload, expected_payload);
                    }
                    None => {
                        assert_eq!(&test.transport, &None);
                        assert_eq!(result.payload, expected_payload);
                    }
                }
            }
        }

        // setup payload
        let payload = [1, 2, 3, 4];

        // set length fields in ip headers
        let test = {
            let mut test = test_base.clone();
            test.set_payload_len(payload.len());
            test
        };

        // write data
        let data = test.to_vec(&payload);

        // from_ethernet
        if test.link.is_some() {
            let result = SlicedPacket::from_ethernet(&data).unwrap();
            assert_test_result(&test, &payload, &data, &result);
        }
        // from_ether_type (vlan at start)
        if test.link.is_none() && test.vlan.is_some() {
            for ether_type in VLAN_ETHER_TYPES {
                let result = SlicedPacket::from_ether_type(ether_type, &data).unwrap();
                assert_test_result(&test, &payload, &data, &result);
            }
        }
        // from_ether_type (ip at start)
        if test.link.is_none() && test.vlan.is_none() {
            if let Some(ip) = &test.ip {
                let result = SlicedPacket::from_ether_type(
                    match ip {
                        IpHeader::Version4(_, _) => ether_type::IPV4,
                        IpHeader::Version6(_, _) => ether_type::IPV6,
                    },
                    &data,
                )
                .unwrap();
                assert_test_result(&test, &payload, &data, &result);
            }
        }
        // from_ip_slice
        if test.link.is_none() && test.vlan.is_none() && test.ip.is_some() {
            let result = SlicedPacket::from_ip(&data).unwrap();
            assert_test_result(&test, &payload, &data, &result);
        }
    }

    /// Check that the given errors get triggered if presented with the given
    /// data.
    fn from_slice_assert_err(
        test: &TestPacket,
        data: &[u8],
        eth_err: EthSliceError,
        ip_err: IpSliceError,
    ) {
        // from_ethernet_slice
        if test.link.is_some() {
            assert_eq!(
                eth_err.clone(),
                SlicedPacket::from_ethernet(&data).unwrap_err()
            );
        }
        // from_ether_type (vlan at start)
        if test.link.is_none() && test.vlan.is_some() {
            for ether_type in VLAN_ETHER_TYPES {
                assert_eq!(
                    eth_err.clone(),
                    SlicedPacket::from_ether_type(ether_type, &data).unwrap_err()
                );
            }
        }
        // from_ether_type (ip at start)
        if test.link.is_none() && test.vlan.is_none() {
            if let Some(ip) = &test.ip {
                let err = SlicedPacket::from_ether_type(
                    match ip {
                        IpHeader::Version4(_, _) => ether_type::IPV4,
                        IpHeader::Version6(_, _) => ether_type::IPV6,
                    },
                    &data,
                )
                .unwrap_err();
                assert_eq!(err, eth_err.clone());
            }
        }
        // from_ip_slice
        if test.link.is_none() && test.vlan.is_none() && test.ip.is_some() {
            assert_eq!(ip_err, SlicedPacket::from_ip(&data).unwrap_err());
        }
    }

    proptest! {
        #[test]
        fn payload_ether_type(
            ref eth in ethernet_2_unknown(),
            ref vlan_outer in vlan_single_unknown(),
            ref vlan_inner in vlan_single_unknown(),
            ref ipv4 in ipv4_unknown(),
            ref udp in udp_any(),
        ) {
            use IpHeader::*;
            use alloc::vec::Vec;

            // empty
            {
                let s = SlicedPacket{
                    link: None,
                    vlan: None,
                    ip: None,
                    transport: None,
                    payload: &[]
                };
                assert_eq!(None, s.payload_ether_type());
            }

            // only ethernet
            {
                let mut serialized = Vec::with_capacity(eth.header_len());
                eth.write(&mut serialized).unwrap();
                assert_eq!(
                    Some(eth.ether_type),
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with single vlan
            {
                let mut eth_mod = eth.clone();
                eth_mod.ether_type = ether_type::VLAN_TAGGED_FRAME;

                let mut serialized = Vec::with_capacity(
                    eth_mod.header_len() +
                    vlan_outer.header_len()
                );
                eth_mod.write(&mut serialized).unwrap();
                vlan_outer.write(&mut serialized).unwrap();
                assert_eq!(
                    Some(vlan_outer.ether_type),
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with double vlan
            {
                let mut eth_mod = eth.clone();
                eth_mod.ether_type = ether_type::VLAN_TAGGED_FRAME;

                let mut vlan_outer_mod = vlan_outer.clone();
                vlan_outer_mod.ether_type = ether_type::VLAN_TAGGED_FRAME;

                let mut serialized = Vec::with_capacity(
                    eth_mod.header_len() +
                    vlan_outer_mod.header_len() +
                    vlan_inner.header_len()
                );
                eth_mod.write(&mut serialized).unwrap();
                vlan_outer_mod.write(&mut serialized).unwrap();
                vlan_inner.write(&mut serialized).unwrap();
                assert_eq!(
                    Some(vlan_inner.ether_type),
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with ip
            {
                let builder = PacketBuilder::ethernet2(eth.source, eth.destination)
                    .ip(Version4(ipv4.clone(), Default::default()));

                let mut serialized = Vec::with_capacity(builder.size(0));
                builder.write(&mut serialized, ipv4.protocol, &[]).unwrap();

                assert_eq!(
                    None,
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }

            // with transport
            {
                let builder = PacketBuilder::ethernet2(eth.source, eth.destination)
                    .ip(Version4(ipv4.clone(), Default::default()))
                    .udp(udp.source_port, udp.destination_port);
                let mut serialized = Vec::with_capacity(builder.size(0));
                builder.write(&mut serialized, &[]).unwrap();

                assert_eq!(
                    None,
                    SlicedPacket::from_ethernet(&serialized)
                        .unwrap()
                        .payload_ether_type()
                );
            }
        }
    }
}
