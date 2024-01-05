use crate::{err::Layer, *};

/// Packet slice split into multiple slices containing
/// the different headers & payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaxSlicedPacket<'a> {
    /// Ethernet II header if present.
    pub link: Option<LinkSlice<'a>>,

    /// Single or double vlan headers if present.
    pub vlan: Option<VlanSlice<'a>>,

    /// IPv4 or IPv6 header, IP extension headers & payload if present.
    pub ip: Option<IpSlice<'a>>,

    /// TCP or UDP header & payload if present.
    pub transport: Option<TransportSlice<'a>>,

    /// Last successfully parsed layer.
    pub last_parsed_layer: Layer,

    /// Error that stopped the parsing and the layer on which the stop occurred.
    pub stop_err: Option<(err::packet::SliceError, Layer)>,
}

impl<'a> LaxSlicedPacket<'a> {

    
    pub fn from_ethernet(data: &'a [u8]) -> Result<LaxSlicedPacket, err::packet::EthSliceError> {
        todo!()
        //SlicedPacketCursor::new(data).slice_ethernet2()
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
    /// match LaxSlicedPacket::from_ether_type(ether_type::IPV4, packet) {
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
    ) -> Result<LaxSlicedPacket, err::packet::EthSliceError> {
        todo!();
        /*
        use ether_type::*;
        match ether_type {
            IPV4 => SlicedPacketCursor::new(data).slice_ipv4_lax(),
            IPV6 => SlicedPacketCursor::new(data).slice_ipv6_lax(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                SlicedPacketCursor::new(data).slice_vlan_lax()
            }
            _ => Ok(SlicedPacket {
                link: None,
                vlan: None,
                ip: None,
                transport: None,
            }),
        }
         */
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
    /// match LaxSlicedPacket::from_ip(&packet) {
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
    pub fn from_ip(data: &'a [u8]) -> Result<LaxSlicedPacket, err::packet::IpSliceError> {
        todo!()
        //SlicedPacketCursor::new(data).slice_ip_lax()
    }
}
