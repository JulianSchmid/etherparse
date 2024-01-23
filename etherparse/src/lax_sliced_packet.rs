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
    pub net: Option<LaxNetSlice<'a>>,

    /// TCP or UDP header & payload if present.
    pub transport: Option<TransportSlice<'a>>,

    /// Error that stopped the parsing and the layer on which the stop occurred.
    pub stop_err: Option<(err::packet::SliceError, Layer)>,
}

impl<'a> LaxSlicedPacket<'a> {
    /// Separates a network packet slice into different slices containing the
    /// headers from the ethernet header downwards with lax length checks and
    /// non-terminating errors.
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
    /// # let mut packet = Vec::<u8>::with_capacity(
    /// #     builder.size(payload.len())
    /// # );
    /// # builder.write(&mut packet, &payload).unwrap();
    /// #
    /// use etherparse::{ether_type, LaxSlicedPacket, err::LenSource};
    ///
    /// match LaxSlicedPacket::from_ethernet(&packet) {
    ///     Err(value) => {
    ///         // An error is returned in case the ethernet II header could
    ///         // not be parsed (other errors are stored in the "stop_err" field)
    ///         println!("Err {:?}", value)
    ///     },
    ///     Ok(value) => {
    ///         if let Some((stop_err, error_layer)) = value.stop_err.as_ref() {
    ///             // error was encountered after parsing the ethernet 2 header
    ///             println!("Error on layer {}: {:?}", stop_err, error_layer);
    ///         }
    ///
    ///         // parts that could be parsed without error
    ///         println!("link: {:?}", value.link);
    ///         println!("vlan: {:?}", value.vlan);
    ///         println!("net: {:?}", value.net);
    ///         println!("transport: {:?}", value.transport);
    ///
    ///         // net (ip) & transport (udp or tcp)
    ///         println!("net: {:?}", value.net);
    ///         if let Some(ip_payload) = value.net.as_ref().map(|net| net.ip_payload()).flatten() {
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
    ///
    /// ```
    pub fn from_ethernet(slice: &'a [u8]) -> Result<LaxSlicedPacket, err::packet::EthSliceError> {
        LaxSlicedPacketCursor::parse_from_ethernet2(slice)
    }

    /// Separates a network packet slice into different slices containing the headers using
    /// the given `ether_type` number to identify the first header with lax length
    /// checks and non-terminating errors.
    ///
    /// The result is returned as a [`LaxSlicedPacket`] struct. Currently supported
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
    /// use etherparse::{ether_type, LaxSlicedPacket};
    ///
    /// let packet = LaxSlicedPacket::from_ether_type(ether_type::IPV4, packet);
    /// if let Some((stop_err, error_layer)) = packet.stop_err.as_ref() {
    ///     // in case an error is encountered parsing is stopped
    ///     println!("Error on layer {}: {:?}", stop_err, error_layer);
    /// }
    ///
    /// // parts that could be parsed without error
    /// println!("link: {:?}", packet.link);
    /// println!("vlan: {:?}", packet.vlan);
    /// println!("net: {:?}", packet.net);
    /// println!("transport: {:?}", packet.transport);
    ///
    /// ```
    pub fn from_ether_type(ether_type: EtherType, slice: &'a [u8]) -> LaxSlicedPacket {
        LaxSlicedPacketCursor::parse_from_ether_type(ether_type, slice)
    }

    /// Separates a network packet slice into different slices containing
    /// the headers from the ip header downwards with lax length checks
    /// and will still return a result even if an error is encountered in
    /// a layer (except IP).
    ///
    /// This function has two main differences to `SlicedPacket::from_ip`:
    ///
    /// * Errors encountered bellow the IpHeader will only stop the parsing and
    ///   return an `Ok` with the successfully parsed parts and the error as optional.
    ///   Only if an unrecoverable error is encountered in the IP header itself an
    ///   `Err` is returned.
    /// * Length in the IP header & UDP headers are allowed to be inconsistent with the
    ///   given slice length (e.g. data is missing from the slice). In this case it falls
    ///   back to the length of slice. See [`LaxIpSlice::from_slice`] for a detailed
    ///   description of when the slice length is used as a fallback.
    ///
    /// The result is returned as a [`SlicedPacket`] struct. This function
    /// assumes the given data starts with an IPv4 or IPv6 header.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    ///```
    /// # use etherparse::{PacketBuilder, IpSlice, err::LenSource};
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
    /// use etherparse::LaxSlicedPacket;
    ///
    /// match LaxSlicedPacket::from_ip(&packet) {
    ///     Err(value) => {
    ///         // An error is returned in case the ip header could
    ///         // not parsed (other errors are stored in the "stop_err" field)
    ///         println!("Err {:?}", value)
    ///     },
    ///     Ok(value) => {
    ///         if let Some((stop_err, error_layer)) = value.stop_err.as_ref() {
    ///             // error is encountered after the ip header (stops parsing)
    ///             println!("Error on layer {}: {:?}", stop_err, error_layer);
    ///         }
    ///
    ///         // link & vlan fields are empty when parsing from ip downwards
    ///         assert_eq!(None, value.link);
    ///         assert_eq!(None, value.vlan);
    ///
    ///         // net (ip) & transport (udp or tcp)
    ///         println!("net: {:?}", value.net);
    ///         if let Some(ip_payload) = value.net.as_ref().map(|net| net.ip_payload()).flatten() {
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
    pub fn from_ip(slice: &'a [u8]) -> Result<LaxSlicedPacket, err::ip::LaxHeaderSliceError> {
        LaxSlicedPacketCursor::parse_from_ip(slice)
    }
}
