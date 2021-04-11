use super::*;
use proptest::*;
use proptest::prelude::*;

pub fn error_field_any() -> impl Strategy<Value = ErrorField> {
    use ErrorField::*;
    prop_oneof![
        Just(Ipv4PayloadLength),
        Just(Ipv4Dscp),
        Just(Ipv4Ecn),
        Just(Ipv4FragmentsOffset),
        Just(Ipv6FlowLabel),
        Just(VlanTagPriorityCodePoint),
        Just(VlanTagVlanId)
    ]
}

prop_compose! {
    pub(crate) fn ethernet_2_with(ether_type: u16)(
        source in prop::array::uniform6(any::<u8>()),
        dest in prop::array::uniform6(any::<u8>()),
        ether_type in proptest::strategy::Just(ether_type))
        -> Ethernet2Header
    {
        Ethernet2Header {
            source: source,
            destination: dest,
            ether_type: ether_type
        }
    }
}

prop_compose! {
    pub(crate) fn ethernet_2_any()
        (ether_type in any::<u16>())
        (result in ethernet_2_with(ether_type)) 
        -> Ethernet2Header
    {
        result
    }
}

pub static ETHERNET_KNOWN_ETHER_TYPES: &'static [u16] = &[
    EtherType::Ipv4 as u16,
    EtherType::Ipv6 as u16,
    EtherType::VlanTaggedFrame as u16,
    EtherType::ProviderBridging as u16,
    EtherType::VlanDoubleTaggedFrame as u16
];

prop_compose! {
    pub(crate) fn ethernet_2_unknown()(
        source in prop::array::uniform6(any::<u8>()),
        dest in prop::array::uniform6(any::<u8>()),
        ether_type in any::<u16>().prop_filter("ether_type must be unknown",
            |v| !ETHERNET_KNOWN_ETHER_TYPES.iter().any(|&x| v == &x)))
        -> Ethernet2Header
    {
        Ethernet2Header {
            source: source,
            destination: dest,
            ether_type: ether_type
        }
    }
}

prop_compose! {
    pub(crate) fn vlan_single_unknown()(
        priority_code_point in prop::bits::u8::between(0,3),
        drop_eligible_indicator in any::<bool>(),
        vlan_identifier in prop::bits::u16::between(0,12),
        ether_type in any::<u16>().prop_filter("ether_type must be unknown",
            |v| !ETHERNET_KNOWN_ETHER_TYPES.iter().any(|&x| v == &x)))
        -> SingleVlanHeader
    {
        SingleVlanHeader {
            priority_code_point: priority_code_point,
            drop_eligible_indicator: drop_eligible_indicator,
            vlan_identifier: vlan_identifier,
            ether_type: ether_type
        }
    }
}

prop_compose! {
    pub(crate) fn vlan_single_with(ether_type: u16)(
        priority_code_point in prop::bits::u8::between(0,3),
        drop_eligible_indicator in any::<bool>(),
        vlan_identifier in prop::bits::u16::between(0,12),
        ether_type in proptest::strategy::Just(ether_type))
        -> SingleVlanHeader
    {
        SingleVlanHeader {
            priority_code_point: priority_code_point,
            drop_eligible_indicator: drop_eligible_indicator,
            vlan_identifier: vlan_identifier,
            ether_type: ether_type
        }
    }
}

prop_compose! {
    pub(crate) fn vlan_single_any()
        (ether_type in any::<u16>())
        (result in vlan_single_with(ether_type)) 
        -> SingleVlanHeader
    {
        result
    }
}

prop_compose! {
    pub(crate) fn ipv4_with(protocol: u8)
    (
        ihl in 0u8..10,
        protocol in proptest::strategy::Just(protocol))
        (source in prop::array::uniform4(any::<u8>()),
        dest in prop::array::uniform4(any::<u8>()),
        dscp in prop::bits::u8::between(0,6),
        ecn in prop::bits::u8::between(0,2),
        identification in any::<u16>(),
        ttl in any::<u8>(),
        dont_fragment in any::<bool>(),
        more_fragments in any::<bool>(),
        fragments_offset in prop::bits::u16::between(0, 13),
        header_checksum in any::<u16>(),
        payload_len in 0..(std::u16::MAX - u16::from(ihl*4) - (Ipv4Header::SERIALIZED_SIZE as u16)),
        protocol in proptest::strategy::Just(protocol),
        options_len in proptest::strategy::Just(ihl*4),
        options_part0 in prop::array::uniform32(any::<u8>()),
        options_part1 in prop::array::uniform8(any::<u8>())
    ) -> Ipv4Header
    {
        let mut result: Ipv4Header = Default::default();
        {
            let mut options: [u8;40] = [0;40];
            //copy together 40 bytes of random data (the limit for static arrays in proptest 32,
            //so a 32 & 8 byte array get combined here)
            let len = usize::from(options_len);
            if len > 0 {
                let sub_len = std::cmp::min(len,32);
                options[..sub_len].copy_from_slice(&options_part0[..sub_len]);
            }
            if len > 32 {
                let sub_len = len - 32;
                options[32..len].copy_from_slice(&options_part1[..sub_len]);
            }

            //set the options
            result.set_options(&options[..len]).unwrap();
        }
        
        result.differentiated_services_code_point = dscp;
        result.explicit_congestion_notification = ecn;
        result.payload_len = payload_len;
        result.identification = identification;
        result.dont_fragment = dont_fragment;
        result.more_fragments = more_fragments;
        result.fragments_offset = fragments_offset;
        result.time_to_live = ttl;
        result.protocol = protocol;
        result.header_checksum = header_checksum;
        result.source = source;
        result.destination = dest;

        return result;
    }
}
prop_compose! {
    pub(crate) fn ipv4_any()
               (protocol in any::<u8>())
               (result in ipv4_with(protocol)) 
               -> Ipv4Header
    {
        result
    }
}

static IPV4_KNOWN_PROTOCOLS: &'static [u8] = &[
    ip_number::UDP,
    ip_number::TCP
];

prop_compose! {
    pub(crate) fn ipv4_unknown()
        (protocol in any::<u8>().prop_filter("protocol must be unknown",
            |v| !IPV4_KNOWN_PROTOCOLS.iter().any(|&x| v == &x))
        )
        (header in ipv4_with(protocol)
    ) -> Ipv4Header
    {
        header
    }
}

prop_compose! {
    pub(crate) fn ipv6_with(next_header: u8)
    (
        source in prop::array::uniform16(any::<u8>()),
        dest in prop::array::uniform16(any::<u8>()),
        traffic_class in any::<u8>(),
        flow_label in prop::bits::u32::between(0,20),
        payload_length in any::<u16>(),
        hop_limit in any::<u8>(),
        next_header in proptest::strategy::Just(next_header)
    ) -> Ipv6Header
    {
        Ipv6Header {
            traffic_class: traffic_class,
            flow_label: flow_label,
            payload_length: payload_length,
            next_header: next_header,
            hop_limit: hop_limit,
            source: source,
            destination: dest
        }
    }
}

prop_compose! {
    pub(crate) fn ipv6_any()
        (next_header in any::<u8>())
        (result in ipv6_with(next_header)
    ) -> Ipv6Header
    {
        result
    }
}

static IPV6_KNOWN_NEXT_HEADERS: &'static [u8] = &[
    ip_number::UDP,
    ip_number::TCP,
    ip_number::IPV6_HOP_BY_HOP,
    ip_number::IPV6_ROUTE,
    ip_number::IPV6_FRAG,
    ip_number::AUTH,
    ip_number::IPV6_DEST_OPTIONS,
    ip_number::MOBILITY,
    ip_number::HIP,
    ip_number::SHIM6,
    // currently not supported:
    // - EncapsulatingSecurityPayload
    // - ExperimentalAndTesting0
    // - ExperimentalAndTesting1
];

prop_compose! {
    pub(crate) fn ipv6_unknown()(
        source in prop::array::uniform16(any::<u8>()),
        dest in prop::array::uniform16(any::<u8>()),
        traffic_class in any::<u8>(),
        flow_label in prop::bits::u32::between(0,20),
        payload_length in any::<u16>(),
        hop_limit in any::<u8>(),
        next_header in any::<u8>().prop_filter("next_header must be unknown",
            |v| !IPV6_KNOWN_NEXT_HEADERS.iter().any(|&x| v == &x))
    ) -> Ipv6Header
    {
        Ipv6Header {
            traffic_class: traffic_class,
            flow_label: flow_label,
            payload_length: payload_length,
            next_header: next_header,
            hop_limit: hop_limit,
            source: source,
            destination: dest
        }
    }
}

prop_compose! {
    pub(crate) fn ipv6_generic_extension_with(
        next_header: u8,
        len: u8
    ) (
        next_header in proptest::strategy::Just(next_header),
        payload in proptest::collection::vec(any::<u8>(), (len as usize)*8 + 6)
    ) -> Ipv6GenericExtensionHeader
    {
        Ipv6GenericExtensionHeader::new_raw(
            next_header,
            &payload[..]
        ).unwrap()
    }
}

prop_compose! {
    pub(crate) fn ipv6_generic_extension_any() 
        (
            next_header in any::<u8>(),
            len in any::<u8>()
        ) (
            result in ipv6_generic_extension_with(next_header, len)
    ) -> Ipv6GenericExtensionHeader
    {
        result
    }
}

/*
/// Contains everything to construct the supported ip extension headers
pub enum IpExtensionComponent {
    Ipv6HeaderHopByHop(Ipv6GenericExtensionHeader),
    Ipv6Route(Ipv6GenericExtensionHeader),
    Ipv6DestinationOptions(Ipv6GenericExtensionHeader),

    MobilityHeader(Ipv6GenericExtensionHeader),
    Hip(Ipv6GenericExtensionHeader),
    Shim6(Ipv6GenericExtensionHeader),

    AuthenticationHeader(IpAuthenticationHeader),
    Ipv6Fragment(Ipv6FragmentHeader),
}

impl IpExtensionComponent {
    pub fn traffic_class(&self) -> u8 {
        match self {
            Ipv6HeaderHopByHop(_) => IpTrafficClass::IPv6HeaderHopByHop as u8,
            Ipv6Route(_) => IpTrafficClass::IPv6RouteHeader as u8,
            Ipv6DestinationOptions(_) => IpTrafficClass::IPv6DestinationOptions as u8,

            MobilityHeader(_) => IpTrafficClass::MobilityHeader as u8,
            Hip(_) => IpTrafficClass::Hip as u8,
            Shim6(_) => IpTrafficClass::Shim6 as u8,

            AuthenticationHeader(_) => IpTrafficClass::AuthenticationHeader as u8,
            Ipv6Fragment(_) => IpTrafficClass::IPv6FragmentationHeader as u8,
        }
    }
}

prop_compose! {
    pub(crate) fn ip_extension_component(
        next_header: u8,
        len: u8
    ) (
        component_type in 0..8usize,
        next_header in proptest::strategy::Just(next_header),
        len in proptest::strategy::Just(len),
        ext in ipv6_extension_with(next_header, len),
        frag in ipv6_fragment_with(next_header),
        auth in ipv6_fragment_with(next_header)
    ) {
        use IpExtensionComponent::*;
        match component_type {
            0 => Ipv6HeaderHopByHop(ext),
            1 => Ipv6Route(ext),
            2 => Ipv6DestinationOptions(ext),

            3 => MobilityHeader(ext),
            4 => Hip(ext),
            5 => Shim6(ext),

            6 => AuthenticationHeader(auth),
            7 => Ipv6Fragment(frag),

            _ => panic!("unsupported ip_extension_component");
        }
    }
}

prop_compose! {
    pub(crate) fn ipv6_extension_with(
        next_header: u8,
        len: u8
    ) (
        next_header in proptest::strategy::Just(next_header),
        len in proptest::strategy::Just(len),
        payload in proptest::collection::vec(any::<u8>(), (len as usize)*8 + 8)
    ) -> Ipv6ExtensionComponents
    {
        Ipv6ExtensionComponents {
            next_header,
            data: payload.clone()
        }
    }
}
//Order of ipv6 heder extensions defined by ipv6 rfc
// * Hop-by-Hop Options header
// * Destination Options header (note 1)
// * Routing header
// * Fragment header
// * Authentication header (note 2)
// * Encapsulating Security Payload header (note 2)
// * Destination Options header (note 3)
// (rest appended to the end)

static IPV6_EXTENSION_HEADER_ORDER: &'static [u8] = &[
    IpTrafficClass::IPv6HeaderHopByHop as u8,
    IpTrafficClass::IPv6DestinationOptions as u8,
    IpTrafficClass::IPv6RouteHeader as u8,
    IpTrafficClass::IPv6FragmentationHeader as u8,
    IpTrafficClass::AuthenticationHeader as u8,
    IpTrafficClass::EncapsulatingSecurityPayload as u8,
    IpTrafficClass::IPv6DestinationOptions as u8,
    IpTrafficClass::MobilityHeader as u8,
    IpTrafficClass::Hip as u8,
    IpTrafficClass::Shim6 as u8,
    IpTrafficClass::ExperimentalAndTesting0 as u8,
    IpTrafficClass::ExperimentalAndTesting1 as u8
];

prop_compose! {
    pub(crate) fn ipv6_extensions_unknown()
    (
        last_next_header in any::<u8>().prop_filter("next_header must be unknown",
        |v| !IPV6_KNOWN_NEXT_HEADERS.iter().any(|&x| v == &x)),
        len0 in 0u8..5,
        len1 in 0u8..5,
        len2 in 0u8..5,
        //skip fragmenetation header (fixed size 0))
        len4 in 0u8..5,
        len5 in 0u8..5,
        len6 in 0u8..5,
        len7 in 0u8..5,
        len8 in 0u8..5,
        len9 in 0u8..5,
        len10 in 0u8..5,
        len11 in 0u8..5
    )
    (
        last_next_header in proptest::strategy::Just(last_next_header),
        hdr0 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len0),
        hdr1 in ipv6_extension_with(IpTrafficClass::IPv6RouteHeader as u8, len1),
        hdr2 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len2),
        hdr3 in ipv6_extension_with(IpTrafficClass::IPv6FragmentationHeader as u8, 0),
        hdr4 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len4),
        hdr5 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len5),
        hdr6 in ipv6_extension_with(IpTrafficClass::MobilityHeader as u8, len6),
        hdr7 in ipv6_extension_with(IpTrafficClass::Hip as u8, len7),
        hdr8 in ipv6_extension_with(IpTrafficClass::Shim6 as u8, len8),
        hdr9 in ipv6_extension_with(IpTrafficClass::ExperimentalAndTesting0 as u8, len9),
        hdr10 in ipv6_extension_with(IpTrafficClass::ExperimentalAndTesting1 as u8, len10),
        hdr11 in ipv6_extension_with(last_next_header, len11),
        order in proptest::sample::subsequence((0..IPV6_EXTENSION_HEADER_ORDER.len()).collect::<Vec<usize>>(), 1..IPV6_EXTENSION_HEADER_ORDER.len())
    ) -> Vec<Ipv6ExtensionComponents>
    {
        let all_headers = vec![hdr0, hdr1, hdr2, hdr3, hdr4, 
                               hdr5, hdr6, hdr7, hdr8, hdr9, 
                               hdr10, hdr11];

        //get the corresponding next headers
        let mut next_headers : Vec<u8> = order.iter()
                                              .skip(1) //skip the first entry
                                              .map(|i| IPV6_EXTENSION_HEADER_ORDER[*i])
                                              .collect();
        next_headers.push(last_next_header);

        let mut result = Vec::with_capacity(order.len());
        for (h, next) in order.iter()
                              .map(|i| (IPV6_EXTENSION_HEADER_ORDER[*i], &all_headers[*i]))
                              .zip(next_headers)
        {
            let mut header = h.1.clone();
            header[0] = next;
            result.push((h.0, header));
        }

        result
    }
}
*/
prop_compose! {
    pub(crate) fn ipv6_fragment_with(
        next_header: u8
    ) (
        next_header in proptest::strategy::Just(next_header),
        fragment_offset in 0u16..=0b0001_1111_1111_1111u16,
        more_fragments in any::<bool>(),
        identification in any::<u32>(),
    ) -> Ipv6FragmentHeader
    {
        Ipv6FragmentHeader::new(
            next_header,
            fragment_offset,
            more_fragments,
            identification
        )
    }
}

prop_compose! {
    pub(crate) fn ipv6_fragment_any()
        (next_header in any::<u8>())
        (result in ipv6_fragment_with(next_header)
    ) -> Ipv6FragmentHeader
    {
        result
    }
}

prop_compose! {
    pub(crate) fn ip_authentication_with(
        next_header: u8
    ) (
        next_header in proptest::strategy::Just(next_header),
        len in 1..0xffu8
    ) (
        next_header in proptest::strategy::Just(next_header),
        spi in any::<u32>(),
        sequence_number in any::<u32>(),
        icv in proptest::collection::vec(any::<u8>(), (len as usize)*4)
    ) -> IpAuthenticationHeader {
        IpAuthenticationHeader::new(
            next_header,
            spi,
            sequence_number,
            &icv
        ).unwrap()
    }
}

prop_compose! {
    pub(crate) fn ip_authentication_any() (
        next_header in any::<u8>()
    ) (
        header in ip_authentication_with(next_header)
    ) -> IpAuthenticationHeader {
        header
    }
}

prop_compose! {
    pub(crate) fn udp_any()(
            source_port in any::<u16>(),
            destination_port in any::<u16>(),
            length in any::<u16>(),
            checksum in any::<u16>())
        -> UdpHeader
    {
        UdpHeader {
            source_port: source_port,
            destination_port: destination_port,
            length: length,
            checksum: checksum
        }
    }
}

prop_compose! {
    pub(crate) fn tcp_any()
        (data_offset in TCP_MINIMUM_DATA_OFFSET..(TCP_MAXIMUM_DATA_OFFSET + 1))
        (
            source_port in any::<u16>(),
            destination_port in any::<u16>(),
            sequence_number in any::<u32>(),
            acknowledgment_number in any::<u32>(),
            ns in any::<bool>(),
            fin in any::<bool>(),
            syn in any::<bool>(),
            rst in any::<bool>(),
            psh in any::<bool>(),
            ack in any::<bool>(),
            ece in any::<bool>(),
            urg in any::<bool>(),
            cwr  in any::<bool>(),
            window_size in any::<u16>(),
            checksum in any::<u16>(),
            urgent_pointer in any::<u16>(),
            options in proptest::collection::vec(any::<u8>(), ((data_offset - 5) as usize)*4))
        -> TcpHeader
    {
        let mut result = TcpHeader::new(source_port, destination_port, sequence_number, window_size);
        result.acknowledgment_number = acknowledgment_number;
        result.ns = ns;
        result.fin = fin;
        result.syn = syn;
        result.rst = rst;
        result.psh = psh;
        result.ack = ack;
        result.ece = ece;
        result.urg = urg;
        result.cwr = cwr;
        result.checksum = checksum;
        result.urgent_pointer = urgent_pointer;
        result.set_options_raw(&options[..]).unwrap();
        result
    }
}

pub fn ip_number_any() -> impl Strategy<Value = IpNumber> {
    use IpNumber::*;
    prop_oneof![
        Just(IPv6HeaderHopByHop),
        Just(Icmp),
        Just(Igmp),
        Just(Ggp),
        Just(IPv4),
        Just(Stream),
        Just(Tcp),
        Just(Cbt),
        Just(Egp),
        Just(Igp),
        Just(BbnRccMon),
        Just(NvpII),
        Just(Pup),
        Just(Argus),
        Just(Emcon),
        Just(Xnet),
        Just(Chaos),
        Just(Udp),
        Just(Mux),
        Just(DcnMeas),
        Just(Hmp),
        Just(Prm),
        Just(XnsIdp),
        Just(Trunk1),
        Just(Trunk2),
        Just(Leaf1),
        Just(Leaf2),
        Just(Rdp),
        Just(Irtp),
        Just(IsoTp4),
        Just(NetBlt),
        Just(MfeNsp),
        Just(MeritInp),
        Just(Dccp),
        Just(ThirdPartyConnectProtocol),
        Just(Idpr),
        Just(Xtp),
        Just(Ddp),
        Just(IdprCmtp),
        Just(TpPlusPlus),
        Just(Il),
        Just(Ipv6),
        Just(Sdrp),
        Just(IPv6RouteHeader),
        Just(IPv6FragmentationHeader),
        Just(Idrp),
        Just(Rsvp),
        Just(Gre),
        Just(Dsr),
        Just(Bna),
        Just(EncapsulatingSecurityPayload),
        Just(AuthenticationHeader),
        Just(Inlsp),
        Just(Swipe),
        Just(Narp),
        Just(Mobile),
        Just(Tlsp),
        Just(Skip),
        Just(IPv6Icmp),
        Just(IPv6NoNextHeader),
        Just(IPv6DestinationOptions),
        Just(AnyHostInternalProtocol),
        Just(Cftp),
        Just(AnyLocalNetwork),
        Just(SatExpak),
        Just(Krytolan),
        Just(Rvd),
        Just(Ippc),
        Just(AnyDistributedFileSystem),
        Just(SatMon),
        Just(Visa),
        Just(Ipcv),
        Just(Cpnx),
        Just(Cphb),
        Just(Wsn),
        Just(Pvp),
        Just(BrSatMon),
        Just(SunNd),
        Just(WbMon),
        Just(WbExpak),
        Just(IsoIp),
        Just(Vmtp),
        Just(SecureVmtp),
        Just(Vines),
        Just(TtpOrIptm),
        Just(NsfnetIgp),
        Just(Dgp),
        Just(Tcf),
        Just(Eigrp),
        Just(Ospfigp),
        Just(SpriteRpc),
        Just(Larp),
        Just(Mtp),
        Just(Ax25),
        Just(Ipip),
        Just(Micp),
        Just(SccSp),
        Just(EtherIp),
        Just(Encap),
        Just(Gmtp),
        Just(Ifmp),
        Just(Pnni),
        Just(Pim),
        Just(Aris),
        Just(Scps),
        Just(Qnx),
        Just(ActiveNetworks),
        Just(IpComp),
        Just(SitraNetworksProtocol),
        Just(CompaqPeer),
        Just(IpxInIp),
        Just(Vrrp),
        Just(Pgm),
        Just(AnyZeroHopProtocol),
        Just(Layer2TunnelingProtocol),
        Just(Ddx),
        Just(Iatp),
        Just(Stp),
        Just(Srp),
        Just(Uti),
        Just(SimpleMessageProtocol),
        Just(Sm),
        Just(Ptp),
        Just(IsisOverIpv4),
        Just(Fire),
        Just(Crtp),
        Just(Crudp),
        Just(Sscopmce),
        Just(Iplt),
        Just(Sps),
        Just(Pipe),
        Just(Sctp),
        Just(Fc),
        Just(RsvpE2eIgnore),
        Just(MobilityHeader),
        Just(UdpLite),
        Just(MplsInIp),
        Just(Manet),
        Just(Hip),
        Just(Shim6),
        Just(Wesp),
        Just(Rohc),
        Just(ExperimentalAndTesting0),
        Just(ExperimentalAndTesting1)
    ]
}
