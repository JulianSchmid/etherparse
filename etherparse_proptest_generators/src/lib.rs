use etherparse::*;
use proptest::prelude::*;
use proptest::*;

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

pub fn vlan_ethertype_any() -> impl Strategy<Value = u16> {
    prop_oneof![
        Just(ether_type::VLAN_TAGGED_FRAME),
        Just(ether_type::PROVIDER_BRIDGING),
        Just(ether_type::VLAN_DOUBLE_TAGGED_FRAME),
    ]
}

prop_compose! {
    pub fn ethernet_2_with(ether_type: u16)(
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
    pub fn ethernet_2_any()
        (ether_type in any::<u16>())
        (result in ethernet_2_with(ether_type))
        -> Ethernet2Header
    {
        result
    }
}

pub static ETHERNET_KNOWN_ETHER_TYPES: &'static [u16] = &[
    ether_type::IPV4,
    ether_type::IPV6,
    ether_type::VLAN_TAGGED_FRAME,
    ether_type::PROVIDER_BRIDGING,
    ether_type::VLAN_DOUBLE_TAGGED_FRAME,
];

prop_compose! {
    pub fn ethernet_2_unknown()(
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
    pub fn vlan_single_unknown()(
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
    pub fn vlan_single_with(ether_type: u16)(
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
    pub fn vlan_single_any()
        (ether_type in any::<u16>())
        (result in vlan_single_with(ether_type))
        -> SingleVlanHeader
    {
        result
    }
}

prop_compose! {
    pub fn vlan_double_any()
        (ether_type in any::<u16>())
        (result in vlan_double_with(ether_type))
        -> DoubleVlanHeader
    {
        result
    }
}

prop_compose! {
    pub fn vlan_double_with(ether_type: u16)(
        outer_ethertype in vlan_ethertype_any(),
        inner_ethertype in proptest::strategy::Just(ether_type)
    )(
        outer in vlan_single_with(outer_ethertype),
        inner in vlan_single_with(inner_ethertype)
    ) -> DoubleVlanHeader {
        DoubleVlanHeader {
            outer,
            inner
        }
    }
}

prop_compose! {
    pub fn ipv4_with(protocol: u8)
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
        payload_len in 0..(std::u16::MAX - u16::from(ihl*4) - (Ipv4Header::MIN_LEN as u16)),
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
    pub fn ipv4_any()
               (protocol in any::<u8>())
               (result in ipv4_with(protocol))
               -> Ipv4Header
    {
        result
    }
}

static IPV4_KNOWN_PROTOCOLS: &'static [u8] = &[
    ip_number::ICMP,
    ip_number::UDP,
    ip_number::TCP,
    ip_number::AUTH,
    ip_number::IPV6_ICMP,
];

prop_compose! {
    pub fn ipv4_unknown()
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
    pub fn ipv4_extensions_with(next_header: u8)
    (
        has_auth in any::<bool>(),
        auth in ip_auth_with(next_header)
    ) -> Ipv4Extensions
    {
        if has_auth {
            Ipv4Extensions{
                auth: Some(auth),
            }
        } else {
            Ipv4Extensions{
                auth: None,
            }
        }
    }
}

prop_compose! {
    pub fn ipv4_extensions_any()
               (protocol in any::<u8>())
               (result in ipv4_extensions_with(protocol))
               -> Ipv4Extensions
    {
        result
    }
}

prop_compose! {
    pub fn ipv4_extensions_unknown()
        (
            next_header in any::<u8>().prop_filter(
                "next_header must be unknown",
                |v| !IPV4_KNOWN_PROTOCOLS.iter().any(|&x| v == &x)
            )
        ) (
            result in ipv4_extensions_with(next_header)
        ) -> Ipv4Extensions
    {
        result
    }
}

prop_compose! {
    pub fn ipv6_with(next_header: u8)
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
    pub fn ipv6_any()
        (next_header in any::<u8>())
        (result in ipv6_with(next_header)
    ) -> Ipv6Header
    {
        result
    }
}

static IPV6_KNOWN_NEXT_HEADERS: &'static [u8] = &[
    ip_number::ICMP,
    ip_number::UDP,
    ip_number::TCP,
    ip_number::IPV6_HOP_BY_HOP,
    ip_number::IPV6_ICMP,
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
    pub fn ipv6_unknown()(
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
    pub fn ipv6_raw_ext_with(
        next_header: u8,
        len: u8
    ) (
        next_header in proptest::strategy::Just(next_header),
        payload in proptest::collection::vec(any::<u8>(), (len as usize)*8 + 6)
    ) -> Ipv6RawExtHeader
    {
        Ipv6RawExtHeader::new_raw(
            next_header,
            &payload[..]
        ).unwrap()
    }
}

prop_compose! {
    pub fn ipv6_raw_ext_any()
        (
            next_header in any::<u8>(),
            len in any::<u8>()
        ) (
            result in ipv6_raw_ext_with(next_header, len)
    ) -> Ipv6RawExtHeader
    {
        result
    }
}

prop_compose! {
    pub fn ipv6_extensions_with(next_header: u8)
    (
        has_hop_by_hop_options in any::<bool>(),
        hop_by_hop_options in ipv6_raw_ext_any(),
        has_destination_options in any::<bool>(),
        destination_options in ipv6_raw_ext_any(),
        has_routing in any::<bool>(),
        routing in ipv6_raw_ext_any(),
        has_fragment in any::<bool>(),
        fragment in ipv6_fragment_any(),
        has_auth in any::<bool>(),
        auth in ip_auth_with(next_header),
        has_final_destination_options in any::<bool>(),
        final_destination_options in ipv6_raw_ext_any()
    ) -> Ipv6Extensions
    {
        let mut result = Ipv6Extensions {
            hop_by_hop_options: if has_hop_by_hop_options {
                Some(hop_by_hop_options)
            } else {
                None
            },
            destination_options: if has_destination_options {
                Some(destination_options)
            } else {
                None
            },
            routing: if has_routing {
                Some(
                    Ipv6RoutingExtensions{
                        routing,
                        final_destination_options: if has_final_destination_options {
                            Some(final_destination_options)
                        } else {
                            None
                        }
                    }
                )
            } else {
                None
            },
            fragment: if has_fragment {
                Some(fragment)
            } else {
                None
            },
            auth: if has_auth {
                Some(auth)
            } else {
                None
            },
        };
        result.set_next_headers(next_header);
        result
    }
}

prop_compose! {
    pub fn ipv6_extensions_any()
        (
            next_header in any::<u8>()
        ) (
            result in ipv6_extensions_with(next_header)
    ) -> Ipv6Extensions
    {
        result
    }
}

prop_compose! {
    pub fn ipv6_extensions_unknown()
        (
            next_header in any::<u8>().prop_filter(
                "next_header must be unknown",
                |v| !IPV6_KNOWN_NEXT_HEADERS.iter().any(|&x| v == &x)
            )
        ) (
            result in ipv6_extensions_with(next_header)
        ) -> Ipv6Extensions
    {
        result
    }
}

prop_compose! {
    pub fn ipv6_fragment_with(
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
    pub fn ipv6_fragment_any()
        (next_header in any::<u8>())
        (result in ipv6_fragment_with(next_header)
    ) -> Ipv6FragmentHeader
    {
        result
    }
}

prop_compose! {
    pub fn ip_auth_with(
        next_header: u8
    ) (
        next_header in proptest::strategy::Just(next_header),
        len in 1..0xffu8
    ) (
        next_header in proptest::strategy::Just(next_header),
        spi in any::<u32>(),
        sequence_number in any::<u32>(),
        icv in proptest::collection::vec(any::<u8>(), (len as usize)*4)
    ) -> IpAuthHeader {
        IpAuthHeader::new(
            next_header,
            spi,
            sequence_number,
            &icv
        ).unwrap()
    }
}

prop_compose! {
    pub fn ip_auth_any() (
        next_header in any::<u8>()
    ) (
        header in ip_auth_with(next_header)
    ) -> IpAuthHeader {
        header
    }
}

prop_compose! {
    pub fn udp_any()(
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
    pub fn tcp_any()
        (data_offset in TcpHeader::MIN_DATA_OFFSET..(TcpHeader::MAX_DATA_OFFSET + 1))
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
    prop_oneof![
        Just(IpNumber::IPV6_HEADER_HOP_BY_HOP),
        Just(IpNumber::ICMP),
        Just(IpNumber::IGMP),
        Just(IpNumber::GGP),
        Just(IpNumber::IPV4),
        Just(IpNumber::STREAM),
        Just(IpNumber::TCP),
        Just(IpNumber::CBT),
        Just(IpNumber::EGP),
        Just(IpNumber::IGP),
        Just(IpNumber::BBN_RCC_MON),
        Just(IpNumber::NVP_II),
        Just(IpNumber::PUP),
        Just(IpNumber::ARGUS),
        Just(IpNumber::EMCON),
        Just(IpNumber::XNET),
        Just(IpNumber::CHAOS),
        Just(IpNumber::UDP),
        Just(IpNumber::MUX),
        Just(IpNumber::DCN_MEAS),
        Just(IpNumber::HMP),
        Just(IpNumber::PRM),
        Just(IpNumber::XNS_IDP),
        Just(IpNumber::TRUNK1),
        Just(IpNumber::TRUNK2),
        Just(IpNumber::LEAF1),
        Just(IpNumber::LEAF2),
        Just(IpNumber::RDP),
        Just(IpNumber::IRTP),
        Just(IpNumber::ISO_TP4),
        Just(IpNumber::NET_BLT),
        Just(IpNumber::MFE_NSP),
        Just(IpNumber::MERIT_INP),
        Just(IpNumber::DCCP),
        Just(IpNumber::THIRD_PARTY_CONNECT_PROTOCOL),
        Just(IpNumber::IDPR),
        Just(IpNumber::XTP),
        Just(IpNumber::DDP),
        Just(IpNumber::IDPR_CMTP),
        Just(IpNumber::TP_PLUS_PLUS),
        Just(IpNumber::IL),
        Just(IpNumber::IPV6),
        Just(IpNumber::SDRP),
        Just(IpNumber::IPV6_ROUTE_HEADER),
        Just(IpNumber::IPV6_FRAGMENTATION_HEADER),
        Just(IpNumber::IDRP),
        Just(IpNumber::RSVP),
        Just(IpNumber::GRE),
        Just(IpNumber::DSR),
        Just(IpNumber::BNA),
        Just(IpNumber::ENCAPSULATING_SECURITY_PAYLOAD),
        Just(IpNumber::AUTHENTICATION_HEADER),
        Just(IpNumber::INLSP),
        Just(IpNumber::SWIPE),
        Just(IpNumber::NARP),
        Just(IpNumber::MOBILE),
        Just(IpNumber::TLSP),
        Just(IpNumber::SKIP),
        Just(IpNumber::IPV6_ICMP),
        Just(IpNumber::IPV6_NO_NEXT_HEADER),
        Just(IpNumber::IPV6_DESTINATION_OPTIONS),
        Just(IpNumber::ANY_HOST_INTERNAL_PROTOCOL),
        Just(IpNumber::CFTP),
        Just(IpNumber::ANY_LOCAL_NETWORK),
        Just(IpNumber::SAT_EXPAK),
        Just(IpNumber::KRYTOLAN),
        Just(IpNumber::RVD),
        Just(IpNumber::IPPC),
        Just(IpNumber::ANY_DISTRIBUTED_FILE_SYSTEM),
        Just(IpNumber::SAT_MON),
        Just(IpNumber::VISA),
        Just(IpNumber::IPCV),
        Just(IpNumber::CPNX),
        Just(IpNumber::CPHB),
        Just(IpNumber::WSN),
        Just(IpNumber::PVP),
        Just(IpNumber::BR_SAT_MON),
        Just(IpNumber::SUN_ND),
        Just(IpNumber::WB_MON),
        Just(IpNumber::WB_EXPAK),
        Just(IpNumber::ISO_IP),
        Just(IpNumber::VMTP),
        Just(IpNumber::SECURE_VMTP),
        Just(IpNumber::VINES),
        Just(IpNumber::TTP_OR_IPTM),
        Just(IpNumber::NSFNET_IGP),
        Just(IpNumber::DGP),
        Just(IpNumber::TCF),
        Just(IpNumber::EIGRP),
        Just(IpNumber::OSPFIGP),
        Just(IpNumber::SPRITE_RPC),
        Just(IpNumber::LARP),
        Just(IpNumber::MTP),
        Just(IpNumber::AX25),
        Just(IpNumber::IPIP),
        Just(IpNumber::MICP),
        Just(IpNumber::SCC_SP),
        Just(IpNumber::ETHER_IP),
        Just(IpNumber::ENCAP),
        Just(IpNumber::GMTP),
        Just(IpNumber::IFMP),
        Just(IpNumber::PNNI),
        Just(IpNumber::PIM),
        Just(IpNumber::ARIS),
        Just(IpNumber::SCPS),
        Just(IpNumber::QNX),
        Just(IpNumber::ACTIVE_NETWORKS),
        Just(IpNumber::IP_COMP),
        Just(IpNumber::SITRA_NETWORKS_PROTOCOL),
        Just(IpNumber::COMPAQ_PEER),
        Just(IpNumber::IPX_IN_IP),
        Just(IpNumber::VRRP),
        Just(IpNumber::PGM),
        Just(IpNumber::ANY_ZERO_HOP_PROTOCOL),
        Just(IpNumber::LAYER2_TUNNELING_PROTOCOL),
        Just(IpNumber::DDX),
        Just(IpNumber::IATP),
        Just(IpNumber::STP),
        Just(IpNumber::SRP),
        Just(IpNumber::UTI),
        Just(IpNumber::SIMPLE_MESSAGE_PROTOCOL),
        Just(IpNumber::SM),
        Just(IpNumber::PTP),
        Just(IpNumber::ISIS_OVER_IPV4),
        Just(IpNumber::FIRE),
        Just(IpNumber::CRTP),
        Just(IpNumber::CRUDP),
        Just(IpNumber::SSCOPMCE),
        Just(IpNumber::IPLT),
        Just(IpNumber::SPS),
        Just(IpNumber::PIPE),
        Just(IpNumber::SCTP),
        Just(IpNumber::FC),
        Just(IpNumber::RSVP_E2E_IGNORE),
        Just(IpNumber::MOBILITY_HEADER),
        Just(IpNumber::UDP_LITE),
        Just(IpNumber::MPLS_IN_IP),
        Just(IpNumber::MANET),
        Just(IpNumber::HIP),
        Just(IpNumber::SHIM6),
        Just(IpNumber::WESP),
        Just(IpNumber::ROHC),
        Just(IpNumber::EXPERIMENTAL_AND_TESTING_0),
        Just(IpNumber::EXPERIMENTAL_AND_TESTING_1),
    ]
}

prop_compose! {
    pub fn icmpv4_type_any()
        (
            bytes in any::<[u8;20]>(),
        ) -> Icmpv4Type
    {
        Icmpv4Header::from_slice(&bytes).unwrap().0.icmp_type
    }
}

prop_compose! {
    pub fn icmpv4_header_any()
        (
            bytes in any::<[u8;20]>(),
        ) -> Icmpv4Header
    {
        Icmpv4Header::from_slice(&bytes).unwrap().0
    }
}

prop_compose! {
    pub fn icmpv6_type_any()
        (
            bytes in any::<[u8;8]>(),
        ) -> Icmpv6Type
    {
        Icmpv6Header::from_slice(&bytes).unwrap().0.icmp_type
    }
}

prop_compose! {
    pub fn icmpv6_header_any()
        (
            bytes in any::<[u8;8]>(),
        ) -> Icmpv6Header
    {
        Icmpv6Header::from_slice(&bytes).unwrap().0
    }
}

pub fn err_layer_any() -> impl Strategy<Value = err::Layer> {
    use err::Layer::*;
    prop_oneof![
        Just(Ethernet2Header),
        Just(VlanHeader),
        Just(IpHeader),
        Just(Ipv4Header),
        Just(Ipv4Packet),
        Just(IpAuthHeader),
        Just(Ipv6Header),
        Just(Ipv6FragHeader),
        Just(Ipv6ExtHeader),
        Just(UdpHeader),
        Just(TcpHeader),
        Just(Icmpv4),
        Just(Icmpv6),
    ]
}
