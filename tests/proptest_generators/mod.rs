use super::*;
use proptest::*;
use proptest::prelude::*;

prop_compose! {
    [pub] fn ethernet_2_with(ether_type: u16)(source in prop::array::uniform6(any::<u8>()),
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
    [pub] fn ethernet_2_any()
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
    [pub] fn ethernet_2_unknown()(source in prop::array::uniform6(any::<u8>()),
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
    [pub] fn vlan_single_unknown()(priority_code_point in prop::bits::u8::between(0,3),
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
    [pub] fn ipv4_with(protocol: u8)
                (ihl in 5u8..16,
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
                  total_length in any::<u16>(),
                  protocol in proptest::strategy::Just(protocol),
                  ihl in proptest::strategy::Just(ihl),
                  options in proptest::collection::vec(any::<u8>(), (ihl as usize - 5)*4))
                  -> (Ipv4Header, Vec<u8>)
    {
        (Ipv4Header {
            header_length: ihl,
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            total_length: total_length,
            identification: identification,
            dont_fragment: dont_fragment,
            more_fragments: more_fragments,
            fragments_offset: fragments_offset,
            time_to_live: ttl,
            protocol: protocol,
            header_checksum: header_checksum,
            source: source,
            destination: dest
        },
        options)
    }
}
prop_compose! {
    [pub] fn ipv4_any()
               (protocol in any::<u8>())
               (result in ipv4_with(protocol)) 
               -> (Ipv4Header, Vec<u8>)
    {
        result
    }
}

prop_compose! {
    [pub] fn ipv4_unknown()
                   (ihl in 5u8..16)
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
                    total_length in any::<u16>(),
                    protocol in any::<u8>().prop_filter("protocol must be unknown",
                               |v| (IpTrafficClass::Udp as u8 != *v)),
                    options in proptest::collection::vec(any::<u8>(), (ihl as usize - 5)*4),
                    ihl in proptest::strategy::Just(ihl))
                  -> (Ipv4Header, Vec<u8>)
    {
        (Ipv4Header {
            header_length: ihl,
            differentiated_services_code_point: dscp,
            explicit_congestion_notification: ecn,
            total_length: total_length,
            identification: identification,
            dont_fragment: dont_fragment,
            more_fragments: more_fragments,
            fragments_offset: fragments_offset,
            time_to_live: ttl,
            protocol: protocol,
            header_checksum: header_checksum,
            source: source,
            destination: dest
        }, options)
    }
}

prop_compose! {
    [pub] fn ipv6_with(next_header: u8)
                (source in prop::array::uniform16(any::<u8>()),
                 dest in prop::array::uniform16(any::<u8>()),
                 traffic_class in any::<u8>(),
                 flow_label in prop::bits::u32::between(0,20),
                 payload_length in any::<u16>(),
                 hop_limit in any::<u8>(),
                 next_header in proptest::strategy::Just(next_header))
                -> Ipv6Header
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
    [pub] fn ipv6_any()
               (next_header in any::<u8>())
               (result in ipv6_with(next_header)) 
               -> Ipv6Header
    {
        result
    }
}

static IPV6_KNOWN_NEXT_HEADERS: &'static [u8] = &[
    IpTrafficClass::Udp as u8,
    IpTrafficClass::Tcp as u8,
    IpTrafficClass::IPv6HeaderHopByHop as u8,
    IpTrafficClass::IPv6RouteHeader as u8,
    IpTrafficClass::IPv6FragmentationHeader as u8,
    IpTrafficClass::IPv6EncapSecurityPayload as u8,
    IpTrafficClass::IPv6AuthenticationHeader as u8,
    IpTrafficClass::IPv6DestinationOptions as u8
];

prop_compose! {
    [pub] fn ipv6_unknown()(source in prop::array::uniform16(any::<u8>()),
                      dest in prop::array::uniform16(any::<u8>()),
                      traffic_class in any::<u8>(),
                      flow_label in prop::bits::u32::between(0,20),
                      payload_length in any::<u16>(),
                      hop_limit in any::<u8>(),
                      next_header in any::<u8>().prop_filter("next_header must be unknown",
                               |v| !IPV6_KNOWN_NEXT_HEADERS.iter().any(|&x| v == &x)))
                  -> Ipv6Header
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
    [pub] fn ipv6_extension_with(next_header: u8,
                           len: u8)
                          (next_header in proptest::strategy::Just(next_header),
                           len in proptest::strategy::Just(len),
                           payload in proptest::collection::vec(any::<u8>(), (len as usize)*8 + 8))
                          -> Vec<u8>
    {
        let mut result = payload.clone();
        //insert next header & length
        result[0] = next_header;
        result[1] = len;
        result
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

static IPV6_EXTENSION_HEADER_ORDER: &'static [u8] = &[
    IpTrafficClass::IPv6HeaderHopByHop as u8,
    IpTrafficClass::IPv6DestinationOptions as u8,
    IpTrafficClass::IPv6RouteHeader as u8,
    IpTrafficClass::IPv6FragmentationHeader as u8,
    IpTrafficClass::IPv6AuthenticationHeader as u8,
    IpTrafficClass::IPv6EncapSecurityPayload as u8,
    IpTrafficClass::IPv6DestinationOptions as u8
];

prop_compose! {
    [pub] fn ipv6_extensions_unknown()
                              (last_next_header in any::<u8>().prop_filter("next_header must be unknown",
                               |v| !IPV6_KNOWN_NEXT_HEADERS.iter().any(|&x| v == &x)),
                               len0 in 0u8..5,//any::<u8>(),
                               len1 in 0u8..5,//any::<u8>(),
                               len2 in 0u8..5,//any::<u8>(),
                               //skip fragmenetation header (fixed size 0))
                               len4 in 0u8..5,//any::<u8>(),
                               len5 in 0u8..5,//any::<u8>(),
                               len6 in 0u8..5)//any::<u8>())
                              (last_next_header in proptest::strategy::Just(last_next_header),
                               hdr0 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len0),
                               hdr1 in ipv6_extension_with(IpTrafficClass::IPv6RouteHeader as u8, len1),
                               hdr2 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len2),
                               hdr3 in ipv6_extension_with(IpTrafficClass::IPv6FragmentationHeader as u8, 0),
                               hdr4 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len4),
                               hdr5 in ipv6_extension_with(IpTrafficClass::IPv6DestinationOptions as u8, len5),
                               hdr6 in ipv6_extension_with(last_next_header, len6),
                               order in proptest::sample::subsequence((0..IPV6_EXTENSION_HEADER_ORDER.len()).collect::<Vec<usize>>(), 1..IPV6_EXTENSION_HEADER_ORDER.len()))
                              -> Vec<(u8, Vec<u8>)>
    {
        let all_headers = vec![hdr0, hdr1, hdr2, hdr3, hdr4, hdr5, hdr6];

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

prop_compose! {
    [pub] fn udp_any()(source_port in any::<u16>(),
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
    [pub] fn tcp_any()(data_offset in TCP_MINIMUM_DATA_OFFSET..(TCP_MAXIMUM_DATA_OFFSET + 1))
                      (source_port in any::<u16>(),
                       destination_port in any::<u16>(),
                       sequence_number in any::<u32>(),
                       acknowledgment_number in any::<u32>(),
                       data_offset in proptest::strategy::Just(data_offset),
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
        TcpHeader {
            source_port: source_port,
            destination_port: destination_port,
            sequence_number: sequence_number,
            acknowledgment_number: acknowledgment_number,
            data_offset: data_offset,
            ns: ns,
            fin: fin,
            syn: syn,
            rst: rst,
            psh: psh,
            ack: ack,
            ece: ece,
            urg: urg,
            cwr: cwr,
            window_size: window_size,
            checksum: checksum,
            urgent_pointer: urgent_pointer,
            options: {
                let mut value: [u8;40] = [0;40];
                value[..options.len()].copy_from_slice(&options[..]);
                value
            }
        }
    }
}
