extern crate etherparse;
use etherparse::*;

#[cfg(test)] #[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate proptest;
use proptest::prelude::*;

use std::io;

mod link;
mod internet;
mod transport;
mod packet_builder;
mod packet_decoder;
mod packet_slicer;

#[test]
fn test_debug_write() {
    //slice
    {
        let input = Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [10,11,12,13,14,15],
            ether_type: 0x0800
        };

        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        println!("{:?}", PacketSlice::<Ethernet2Header>::from_slice(&buffer));
    }
    //read error
    {
        use ReadError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            VlanDoubleTaggingUnexpectedOuterTpid(0),
            IpUnsupportedVersion(0),
            Ipv4UnexpectedVersion(0),
            Ipv4HeaderLengthBad(0),
            Ipv6UnexpectedVersion(0),
            Ipv6TooManyHeaderExtensions
        ].iter() {
            println!("{:?}", value);
        }
    }
    //write error
    {
        use ValueError::Ipv4OptionsLengthBad;
        use WriteError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            ValueError(Ipv4OptionsLengthBad(0))
        ].iter() {
            println!("{:?}", value);
        }
    }
    //value error
    {
        use ValueError::*;
        for value in [
            Ipv4OptionsLengthBad(0),
            Ipv4PayloadAndOptionsLengthTooLarge(0),
            Ipv6PayloadLengthTooLarge(0),
            UdpPayloadLengthTooLarge(0),
            U8TooLarge{value: 0, max: 0, field: ErrorField::Ipv4Ecn},
            U16TooLarge{value: 0, max: 0, field: ErrorField::Ipv4Ecn},
            U32TooLarge{value: 0, max: 0, field: ErrorField::Ipv4Ecn}
        ].iter() {
            println!("{:?}", value);
        }
    }
    //error field
    {
        use ErrorField::*;
        for value in [
            Ipv4HeaderLength,
            Ipv4Dscp,
            Ipv4Ecn,
            Ipv4FragmentsOffset,
            Ipv6FlowLabel,
            VlanTagPriorityCodePoint,
            VlanTagVlanId
        ].iter() {
            println!("{:?}", value);
        }
    }
}

#[test]
fn test_io_error_to_write_error() {
    assert_matches!(WriteError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
                    WriteError::IoError(_));
}

#[test]
fn test_io_error_to_read_error() {
    assert_matches!(ReadError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
                    ReadError::IoError(_));
}

prop_compose! {
    fn ethernet_2_with(ether_type: EtherType)(source in prop::array::uniform6(any::<u8>()),
                         dest in prop::array::uniform6(any::<u8>()),
                         ether_type in proptest::strategy::Just(ether_type))
                         -> Ethernet2Header
    {
        Ethernet2Header {
            source: source,
            destination: dest,
            ether_type: ether_type as u16
        }
    }
}

prop_compose! {
    fn ethernet_2_unknown()(source in prop::array::uniform6(any::<u8>()),
                           dest in prop::array::uniform6(any::<u8>()),
                           ether_type in any::<u16>().prop_filter("ether_type must be unknown",
                               |v| (EtherType::Ipv4 as u16 != *v)))
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
    fn ipv4_with(protocol: u8)(source in prop::array::uniform4(any::<u8>()),
                  dest in prop::array::uniform4(any::<u8>()),
                  ihl in 5u8..16,
                  dscp in prop::bits::u8::between(0,6),
                  ecn in prop::bits::u8::between(0,2),
                  identification in any::<u16>(),
                  ttl in any::<u8>(),
                  dont_fragment in any::<bool>(),
                  more_fragments in any::<bool>(),
                  fragments_offset in prop::bits::u16::between(0, 13),
                  header_checksum in any::<u16>(),
                  total_length in any::<u16>(),
                  protocol in proptest::strategy::Just(protocol))
                  -> Ipv4Header
    {
        Ipv4Header {
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
        }
    }
}

prop_compose! {
    fn ipv4_unknown()(ihl in 5u8..16)
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
                      options in proptest::collection::vec(any::<u8>(), (ihl as usize - 5)*4))
                  -> (Ipv4Header, Vec<u8>)
    {
        (Ipv4Header {
            header_length: ((options.len() / 4) + 5) as u8,
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

static IPV6_KNOWN_NEXT_HEADERS: &'static [u8] = &[
    IpTrafficClass::Udp as u8,
    IpTrafficClass::IPv6HeaderHopByHop as u8,
    IpTrafficClass::IPv6RouteHeader as u8,
    IpTrafficClass::IPv6FragmentationHeader as u8,
    IpTrafficClass::IPv6EncapSecurityPayload as u8,
    IpTrafficClass::IPv6AuthenticationHeader as u8,
    IpTrafficClass::IPv6DestinationOptions as u8
];

prop_compose! {
    fn ipv6_unknown()(source in prop::array::uniform16(any::<u8>()),
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
