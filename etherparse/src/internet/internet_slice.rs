use crate::*;

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

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr, Ipv4Addr};

    #[test]
    fn is_fragmenting_payload() {
        for fragment in [false, true] {
                
            // ipv4
            {
                let mut ipv4 = Ipv4Header::new(
                    0,
                    1,
                    2,
                    [3,4,5,6],
                    [7,8,9,10]
                );
                if fragment {
                    ipv4.fragments_offset = 123;
                }

                let data = ipv4.to_bytes().unwrap();
                let ipv4_slice = Ipv4HeaderSlice::from_slice(&data[..]).unwrap();
                assert_eq!(
                    fragment,
                    InternetSlice::Ipv4(
                        ipv4_slice,
                        Ipv4ExtensionsSlice { auth: None }
                    ).is_fragmenting_payload()
                );
            }

            // ipv6
            {
                let ipv6 = Ipv6Header{
                    traffic_class: 0,
                    flow_label: 1,
                    payload_length: 2,
                    next_header: ip_number::IPV6_FRAG,
                    hop_limit: 4,
                    source: [1;16],
                    destination: [2;16],
                };
                let ipv6_data = ipv6.to_bytes().unwrap();
                let ipv6_frag = Ipv6FragmentHeader{
                    next_header: ip_number::IGMP,
                    fragment_offset: 0,
                    more_fragments: fragment,
                    identification: 0,
                };
                let ipv6_frag_data = ipv6_frag.to_bytes().unwrap();
                assert_eq!(
                    fragment,
                    InternetSlice::Ipv6(
                        Ipv6HeaderSlice::from_slice(&ipv6_data).unwrap(),
                        Ipv6ExtensionsSlice::from_slice(ip_number::IPV6_FRAG, &ipv6_frag_data).unwrap().0
                    ).is_fragmenting_payload()
                );
            }
        }
    }

    #[test]
    fn source_addr() {
        // ipv4
        {
            let data = Ipv4Header::new(
                0,
                1,
                2,
                [3,4,5,6],
                [7,8,9,10]
            ).to_bytes().unwrap();
            let ipv4_slice = Ipv4HeaderSlice::from_slice(&data[..]).unwrap();
            assert_eq!(
                IpAddr::V4(Ipv4Addr::from([3,4,5,6])),
                InternetSlice::Ipv4(
                    ipv4_slice,
                    Ipv4ExtensionsSlice{ auth: None }
                ).source_addr()
            );
        }

        // ipv6
        {
            let data = Ipv6Header{
                traffic_class: 0,
                flow_label: 1,
                payload_length: 2,
                next_header: ip_number::IGMP,
                hop_limit: 4,
                source: [1;16],
                destination: [2;16],
            }.to_bytes().unwrap();
            assert_eq!(
                IpAddr::V6(Ipv6Addr::from([1;16])),
                InternetSlice::Ipv6(
                    Ipv6HeaderSlice::from_slice(&data).unwrap(),
                    Default::default()
                ).source_addr()
            );
        }
    }

    #[test]
    fn destination_addr() {
        // ipv4
        {
            let data = Ipv4Header::new(
                0,
                1,
                2,
                [3,4,5,6],
                [7,8,9,10]
            ).to_bytes().unwrap();
            let ipv4_slice = Ipv4HeaderSlice::from_slice(&data[..]).unwrap();
            assert_eq!(
                IpAddr::V4(Ipv4Addr::from([7,8,9,10])),
                InternetSlice::Ipv4(
                    ipv4_slice,
                    Ipv4ExtensionsSlice{ auth: None }
                ).destination_addr()
            );
        }

        // ipv6
        {
            let data = Ipv6Header{
                traffic_class: 0,
                flow_label: 1,
                payload_length: 2,
                next_header: ip_number::IGMP,
                hop_limit: 4,
                source: [1;16],
                destination: [2;16],
            }.to_bytes().unwrap();
            assert_eq!(
                IpAddr::V6(Ipv6Addr::from([2;16])),
                InternetSlice::Ipv6(
                    Ipv6HeaderSlice::from_slice(&data).unwrap(),
                    Default::default()
                ).destination_addr()
            );
        }
    }
}
