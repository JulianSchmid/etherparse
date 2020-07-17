use super::super::*;

/// Currently not supported:
/// - Encapsulating Security Payload Header (ESP)
/// - Host Identity Protocol (HIP)
/// - IP Mobility
/// - Site Multihoming by IPv6 Intermediation (SHIM6)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Ipv6Extensions {
    pub hop_by_hop_options: Option<Ipv6GenericExtensionHeader>,
    pub destination_options: Option<Ipv6GenericExtensionHeader>,
    pub routing: Option<Ipv6GenericExtensionHeader>,
    pub shim6: Option<Ipv6GenericExtensionHeader>,
    pub fragment: Option<Ipv6FragmentHeader>,
    pub auth: Option<IpAuthenticationHeader>,
    pub final_destination_options: Option<Ipv6GenericExtensionHeader>
}

/// Currently not supported:
/// - Encapsulating Security Payload Header (ESP)
/// - Host Identity Protocol (HIP)
/// - IP Mobility
/// - Site Multihoming by IPv6 Intermediation (SHIM6)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Ipv6ExtensionSlices<'a> {
    pub hop_by_hop_options: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    pub destination_options: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    pub routing: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    pub shim6: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    pub fragment: Option<Ipv6FragmentHeaderSlice<'a>>,
    pub auth: Option<IpAuthenticationHeaderSlice<'a>>,
    pub final_destination_options: Option<Ipv6GenericExtensionHeaderSlice<'a>>
}