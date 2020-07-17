use super::super::*;

pub const IP_MAX_NUM_HEADER_EXTENSIONS: usize = 12;

/// Headers that can follow an ip header but are not transport related headers
/// (e.g. ipsec authentication headers or ipv6 extension headers like fragmentation).
///
/// Note: ESP & ExperimentalAndTesting headers are currently not supported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpExtensionHeader<'a> {
    Ipv6HopByHop(Ipv6ExtensionHeader<'a>),
    Ipv6Route(Ipv6ExtensionHeader<'a>),
    Ipv6Fragmentation(Ipv6FragmentHeader),
    //not supported: EncapsulatingSecurityPayload,
    AuthenticationHeader(IpAuthenticationHeader),
    IPv6DestinationOptions(Ipv6ExtensionHeader<'a>),
    Mobility(Ipv6ExtensionHeader<'a>),
    Hip(Ipv6ExtensionHeader<'a>),
    Shim6(Ipv6ExtensionHeader<'a>),
    //not supported ExperimentalAndTesting0 & ExperimentalAndTesting1
}

impl<'a> IpExtensionHeader<'a> {
    /// Returns the ip traffic class of the header.
    pub fn traffic_class(&self) -> IpTrafficClass {
        use IpExtensionHeader::*;
        match self {
            Ipv6HopByHop(_) => IpTrafficClass::IPv6HeaderHopByHop,
            Ipv6Route(_) => IpTrafficClass::IPv6RouteHeader,
            Ipv6Fragmentation(_)=> IpTrafficClass::IPv6FragmentationHeader,
            AuthenticationHeader(_)=> IpTrafficClass::AuthenticationHeader,
            IPv6DestinationOptions(_)=> IpTrafficClass::IPv6DestinationOptions,
            Mobility(_)=> IpTrafficClass::MobilityHeader,
            Hip(_)=> IpTrafficClass::Hip,
            Shim6(_)=> IpTrafficClass::Shim6,
        }
    }
}

/// Slices of headers that can follow an ip header but are not transport related headers
/// (e.g. ipsec authentication headers or ipv6 extension headers like fragmentation).
///
/// Note: ESP & ExperimentalAndTesting headers are currently not supported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpExtensionHeaderSlice<'a> {
    Ipv6HopByHop(Ipv6ExtensionHeaderSlice<'a>),
    Ipv6Route(Ipv6ExtensionHeaderSlice<'a>),
    Ipv6Fragmentation(Ipv6FragmentHeaderSlice<'a>),
    //not supported: EncapsulatingSecurityPayload,
    AuthenticationHeader(IpAuthenticationHeaderSlice<'a>),
    IPv6DestinationOptions(Ipv6ExtensionHeaderSlice<'a>),
    Mobility(Ipv6ExtensionHeaderSlice<'a>),
    Hip(Ipv6ExtensionHeaderSlice<'a>),
    Shim6(Ipv6ExtensionHeaderSlice<'a>),
    //not supported ExperimentalAndTesting0 & ExperimentalAndTesting1
}

impl<'a> IpExtensionHeaderSlice<'a> {
    /// Returns the ip traffic class of the header.
    pub fn traffic_class(&self) -> IpTrafficClass {
        use IpExtensionHeaderSlice::*;
        match self {
            Ipv6HopByHop(_) => IpTrafficClass::IPv6HeaderHopByHop,
            Ipv6Route(_) => IpTrafficClass::IPv6RouteHeader,
            Ipv6Fragmentation(_)=> IpTrafficClass::IPv6FragmentationHeader,
            AuthenticationHeader(_)=> IpTrafficClass::AuthenticationHeader,
            IPv6DestinationOptions(_)=> IpTrafficClass::IPv6DestinationOptions,
            Mobility(_)=> IpTrafficClass::MobilityHeader,
            Hip(_)=> IpTrafficClass::Hip,
            Shim6(_)=> IpTrafficClass::Shim6,
        }
    }
}
