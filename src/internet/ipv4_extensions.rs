use super::super::*;

/// IPv4 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
///
/// Currently not supported:
/// - Encapsulating Security Payload Header (ESP)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Ipv4Extensions {
    pub auth: Option<IpAuthenticationHeader>,
}

/// Slices of the IPv4 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
///
/// Currently not supported:
/// * Encapsulating Security Payload Header (ESP)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Ipv4ExtensionSlices<'a> {
    pub auth: Option<IpAuthenticationHeaderSlice<'a>>,
}
