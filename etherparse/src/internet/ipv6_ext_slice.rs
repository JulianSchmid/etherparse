use crate::*;

/// Enum containing a slice of a supported ipv6 extension header.
///
/// This enum is used as item type when iterating over a list of extension headers
/// with an [Ipv6ExtensionSliceIter].
///
/// Note the following extension headers are missing from
/// this enum and currently not supported (list taken on 2021-07-17
/// from <https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml>):
///
/// * Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
/// * Mobility Header \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
/// * Host Identity Protocol \[[RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)\]
/// * Shim6 Protocol \[[RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)\]
/// * 253 Use for experimentation and testing \[[RFC3692](https://datatracker.ietf.org/doc/html/rfc3692)\]\[[RFC4727](https://datatracker.ietf.org/doc/html/rfc4727)\]
/// * 254 Use for experimentation and testing \[[RFC3692](https://datatracker.ietf.org/doc/html/rfc3692)\]\[[RFC4727](https://datatracker.ietf.org/doc/html/rfc4727)\]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ipv6ExtensionSlice<'a> {
    /// IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    HopByHop(Ipv6RawExtHeaderSlice<'a>),
    /// Routing Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\] \[[RFC5095](https://datatracker.ietf.org/doc/html/rfc5095)\]
    Routing(Ipv6RawExtHeaderSlice<'a>),
    /// Fragment Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    Fragment(Ipv6FragmentHeaderSlice<'a>),
    /// Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    DestinationOptions(Ipv6RawExtHeaderSlice<'a>),
    /// Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    Authentication(IpAuthHeaderSlice<'a>),
}
