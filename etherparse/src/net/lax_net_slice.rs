use crate::*;

/// Slice containing laxly parsed the network headers & payloads (e.g. IPv4, IPv6, ARP).
///
/// Compared to the normal [`NetSlice`] this slice allows the
/// payload to be incomplete/cut off and also errors in the extension headers.
///
/// The main usecases for "laxly" parsed slices are are:
///
/// * Parsing packets that have been cut off. This is, for example, useful to
///   parse packets returned via ICMP as these usually only contain the start.
/// * Parsing packets where the `total_len` (for IPv4) or `payload_len` (for IPv6)
///   have not yet been set. This can be useful when parsing packets which have
///   been recorded in a layer before the length field was set (e.g. before the
///   operating system set the length fields).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaxNetSlice<'a> {
    /// The ipv4 header & the decoded extension headers.
    Ipv4(LaxIpv4Slice<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(LaxIpv6Slice<'a>),
}

impl<'a> LaxNetSlice<'a> {
    #[inline]
    pub fn ip_payload(&self) -> Option<&LaxIpPayloadSlice<'a>> {
        match self {
            LaxNetSlice::Ipv4(s) => Some(&s.payload),
            LaxNetSlice::Ipv6(s) => Some(&s.payload),
        }
    }
}

impl<'a> From<LaxIpSlice<'a>> for LaxNetSlice<'a> {
    #[inline]
    fn from(value: LaxIpSlice<'a>) -> LaxNetSlice<'a> {
        match value {
            LaxIpSlice::Ipv4(ipv4) => LaxNetSlice::Ipv4(ipv4),
            LaxIpSlice::Ipv6(ipv6) => LaxNetSlice::Ipv6(ipv6),
        }
    }
}
