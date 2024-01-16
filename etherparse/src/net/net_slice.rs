use crate::*;

/// Deprecated use [`crate::NetSlice`] or [`crate::IpSlice`] instead.
#[cfg(feature = "std")]
#[deprecated(
    since = "0.14.0",
    note = "Deprecated use crate::NetSlice or crate::IpSlice instead"
)]
pub use NetSlice as InternetSlice;

/// Slice containing the network headers & payloads (e.g. IPv4, IPv6, ARP).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetSlice<'a> {
    /// The ipv4 header & the decoded extension headers.
    Ipv4(Ipv4Slice<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(Ipv6Slice<'a>),
}

impl<'a> NetSlice<'a> {
    #[inline]
    pub fn ip_payload(&self) -> Option<&IpPayloadSlice<'a>> {
        match self {
            NetSlice::Ipv4(s) => Some(&s.payload),
            NetSlice::Ipv6(s) => Some(&s.payload),
        }
    }
}

impl<'a> From<IpSlice<'a>> for NetSlice<'a> {
    #[inline]
    fn from(value: IpSlice<'a>) -> NetSlice<'a> {
        match value {
            IpSlice::Ipv4(ipv4) => NetSlice::Ipv4(ipv4),
            IpSlice::Ipv6(ipv6) => NetSlice::Ipv6(ipv6),
        }
    }
}
