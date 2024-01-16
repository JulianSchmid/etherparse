use crate::*;

/// Deprecated use [`crate::NetHeaders`] instead.
#[deprecated(since = "0.14.0", note = "`IpHeader` was renamed to `NetHeaders`")]
pub type IpHeader = NetHeaders;

/// Headers on the network layer (e.g. IP, ARP, ...).
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NetHeaders {
    /// IPv4 header & extension headers.
    Ipv4(Ipv4Header, Ipv4Extensions),
    /// IPv6 header & extension headers.
    Ipv6(Ipv6Header, Ipv6Extensions),
}

impl NetHeaders {
    /// Returns the size when the header & extension headers are serialized
    pub fn header_len(&self) -> usize {
        use crate::NetHeaders::*;
        match *self {
            Ipv4(ref header, ref extensions) => header.header_len() + extensions.header_len(),
            Ipv6(_, ref extensions) => Ipv6Header::LEN + extensions.header_len(),
        }
    }
}

impl From<IpHeaders> for NetHeaders {
    #[inline]
    fn from(value: IpHeaders) -> Self {
        match value {
            IpHeaders::Ipv4(h, e) => NetHeaders::Ipv4(h, e),
            IpHeaders::Ipv6(h, e) => NetHeaders::Ipv6(h, e),
        }
    }
}
