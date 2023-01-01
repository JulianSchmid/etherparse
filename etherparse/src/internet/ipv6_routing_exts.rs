use crate::*;

/// In case a route header is present it is also possible
/// to attach a "final destination" header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6RoutingExtensions {
    pub routing: Ipv6RawExtHeader,
    pub final_destination_options: Option<Ipv6RawExtHeader>,
}

impl Ipv6RoutingExtensions {
    /// Minimum length required for routing extension headers in bytes/octets.
    pub const MIN_LEN: usize = Ipv6RawExtHeader::MAX_LEN;

    /// Maximum summed up length of all extension headers in bytes/octets.
    pub const MAX_LEN: usize = Ipv6RawExtHeader::MAX_LEN * 2;
}
