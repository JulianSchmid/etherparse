
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Layer {
    /// Error occured in the ethernet 2 header.
    Ethernet2Header,
    /// Error occured in the vlan header.
    VlanHeader,
    /// Error occured in the IPv4 layer.
    Ipv4Header,
    /// Error occured verifying the total length of an IPv4 packet.
    Ipv4TotalLength,
    /// Error occured in the IP authentification header.
    IpAuthHeader,
    /// Error occured in the IPv6 layer.
    Ipv6Header,
}
