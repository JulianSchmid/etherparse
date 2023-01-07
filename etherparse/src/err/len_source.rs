/// Sources of length values that limit lower layers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum LenSource {
    /// Limiting length was the slice length (we don't know what determined
    /// that one originally).
    Slice,
    /// Length
    Ipv4HeaderTotalLen,
    /// Error occured in the IPv6 layer.
    Ipv6HeaderPayloadLen,
    /// Error occured while decoding an UDP header.
    UdpHeaderLen,
    /// Error occured while decoding a TCP header.
    TcpHeaderLen,
}
