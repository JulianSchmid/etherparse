use crate::{Icmpv4Slice, Icmpv6Slice, TcpHeaderSlice, UdpHeaderSlice};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportSlice<'a> {
    /// A slice containing an Icmp4 header
    Icmpv4(Icmpv4Slice<'a>),
    /// A slice containing an Icmp6 header
    Icmpv6(Icmpv6Slice<'a>),
    /// A slice containing an UDP header.
    Udp(UdpHeaderSlice<'a>),
    /// A slice containing a TCP header.
    Tcp(TcpHeaderSlice<'a>),
    /// Unknonwn transport layer protocol. The value is the last parsed ip protocol number.
    Unknown(u8),
}
