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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{TcpHeader, UdpHeader};
    use alloc::{format, vec::Vec};

    #[test]
    fn debug_clone_eq() {
        // udp
        {
            let header: UdpHeader = Default::default();
            let raw = header.to_bytes();
            let u = UdpHeaderSlice::from_slice(&raw).unwrap();
            let slice = TransportSlice::Udp(u.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(format!("{:?}", slice), format!("Udp({:?})", u));
        }
        // tcp
        {
            let header: TcpHeader = Default::default();
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len() as usize);
                header.write(&mut buffer).unwrap();
                buffer
            };
            let t = TcpHeaderSlice::from_slice(&buffer).unwrap();
            let slice = TransportSlice::Tcp(t.clone());

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(format!("{:?}", slice), format!("Tcp({:?})", t));
        }
    }
}
