/// One end of a TCP connection (IP address & port).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TcpEndpoint {
    /// IP address of the endpoint.
    pub ip: core::net::IpAddr,

    /// TCP port of the endpoint.
    pub port: u16,
}

impl TcpEndpoint {
    /// Creates a new endpoint.
    #[inline]
    pub const fn new(ip: core::net::IpAddr, port: u16) -> TcpEndpoint {
        TcpEndpoint { ip, port }
    }

    /// Creates an endpoint from IPv4 address bytes & a port.
    #[inline]
    pub const fn from_ipv4(ip: [u8; 4], port: u16) -> TcpEndpoint {
        TcpEndpoint {
            ip: core::net::IpAddr::V4(core::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            port,
        }
    }

    /// Creates an endpoint from IPv6 address bytes & a port.
    #[inline]
    pub const fn from_ipv6(ip: [u8; 16], port: u16) -> TcpEndpoint {
        TcpEndpoint {
            ip: core::net::IpAddr::V6(core::net::Ipv6Addr::new(
                u16::from_be_bytes([ip[0], ip[1]]),
                u16::from_be_bytes([ip[2], ip[3]]),
                u16::from_be_bytes([ip[4], ip[5]]),
                u16::from_be_bytes([ip[6], ip[7]]),
                u16::from_be_bytes([ip[8], ip[9]]),
                u16::from_be_bytes([ip[10], ip[11]]),
                u16::from_be_bytes([ip[12], ip[13]]),
                u16::from_be_bytes([ip[14], ip[15]]),
            )),
            port,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn debug_clone_eq_hash_ord() {
        let value = TcpEndpoint::from_ipv4([1, 2, 3, 4], 80);
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_ne!(value, TcpEndpoint::from_ipv4([1, 2, 3, 4], 81));
        assert_eq!(value.cmp(&value), core::cmp::Ordering::Equal);
        assert_eq!(value.partial_cmp(&value), Some(core::cmp::Ordering::Equal));

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            value.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            value.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn constructors() {
        assert_eq!(
            TcpEndpoint::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80),
            TcpEndpoint::from_ipv4([1, 2, 3, 4], 80)
        );
        assert_eq!(
            TcpEndpoint::from_ipv4([1, 2, 3, 4], 80).ip,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );

        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(
            TcpEndpoint::from_ipv6(v6, 443).ip,
            IpAddr::V6(Ipv6Addr::from(v6))
        );
        assert_eq!(TcpEndpoint::from_ipv6(v6, 443).port, 443);
    }

    #[test]
    fn ordering_is_by_ip_then_port() {
        let a = TcpEndpoint::from_ipv4([1, 2, 3, 4], 80);
        let b = TcpEndpoint::from_ipv4([1, 2, 3, 5], 1);
        let c = TcpEndpoint::from_ipv4([1, 2, 3, 4], 81);
        assert!(a < b);
        assert!(a < c);
        assert!(c < b);
    }
}
