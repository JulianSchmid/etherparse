/// IPv4 & IPv6 specific source & destination addresses identifying a TCP stream.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum TcpStreamIpId {
    /// IPv4 source & destination address.
    Ipv4 {
        source: [u8; 4],
        destination: [u8; 4],
    },
    /// IPv6 source & destination address.
    Ipv6 {
        source: [u8; 16],
        destination: [u8; 16],
    },
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq_hash_ord() {
        let value = TcpStreamIpId::Ipv4 {
            source: [1, 2, 3, 4],
            destination: [5, 6, 7, 8],
        };
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_eq!(value.cmp(&value), core::cmp::Ordering::Equal);
        assert_eq!(value.partial_cmp(&value), Some(core::cmp::Ordering::Equal));
        assert_ne!(
            value,
            TcpStreamIpId::Ipv6 {
                source: [0; 16],
                destination: [0; 16],
            }
        );

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
}
