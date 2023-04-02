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

#[cfg(test)]
mod test {
    use super::LenSource::*;
    use alloc::format;
    use std::{
        cmp::{Ord, Ordering},
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!("Slice", format!("{:?}", Slice));
    }

    #[test]
    fn clone_eq_hash_ord() {
        let layer = Slice;
        assert_eq!(layer, layer.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            layer.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            layer.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
        assert_eq!(Ordering::Equal, layer.cmp(&layer));
        assert_eq!(Some(Ordering::Equal), layer.partial_cmp(&layer));
    }
}
