use crate::*;

/// Payload of an IP packet.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct EtherPayloadSlice<'a> {
    /// Identifying content of the payload.
    pub ether_type: EtherType,

    /// Payload
    pub payload: &'a [u8],
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn debug() {
        let s = EtherPayloadSlice {
            ether_type: EtherType::IPV4,
            payload: &[],
        };
        assert_eq!(
            format!(
                "EtherPayloadSlice {{ ether_type: {:?}, payload: {:?} }}",
                s.ether_type, s.payload
            ),
            format!("{:?}", s)
        );
    }

    #[test]
    fn clone_eq_hash_ord() {
        let s = EtherPayloadSlice {
            ether_type: EtherType::IPV4,
            payload: &[],
        };
        assert_eq!(s.clone(), s);

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a_hash = {
            let mut hasher = DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        };
        let b_hash = {
            let mut hasher = DefaultHasher::new();
            s.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(a_hash, b_hash);

        use std::cmp::Ordering;
        assert_eq!(s.clone().cmp(&s), Ordering::Equal);
        assert_eq!(s.clone().partial_cmp(&s), Some(Ordering::Equal));
    }
}
