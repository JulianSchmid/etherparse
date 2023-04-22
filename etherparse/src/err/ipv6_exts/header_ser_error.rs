use crate::IpNumber;

/// Errors in content of IPv6 header extensions that prevent serialization.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderSerError {
    /// Error when a hop-by-hop header is not referenced as the
    /// first header after the ipv6 header but as a later extension
    /// header.
    HopByHopNotAtStart,

    /// Error when a header in `Ipv6Extensions` is never written
    /// as it is never referenced by any of the other `next_header`
    /// fields or the initial ip number.
    ExtNotReferenced(IpNumber),

    /// Error when a header in `Ipv6Extensions` is referenced multiple
    /// times or is referenced and not defined.
    ExtNotDefinedReference(IpNumber),
}

impl core::fmt::Display for HeaderSerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeaderSerError::HopByHopNotAtStart =>
                write!(f, "IPv6 extensions hop-by-hop is not located directly after the IPv6 header (required by IPv6)."),
            HeaderSerError::ExtNotReferenced(ip_number) =>
                write!(f, "IPv6 extensions '{:?}' is defined but is not referenced by any of the 'next_header' of the other extension headers or the IPv6 header.", ip_number),
            HeaderSerError::ExtNotDefinedReference(ip_number) =>
                write!(f, "IPv6 extensions '{:?}' is referenced by the 'next_header' field of an extension headers or the IPv6 header but is not defined in the 'Ipv6Extensions'.", ip_number),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeaderSerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderSerError::*;
    use crate::*;
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!("HopByHopNotAtStart", format!("{:?}", HopByHopNotAtStart));
    }

    #[test]
    fn clone_eq_hash() {
        let err = HopByHopNotAtStart;
        assert_eq!(err, err.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            err.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            err.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn fmt() {
        assert_eq!(
            "IPv6 extensions hop-by-hop is not located directly after the IPv6 header (required by IPv6).",
            format!("{}", HopByHopNotAtStart)
        );
        assert_eq!(
            "IPv6 extensions '44 (IPv6-Frag - Fragment Header for IPv6)' is defined but is not referenced by any of the 'next_header' of the other extension headers or the IPv6 header.",
            format!("{}", ExtNotReferenced(IpNumber::IPV6_FRAGMENTATION_HEADER))
        );
        assert_eq!(
            "IPv6 extensions '44 (IPv6-Frag - Fragment Header for IPv6)' is referenced by the 'next_header' field of an extension headers or the IPv6 header but is not defined in the 'Ipv6Extensions'.",
            format!("{}", ExtNotDefinedReference(IpNumber::IPV6_FRAGMENTATION_HEADER))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(HopByHopNotAtStart.source().is_none());
        assert!(ExtNotReferenced(IpNumber::IPV6_FRAGMENTATION_HEADER).source().is_none());
        assert!(ExtNotDefinedReference(IpNumber::IPV6_FRAGMENTATION_HEADER).source().is_none());
    }
}
