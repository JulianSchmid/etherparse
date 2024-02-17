
/// Error if a checksum check in a packet fails.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChecksumError {
    /// IPv4 header checksum invalid.
    Ipv4HeaderChecksum,

    /// UDP checksum invalid.
    UdpChecksum,

    /// ICMPv4 checksum invalid.
    Icmpv4Checksum,

    /// ICMPv6 checksum invalid.
    Icmpv6Checksum,

    /// Error if the ICMPv6 checksum could not be verified
    /// as there was no IPv6 header present needed to
    /// calculate the checksum.
    Icmpv6MissingIpv6,
}


impl core::fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use ChecksumError::*;
        match self {
            Ipv4HeaderChecksum => write!(f, "IPv4Header checksum invalid"),
            UdpChecksum => write!(f, "UDP checksum invalid"),
            Icmpv4Checksum => write!(f, "ICMPv4 checksum invalid"),
            Icmpv6Checksum => write!(f, "ICMPv6 checksum invalid"),
            Icmpv6MissingIpv6 => write!(f, "ICMPv6 checksum can not be validated (IPv6 header missing)"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ChecksumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}


#[cfg(test)]
mod tests {
    use super::ChecksumError::*;
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            "Ipv4HeaderChecksum",
            format!("{:?}", Ipv4HeaderChecksum)
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = Ipv4HeaderChecksum;
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
        let values = [
            (Ipv4HeaderChecksum, "IPv4Header checksum invalid"),
            (UdpChecksum, "UDP checksum invalid"),
            (Icmpv4Checksum, "ICMPv4 checksum invalid"),
            (Icmpv6Checksum, "ICMPv6 checksum invalid"),
            (Icmpv6MissingIpv6, "ICMPv6 checksum can not be validated (IPv6 header missing)"),
        ];
        for (v, expected) in values {
            assert_eq!(format!("{}", v), expected);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        let values = [
            Ipv4HeaderChecksum,
            UdpChecksum,
            Icmpv4Checksum,
            Icmpv6Checksum,
            Icmpv6MissingIpv6,
        ];
        for v in values {
            assert!(v.source().is_none());
        }
    }
}
