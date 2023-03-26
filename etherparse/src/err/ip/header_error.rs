use crate::*;

/// Error when decoding the IP header part of a message.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderError {
    /// Error when the IP header version field is not equal to 4 or 6.
    UnsupportedIpVersion {
        /// The unexpected version number in the IP header.
        version_number: u8,
    },

    /// Error when the ipv4 internet header length is smaller then the header itself (5).
    Ipv4HeaderLengthSmallerThanHeader {
        /// The internet header length that was too small.
        ihl: u8,
    },

    /// Error when the total length of the ipv4 packet is smaller then the ipv4 header itself.
    Ipv4TotalLengthSmallerThanHeader {
        /// The total length value present in the header that was smaller then the header itself.
        total_length: u16,
        /// The minimum expected length based on the
        min_expected_length: u16,
    },

    /// Error in the IPv4 extension headers (only authentification header).
    Ipv4Ext(err::ip_auth::HeaderError),

    /// Error in the IPv6 extension headers.
    Ipv6Ext(err::ipv6_exts::HeaderError),
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderError::*;
        match self {
            UnsupportedIpVersion { version_number } => write!(f, "IP Header Error: Encountered '{}' as IP version number in the IP header (only '4' or '6' are supported).", version_number),
            Ipv4HeaderLengthSmallerThanHeader { ihl } => write!(f, "IPv4 Header Error: The 'internet header length' value '{}' present in the IPv4 header is smaller than the minimum size of an IPv4 header. The minimum allowed value is '5'.", ihl),
            Ipv4TotalLengthSmallerThanHeader { total_length, min_expected_length } => write!(f, "IPv4 Header Error: The 'total length' value ({} bytes/octets) present in the IPv4 header is smaller then the bytes/octet lenght of the header ({}) itself. 'total length' should describe the bytes/octets count of the IPv4 header and it's payload.", total_length, min_expected_length),
            Ipv4Ext(err) => err.fmt(f),
            Ipv6Ext(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for HeaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HeaderError::*;
        match self {
            UnsupportedIpVersion { version_number: _ } => None,
            Ipv4HeaderLengthSmallerThanHeader { ihl: _ } => None,
            Ipv4TotalLengthSmallerThanHeader {
                total_length: _,
                min_expected_length: _,
            } => None,
            Ipv4Ext(err) => Some(err),
            Ipv6Ext(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderError::*, *};
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            "UnsupportedIpVersion { version_number: 6 }",
            format!("{:?}", UnsupportedIpVersion { version_number: 6 })
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = HeaderError::UnsupportedIpVersion { version_number: 6 };
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
            "IP Header Error: Encountered '1' as IP version number in the IP header (only '4' or '6' are supported).",
            format!("{}", UnsupportedIpVersion{ version_number: 1 })
        );
        assert_eq!(
            "IPv4 Header Error: The 'internet header length' value '2' present in the IPv4 header is smaller than the minimum size of an IPv4 header. The minimum allowed value is '5'.",
            format!("{}", Ipv4HeaderLengthSmallerThanHeader{ ihl: 2 })
        );
        assert_eq!(
            "IPv4 Header Error: The 'total length' value (3 bytes/octets) present in the IPv4 header is smaller then the bytes/octet lenght of the header (4) itself. 'total length' should describe the bytes/octets count of the IPv4 header and it's payload.",
            format!("{}", Ipv4TotalLengthSmallerThanHeader{ total_length: 3, min_expected_length: 4 })
        );
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert_eq!(format!("{}", Ipv4Ext(err.clone())), format!("{}", err));
        }
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert_eq!(format!("{}", Ipv6Ext(err.clone())), format!("{}", err));
        }
    }

    #[test]
    fn source() {
        {
            let values = [
                UnsupportedIpVersion { version_number: 0 },
                Ipv4HeaderLengthSmallerThanHeader { ihl: 0 },
                Ipv4TotalLengthSmallerThanHeader {
                    total_length: 0,
                    min_expected_length: 0,
                },
            ];
            for v in values {
                assert!(v.source().is_none());
            }
        }
        {
            let values = [
                Ipv4Ext(err::ip_auth::HeaderError::ZeroPayloadLen),
                Ipv6Ext(err::ipv6_exts::HeaderError::HopByHopNotAtStart),
            ];
            for v in values {
                assert!(v.source().is_some());
            }
        }
    }
}
