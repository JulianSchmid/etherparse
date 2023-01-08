use crate::*;

/// Error when slicing an packet from the IP layer downwards.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum IpSliceError {
    /// Length related errors (e.g. not enough data in slice).
    Len(err::LenError),
    /// Error when decoding an IP header (v4 or v6).
    IpHeader(err::ip::HeaderError),
    /// Error when decoding a IPv6 extension headers.
    Ipv6ExtsHeader(err::ipv6_exts::HeaderError),
    /// Error when decoding an IP authentification header.
    IpAuthHeader(err::ip_auth::HeaderError),
    /// Error when decoding a TCP header.
    TcpHeader(err::tcp::HeaderError),
}

impl std::fmt::Display for IpSliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IpSliceError::*;

        match self {
            Len(err) => err.fmt(f),
            IpHeader(err) => err.fmt(f),
            Ipv6ExtsHeader(err) => err.fmt(f),
            IpAuthHeader(err) => err.fmt(f),
            TcpHeader(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for IpSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IpSliceError::*;
        match self {
            Len(err) => Some(err),
            IpHeader(err) => Some(err),
            Ipv6ExtsHeader(err) => Some(err),
            TcpHeader(err) => Some(err),
            IpAuthHeader(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IpSliceError::*, *};
    use crate::err::{LenSource, Layer};
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        let err = err::ip::HeaderError::UnsupportedIpVersion{
            version_number: 1,
        };
        assert_eq!(
            format!("IpHeader({:?})", err.clone()),
            format!("{:?}", IpHeader(err))
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = IpHeader(err::ip::HeaderError::UnsupportedIpVersion{
            version_number: 1,
        });
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
        // Len
        {
            let err = err::LenError{
                required_len: 2,
                len: 1,
                len_source: LenSource::Slice,
                layer: Layer::TcpHeader,
                layer_start_offset: 3,
            };
            assert_eq!(format!("{}", err), format!("{}", Len(err)));
        }

        // IpHeader
        {
            let err = err::ip::HeaderError::UnsupportedIpVersion{
                version_number: 1,
            };
            assert_eq!(format!("{}", err), format!("{}", IpHeader(err)));
        }

        // Ipv6ExtsHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert_eq!(format!("{}", err), format!("{}", Ipv6ExtsHeader(err)));
        }
        
        // IpAuthHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert_eq!(format!("{}", err), format!("{}", IpAuthHeader(err)));
        }
        
        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall{
                data_offset: 1,
            };
            assert_eq!(format!("{}", err), format!("{}", TcpHeader(err)));
        }
    }

    #[test]
    fn source() {
        // Len
        {
            let err = err::LenError{
                required_len: 2,
                len: 1,
                len_source: LenSource::Slice,
                layer: Layer::TcpHeader,
                layer_start_offset: 3,
            };
            assert!(Len(err).source().is_some());
        }

        // IpHeader
        {
            let err = err::ip::HeaderError::UnsupportedIpVersion{
                version_number: 1,
            };
            assert!(IpHeader(err).source().is_some());
        }
        
        // Ipv6ExtsHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert!(Ipv6ExtsHeader(err).source().is_some());
        }
        
        // IpAuthHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert!(IpAuthHeader(err).source().is_some());
        }
        
        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall{
                data_offset: 1,
            };
            assert!(TcpHeader(err).source().is_some());
        }
    }
}
