use crate::*;

/// Error when slicing an packet from the ethernet layer downwards.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum EthSliceError {
    /// Length related errors (e.g. not enough data in slice).
    Len(err::LenError),
    /// Error when decoding an IPv4 header.
    Ipv4Header(err::ipv4::HeaderError),
    /// Error when decoding an IPv6 header.
    Ipv6Header(err::ipv6::HeaderError),
    /// Error when decoding an IPv4 extension header.
    Ipv4ExtHeader(err::ip_auth::HeaderError),
    /// Error when decoding an IPv6 extension header.
    Ipv6ExtHeader(err::ipv6_exts::HeaderError),
    /// Error when decoding a TCP header.
    TcpHeader(err::tcp::HeaderError),
}

impl std::fmt::Display for EthSliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use EthSliceError::*;

        match self {
            Len(err) => err.fmt(f),
            Ipv4Header(err) => err.fmt(f),
            Ipv6Header(err) => err.fmt(f),
            Ipv4ExtHeader(err) => err.fmt(f),
            Ipv6ExtHeader(err) => err.fmt(f),
            TcpHeader(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for EthSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use EthSliceError::*;
        match self {
            Len(err) => Some(err),
            Ipv4Header(err) => Some(err),
            Ipv6Header(err) => Some(err),
            Ipv4ExtHeader(err) => Some(err),
            Ipv6ExtHeader(err) => Some(err),
            TcpHeader(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EthSliceError::*, *};
    use crate::err::{Layer, LenSource};
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
        assert_eq!(
            format!("Ipv4Header({:?})", err.clone()),
            format!("{:?}", Ipv4Header(err))
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = Ipv4Header(err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 });
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
            let err = err::LenError {
                required_len: 2,
                len: 1,
                len_source: LenSource::Slice,
                layer: Layer::TcpHeader,
                layer_start_offset: 3,
            };
            assert_eq!(format!("{}", err), format!("{}", Len(err)));
        }

        // Ipv4Header
        {
            let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
            assert_eq!(format!("{}", err), format!("{}", Ipv4Header(err)));
        }

        // Ipv6Header
        {
            let err = err::ipv6::HeaderError::UnexpectedVersion { version_number: 1 };
            assert_eq!(format!("{}", err), format!("{}", Ipv6Header(err)));
        }

        // Ipv4ExtHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert_eq!(format!("{}", err), format!("{}", Ipv4ExtHeader(err)));
        }

        // Ipv6ExtHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert_eq!(format!("{}", err), format!("{}", Ipv6ExtHeader(err)));
        };

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            assert_eq!(format!("{}", err), format!("{}", TcpHeader(err)));
        }
    }

    #[test]
    fn source() {
        // Len
        {
            let err = err::LenError {
                required_len: 2,
                len: 1,
                len_source: LenSource::Slice,
                layer: Layer::TcpHeader,
                layer_start_offset: 3,
            };
            assert!(Len(err).source().is_some());
        }

        // Ipv4Header
        {
            let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
            assert!(Ipv4Header(err).source().is_some());
        }

        // Ipv6Header
        {
            let err = err::ipv6::HeaderError::UnexpectedVersion { version_number: 1 };
            assert!(Ipv6Header(err).source().is_some());
        }

        // Ipv4ExtHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert!(Ipv4ExtHeader(err).source().is_some());
        }

        // Ipv6ExtHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert!(Ipv6ExtHeader(err).source().is_some());
        };

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            assert!(TcpHeader(err).source().is_some());
        }
    }
}
