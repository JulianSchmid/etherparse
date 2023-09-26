use crate::*;

/// Error when slicing an packet from the IP layer downwards.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum IpSliceError {
    /// Length related errors (e.g. not enough data in slice).
    Len(err::LenError),
    /// Error when decoding an IP header (v4 or v6).
    Ip(err::ip::HeadersError),
    /// Error when decoding a TCP header.
    Tcp(err::tcp::HeaderError),
}

impl core::fmt::Display for IpSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use IpSliceError::*;

        match self {
            Len(err) => err.fmt(f),
            Ip(err) => err.fmt(f),
            Tcp(err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IpSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IpSliceError::*;
        match self {
            Len(err) => Some(err),
            Ip(err) => Some(err),
            Tcp(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IpSliceError::*, *};
    use crate::err::{Layer, LenSource};
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        let err = err::ip::HeadersError::UnsupportedIpVersion { version_number: 1 };
        assert_eq!(format!("Ip({:?})", err.clone()), format!("{:?}", Ip(err)));
    }

    #[test]
    fn clone_eq_hash() {
        let err = Ip(err::ip::HeadersError::UnsupportedIpVersion { version_number: 1 });
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

        // IpHeader
        {
            let err = err::ip::HeadersError::UnsupportedIpVersion { version_number: 1 };
            assert_eq!(format!("{}", err), format!("{}", Ip(err)));
        }

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            assert_eq!(format!("{}", err), format!("{}", Tcp(err)));
        }
    }

    #[cfg(feature = "std")]
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

        // IpHeader
        {
            let err = err::ip::HeadersError::UnsupportedIpVersion { version_number: 1 };
            assert!(Ip(err).source().is_some());
        }

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            assert!(Tcp(err).source().is_some());
        }
    }
}
