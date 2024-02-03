use crate::*;

/// Error when slicing an packet from downwards (both
/// starting from ethernet or ip layer downwards).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SliceError {
    /// Length related errors (e.g. not enough data in slice).
    Len(err::LenError),
    /// Error when decoding starting at an IP header (v4 or v6).
    Ip(err::ip::HeaderError),
    /// Error when decoding an IPv4 header.
    Ipv4(err::ipv4::HeaderError),
    /// Error when decoding an IPv6 header.
    Ipv6(err::ipv6::HeaderError),
    /// Error when decoding an IPv4 extension header.
    Ipv4Exts(err::ip_auth::HeaderError),
    /// Error when decoding an IPv6 extension header.
    Ipv6Exts(err::ipv6_exts::HeaderError),
    /// Error when decoding a TCP header.
    Tcp(err::tcp::HeaderError),
}

impl core::fmt::Display for SliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SliceError::*;

        match self {
            Len(err) => err.fmt(f),
            Ip(err) => err.fmt(f),
            Ipv4(err) => err.fmt(f),
            Ipv6(err) => err.fmt(f),
            Ipv4Exts(err) => err.fmt(f),
            Ipv6Exts(err) => err.fmt(f),
            Tcp(err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for SliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SliceError::*;
        match self {
            Len(err) => Some(err),
            Ip(err) => Some(err),
            Ipv4(err) => Some(err),
            Ipv6(err) => Some(err),
            Ipv4Exts(err) => Some(err),
            Ipv6Exts(err) => Some(err),
            Tcp(err) => Some(err),
        }
    }
}

impl From<err::packet::EthSliceError> for SliceError {
    fn from(value: err::packet::EthSliceError) -> Self {
        use err::packet::EthSliceError as I;
        use SliceError as O;
        match value {
            I::Len(err) => O::Len(err),
            I::Ipv4(err) => O::Ipv4(err),
            I::Ipv6(err) => O::Ipv6(err),
            I::Ipv4Exts(err) => O::Ipv4Exts(err),
            I::Ipv6Exts(err) => O::Ipv6Exts(err),
            I::Tcp(err) => O::Tcp(err),
        }
    }
}

impl From<err::packet::IpSliceError> for SliceError {
    fn from(value: err::packet::IpSliceError) -> Self {
        use err::ip::HeadersError as X;
        use err::packet::IpSliceError as I;
        use SliceError as O;
        match value {
            I::Len(err) => O::Len(err),
            I::Ip(iperr) => match iperr {
                X::Ip(err) => O::Ip(err),
                X::Ipv4Ext(err) => O::Ipv4Exts(err),
                X::Ipv6Ext(err) => O::Ipv6Exts(err),
            },
            I::Tcp(err) => O::Tcp(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SliceError::*, *};
    use crate::{err::Layer, LenSource};
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
        assert_eq!(
            format!("Ipv4({:?})", err.clone()),
            format!("{:?}", Ipv4(err))
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = Ipv4(err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 });
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
            let err = err::ip::HeaderError::UnsupportedIpVersion { version_number: 1 };
            assert_eq!(
                format!("{}", err),
                format!("{}", err::packet::SliceError::Ip(err))
            );
        }

        // Ipv4Header
        {
            let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
            assert_eq!(format!("{}", err), format!("{}", Ipv4(err)));
        }

        // Ipv6Header
        {
            let err = err::ipv6::HeaderError::UnexpectedVersion { version_number: 1 };
            assert_eq!(format!("{}", err), format!("{}", Ipv6(err)));
        }

        // Ipv4ExtHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert_eq!(format!("{}", err), format!("{}", Ipv4Exts(err)));
        }

        // Ipv6ExtHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert_eq!(format!("{}", err), format!("{}", Ipv6Exts(err)));
        };

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

        // IpHeaders
        {
            let err = err::ip::HeaderError::UnsupportedIpVersion { version_number: 1 };
            assert!(Ip(err).source().is_some());
        }

        // Ipv4Header
        {
            let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
            assert!(Ipv4(err).source().is_some());
        }

        // Ipv6Header
        {
            let err = err::ipv6::HeaderError::UnexpectedVersion { version_number: 1 };
            assert!(Ipv6(err).source().is_some());
        }

        // Ipv4ExtHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            assert!(Ipv4Exts(err).source().is_some());
        }

        // Ipv6ExtHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            assert!(Ipv6Exts(err).source().is_some());
        };

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            assert!(Tcp(err).source().is_some());
        }
    }

    #[test]
    fn from_eth_slice_error() {
        use err::packet::EthSliceError as I;
        use SliceError as O;

        // Len
        {
            let err = err::LenError {
                required_len: 2,
                len: 1,
                len_source: LenSource::Slice,
                layer: Layer::TcpHeader,
                layer_start_offset: 3,
            };
            let actual: O = I::Len(err.clone()).into();
            assert_eq!(actual, O::Len(err));
        }

        // Ipv4
        {
            let err = err::ipv4::HeaderError::UnexpectedVersion { version_number: 1 };
            let actual: O = I::Ipv4(err.clone()).into();
            assert_eq!(actual, O::Ipv4(err));
        }

        // Ipv6
        {
            let err = err::ipv6::HeaderError::UnexpectedVersion { version_number: 1 };
            let actual: O = I::Ipv6(err.clone()).into();
            assert_eq!(actual, O::Ipv6(err));
        }

        // Ipv4ExtHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            let actual: O = I::Ipv4Exts(err.clone()).into();
            assert_eq!(actual, O::Ipv4Exts(err));
        }

        // Ipv6ExtHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            let actual: O = I::Ipv6Exts(err.clone()).into();
            assert_eq!(actual, O::Ipv6Exts(err));
        };

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            let actual: O = I::Tcp(err.clone()).into();
            assert_eq!(actual, O::Tcp(err));
        }
    }

    #[test]
    fn from_ip_slice_error() {
        use err::ip::HeadersError as X;
        use err::packet::IpSliceError as I;
        use SliceError as O;

        // Len
        {
            let err = err::LenError {
                required_len: 2,
                len: 1,
                len_source: LenSource::Slice,
                layer: Layer::TcpHeader,
                layer_start_offset: 3,
            };
            let actual: O = I::Len(err.clone()).into();
            assert_eq!(actual, O::Len(err));
        }

        // Ip
        {
            let err = err::ip::HeaderError::UnsupportedIpVersion { version_number: 1 };
            let actual: O = I::Ip(X::Ip(err.clone())).into();
            assert_eq!(actual, O::Ip(err));
        }

        // Ipv4ExtHeader
        {
            let err = err::ip_auth::HeaderError::ZeroPayloadLen;
            let actual: O = I::Ip(X::Ipv4Ext(err.clone())).into();
            assert_eq!(actual, O::Ipv4Exts(err));
        }

        // Ipv6ExtHeader
        {
            let err = err::ipv6_exts::HeaderError::HopByHopNotAtStart;
            let actual: O = I::Ip(X::Ipv6Ext(err.clone())).into();
            assert_eq!(actual, O::Ipv6Exts(err));
        };

        // TcpHeader
        {
            let err = err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 };
            let actual: O = I::Tcp(err.clone()).into();
            assert_eq!(actual, O::Tcp(err));
        }
    }
}
