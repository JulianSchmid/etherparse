use crate::err::{ip_auth, ipv4, LenError};

/// Errors that can occur when slicing the IPv4 part of a packet.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SliceError {
    /// Length related errors (e.g. not enough data in slice).
    Len(LenError),

    /// Error while slicing the header.
    Header(ipv4::HeaderError),

    /// Error while slicing an ipv4 extension header.
    Extensions(ip_auth::HeaderError),
}

impl core::fmt::Display for SliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use SliceError::*;
        match self {
            Len(value) => value.fmt(f),
            Header(err) => err.fmt(f),
            Extensions(value) => value.fmt(f),
        }
    }
}

impl std::error::Error for SliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SliceError::*;
        match self {
            Len(err) => Some(err),
            Header(err) => Some(err),
            Extensions(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::HeaderError, SliceError::*, *};
    use crate::err::{Layer, LenError, LenSource};
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        let err = HeaderError::UnexpectedVersion { version_number: 6 };
        assert_eq!(
            format!("Header({:?})", err.clone()),
            format!("{:?}", Header(err))
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = Header(HeaderError::UnexpectedVersion { version_number: 6 });
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
        // len
        {
            let err = LenError {
                required_len: 1,
                layer: Layer::Ipv4Packet,
                len: 2,
                len_source: LenSource::Slice,
                layer_start_offset: 3,
            };
            assert_eq!(format!("{}", &err), format!("{}", Len(err)));
        }
        // header
        {
            let err = HeaderError::UnexpectedVersion { version_number: 6 };
            assert_eq!(format!("{}", &err), format!("{}", Header(err.clone())));
        }
        // extensions
        {
            let err = ip_auth::HeaderError::ZeroPayloadLen;
            assert_eq!(format!("{}", &err), format!("{}", Extensions(err.clone())));
        }
    }

    #[test]
    fn source() {
        assert!(Len(LenError {
            required_len: 1,
            layer: Layer::Ipv4Packet,
            len: 2,
            len_source: LenSource::Slice,
            layer_start_offset: 3
        })
        .source()
        .is_some());
        assert!(Header(HeaderError::UnexpectedVersion { version_number: 6 })
            .source()
            .is_some());
        assert!(Extensions(ip_auth::HeaderError::ZeroPayloadLen)
            .source()
            .is_some());
    }
}
