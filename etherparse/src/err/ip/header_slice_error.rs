use super::HeaderError;
use crate::err::LenError;

/// Error when decoding an IP header from a slice.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderSliceError {
    /// Error when an length error is encountered (e.g. unexpected
    /// end of slice).
    Len(LenError),

    /// Error caused by the contents of the header.
    Content(HeaderError),
}

impl HeaderSliceError {
    /// Adds an offset value to all slice length related fields.
    #[inline]
    pub const fn add_slice_offset(self, offset: usize) -> Self {
        use HeaderSliceError::*;
        match self {
            Len(err) => Len(err.add_offset(offset)),
            Content(err) => Content(err),
        }
    }
}

impl core::fmt::Display for HeaderSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderSliceError::*;
        match self {
            Len(err) => err.fmt(f),
            Content(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for HeaderSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HeaderSliceError::*;
        match self {
            Len(err) => Some(err),
            Content(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderSliceError::*, *};
    use crate::err::{Layer, LenError, LenSource};
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn add_slice_offset() {
        use HeaderSliceError::*;
        assert_eq!(
            Len(LenError {
                required_len: 1,
                layer: Layer::Icmpv4,
                actual_len: 2,
                actual_len_source: LenSource::Slice,
                layer_start_offset: 3
            }).add_slice_offset(200),
            Len(LenError {
                required_len: 1,
                layer: Layer::Icmpv4,
                actual_len: 2,
                actual_len_source: LenSource::Slice,
                layer_start_offset: 203
            })
        );
        assert_eq!(
            Content(HeaderError::UnsupportedIpVersion { version_number: 1 }).add_slice_offset(200),
            Content(HeaderError::UnsupportedIpVersion { version_number: 1 })
        );
    }

    #[test]
    fn debug() {
        let err = HeaderError::UnsupportedIpVersion { version_number: 6 };
        assert_eq!(
            format!("Content({:?})", err.clone()),
            format!("{:?}", Content(err))
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = Content(HeaderError::UnsupportedIpVersion { version_number: 6 });
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
        {
            let err = LenError{
                required_len: 1,
                layer: Layer::Icmpv4,
                actual_len: 2,
                actual_len_source: LenSource::Slice,
                layer_start_offset: 3
            };
            assert_eq!(format!("{}", &err), format!("{}", Len(err)));
        }
        {
            let err = HeaderError::UnsupportedIpVersion { version_number: 6 };
            assert_eq!(format!("{}", &err), format!("{}", Content(err.clone())));
        }
    }

    #[test]
    fn source() {
        assert!(Len(LenError {
            required_len: 1,
            layer: Layer::Icmpv4,
            actual_len: 2,
            actual_len_source: LenSource::Slice,
            layer_start_offset: 3
        })
        .source()
        .is_some());
        assert!(
            Content(HeaderError::UnsupportedIpVersion { version_number: 6 })
                .source()
                .is_some()
        );
    }
}
