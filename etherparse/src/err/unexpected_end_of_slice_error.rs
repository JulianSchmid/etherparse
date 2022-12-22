use crate::err::Layer;

/// Error when an unexpected end of a slice is reached even though more data was expected to be present.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnexpectedEndOfSliceError {
    /// Expected minimum length of the slice.
    pub expected_min_len: usize,

    /// Actual length of the slice.
    pub actual_len: usize,

    /// Layer in which the length was smaller then expected.
    pub layer: Layer,
}

impl UnexpectedEndOfSliceError {
    /// Adds an offset value to the `expected_min_len` & `actual_len` fields to the UnexpectedEndOfSliceError.
    #[inline]
    pub const fn add_offset(self, offset: usize) -> Self {
        UnexpectedEndOfSliceError {
            expected_min_len: self.expected_min_len + offset,
            actual_len: self.actual_len + offset,
            layer: self.layer,
        }
    }
}

impl core::fmt::Display for UnexpectedEndOfSliceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.layer.name_starts_with_vocal() {
            write!(
                f,
                "{}: Not enough data to decode. The length of the given slice ({} bytes/octets) is too small to contain an {}. The slice must at least contain {} bytes/octets.",
                self.layer.error_title(),
                self.actual_len,
                self.layer,
                self.expected_min_len
            )
        } else {
            write!(
                f,
                "{}: Not enough data to decode. The length of the given slice ({} bytes/octets) is too small to contain a {}. The slice must at least contain {} bytes/octets.",
                self.layer.error_title(),
                self.actual_len,
                self.layer,
                self.expected_min_len
            )
        }
    }
}

impl std::error::Error for UnexpectedEndOfSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::Layer;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn add_offset() {
        assert_eq!(
            UnexpectedEndOfSliceError {
                expected_min_len: 1,
                actual_len: 2,
                layer: Layer::Icmpv4,
            }
            .add_offset(100),
            UnexpectedEndOfSliceError {
                expected_min_len: 101,
                actual_len: 102,
                layer: Layer::Icmpv4,
            }
        );
    }

    #[test]
    fn debug() {
        assert_eq!(
            format!("{:?}", UnexpectedEndOfSliceError{ expected_min_len: 2, actual_len: 1, layer: Layer::Ipv4Header }),
            format!(
                "UnexpectedEndOfSliceError {{ expected_min_len: {:?}, actual_len: {:?}, layer: {:?} }}",
                2, 1, Layer::Ipv4Header
            ),
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = UnexpectedEndOfSliceError {
            expected_min_len: 0,
            actual_len: 0,
            layer: Layer::Ipv4Header,
        };
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
        // name starting with a vocal
        assert_eq!(
            format!(
                "{}: Not enough data to decode. The length of the given slice (1 bytes/octets) is too small to contain an {}. The slice must at least contain 2 bytes/octets.",
                Layer::Ipv4Header.error_title(),
                Layer::Ipv4Header,
            ),
            format!(
                "{}",
                UnexpectedEndOfSliceError{ expected_min_len: 2, actual_len: 1, layer: Layer::Ipv4Header }
            )
        );

        // name not starting with a vocal
        assert_eq!(
            format!(
                "{}: Not enough data to decode. The length of the given slice (1 bytes/octets) is too small to contain a {}. The slice must at least contain 2 bytes/octets.",
                Layer::VlanHeader.error_title(),
                Layer::VlanHeader
            ),
            format!(
                "{}",
                UnexpectedEndOfSliceError{ expected_min_len: 2, actual_len: 1, layer: Layer::VlanHeader }
            )
        );
    }

    #[test]
    fn source() {
        assert!(UnexpectedEndOfSliceError {
            expected_min_len: 0,
            actual_len: 0,
            layer: Layer::Ipv4Header
        }
        .source()
        .is_none());
    }
}
