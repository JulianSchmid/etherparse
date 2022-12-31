/// Error when decoding the IPv6 header.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderError {
    /// Error when the IPv6 header version field is not equal to 6.
    UnexpectedVersion {
        /// The unexpected version number in the IPv6 header.
        version_number: u8,
    },
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderError::*;
        match self {
            UnexpectedVersion { version_number } => write!(f, "IPv6 Header Error: Encountered '{}' as IP version number in the IPv6 header (must be '6' in an IPv6 header).", version_number),
        }
    }
}

impl std::error::Error for HeaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
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
            "UnexpectedVersion { version_number: 1 }",
            format!("{:?}", UnexpectedVersion { version_number: 1 })
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = HeaderError::UnexpectedVersion { version_number: 6 };
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
            "IPv6 Header Error: Encountered '1' as IP version number in the IPv6 header (must be '6' in an IPv6 header).",
            format!("{}", UnexpectedVersion{ version_number: 1 })
        );
    }

    #[test]
    fn source() {
        let values = [UnexpectedVersion { version_number: 0 }];
        for v in values {
            assert!(v.source().is_none());
        }
    }
}
