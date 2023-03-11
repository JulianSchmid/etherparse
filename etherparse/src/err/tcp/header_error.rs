
/// Errors that can be encountered while decoding a TCP header.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderError {
    /// Error when the data_offset is so small that the data would
    /// start within the TCP header itself.
    DataOffsetTooSmall{
        data_offset: u8
    },
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderError::*;
        match self {
            DataOffsetTooSmall{ data_offset } => write!(
                f,
                "TCP Header Error: 'data offset' too small ({}). The 'data offset' must be at least 5 so the data is not overlapping with the TCP header itself.",
                data_offset
            ),
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
    use super::HeaderError::*;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!("DataOffsetTooSmall { data_offset: 1 }", format!("{:?}", DataOffsetTooSmall{ data_offset: 1 }));
    }

    #[test]
    fn clone_eq_hash() {
        let err = DataOffsetTooSmall{ data_offset: 1 };
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
            "TCP Header Error: 'data offset' too small (1). The 'data offset' must be at least 5 so the data is not overlapping with the TCP header itself.",
            format!("{}", DataOffsetTooSmall{ data_offset: 1 })
        );
    }

    #[test]
    fn source() {
        assert!(DataOffsetTooSmall{ data_offset: 0 }.source().is_none());
    }
}
