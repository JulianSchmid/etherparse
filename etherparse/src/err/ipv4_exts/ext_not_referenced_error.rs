use crate::IpNumber;

/// Error when a header in [`Ipv4Extensions`] is never referenced even
/// though it is present in the [`Ipv4Extensions`].
/// 
/// This can occur when calculating the "next header" value or when
/// trying to write [`Ipv4Extensions`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ExtNotReferencedError {
    /// IpNumber of the header which was not referenced.
    pub missing_ext: IpNumber,
}

impl core::fmt::Display for ExtNotReferencedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f, 
            "IPv4 extensions '{:?}' is defined but is not referenced by the 'protocol' the IPv4 header.",
            self.missing_ext
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtNotReferencedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            format!(
                "ExtNotReferencedError {{ missing_ext: {:?} }}",
                IpNumber::AUTHENTICATION_HEADER
            ),
            format!("{:?}", ExtNotReferencedError{ missing_ext: IpNumber::AUTHENTICATION_HEADER })
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = ExtNotReferencedError{ missing_ext: IpNumber::AUTHENTICATION_HEADER };
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
            "IPv4 extensions '51 (AH - Authentication Header)' is defined but is not referenced by the 'protocol' the IPv4 header.",
            format!("{}", ExtNotReferencedError{ missing_ext: IpNumber::AUTHENTICATION_HEADER })
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(ExtNotReferencedError{ missing_ext: IpNumber::IPV6_FRAGMENTATION_HEADER }.source().is_none());
    }
}
