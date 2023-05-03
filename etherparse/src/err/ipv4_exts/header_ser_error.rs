use super::ExtNotReferencedError;

/// Errors in content of IPv4 header extensions that prevent serialization.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderSerError {
    /// Error when a header in `Ipv6Extensions` is never written
    /// as it is never referenced by any of the other `next_header`
    /// fields or the initial ip number.
    ExtNotReferenced(ExtNotReferencedError),
}

impl core::fmt::Display for HeaderSerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderSerError::*;
        match self {
            ExtNotReferenced(err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeaderSerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HeaderSerError::*;
        match self {
            ExtNotReferenced(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{*, HeaderSerError::*};
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
                "ExtNotReferenced({:?})",
                ExtNotReferencedError{
                    missing_ext: IpNumber::AUTHENTICATION_HEADER,
                }
            ),
            format!(
                "{:?}",
                ExtNotReferenced(ExtNotReferencedError{
                    missing_ext: IpNumber::AUTHENTICATION_HEADER
                })
            )
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = ExtNotReferenced(ExtNotReferencedError{
            missing_ext: IpNumber::AUTHENTICATION_HEADER,
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
        assert_eq!(
            "IPv4 extensions '51 (AH - Authentication Header)' is defined but is not referenced by the 'protocol' the IPv4 header.",
            format!("{}", ExtNotReferenced(ExtNotReferencedError{
                missing_ext: IpNumber::AUTHENTICATION_HEADER,
            }))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(ExtNotReferenced(ExtNotReferencedError{
            missing_ext: IpNumber::IPV6_FRAGMENTATION_HEADER
        }).source().is_some());
    }
}
