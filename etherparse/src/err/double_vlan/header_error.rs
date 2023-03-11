/// Errors in an double vlan header encountered while decoding it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderError {
    /// Error when two vlan header were expected but the ether_type
    /// value of the first vlan header is not an vlan header type.
    NonVlanEtherType{
        /// Non-VLAN ether type encountered in the outer vlan
        /// header.
        unexpected_ether_type: u16
    }
}


impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderError::*;
        match self {
            NonVlanEtherType { unexpected_ether_type } => write!(f, "Double VLAN Error: Expected two VLAN headers but the outer VLAN header is followed by a non-VLAN header of ether type {}.", unexpected_ether_type),
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
    use super::{HeaderError::*};
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            "NonVlanEtherType { unexpected_ether_type: 1 }",
            format!("{:?}", NonVlanEtherType{ unexpected_ether_type: 1 })
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = NonVlanEtherType{ unexpected_ether_type: 1 };
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
            "Double VLAN Error: Expected two VLAN headers but the outer VLAN header is followed by a non-VLAN header of ether type 1.",
            format!("{}", NonVlanEtherType{ unexpected_ether_type: 1 })
        );
    }

    #[test]
    fn source() {
        assert!(NonVlanEtherType{ unexpected_ether_type: 1 }.source().is_none());
    }
}
