/// Errors that can be encountered while decoding an IGMP header.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HeaderError {
    /// Error when the IGMP type byte does not match any of the message
    /// types defined in RFC 1112, RFC 2236 or RFC 9776
    /// (`0x11`, `0x12`, `0x16`, `0x17`, `0x22`).
    UnknownType { type_u8: u8 },
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderError::*;
        match self {
            UnknownType { type_u8 } => write!(
                f,
                "IGMP Header Error: Unknown IGMP message type {type_u8:#04x}. Expected one of 0x11 (Membership Query), 0x12 (IGMPv1 Membership Report), 0x16 (IGMPv2 Membership Report), 0x17 (IGMPv2 Leave Group) or 0x22 (IGMPv3 Membership Report)."
            ),
        }
    }
}

impl core::error::Error for HeaderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderError::*;
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            "UnknownType { type_u8: 255 }",
            format!("{:?}", UnknownType { type_u8: 0xff })
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = UnknownType { type_u8: 0xff };
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
            "IGMP Header Error: Unknown IGMP message type 0xff. Expected one of 0x11 (Membership Query), 0x12 (IGMPv1 Membership Report), 0x16 (IGMPv2 Membership Report), 0x17 (IGMPv2 Leave Group) or 0x22 (IGMPv3 Membership Report).",
            format!("{}", UnknownType { type_u8: 0xff })
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(UnknownType { type_u8: 0xff }.source().is_none());
    }
}
