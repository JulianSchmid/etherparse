/// Error while creating a new [`crate::ArpPacket`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ArpNewError {
    /// Error if the given hardware address is longer than
    /// the maximum of 255 bytes/octets.
    HwAddrLenTooBig(usize),

    /// Error if the given protocol address is longer than
    /// the maximum of 255 bytes/octets.
    ProtocolAddrLenTooBig(usize),

    /// Hardware address lengths of sender and target differ.
    HwAddrLenInconsistent(usize, usize),

    /// Protocol address lengths of sender and target differ.
    ProtocolAddrLenInconsistent(usize, usize),
}

impl core::fmt::Display for ArpNewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ArpNewError::HwAddrLenTooBig(len) =>
                write!(f, "ARP Header Creation Error: Given hardware address has a length of {len} which is greater then the maximum of 255."),
            ArpNewError::ProtocolAddrLenTooBig(len) =>
                write!(f, "ARP Header Creation Error: Given protocol address has a length of {len} which is greater then the maximum of 255."),
            ArpNewError::HwAddrLenInconsistent(len_sender, len_target) =>
                write!(f, "ARP Header Creation Error: Given sender & target hardware addresses have differing lengths of {len_sender} & {len_target} (must be matching)."),
            ArpNewError::ProtocolAddrLenInconsistent(len_sender, len_target) =>
                write!(f, "ARP Header Creation Error: Given sender & target protocol addresses have differing lengths of {len_sender} & {len_target} (must be matching)."),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ArpNewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ArpNewError::*;
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!(
            "HwAddrLenTooBig(300)",
            format!("{:?}", HwAddrLenTooBig(300))
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = HwAddrLenTooBig(300);
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
        let tests = [
            (HwAddrLenTooBig(300), "ARP Header Creation Error: Given hardware address has a length of 300 which is greater then the maximum of 255."),
            (ProtocolAddrLenTooBig(301), "ARP Header Creation Error: Given protocol address has a length of 301 which is greater then the maximum of 255."),
            (HwAddrLenInconsistent(21, 22), "ARP Header Creation Error: Given sender & target hardware addresses have differing lengths of 21 & 22 (must be matching)."),
            (ProtocolAddrLenInconsistent(23, 24), "ARP Header Creation Error: Given sender & target protocol addresses have differing lengths of 23 & 24 (must be matching).")
        ];
        for test in tests {
            assert_eq!(format!("{}", test.0), test.1);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(HwAddrLenTooBig(300).source().is_none());
    }
}
