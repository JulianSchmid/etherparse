/// Reason why a [`crate::tcp_reassembly::TcpReassemblyPool`] applied a
/// packet to no connection.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpIgnoreReason {
    /// The packet belongs to no known connection and does not start one.
    NoConnection,
}

#[cfg(test)]
mod test {
    use super::*;
    use core::hash::{Hash, Hasher};
    use std::format;

    #[test]
    fn derived_traits() {
        // copy & clone
        {
            let a = TcpIgnoreReason::NoConnection;
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // debug
        assert_eq!(
            "NoConnection",
            format!("{:?}", TcpIgnoreReason::NoConnection)
        );

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |reason: TcpIgnoreReason| {
                let mut hasher = DefaultHasher::new();
                reason.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(
                hash(TcpIgnoreReason::NoConnection),
                hash(TcpIgnoreReason::NoConnection)
            );
        }
    }
}
