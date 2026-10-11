/// Role of an endpoint in a TCP connection.
///
/// If the handshake was not captured, the roles are guessed (see
/// [`crate::tcp_reassembly::TcpConnection::roles_guessed`]).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum TcpRole {
    /// Endpoint that sent the SYN.
    Initiator,
    /// Endpoint that answered the SYN.
    Responder,
}

impl TcpRole {
    /// Returns the role of the other endpoint.
    pub const fn other(self) -> TcpRole {
        match self {
            TcpRole::Initiator => TcpRole::Responder,
            TcpRole::Responder => TcpRole::Initiator,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::format;

    #[test]
    fn derived_traits() {
        // copy & clone
        {
            let a = TcpRole::Initiator;
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // debug
        {
            assert_eq!("Initiator", format!("{:?}", TcpRole::Initiator));
            assert_eq!("Responder", format!("{:?}", TcpRole::Responder));
        }

        // ord & partial ord
        {
            use core::cmp::Ordering;
            assert_eq!(Ordering::Less, TcpRole::Initiator.cmp(&TcpRole::Responder));
            assert_eq!(
                Some(Ordering::Greater),
                TcpRole::Responder.partial_cmp(&TcpRole::Initiator)
            );
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |role: TcpRole| {
                let mut hasher = DefaultHasher::new();
                role.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(hash(TcpRole::Initiator), hash(TcpRole::Initiator));
            assert_ne!(hash(TcpRole::Initiator), hash(TcpRole::Responder));
        }
    }

    proptest! {
        #[test]
        fn other(role in tcp_role_any()) {
            assert_eq!(TcpRole::Responder, TcpRole::Initiator.other());
            assert_eq!(TcpRole::Initiator, TcpRole::Responder.other());
            assert_ne!(role, role.other());
            assert_eq!(role, role.other().other());
        }
    }
}
