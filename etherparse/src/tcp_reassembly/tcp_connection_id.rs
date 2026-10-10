/// Number that a [`crate::tcp_reassembly::TcpReassemblyPool`] assigns to
/// each connection.
///
/// The pool numbers its connections from 0 in the order they were created,
/// so a reconnect gets a different id than the connection it replaces.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TcpConnectionId(pub u64);

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::format;

    proptest! {
        #[test]
        fn derived_traits(
            a in tcp_connection_id_any(),
            b in tcp_connection_id_any(),
        ) {
            // copy & clone
            {
                let copy = a;
                assert_eq!(a, copy);
                assert_eq!(a.clone(), a);
            }

            // default
            {
                let actual: TcpConnectionId = Default::default();
                assert_eq!(TcpConnectionId(0), actual);
            }

            // debug
            assert_eq!(format!("TcpConnectionId({})", a.0), format!("{:?}", a));

            // ord & partial ord
            assert_eq!(a.0.cmp(&b.0), a.cmp(&b));
            assert_eq!(a.0.partial_cmp(&b.0), a.partial_cmp(&b));

            // hash
            {
                use std::collections::hash_map::DefaultHasher;
                let hash = |id: TcpConnectionId| {
                    let mut hasher = DefaultHasher::new();
                    id.hash(&mut hasher);
                    hasher.finish()
                };
                assert_eq!(hash(a), hash(a.clone()));
            }
        }
    }
}
