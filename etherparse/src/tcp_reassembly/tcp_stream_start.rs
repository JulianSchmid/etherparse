/// How the start of a [`crate::tcp_reassembly::TcpStream`] is known.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpStreamStart {
    /// The handshake showed the stream's first byte, which is at offset 0.
    Observed,

    /// The stream's SYN was not seen (yet), so the bytes before offset 0 are
    /// unknown.
    ///
    /// Offset 0 is the first byte captured, so it is most likely not the
    /// start of a message.
    MidStreamPickup,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::format;

    proptest! {
        #[test]
        fn derived_traits(start in tcp_stream_start_any()) {
            // copy & clone
            {
                let copy = start;
                assert_eq!(copy, start);
                assert_eq!(start.clone(), start);
            }

            // debug
            assert_eq!("Observed", format!("{:?}", TcpStreamStart::Observed));
            assert_eq!("MidStreamPickup", format!("{:?}", TcpStreamStart::MidStreamPickup));

            // hash
            {
                use std::collections::hash_map::DefaultHasher;
                let hash = |start: TcpStreamStart| {
                    let mut hasher = DefaultHasher::new();
                    start.hash(&mut hasher);
                    hasher.finish()
                };
                assert_eq!(hash(start), hash(start.clone()));
                assert_ne!(
                    hash(TcpStreamStart::Observed),
                    hash(TcpStreamStart::MidStreamPickup)
                );
            }
        }
    }
}
