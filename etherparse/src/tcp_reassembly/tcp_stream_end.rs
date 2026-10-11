/// Reason why no more bytes can be read from a
/// [`crate::tcp_reassembly::TcpStream`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpStreamEnd {
    /// The sender ended the stream with a FIN.
    Fin,

    /// The connection was reset before the read position reached a FIN
    /// (see [`crate::tcp_reassembly::TcpConnectionEnd::Reset`]).
    Reset,
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
            let a = TcpStreamEnd::Fin;
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
            assert_ne!(TcpStreamEnd::Reset, a);
        }

        // debug
        {
            assert_eq!("Fin", format!("{:?}", TcpStreamEnd::Fin));
            assert_eq!("Reset", format!("{:?}", TcpStreamEnd::Reset));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |end: TcpStreamEnd| {
                let mut hasher = DefaultHasher::new();
                end.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(hash(TcpStreamEnd::Fin), hash(TcpStreamEnd::Fin));
        }
    }
}
