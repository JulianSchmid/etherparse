/// Result of reading from a [`crate::tcp_reassembly::TcpStream`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpRead<'a> {
    /// Contiguous bytes starting at the read position.
    Data(&'a [u8]),

    /// Nothing is readable yet, but more bytes can still arrive.
    Pending,
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
            let a = TcpRead::Data(&[1, 2]);
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
            assert_ne!(TcpRead::Pending, a);
        }

        // debug
        {
            assert_eq!("Data([1, 2])", format!("{:?}", TcpRead::Data(&[1, 2])));
            assert_eq!("Pending", format!("{:?}", TcpRead::Pending));
        }

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |read: TcpRead| {
                let mut hasher = DefaultHasher::new();
                read.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(hash(TcpRead::Data(&[1, 2])), hash(TcpRead::Data(&[1, 2])));
        }
    }
}
