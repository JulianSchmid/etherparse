use crate::tcp_reassembly::*;

/// Result of reading from a [`crate::tcp_reassembly::TcpStream`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpRead<'a> {
    /// Contiguous bytes starting at the read position.
    Data(&'a [u8]),

    /// Bytes at the read position are missing and will never be delivered.
    ///
    /// Call [`crate::tcp_reassembly::TcpStream::consume_gap`] to continue
    /// with the bytes after the gap.
    Gap {
        /// Number of missing bytes, `None` if it is unknown because the
        /// sequence numbers jumped (see
        /// [`crate::tcp_reassembly::TcpStreamStatus::resyncs`]).
        len: Option<u64>,
    },

    /// Nothing is readable yet, but more bytes can still arrive.
    Pending,

    /// Everything was read and no more bytes can arrive.
    End(TcpStreamEnd),
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
            assert_ne!(TcpRead::Gap { len: Some(2) }, a);
            assert_ne!(TcpRead::Pending, a);
            assert_ne!(TcpRead::End(TcpStreamEnd::Fin), a);
        }

        // debug
        {
            assert_eq!("Data([1, 2])", format!("{:?}", TcpRead::Data(&[1, 2])));
            assert_eq!(
                "Gap { len: Some(2) }",
                format!("{:?}", TcpRead::Gap { len: Some(2) })
            );
            assert_eq!(
                "Gap { len: None }",
                format!("{:?}", TcpRead::Gap { len: None })
            );
            assert_eq!("Pending", format!("{:?}", TcpRead::Pending));
            assert_eq!("End(Fin)", format!("{:?}", TcpRead::End(TcpStreamEnd::Fin)));
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
