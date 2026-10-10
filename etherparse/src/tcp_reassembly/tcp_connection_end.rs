/// Reason why a [`crate::tcp_reassembly::TcpConnection`] ended.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpConnectionEnd {
    /// Both endpoints sent a FIN, and both FINs were ACKed.
    Finished,
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
            let a = TcpConnectionEnd::Finished;
            let b = a;
            assert_eq!(a, b);
            assert_eq!(a.clone(), a);
        }

        // debug
        assert_eq!("Finished", format!("{:?}", TcpConnectionEnd::Finished));

        // hash
        {
            use std::collections::hash_map::DefaultHasher;
            let hash = |end: TcpConnectionEnd| {
                let mut hasher = DefaultHasher::new();
                end.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(
                hash(TcpConnectionEnd::Finished),
                hash(TcpConnectionEnd::Finished)
            );
        }
    }
}
