/// Direction a TCP segment is travelling in, relative to the endpoint order
/// of a [`crate::tcp_reassembly::TcpConnectionId`].
///
/// A TCP connection consists of two independent payload byte streams, one per
/// direction.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TcpDirection {
    /// From [`crate::tcp_reassembly::TcpConnectionId::first`] to
    /// [`crate::tcp_reassembly::TcpConnectionId::second`].
    FirstToSecond,

    /// From [`crate::tcp_reassembly::TcpConnectionId::second`] to
    /// [`crate::tcp_reassembly::TcpConnectionId::first`].
    SecondToFirst,
}

impl TcpDirection {
    /// Returns the opposite direction.
    #[inline]
    pub const fn reverse(&self) -> TcpDirection {
        match self {
            TcpDirection::FirstToSecond => TcpDirection::SecondToFirst,
            TcpDirection::SecondToFirst => TcpDirection::FirstToSecond,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq_hash_ord() {
        let value = TcpDirection::FirstToSecond;
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());
        assert_ne!(value, TcpDirection::SecondToFirst);
        assert_eq!(value.cmp(&value), core::cmp::Ordering::Equal);
        assert_eq!(value.partial_cmp(&value), Some(core::cmp::Ordering::Equal));

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            value.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            value.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn reverse() {
        assert_eq!(
            TcpDirection::FirstToSecond.reverse(),
            TcpDirection::SecondToFirst
        );
        assert_eq!(
            TcpDirection::SecondToFirst.reverse(),
            TcpDirection::FirstToSecond
        );
        assert_eq!(
            TcpDirection::FirstToSecond.reverse().reverse(),
            TcpDirection::FirstToSecond
        );
    }
}
