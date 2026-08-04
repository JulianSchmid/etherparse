/// Describes a range of reconstructed stream data in absolute stream offsets.
///
/// The offsets are "absolute stream offsets" as used by
/// [`crate::tcp_reassembly::TcpStreamReassemblyBuf`] (a 64 bit, non-wrapping
/// position within the stream), not raw 32 bit TCP sequence numbers.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct TcpStreamRange {
    /// Absolute offset of the first byte of the section.
    pub start: u64,
    /// Absolute offset one past the last byte of the section (offset + length).
    pub end: u64,
}

impl TcpStreamRange {
    /// Return if the value is contained within the section.
    fn is_value_connected(&self, value: u64) -> bool {
        self.start <= value && self.end >= value
    }

    /// Combine both sections if they overlap or are directly adjacent.
    pub fn merge(&self, other: TcpStreamRange) -> Option<TcpStreamRange> {
        if self.is_value_connected(other.start)
            || self.is_value_connected(other.end)
            || other.is_value_connected(self.start)
            || other.is_value_connected(self.end)
        {
            Some(TcpStreamRange {
                start: core::cmp::min(self.start, other.start),
                end: core::cmp::max(self.end, other.end),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_clone_eq() {
        let section = TcpStreamRange { start: 1, end: 2 };
        let _ = format!("{:?}", section);
        assert_eq!(section, section.clone());
        assert_eq!(section.cmp(&section), core::cmp::Ordering::Equal);
        assert_eq!(
            section.partial_cmp(&section),
            Some(core::cmp::Ordering::Equal)
        );

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            section.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            section.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn is_value_connected() {
        let s = TcpStreamRange { start: 5, end: 9 };
        assert_eq!(false, s.is_value_connected(3));
        assert_eq!(false, s.is_value_connected(4));
        assert!(s.is_value_connected(5));
        assert!(s.is_value_connected(6));
        assert!(s.is_value_connected(7));
        assert!(s.is_value_connected(8));
        assert!(s.is_value_connected(9));
        assert_eq!(false, s.is_value_connected(10));
        assert_eq!(false, s.is_value_connected(11));
    }

    #[test]
    fn merge() {
        let tests = [
            ((0, 1), (1, 2), Some((0, 2))),
            ((0, 1), (2, 3), None),
            ((3, 7), (1, 2), None),
            ((3, 7), (1, 3), Some((1, 7))),
            ((3, 7), (1, 4), Some((1, 7))),
            ((3, 7), (1, 5), Some((1, 7))),
            ((3, 7), (1, 6), Some((1, 7))),
            ((3, 7), (1, 7), Some((1, 7))),
            ((3, 7), (1, 8), Some((1, 8))),
            // large offsets (would overflow u16, valid for u64)
            (
                (0x00ff_ffff_ffff, 0x0100_0000_0000),
                (0x0100_0000_0000, 0x0100_0000_0001),
                Some((0x00ff_ffff_ffff, 0x0100_0000_0001)),
            ),
        ];
        for t in tests {
            let a = TcpStreamRange {
                start: t.0 .0,
                end: t.0 .1,
            };
            let b = TcpStreamRange {
                start: t.1 .0,
                end: t.1 .1,
            };
            let expected = t.2.map(|v| TcpStreamRange {
                start: v.0,
                end: v.1,
            });
            assert_eq!(a.merge(b), expected);
            assert_eq!(b.merge(a), expected);
        }
    }
}
