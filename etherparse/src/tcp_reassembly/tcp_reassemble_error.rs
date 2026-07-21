/// Error while adding a TCP segment to a [`crate::tcp_reassembly::TcpStreamReassemblyBuf`].
///
/// Note that "normal" occurrences during a TCP capture (retransmits,
/// re-ordered segments and duplicated/overlapping payloads) are **not**
/// treated as errors. They are silently handled by the reassembly. Only
/// conditions that require a decision by the caller (a segment landing far
/// outside the buffered window or a failed allocation) are reported here.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TcpReassembleError {
    /// Error if a segment references data that is more than `max_capacity`
    /// bytes ahead of the current read cursor (the start of the still
    /// buffered data).
    ///
    /// This guards against unbounded memory growth caused by big jumps in
    /// the sequence number (e.g. from lost segments, re-orderings or
    /// maliciously crafted packets).
    SegmentBeyondMaxWindow {
        /// Absolute stream offset (relative to the current read cursor)
        /// at which the received segment would have ended.
        end_offset: u64,

        /// Maximum number of bytes that can be buffered ahead of the read
        /// cursor.
        max_capacity: usize,
    },

    /// Error if not enough memory could be allocated to store the payload.
    AllocationFailure {
        /// Number of bytes that were attempted to be allocated.
        len: usize,
    },
}

impl core::fmt::Display for TcpReassembleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use TcpReassembleError::*;
        match self {
            SegmentBeyondMaxWindow { end_offset, max_capacity } => write!(f, "Received a TCP segment that ends {end_offset} bytes ahead of the read cursor which exceeds the maximum buffer capacity of {max_capacity} bytes."),
            AllocationFailure { len } => write!(f, "Failed to allocate {len} bytes of memory to reconstruct the TCP stream."),
        }
    }
}

impl core::error::Error for TcpReassembleError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::TcpReassembleError::*;
    use std::format;

    #[test]
    fn debug() {
        let err = AllocationFailure { len: 16 };
        let _ = format!("{err:?}");
    }

    #[test]
    fn clone_eq_hash_ord() {
        use core::cmp::Ordering;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let err = AllocationFailure { len: 16 };
        assert_eq!(err, err.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            err.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            err.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
        assert_eq!(Ordering::Equal, err.cmp(&err));
        assert_eq!(Some(Ordering::Equal), err.partial_cmp(&err));
    }

    #[test]
    fn fmt() {
        let tests = [
            (
                SegmentBeyondMaxWindow { end_offset: 5000, max_capacity: 4096 },
                "Received a TCP segment that ends 5000 bytes ahead of the read cursor which exceeds the maximum buffer capacity of 4096 bytes.",
            ),
            (
                AllocationFailure { len: 128 },
                "Failed to allocate 128 bytes of memory to reconstruct the TCP stream.",
            ),
        ];
        for test in tests {
            assert_eq!(format!("{}", test.0), test.1);
        }
    }

    #[test]
    fn source() {
        use core::error::Error;
        assert!(AllocationFailure { len: 0 }.source().is_none());
        assert!(SegmentBeyondMaxWindow {
            end_offset: 0,
            max_capacity: 0
        }
        .source()
        .is_none());
    }
}
