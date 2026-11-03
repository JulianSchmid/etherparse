use crate::*;

/// Iterates over all TCP options (known & unknown kinds) as zero-copy
/// [`TcpOptionSlice`]s.
///
/// Unknown kinds are skipped using their length octet (the same way
/// operating system TCP stacks process options), so options following an
/// unknown kind are still returned. Iteration ends at the
/// `End of Option List` option or after the first error (missing or
/// invalid length octet or truncated option), as the start of the next
/// option can no longer be determined.
///
/// ```
/// use etherparse::{tcp_option::*, TcpOptionElement, TcpOptionsRawIterator};
///
/// let options = [
///     KIND_MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4,
///     KIND_FAST_OPEN_COOKIE, 6, 1, 2, 3, 4,
///     KIND_WINDOW_SCALE, 3, 7,
///     KIND_END,
/// ];
/// let kinds: Vec<u8> = TcpOptionsRawIterator::from_slice(&options)
///     .map(|o| o.unwrap().kind())
///     .collect();
/// assert_eq!(kinds, [KIND_MAXIMUM_SEGMENT_SIZE, KIND_FAST_OPEN_COOKIE, KIND_WINDOW_SCALE]);
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct TcpOptionsRawIterator<'a> {
    options: &'a [u8],
}

impl<'a> TcpOptionsRawIterator<'a> {
    /// Creates an iterator from a slice containing encoded tcp options.
    #[inline]
    pub fn from_slice(options: &'a [u8]) -> TcpOptionsRawIterator<'a> {
        TcpOptionsRawIterator { options }
    }

    /// Returns the non processed part of the options slice.
    #[inline]
    pub fn rest(&self) -> &'a [u8] {
        self.options
    }
}

impl<'a> Iterator for TcpOptionsRawIterator<'a> {
    type Item = Result<TcpOptionSlice<'a>, TcpOptionReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.options.is_empty() {
            return None;
        }
        match TcpOptionSlice::from_slice(self.options) {
            Ok((option, _)) if option.kind() == tcp_option::KIND_END => {
                self.options = &self.options[self.options.len()..];
                None
            }
            Ok((option, rest)) => {
                self.options = rest;
                Some(Ok(option))
            }
            Err(err) => {
                self.options = &self.options[self.options.len()..];
                Some(Err(err))
            }
        }
    }
}

impl core::iter::FusedIterator for TcpOptionsRawIterator<'_> {}

impl core::fmt::Debug for TcpOptionsRawIterator<'_> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        fmt.debug_list().entries(self.clone()).finish()
    }
}

#[cfg(test)]
mod test {
    use crate::{tcp_option::*, *};
    use alloc::{format, vec::Vec};

    fn collect(options: &[u8]) -> Vec<Result<(u8, &[u8]), TcpOptionReadError>> {
        TcpOptionsRawIterator::from_slice(options)
            .map(|r| r.map(|o| (o.kind(), o.data())))
            .collect()
    }

    #[test]
    #[rustfmt::skip]
    fn next_known_and_unknown() {
        let options = [
            KIND_MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4,
            KIND_FAST_OPEN_COOKIE, 6, 1, 2, 3, 4,
            KIND_NOOP,
            KIND_WINDOW_SCALE, 3, 7,
            KIND_MULTIPATH, 4, 0x00, 0x81,
            99, 2,
            KIND_SELECTIVE_ACK_PERMITTED, 2,
        ];
        assert_eq!(
            collect(&options),
            [
                Ok((KIND_MAXIMUM_SEGMENT_SIZE, &[0x05, 0xb4][..])),
                Ok((KIND_FAST_OPEN_COOKIE, &[1, 2, 3, 4][..])),
                Ok((KIND_NOOP, &[][..])),
                Ok((KIND_WINDOW_SCALE, &[7][..])),
                Ok((KIND_MULTIPATH, &[0x00, 0x81][..])),
                Ok((99, &[][..])),
                Ok((KIND_SELECTIVE_ACK_PERMITTED, &[][..])),
            ]
        );
    }

    #[test]
    fn next_stops_at_end() {
        let mut it = TcpOptionsRawIterator::from_slice(&[KIND_NOOP, KIND_END, KIND_NOOP]);
        assert_eq!(KIND_NOOP, it.next().unwrap().unwrap().kind());
        assert_eq!(None, it.next());
        assert!(it.rest().is_empty());
        assert_eq!(None, it.next());
    }

    #[test]
    fn next_empty() {
        assert!(collect(&[]).is_empty());
    }

    #[test]
    fn next_errors_stop_iteration() {
        use TcpOptionReadError::*;
        assert_eq!(
            collect(&[KIND_NOOP, 99, 0, KIND_NOOP]),
            [
                Ok((KIND_NOOP, &[][..])),
                Err(UnexpectedSize {
                    option_id: 99,
                    size: 0
                }),
            ]
        );
        assert_eq!(
            collect(&[KIND_NOOP, KIND_MULTIPATH]),
            [
                Ok((KIND_NOOP, &[][..])),
                Err(UnexpectedEndOfSlice {
                    option_id: KIND_MULTIPATH,
                    expected_len: 2,
                    actual_len: 1
                }),
            ]
        );
        let mut it = TcpOptionsRawIterator::from_slice(&[KIND_FAST_OPEN_COOKIE, 10, 1, 2]);
        assert_eq!(
            Some(Err(UnexpectedEndOfSlice {
                option_id: KIND_FAST_OPEN_COOKIE,
                expected_len: 10,
                actual_len: 4
            })),
            it.next()
        );
        assert!(it.rest().is_empty());
        assert_eq!(None, it.next());
    }

    #[test]
    fn known_kind_with_unexpected_size_is_returned_raw() {
        let mut it = TcpOptionsRawIterator::from_slice(&[
            KIND_MAXIMUM_SEGMENT_SIZE,
            3,
            0,
            KIND_WINDOW_SCALE,
            3,
            7,
        ]);
        let mss = it.next().unwrap().unwrap();
        assert_eq!(
            Err(TcpOptionReadError::UnexpectedSize {
                option_id: KIND_MAXIMUM_SEGMENT_SIZE,
                size: 3
            }),
            mss.to_element()
        );
        assert_eq!(
            Ok(Some(TcpOptionElement::WindowScale(7))),
            it.next().unwrap().unwrap().to_element()
        );
    }

    #[test]
    fn from_slice_and_rest() {
        let buffer = [KIND_NOOP, KIND_NOOP, KIND_MAXIMUM_SEGMENT_SIZE, 4];
        let mut it = TcpOptionsRawIterator::from_slice(&buffer);
        assert_eq!(it.rest(), &buffer[..]);
        it.next();
        assert_eq!(it.rest(), &buffer[1..]);
    }

    #[test]
    fn debug_clone_eq() {
        let it = TcpOptionsRawIterator::from_slice(&[KIND_NOOP, 99, 0]);
        assert_eq!(it, it.clone());
        assert_eq!(
            "[Ok(TcpOptionSlice { slice: [1] }), Err(UnexpectedSize { option_id: 99, size: 0 })]",
            format!("{:?}", it)
        );
    }
}
