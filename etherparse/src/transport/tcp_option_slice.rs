use crate::*;

/// Zero-copy view of a single (known or unknown) TCP option.
///
/// Unlike [`TcpOptionElement`] this can represent every option kind, as
/// the content of options that etherparse does not decode is exposed as
/// a raw byte slice via [`TcpOptionSlice::data`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TcpOptionSlice<'a> {
    /// Complete option including the kind & (if present) length octets.
    slice: &'a [u8],
}

impl<'a> TcpOptionSlice<'a> {
    /// Reads the first option in `slice` and returns it together with the
    /// remaining unprocessed bytes.
    ///
    /// `End of Option List` & `No-Operation` options are one byte long, all
    /// other kinds (including unknown ones) are expected to be followed by
    /// a length octet that includes the kind & length octets (RFC 9293
    /// section 3.1).
    ///
    /// ```
    /// use etherparse::{tcp_option, TcpOptionSlice};
    ///
    /// let (option, rest) = TcpOptionSlice::from_slice(&[
    ///     tcp_option::KIND_FAST_OPEN_COOKIE, 6, 1, 2, 3, 4,
    ///     tcp_option::KIND_NOOP,
    /// ]).unwrap();
    /// assert_eq!(tcp_option::KIND_FAST_OPEN_COOKIE, option.kind());
    /// assert_eq!(6, option.len());
    /// assert_eq!(&[1, 2, 3, 4], option.data());
    /// assert_eq!(&[tcp_option::KIND_NOOP], rest);
    /// ```
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<(TcpOptionSlice<'a>, &'a [u8]), TcpOptionReadError> {
        use tcp_option::*;
        use TcpOptionReadError::*;

        let Some(&kind) = slice.first() else {
            return Err(UnexpectedEndOfSlice {
                option_id: KIND_END,
                expected_len: 1,
                actual_len: 0,
            });
        };
        let len = match kind {
            KIND_END | KIND_NOOP => 1,
            _ => {
                let Some(&len) = slice.get(1) else {
                    return Err(UnexpectedEndOfSlice {
                        option_id: kind,
                        expected_len: 2,
                        actual_len: slice.len(),
                    });
                };
                if len < 2 {
                    return Err(UnexpectedSize {
                        option_id: kind,
                        size: len,
                    });
                }
                if slice.len() < usize::from(len) {
                    return Err(UnexpectedEndOfSlice {
                        option_id: kind,
                        expected_len: len,
                        actual_len: slice.len(),
                    });
                }
                usize::from(len)
            }
        };
        let (option, rest) = slice.split_at(len);
        Ok((TcpOptionSlice { slice: option }, rest))
    }

    /// Kind of the option (see [`tcp_option`] for known values).
    #[inline]
    pub fn kind(&self) -> u8 {
        // from_slice is the only constructor and never yields an empty slice
        self.slice[0]
    }

    /// Total length of the option in bytes, including the kind & length octets.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> u8 {
        // from_slice guarantees the length fits in a u8
        self.slice.len() as u8
    }

    /// Option content after the kind & length octets (empty for
    /// `End of Option List` & `No-Operation`).
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.slice.get(2..).unwrap_or(&[])
    }

    /// Complete option including the kind & length octets.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// IANA registered meaning of the option kind (see [`tcp_option::kind_name`]).
    #[inline]
    pub fn kind_name(&self) -> Option<&'static str> {
        tcp_option::kind_name(self.kind())
    }

    /// Decodes the option into a [`TcpOptionElement`].
    ///
    /// Returns `Ok(None)` for kinds that cannot be represented as a
    /// [`TcpOptionElement`] (e.g. `End of Option List`, MPTCP or TFO) and an
    /// error if a decodable kind has an unexpected length.
    ///
    /// ```
    /// use etherparse::{tcp_option, TcpOptionElement, TcpOptionSlice};
    ///
    /// let (mss, _) = TcpOptionSlice::from_slice(&[tcp_option::KIND_MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4]).unwrap();
    /// assert_eq!(Ok(Some(TcpOptionElement::MaximumSegmentSize(1460))), mss.to_element());
    ///
    /// let (mptcp, _) = TcpOptionSlice::from_slice(&[tcp_option::KIND_MULTIPATH, 4, 0, 0]).unwrap();
    /// assert_eq!(Ok(None), mptcp.to_element());
    /// ```
    pub fn to_element(&self) -> Result<Option<TcpOptionElement>, TcpOptionReadError> {
        use tcp_option::*;
        let expected_len = match self.kind() {
            KIND_MAXIMUM_SEGMENT_SIZE => Some(LEN_MAXIMUM_SEGMENT_SIZE),
            KIND_WINDOW_SCALE => Some(LEN_WINDOW_SCALE),
            KIND_SELECTIVE_ACK_PERMITTED => Some(LEN_SELECTIVE_ACK_PERMITTED),
            KIND_TIMESTAMP => Some(LEN_TIMESTAMP),
            KIND_NOOP | KIND_SELECTIVE_ACK => None,
            _ => return Ok(None),
        };
        // TcpOptionsIterator reports a short option as UnexpectedEndOfSlice,
        // but here the slice is exactly the advertised length.
        if let Some(expected_len) = expected_len {
            if self.len() != expected_len {
                return Err(TcpOptionReadError::UnexpectedSize {
                    option_id: self.kind(),
                    size: self.len(),
                });
            }
        }
        match TcpOptionsIterator::from_slice(self.slice).next() {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }
}

impl core::fmt::Display for TcpOptionSlice<'_> {
    /// Generic representation usable for any option kind, e.g.
    /// `kind=34 (TCP Fast Open Cookie) len=6 data=0x01020304`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "kind={}", self.kind())?;
        if let Some(name) = self.kind_name() {
            write!(f, " ({name})")?;
        }
        if self.slice.len() > 1 {
            write!(f, " len={}", self.len())?;
        }
        if !self.data().is_empty() {
            f.write_str(" data=0x")?;
            for b in self.data() {
                write!(f, "{b:02x}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{tcp_option::*, *};
    use alloc::format;
    use proptest::prelude::*;

    #[test]
    fn from_slice_single_byte_kinds() {
        for kind in [KIND_END, KIND_NOOP] {
            let buffer = [kind, 99];
            let (option, rest) = TcpOptionSlice::from_slice(&buffer).unwrap();
            assert_eq!(kind, option.kind());
            assert_eq!(1, option.len());
            assert!(option.data().is_empty());
            assert_eq!(&[kind], option.slice());
            assert_eq!(&[99], rest);
        }
    }

    #[test]
    fn from_slice_errors() {
        use TcpOptionReadError::*;
        assert_eq!(
            Err(UnexpectedEndOfSlice {
                option_id: KIND_END,
                expected_len: 1,
                actual_len: 0
            }),
            TcpOptionSlice::from_slice(&[])
        );
        assert_eq!(
            Err(UnexpectedEndOfSlice {
                option_id: 99,
                expected_len: 2,
                actual_len: 1
            }),
            TcpOptionSlice::from_slice(&[99])
        );
        for len in [0, 1] {
            assert_eq!(
                Err(UnexpectedSize {
                    option_id: 99,
                    size: len
                }),
                TcpOptionSlice::from_slice(&[99, len, 0, 0])
            );
        }
        assert_eq!(
            Err(UnexpectedEndOfSlice {
                option_id: KIND_MULTIPATH,
                expected_len: 5,
                actual_len: 4
            }),
            TcpOptionSlice::from_slice(&[KIND_MULTIPATH, 5, 0, 0])
        );
    }

    proptest! {
        #[test]
        fn from_slice_any_kind(
            kind in 2u8..=255,
            data in proptest::collection::vec(any::<u8>(), 0..38),
            rest in proptest::collection::vec(any::<u8>(), 0..4),
        ) {
            let mut buffer = alloc::vec![kind, (data.len() + 2) as u8];
            buffer.extend_from_slice(&data);
            buffer.extend_from_slice(&rest);

            let (option, actual_rest) = TcpOptionSlice::from_slice(&buffer).unwrap();
            prop_assert_eq!(kind, option.kind());
            prop_assert_eq!((data.len() + 2) as u8, option.len());
            prop_assert_eq!(&data[..], option.data());
            prop_assert_eq!(&buffer[..data.len() + 2], option.slice());
            prop_assert_eq!(&rest[..], actual_rest);
            prop_assert_eq!(tcp_option::kind_name(kind), option.kind_name());
        }
    }

    #[test]
    fn to_element() {
        use TcpOptionElement::*;
        let decode = |buffer: &[u8]| TcpOptionSlice::from_slice(buffer).unwrap().0.to_element();

        assert_eq!(Ok(None), decode(&[KIND_END]));
        assert_eq!(Ok(Some(Noop)), decode(&[KIND_NOOP]));
        assert_eq!(
            Ok(Some(MaximumSegmentSize(1460))),
            decode(&[KIND_MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4])
        );
        assert_eq!(Ok(Some(WindowScale(7))), decode(&[KIND_WINDOW_SCALE, 3, 7]));
        assert_eq!(
            Ok(Some(SelectiveAcknowledgementPermitted)),
            decode(&[KIND_SELECTIVE_ACK_PERMITTED, 2])
        );
        assert_eq!(
            Ok(Some(SelectiveAcknowledgement((1, 2), [None, None, None]))),
            decode(&[KIND_SELECTIVE_ACK, 10, 0, 0, 0, 1, 0, 0, 0, 2])
        );
        assert_eq!(
            Ok(Some(Timestamp(1, 2))),
            decode(&[KIND_TIMESTAMP, 10, 0, 0, 0, 1, 0, 0, 0, 2])
        );
        assert_eq!(
            Err(TcpOptionReadError::UnexpectedSize {
                option_id: KIND_MAXIMUM_SEGMENT_SIZE,
                size: 3
            }),
            decode(&[KIND_MAXIMUM_SEGMENT_SIZE, 3, 0])
        );
        assert_eq!(Ok(None), decode(&[KIND_MULTIPATH, 4, 0, 0]));
        assert_eq!(Ok(None), decode(&[99, 2]));
    }

    #[test]
    fn display() {
        let fmt = |buffer: &[u8]| format!("{}", TcpOptionSlice::from_slice(buffer).unwrap().0);

        assert_eq!("kind=0 (End of Option List)", fmt(&[KIND_END]));
        assert_eq!("kind=1 (No-Operation)", fmt(&[KIND_NOOP]));
        assert_eq!(
            "kind=2 (Maximum Segment Size) len=4 data=0x05b4",
            fmt(&[KIND_MAXIMUM_SEGMENT_SIZE, 4, 0x05, 0xb4])
        );
        assert_eq!(
            "kind=34 (TCP Fast Open Cookie) len=6 data=0x0102ab0f",
            fmt(&[KIND_FAST_OPEN_COOKIE, 6, 1, 2, 0xab, 0x0f])
        );
        assert_eq!("kind=99 len=2", fmt(&[99, 2]));
        assert_eq!("kind=255 len=3 data=0xff", fmt(&[255, 3, 0xff]));
    }

    #[test]
    fn debug_clone_eq() {
        let (option, _) = TcpOptionSlice::from_slice(&[99, 3, 1]).unwrap();
        assert_eq!(option, option.clone());
        assert_eq!(
            "TcpOptionSlice { slice: [99, 3, 1] }",
            format!("{:?}", option)
        );
    }
}
