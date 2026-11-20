use crate::icmpv6::{DnsNameReadError, NdpOptionHeader, NdpOptionReadError, NdpOptionType};

/// DNS Search List (DNSSL) option slice (RFC 8106, Section 5.2, type 31).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Length    |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Lifetime                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// :                Domain Names of DNS Search List                :
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This slice stores the full serialized option, including the
/// `Type` and `Length` bytes.
///
/// ```
/// use etherparse::icmpv6::DnsSearchListOptionSlice;
///
/// let bytes = [31, 2, 0, 0, 0, 0, 0, 60, 1, b'a', 0, 0, 0, 0, 0, 0];
/// let option = DnsSearchListOptionSlice::from_slice(&bytes)?;
/// for name in option.search_list_entries() {
///     for label in name?.labels() {
///         assert_eq!(label, b"a");
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsSearchListOptionSlice<'a> {
    slice: &'a [u8],
}

impl<'a> DnsSearchListOptionSlice<'a> {
    const FIXED_PART_LEN: usize = 8;
    const LIFETIME_OFFSET: usize = 4;

    /// Decodes exactly one complete option, including its type and length bytes.
    ///
    /// Requires type 31, a length of at least two eight-byte units, and a slice
    /// whose size equals the encoded length. Domain names and padding are not
    /// checked here: [`Self::search_list_entries`] validates them lazily and
    /// reports [`DnsNameReadError`] during iteration.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, NdpOptionReadError> {
        let (header, _) = NdpOptionHeader::from_slice(slice)?;
        if header.option_type != NdpOptionType::DNSSL {
            return Err(NdpOptionReadError::UnexpectedHeader {
                expected_option_id: NdpOptionType::DNSSL,
                actual_option_id: header.option_type,
                expected_length_units: header.length_units,
                actual_length_units: header.length_units,
            });
        }

        if header.length_units == 0 {
            return Err(NdpOptionReadError::ZeroLength {
                option_id: NdpOptionType::DNSSL,
            });
        }

        if header.length_units < 2 {
            return Err(NdpOptionReadError::UnexpectedHeader {
                expected_option_id: NdpOptionType::DNSSL,
                actual_option_id: header.option_type,
                expected_length_units: 2,
                actual_length_units: header.length_units,
            });
        }

        if slice.len() != header.byte_len() {
            return Err(NdpOptionReadError::UnexpectedSize {
                option_id: NdpOptionType::DNSSL,
                expected_size: header.byte_len(),
                actual_size: slice.len(),
            });
        }

        Ok(Self { slice })
    }

    /// Return the option type value (31).
    pub const fn option_type(&self) -> NdpOptionType {
        NdpOptionType::DNSSL
    }

    /// Returns the serialized option bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the lifetime of the advertised search domains in seconds.
    pub fn lifetime(&self) -> u32 {
        u32::from_be_bytes(*self.slice[Self::LIFETIME_OFFSET..].first_chunk().unwrap())
    }

    /// Lazily validates and returns search domains without allocating.
    /// After an error, the iterator returns no further items.
    pub fn search_list_entries(&self) -> DnsNameIterator<'a> {
        // After the 8-byte fixed header, the option contains back-to-back DNS names.
        // Each name is a sequence of length-prefixed labels ending in a zero byte.
        // For example: www.example.com → [3]www[7]example[3]com[0]
        // The DNS names are padded at the end with zero-bytes to an 8-byte boundary.
        DnsNameIterator {
            rest: &self.slice[Self::FIXED_PART_LEN..],
            offset: 0,
        }
    }
}

/// Iterates over search domains, reporting malformed names or padding.
#[derive(Clone, Debug)]
pub struct DnsNameIterator<'a> {
    rest: &'a [u8],
    offset: usize,
}

/// Returns the encoded length of the DNS name at the start of `bytes`,
/// including each label's length byte and the terminating zero byte.
/// `offset` is the name's byte offset within the domain-name region
/// and is used only for error reporting.
fn name_len(bytes: &[u8], offset: usize) -> Result<usize, DnsNameReadError> {
    let mut end = 0;
    loop {
        let label_offset = end;
        let length = *bytes.get(end).ok_or(DnsNameReadError::UnexpectedEnd {
            offset: offset + end,
            required_len: offset + end + 1,
            actual_len: offset + bytes.len(),
        })?;

        if length > 63 {
            return Err(DnsNameReadError::InvalidLabelLength {
                offset: offset + label_offset,
                value: length,
            });
        }

        end += 1 + length as usize;
        if end > 255 {
            return Err(DnsNameReadError::NameTooLong {
                offset,
                actual_len: end,
            });
        }

        if end > bytes.len() {
            return Err(DnsNameReadError::UnexpectedEnd {
                offset: offset + label_offset,
                required_len: offset + end,
                actual_len: offset + bytes.len(),
            });
        }

        if length == 0 {
            return Ok(end);
        }
    }
}

impl<'a> Iterator for DnsNameIterator<'a> {
    type Item = Result<DnsNameSlice<'a>, DnsNameReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Restore the remainder only on success, so errors and padding finish iteration.
        let bytes = core::mem::take(&mut self.rest);
        let &first = bytes.first()?;

        if first == 0 {
            return match bytes.iter().position(|&byte| byte != 0) {
                Some(index) => Some(Err(DnsNameReadError::InvalidPadding {
                    offset: self.offset + index,
                })),
                None if self.offset == 0 => Some(Err(DnsNameReadError::EmptySearchList)),
                None if bytes.len() > 7 => Some(Err(DnsNameReadError::InvalidPadding {
                    offset: self.offset + 7,
                })),
                None => None,
            };
        }

        Some(match name_len(bytes, self.offset) {
            Ok(length) => {
                let (name, rest) = bytes.split_at(length);
                self.rest = rest;
                self.offset += length;
                Ok(DnsNameSlice { slice: name })
            }
            Err(error) => Err(error),
        })
    }
}

impl core::iter::FusedIterator for DnsNameIterator<'_> {}

/// A validated, borrowed DNS name, including its terminating zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsNameSlice<'a> {
    slice: &'a [u8],
}

impl<'a> DnsNameSlice<'a> {
    /// Returns the encoded name, including length bytes and the terminating zero.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns borrowed label bytes, without length bytes or the terminator.
    pub fn labels(&self) -> LabelIterator<'a> {
        LabelIterator {
            rest: &self.slice[..self.slice.len() - 1],
        }
    }
}

/// Iterates over the labels of a validated DNS name.
#[derive(Clone, Debug)]
pub struct LabelIterator<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for LabelIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let (count, rest) = self.rest.split_first()?;
        let (label, rest) = rest.split_at(*count as usize);
        self.rest = rest;

        Some(label)
    }
}

impl core::iter::FusedIterator for LabelIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::icmpv6::{NdpOptionSlice, NdpOptionsIterator};
    use alloc::vec::Vec;

    fn names(bytes: &[u8]) -> DnsNameIterator<'_> {
        DnsNameIterator {
            rest: bytes,
            offset: 0,
        }
    }

    #[test]
    fn decode() {
        let bytes = [
            31, 3, 0, 0, 1, 2, 3, 4, 1, b'a', 1, b'b', 0, 2, b'c', b'd', 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut options = NdpOptionsIterator::from_slice(&bytes);
        let NdpOptionSlice::DnsSearchList(option) = options.next().unwrap().unwrap() else {
            panic!("expected DNSSL");
        };
        assert_eq!(option.lifetime(), 0x01020304);
        let mut iter = option.search_list_entries();
        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.labels().collect::<Vec<_>>(), [b"a", b"b"]);
        assert_eq!(
            iter.next().unwrap().unwrap().labels().next(),
            Some(b"cd".as_slice())
        );
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
        assert!(options.next().is_none());
    }

    #[test]
    fn rejects_extra_padding_block() {
        let bytes = [
            31, 3, 0, 0, 1, 2, 3, 4, 1, b'a', 1, b'b', 0, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let option = DnsSearchListOptionSlice::from_slice(&bytes).unwrap();
        let mut names = option.search_list_entries();
        assert!(names.next().unwrap().is_ok());
        assert!(names.next().unwrap().is_ok());
        assert_eq!(
            names.next(),
            Some(Err(DnsNameReadError::InvalidPadding { offset: 15 }))
        );
        assert_eq!(names.next(), None);
    }

    #[test]
    fn invalid_framing() {
        for (kind, length, size) in [
            (31, 2, 0),
            (25, 2, 16),
            (31, 0, 16),
            (31, 1, 8),
            (31, 3, 16),
            (31, 2, 17),
        ] {
            let mut bytes = [0; 17];
            bytes[..2].copy_from_slice(&[kind, length]);
            assert!(DnsSearchListOptionSlice::from_slice(&bytes[..size]).is_err());
        }
        let bytes = [31, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for size in 1..16 {
            assert!(DnsSearchListOptionSlice::from_slice(&bytes[..size]).is_err());
        }
    }

    #[test]
    fn invalid_names() {
        use DnsNameReadError::*;
        for bytes in [
            b"\x03a".as_slice(),
            b"\x01a",
            b"\x40",
            b"\xc0\x00",
            b"\x00\x01",
            b"\x00\x00",
        ] {
            let mut iter = names(bytes);
            let error = iter.next().unwrap().unwrap_err();
            match bytes {
                b"\x03a" | b"\x01a" => assert!(matches!(error, UnexpectedEnd { .. })),
                b"\x40" | b"\xc0\x00" => assert!(matches!(error, InvalidLabelLength { .. })),
                b"\x00\x01" => assert!(matches!(error, InvalidPadding { .. })),
                _ => assert_eq!(error, EmptySearchList),
            }
            assert!(iter.next().is_none());
            assert!(iter.next().is_none());
        }
        let mut iter = names(b"\x01a\x00\x03b");
        assert!(iter.next().unwrap().is_ok());
        assert_eq!(
            iter.next(),
            Some(Err(UnexpectedEnd {
                offset: 3,
                required_len: 7,
                actual_len: 5
            }))
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn name_length_limit() {
        let mut bytes = Vec::new();
        for length in [63, 63, 63, 61] {
            bytes.push(length);
            bytes.extend(core::iter::repeat_n(b'x', length as usize));
        }
        bytes.push(0);
        assert_eq!(bytes.len(), 255);
        assert!(names(&bytes).next().unwrap().is_ok());
        bytes[192] = 62;
        bytes.insert(254, b'x');
        assert!(matches!(
            names(&bytes).next(),
            Some(Err(DnsNameReadError::NameTooLong { .. }))
        ));
    }
}
