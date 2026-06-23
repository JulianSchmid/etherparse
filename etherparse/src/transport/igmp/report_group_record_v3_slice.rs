use super::ReportGroupRecordV3Header;
use crate::*;

/// A zero-copy slice of a single IGMPv3 group record.
///
/// Provides access to the 8-byte fixed header fields, the source
/// address list, and the auxiliary data without copying.
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Multicast Address                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address [1]                      |
/// +-                              .                              -+
/// .                               .                               .
/// +-                                                             -+
/// |                       Source Address [N]                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Auxiliary Data                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportGroupRecordV3Slice<'a> {
    /// The full record bytes (header + sources + aux data).
    slice: &'a [u8],
}

impl<'a> ReportGroupRecordV3Slice<'a> {
    /// Creates a group record slice from raw bytes.
    ///
    /// Validates that the slice is at least
    /// [`ReportGroupRecordV3Header::LEN`] bytes and that it contains
    /// enough data for the declared source addresses and auxiliary data.
    ///
    /// Returns a tuple of the group record slice and the remaining
    /// bytes after this record.
    ///
    /// # Errors
    ///
    /// Returns an [`err::LenError`] if the slice is too short.
    #[inline]
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<(ReportGroupRecordV3Slice<'a>, &'a [u8]), err::LenError> {
        if slice.len() < ReportGroupRecordV3Header::LEN {
            return Err(err::LenError {
                required_len: ReportGroupRecordV3Header::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmp,
                layer_start_offset: 0,
            });
        }

        // SAFETY: Safe as the length was checked to be >= LEN (8).
        let num_of_sources =
            u16::from_be_bytes(unsafe { [*slice.get_unchecked(2), *slice.get_unchecked(3)] });
        let aux_data_len = unsafe { *slice.get_unchecked(1) };

        let record_len = ReportGroupRecordV3Header::LEN
            + usize::from(num_of_sources) * 4
            + usize::from(aux_data_len) * 4;

        if slice.len() < record_len {
            return Err(err::LenError {
                required_len: record_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmp,
                layer_start_offset: 0,
            });
        }

        Ok((
            ReportGroupRecordV3Slice {
                slice: &slice[..record_len],
            },
            &slice[record_len..],
        ))
    }

    /// Decode the fixed header into a [`ReportGroupRecordV3Header`].
    #[inline]
    pub fn header(&self) -> ReportGroupRecordV3Header {
        // SAFETY: from_slice guarantees at least LEN bytes.
        let (header, _) = ReportGroupRecordV3Header::from_slice(self.slice).unwrap();
        header
    }

    /// Returns the group record type.
    #[inline]
    pub fn record_type(&self) -> igmp::ReportGroupRecordType {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (8) bytes.
        igmp::ReportGroupRecordType(unsafe { *self.slice.get_unchecked(0) })
    }

    /// Returns the auxiliary data length in units of 32-bit words.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (8) bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the number of source addresses.
    #[inline]
    pub fn num_of_sources(&self) -> u16 {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (8) bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the multicast address.
    #[inline]
    pub fn multicast_address(&self) -> [u8; 4] {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (8) bytes.
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns the raw source address bytes.
    ///
    /// The returned slice contains `num_of_sources * 4` bytes. Each 4
    /// consecutive bytes represent one IPv4 source address.
    #[inline]
    pub fn source_addrs_bytes(&self) -> &'a [u8] {
        let start = ReportGroupRecordV3Header::LEN;
        let len = usize::from(self.num_of_sources()) * 4;
        // SAFETY: Safe as from_slice validates the total record length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns the auxiliary data bytes.
    #[inline]
    pub fn aux_data(&self) -> &'a [u8] {
        let start = ReportGroupRecordV3Header::LEN + usize::from(self.num_of_sources()) * 4;
        let len = usize::from(self.aux_data_len()) * 4;
        // SAFETY: Safe as from_slice validates the total record length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns the full slice of this group record.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

/// An iterator over IGMPv3 group record slices in a report payload.
#[derive(Clone, Debug)]
pub struct ReportGroupRecordV3SliceIter<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> ReportGroupRecordV3SliceIter<'a> {
    /// Creates a new iterator over `count` group records starting at
    /// the beginning of `slice`.
    #[inline]
    pub fn new(slice: &'a [u8], count: u16) -> ReportGroupRecordV3SliceIter<'a> {
        ReportGroupRecordV3SliceIter {
            remaining: slice,
            count,
        }
    }
}

impl<'a> Iterator for ReportGroupRecordV3SliceIter<'a> {
    type Item = Result<ReportGroupRecordV3Slice<'a>, err::LenError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match ReportGroupRecordV3Slice::from_slice(self.remaining) {
            Ok((record, rest)) => {
                self.remaining = rest;
                Some(Ok(record))
            }
            Err(e) => {
                // Stop iteration on error.
                self.count = 0;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(usize::from(self.count)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    fn make_record_bytes(
        record_type: u8,
        aux_data_len: u8,
        num_sources: u16,
        multicast_addr: [u8; 4],
    ) -> Vec<u8> {
        let n = num_sources.to_be_bytes();
        let mut bytes = vec![record_type, aux_data_len, n[0], n[1]];
        bytes.extend_from_slice(&multicast_addr);
        // source addresses (4 bytes each)
        for i in 0..num_sources {
            bytes.extend_from_slice(&[10, 0, 0, (i + 1) as u8]);
        }
        // aux data (4 bytes per word)
        for _ in 0..aux_data_len {
            bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        }
        bytes
    }

    #[test]
    fn from_slice_no_sources() {
        let bytes = make_record_bytes(1, 0, 0, [224, 0, 0, 1]);
        let mut with_trailer = bytes.clone();
        with_trailer.extend_from_slice(&[0xEE]);

        let (slice, rest) = ReportGroupRecordV3Slice::from_slice(&with_trailer).unwrap();
        assert_eq!(rest, &[0xEE]);
        assert_eq!(slice.slice(), &bytes[..]);
        assert_eq!(slice.record_type(), igmp::ReportGroupRecordType(1));
        assert_eq!(slice.aux_data_len(), 0);
        assert_eq!(slice.num_of_sources(), 0);
        assert_eq!(slice.multicast_address(), [224, 0, 0, 1]);
        assert_eq!(slice.source_addrs_bytes(), &[]);
        assert_eq!(slice.aux_data(), &[]);
    }

    #[test]
    fn from_slice_with_sources() {
        let bytes = make_record_bytes(2, 0, 2, [224, 0, 0, 1]);
        let mut with_trailer = bytes.clone();
        with_trailer.push(0xFF);

        let (slice, rest) = ReportGroupRecordV3Slice::from_slice(&with_trailer).unwrap();
        assert_eq!(rest, &[0xFF]);
        assert_eq!(slice.num_of_sources(), 2);
        assert_eq!(slice.source_addrs_bytes(), &[10, 0, 0, 1, 10, 0, 0, 2]);
    }

    #[test]
    fn from_slice_with_aux_data() {
        let bytes = make_record_bytes(1, 1, 1, [224, 0, 0, 1]);

        let (slice, rest) = ReportGroupRecordV3Slice::from_slice(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(slice.source_addrs_bytes(), &[10, 0, 0, 1]);
        assert_eq!(slice.aux_data(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn from_slice_too_short_header() {
        for bad_len in 0..ReportGroupRecordV3Header::LEN {
            let bytes = vec![0u8; bad_len];
            assert_eq!(
                ReportGroupRecordV3Slice::from_slice(&bytes).unwrap_err(),
                err::LenError {
                    required_len: ReportGroupRecordV3Header::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Igmp,
                    layer_start_offset: 0,
                }
            );
        }
    }

    #[test]
    fn from_slice_too_short_sources() {
        // Declare 2 sources but only provide 1
        let n = 2u16.to_be_bytes();
        let mut bytes = vec![1, 0, n[0], n[1], 224, 0, 0, 1];
        bytes.extend_from_slice(&[10, 0, 0, 1]); // only 4 bytes, need 8

        assert_eq!(
            ReportGroupRecordV3Slice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: 8 + 8, // header + 2 sources
                len: 12,
                len_source: LenSource::Slice,
                layer: err::Layer::Igmp,
                layer_start_offset: 0,
            }
        );
    }

    #[test]
    fn from_slice_too_short_aux_data() {
        // Declare 1 word aux data but don't provide it
        let bytes = vec![1, 1, 0, 0, 224, 0, 0, 1]; // aux_data_len=1, 0 sources

        assert_eq!(
            ReportGroupRecordV3Slice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: 8 + 4, // header + 1 word aux
                len: 8,
                len_source: LenSource::Slice,
                layer: err::Layer::Igmp,
                layer_start_offset: 0,
            }
        );
    }

    #[test]
    fn header_accessor() {
        let bytes = make_record_bytes(3, 0, 1, [239, 1, 2, 3]);
        let (slice, _) = ReportGroupRecordV3Slice::from_slice(&bytes).unwrap();
        let header = slice.header();
        assert_eq!(header.record_type, igmp::ReportGroupRecordType(3));
        assert_eq!(header.aux_data_len, 0);
        assert_eq!(header.num_of_sources, 1);
        assert_eq!(header.multicast_address, [239, 1, 2, 3]);
    }

    proptest! {
        #[test]
        fn field_accessors(
            record_type in any::<u8>(),
            aux_data_len in 0u8..4,
            num_sources in 0u16..4,
            multicast_address in any::<[u8; 4]>(),
        ) {
            let bytes = make_record_bytes(record_type, aux_data_len, num_sources, multicast_address);
            let (slice, rest) = ReportGroupRecordV3Slice::from_slice(&bytes).unwrap();
            prop_assert!(rest.is_empty());
            prop_assert_eq!(record_type, slice.record_type().0);
            prop_assert_eq!(aux_data_len, slice.aux_data_len());
            prop_assert_eq!(num_sources, slice.num_of_sources());
            prop_assert_eq!(multicast_address, slice.multicast_address());
            prop_assert_eq!(usize::from(num_sources) * 4, slice.source_addrs_bytes().len());
            prop_assert_eq!(usize::from(aux_data_len) * 4, slice.aux_data().len());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(multicast_address in any::<[u8; 4]>()) {
            let bytes = make_record_bytes(1, 0, 0, multicast_address);
            let (slice, _) = ReportGroupRecordV3Slice::from_slice(&bytes).unwrap();
            prop_assert_eq!(&slice, &slice.clone());
        }
    }

    #[test]
    fn debug_fmt() {
        let bytes = make_record_bytes(1, 0, 0, [224, 0, 0, 1]);
        let (slice, _) = ReportGroupRecordV3Slice::from_slice(&bytes).unwrap();
        let dbg = format!("{:?}", slice);
        assert!(dbg.starts_with("ReportGroupRecordV3Slice"));
    }

    // Iterator tests

    #[test]
    fn iterator_empty() {
        let iter = ReportGroupRecordV3SliceIter::new(&[], 0);
        assert_eq!(0, iter.count());
    }

    #[test]
    fn iterator_single() {
        let bytes = make_record_bytes(1, 0, 0, [224, 0, 0, 1]);
        let mut iter = ReportGroupRecordV3SliceIter::new(&bytes, 1);
        let record = iter.next().unwrap().unwrap();
        assert_eq!(record.multicast_address(), [224, 0, 0, 1]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_multiple() {
        let mut bytes = make_record_bytes(1, 0, 1, [224, 0, 0, 1]);
        bytes.extend_from_slice(&make_record_bytes(2, 0, 0, [224, 0, 0, 2]));

        let records: Vec<_> = ReportGroupRecordV3SliceIter::new(&bytes, 2)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(2, records.len());
        assert_eq!(records[0].record_type().0, 1);
        assert_eq!(records[0].multicast_address(), [224, 0, 0, 1]);
        assert_eq!(records[1].record_type().0, 2);
        assert_eq!(records[1].multicast_address(), [224, 0, 0, 2]);
    }

    #[test]
    fn iterator_error_stops() {
        // Declare 2 records but only provide 1
        let bytes = make_record_bytes(1, 0, 0, [224, 0, 0, 1]);
        let mut iter = ReportGroupRecordV3SliceIter::new(&bytes, 2);
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_size_hint() {
        let bytes = make_record_bytes(1, 0, 0, [224, 0, 0, 1]);
        let iter = ReportGroupRecordV3SliceIter::new(&bytes, 3);
        assert_eq!((0, Some(3)), iter.size_hint());
    }
}
