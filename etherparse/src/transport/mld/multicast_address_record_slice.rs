use super::MulticastAddressRecordHeader;
use crate::*;

/// A zero-copy slice of a single MLDv2 multicast address record.
///
/// Provides access to the 20-byte fixed header fields, the source
/// address list, and the auxiliary data without copying.
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-                      Multicast Address                      -+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-                      Source Address [1]                     -+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-                              .                              -+
/// .                               .                               .
/// +-                                                             -+
/// |                                                               |
/// +-                      Source Address [N]                     -+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Auxiliary Data                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulticastAddressRecordSlice<'a> {
    /// The full record bytes (header + sources + aux data).
    slice: &'a [u8],
}

impl<'a> MulticastAddressRecordSlice<'a> {
    /// Creates a multicast address record slice from raw bytes.
    ///
    /// Validates that the slice is at least
    /// [`MulticastAddressRecordHeader::LEN`] bytes and that it contains
    /// enough data for the declared source addresses and auxiliary data.
    ///
    /// Returns a tuple of the multicast address record slice and the
    /// remaining bytes after this record.
    ///
    /// # Errors
    ///
    /// Returns an [`err::LenError`] if the slice is too short.
    #[inline]
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<(MulticastAddressRecordSlice<'a>, &'a [u8]), err::LenError> {
        if slice.len() < MulticastAddressRecordHeader::LEN {
            return Err(err::LenError {
                required_len: MulticastAddressRecordHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            });
        }

        // SAFETY: Safe as the length was checked to be >= LEN (20).
        let num_of_sources =
            u16::from_be_bytes(unsafe { [*slice.get_unchecked(2), *slice.get_unchecked(3)] });
        let aux_data_len = unsafe { *slice.get_unchecked(1) };

        let record_len = MulticastAddressRecordHeader::LEN
            + usize::from(num_of_sources) * 16
            + usize::from(aux_data_len) * 4;

        if slice.len() < record_len {
            return Err(err::LenError {
                required_len: record_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            });
        }

        Ok((
            MulticastAddressRecordSlice {
                slice: &slice[..record_len],
            },
            &slice[record_len..],
        ))
    }

    /// Decode the fixed header into a [`MulticastAddressRecordHeader`].
    #[inline]
    pub fn header(&self) -> MulticastAddressRecordHeader {
        // `from_slice` guarantees at least LEN bytes, so this cannot fail.
        let (header, _) = MulticastAddressRecordHeader::from_slice(self.slice).unwrap();
        header
    }

    /// Returns the multicast address record type.
    #[inline]
    pub fn record_type(&self) -> mld::MulticastAddressRecordType {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        mld::MulticastAddressRecordType(unsafe { *self.slice.get_unchecked(0) })
    }

    /// Returns the auxiliary data length in units of 32-bit words.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the number of source addresses.
    #[inline]
    pub fn num_of_sources(&self) -> u16 {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the multicast address.
    #[inline]
    pub fn multicast_address(&self) -> [u8; 16] {
        // SAFETY: Safe as from_slice checks that the slice has at least LEN (20) bytes.
        unsafe { get_unchecked_16_byte_array(self.slice.as_ptr().add(4)) }
    }

    /// Returns the raw source address bytes.
    ///
    /// The returned slice contains `num_of_sources * 16` bytes. Each 16
    /// consecutive bytes represent one IPv6 source address.
    #[inline]
    pub fn source_addrs_bytes(&self) -> &'a [u8] {
        let start = MulticastAddressRecordHeader::LEN;
        let len = usize::from(self.num_of_sources()) * 16;
        // SAFETY: Safe as from_slice validates the total record length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns an iterator over the source addresses as `[u8; 16]` arrays.
    #[inline]
    pub fn source_addresses(&self) -> impl ExactSizeIterator<Item = [u8; 16]> + 'a {
        self.source_addrs_bytes().chunks_exact(16).map(|c| {
            let mut address = [0u8; 16];
            address.copy_from_slice(c);
            address
        })
    }

    /// Returns the auxiliary data bytes.
    #[inline]
    pub fn aux_data(&self) -> &'a [u8] {
        let start = MulticastAddressRecordHeader::LEN + usize::from(self.num_of_sources()) * 16;
        let len = usize::from(self.aux_data_len()) * 4;
        // SAFETY: Safe as from_slice validates the total record length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(start), len) }
    }

    /// Returns the full slice of this multicast address record.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

/// An iterator over MLDv2 multicast address record slices in a report payload.
#[derive(Clone, Debug)]
pub struct MulticastAddressRecordSliceIter<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> MulticastAddressRecordSliceIter<'a> {
    /// Creates a new iterator over `count` multicast address records
    /// starting at the beginning of `slice`.
    #[inline]
    pub fn new(slice: &'a [u8], count: u16) -> MulticastAddressRecordSliceIter<'a> {
        MulticastAddressRecordSliceIter {
            remaining: slice,
            count,
        }
    }
}

impl<'a> Iterator for MulticastAddressRecordSliceIter<'a> {
    type Item = Result<MulticastAddressRecordSlice<'a>, err::LenError>;

    /// Decodes the next multicast address record.
    ///
    /// Returns `None` once the record count given to
    /// [`MulticastAddressRecordSliceIter::new`] is exhausted. If the
    /// remaining bytes are too short for the next record a
    /// [`crate::err::LenError`] is returned and the iteration ends (the
    /// record count in an MLDv2 report is attacker controlled, so the
    /// length of each record is only checked as it is reached).
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match MulticastAddressRecordSlice::from_slice(self.remaining) {
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

    /// Returns the number of records left to decode as the upper bound.
    ///
    /// The lower bound is zero, as the first record may already end the
    /// iteration with a [`crate::err::LenError`].
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(usize::from(self.count)))
    }
}

impl core::iter::FusedIterator for MulticastAddressRecordSliceIter<'_> {}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    /// Returns a distinguishable `2001::` source address for the given
    /// index, so the tests can tell the addresses in a record apart.
    fn source_addr(index: u16) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = (index + 1) as u8;
        addr
    }

    /// Returns a distinguishable `ff02::` multicast address ending in
    /// `last`, so the tests can tell the records apart.
    fn multicast_addr(last: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xFF;
        addr[1] = 0x02;
        addr[15] = last;
        addr
    }

    /// Serializes a complete, consistent multicast address record: the 20
    /// byte header, `num_sources` source addresses and `aux_data_len`
    /// words of filler aux data.
    fn make_record_bytes(
        record_type: u8,
        aux_data_len: u8,
        num_sources: u16,
        multicast_address: [u8; 16],
    ) -> Vec<u8> {
        let n = num_sources.to_be_bytes();
        let mut bytes = vec![record_type, aux_data_len, n[0], n[1]];
        bytes.extend_from_slice(&multicast_address);
        // source addresses (16 bytes each)
        for i in 0..num_sources {
            bytes.extend_from_slice(&source_addr(i));
        }
        // aux data (4 bytes per word)
        for _ in 0..aux_data_len {
            bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        }
        bytes
    }

    /// A record with no sources & no aux data must decode with empty
    /// source & aux data slices, and must not consume the trailing byte.
    #[test]
    fn from_slice_no_sources() {
        let bytes = make_record_bytes(1, 0, 0, multicast_addr(1));
        let mut with_trailer = bytes.clone();
        with_trailer.extend_from_slice(&[0xEE]);

        let (slice, rest) = MulticastAddressRecordSlice::from_slice(&with_trailer).unwrap();
        assert_eq!(rest, &[0xEE]);
        assert_eq!(slice.slice(), &bytes[..]);
        assert_eq!(
            slice.record_type(),
            mld::MulticastAddressRecordType::MODE_IS_INCLUDE
        );
        assert_eq!(slice.aux_data_len(), 0);
        assert_eq!(slice.num_of_sources(), 0);
        assert_eq!(slice.multicast_address(), multicast_addr(1));
        assert_eq!(slice.source_addrs_bytes(), &[]);
        assert_eq!(slice.aux_data(), &[]);
    }

    /// A record with sources must expose them both as raw bytes and via
    /// the `source_addresses` iterator, which must report the right length.
    #[test]
    fn from_slice_with_sources() {
        let bytes = make_record_bytes(2, 0, 2, multicast_addr(1));
        let mut with_trailer = bytes.clone();
        with_trailer.push(0xFF);

        let (slice, rest) = MulticastAddressRecordSlice::from_slice(&with_trailer).unwrap();
        assert_eq!(rest, &[0xFF]);
        assert_eq!(slice.num_of_sources(), 2);
        let mut expected_bytes = Vec::new();
        expected_bytes.extend_from_slice(&source_addr(0));
        expected_bytes.extend_from_slice(&source_addr(1));
        assert_eq!(slice.source_addrs_bytes(), &expected_bytes[..]);
        let addrs: Vec<_> = slice.source_addresses().collect();
        assert_eq!(addrs, vec![source_addr(0), source_addr(1)]);
        assert_eq!(slice.source_addresses().len(), 2);
    }

    /// Aux data follows the source addresses, so both must be split out at
    /// the right offset when a record carries each of them.
    #[test]
    fn from_slice_with_aux_data() {
        let bytes = make_record_bytes(1, 1, 1, multicast_addr(1));

        let (slice, rest) = MulticastAddressRecordSlice::from_slice(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(slice.source_addrs_bytes(), &source_addr(0)[..]);
        assert_eq!(slice.aux_data(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    /// Any slice shorter than the 20 byte header must be rejected with a
    /// length error naming the MLD layer.
    #[test]
    fn from_slice_too_short_header() {
        for bad_len in 0..MulticastAddressRecordHeader::LEN {
            let bytes = vec![0u8; bad_len];
            assert_eq!(
                MulticastAddressRecordSlice::from_slice(&bytes).unwrap_err(),
                err::LenError {
                    required_len: MulticastAddressRecordHeader::LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Mld,
                    layer_start_offset: 0,
                }
            );
        }
    }

    /// A record declaring more sources than the slice can hold must be
    /// rejected, with the required length covering all declared sources.
    #[test]
    fn from_slice_too_short_sources() {
        // Declare 2 sources but only provide 1
        let n = 2u16.to_be_bytes();
        let mut bytes = vec![1, 0, n[0], n[1]];
        bytes.extend_from_slice(&multicast_addr(1));
        bytes.extend_from_slice(&source_addr(0)); // only 16 bytes, need 32

        assert_eq!(
            MulticastAddressRecordSlice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: 20 + 32, // header + 2 sources
                len: 36,
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    /// A record declaring aux data that the slice does not contain must be
    /// rejected, counting the aux data length in 4 byte words.
    #[test]
    fn from_slice_too_short_aux_data() {
        // Declare 1 word aux data but don't provide it
        let mut bytes = vec![1, 1, 0, 0]; // aux_data_len=1, 0 sources
        bytes.extend_from_slice(&multicast_addr(1));

        assert_eq!(
            MulticastAddressRecordSlice::from_slice(&bytes).unwrap_err(),
            err::LenError {
                required_len: 20 + 4, // header + 1 word aux
                len: 20,
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    /// `header` must return an owned header with the same field values the
    /// per-field accessors report.
    #[test]
    fn header_accessor() {
        let bytes = make_record_bytes(3, 0, 1, multicast_addr(3));
        let (slice, _) = MulticastAddressRecordSlice::from_slice(&bytes).unwrap();
        let header = slice.header();
        assert_eq!(
            header.record_type,
            mld::MulticastAddressRecordType::CHANGE_TO_INCLUDE_MODE
        );
        assert_eq!(header.aux_data_len, 0);
        assert_eq!(header.num_of_sources, 1);
        assert_eq!(header.multicast_address, multicast_addr(3));
    }

    proptest! {
        /// Every accessor must report the value that was serialized, and
        /// the source & aux data slices must have the declared lengths.
        #[test]
        fn field_accessors(
            record_type in any::<u8>(),
            aux_data_len in 0u8..4,
            num_sources in 0u16..4,
            multicast_address in any::<[u8; 16]>(),
        ) {
            let bytes = make_record_bytes(record_type, aux_data_len, num_sources, multicast_address);
            let (slice, rest) = MulticastAddressRecordSlice::from_slice(&bytes).unwrap();
            prop_assert!(rest.is_empty());
            prop_assert_eq!(record_type, slice.record_type().0);
            prop_assert_eq!(aux_data_len, slice.aux_data_len());
            prop_assert_eq!(num_sources, slice.num_of_sources());
            prop_assert_eq!(multicast_address, slice.multicast_address());
            prop_assert_eq!(usize::from(num_sources) * 16, slice.source_addrs_bytes().len());
            prop_assert_eq!(usize::from(aux_data_len) * 4, slice.aux_data().len());
        }
    }

    proptest! {
        /// `Clone` & `PartialEq` must be derived for the slice.
        #[test]
        fn clone_eq(multicast_address in any::<[u8; 16]>()) {
            let bytes = make_record_bytes(1, 0, 0, multicast_address);
            let (slice, _) = MulticastAddressRecordSlice::from_slice(&bytes).unwrap();
            prop_assert_eq!(&slice, &slice.clone());
        }
    }

    /// `Debug` must be derived for the slice.
    #[test]
    fn debug_fmt() {
        let bytes = make_record_bytes(1, 0, 0, multicast_addr(1));
        let (slice, _) = MulticastAddressRecordSlice::from_slice(&bytes).unwrap();
        let dbg = format!("{:?}", slice);
        assert!(dbg.starts_with("MulticastAddressRecordSlice"));
    }

    // Iterator tests

    /// A record count of zero must yield nothing, even for an empty slice.
    #[test]
    fn iterator_empty() {
        let iter = MulticastAddressRecordSliceIter::new(&[], 0);
        assert_eq!(0, iter.count());
    }

    /// A count of one must yield exactly that record and then end.
    #[test]
    fn iterator_single() {
        let bytes = make_record_bytes(1, 0, 0, multicast_addr(1));
        let mut iter = MulticastAddressRecordSliceIter::new(&bytes, 1);
        let record = iter.next().unwrap().unwrap();
        assert_eq!(record.multicast_address(), multicast_addr(1));
        assert!(iter.next().is_none());
    }

    /// Records have varying lengths, so the iterator must advance by each
    /// record's own length and return them in order.
    #[test]
    fn iterator_multiple() {
        let mut bytes = make_record_bytes(1, 0, 1, multicast_addr(1));
        bytes.extend_from_slice(&make_record_bytes(2, 0, 0, multicast_addr(2)));

        let records: Vec<_> = MulticastAddressRecordSliceIter::new(&bytes, 2)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(2, records.len());
        assert_eq!(records[0].record_type().0, 1);
        assert_eq!(records[0].multicast_address(), multicast_addr(1));
        assert_eq!(records[1].record_type().0, 2);
        assert_eq!(records[1].multicast_address(), multicast_addr(2));
    }

    /// A record count larger than the payload must yield the decodable
    /// records, then one error, then `None` (no error repeats forever).
    #[test]
    fn iterator_error_stops() {
        // Declare 2 records but only provide 1
        let bytes = make_record_bytes(1, 0, 0, multicast_addr(1));
        let mut iter = MulticastAddressRecordSliceIter::new(&bytes, 2);
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none());
    }

    /// `size_hint` must use the remaining record count as the upper bound
    /// and zero as the lower bound, as decoding may fail at any record.
    #[test]
    fn iterator_size_hint() {
        let bytes = make_record_bytes(1, 0, 0, multicast_addr(1));
        let iter = MulticastAddressRecordSliceIter::new(&bytes, 3);
        assert_eq!((0, Some(3)), iter.size_hint());
    }
}
