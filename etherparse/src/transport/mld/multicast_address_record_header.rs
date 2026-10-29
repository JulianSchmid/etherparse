use crate::{err::LenError, mld::MulticastAddressRecordType, *};

/// Header part of an "MLDv2 Multicast Address Record".
///
/// The header contains the following parts for the multicast address record:
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  | part of header and
/// +-                                                             -+  | this type
/// |                                                               |  |
/// +-                      Multicast Address                      -+  |
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-                      Source Address [1]                     -+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-                                                             -+
/// .                               .                               .
/// .                               .                               .
/// +-                                                             -+
/// |                                                               |
/// +-                      Source Address [N]                     -+
/// |                                                               |
/// +-                                                             -+
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                         Auxiliary Data                        .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastAddressRecordHeader {
    /// Identifies what type of record
    pub record_type: MulticastAddressRecordType,

    /// The Aux Data Len field contains the length of the Auxiliary Data
    /// field in this Multicast Address Record, in units of 32-bit words.
    /// It may contain zero, to indicate the absence of any auxiliary data.
    pub aux_data_len: u8,

    /// The Number of Sources (N) field specifies how many source
    /// addresses are present in this Multicast Address Record.
    pub num_of_sources: u16,

    /// The Multicast Address field contains the multicast address to
    /// which this Multicast Address Record pertains.
    pub multicast_address: [u8; 16],
}

impl MulticastAddressRecordHeader {
    /// Number of bytes/octets an [`MulticastAddressRecordHeader`] takes up in serialized form.
    pub const LEN: usize = 20;

    /// Reads an [`MulticastAddressRecordHeader`] from a slice and returns a
    /// tuple containing the resulting header and the unused part of the
    /// slice.
    ///
    /// The "unused part" is the slice that follows the fixed 20 byte
    /// header (i.e. the source addresses and auxiliary data of the
    /// multicast address record).
    ///
    /// # Errors
    ///
    /// * [`err::LenError`] if the slice is shorter than
    ///   [`MulticastAddressRecordHeader::LEN`] (20 bytes).
    pub fn from_slice(slice: &[u8]) -> Result<(MulticastAddressRecordHeader, &[u8]), LenError> {
        if slice.len() < Self::LEN {
            return Err(LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            });
        }

        // SAFETY: length checked above to be >= Self::LEN (20).
        let header = unsafe {
            MulticastAddressRecordHeader {
                record_type: MulticastAddressRecordType(*slice.get_unchecked(0)),
                aux_data_len: *slice.get_unchecked(1),
                num_of_sources: u16::from_be_bytes([
                    *slice.get_unchecked(2),
                    *slice.get_unchecked(3),
                ]),
                multicast_address: get_unchecked_16_byte_array(slice.as_ptr().add(4)),
            }
        };

        // SAFETY: Safe as the slice was previously verified to have at least the length
        //         Self::LEN.
        let rest = unsafe {
            core::slice::from_raw_parts(slice.as_ptr().add(Self::LEN), slice.len() - Self::LEN)
        };

        Ok((header, rest))
    }

    /// Converts the header to its on-the-wire byte representation.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let n = self.num_of_sources.to_be_bytes();
        let m = &self.multicast_address;
        [
            self.record_type.0,
            self.aux_data_len,
            n[0],
            n[1],
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5],
            m[6],
            m[7],
            m[8],
            m[9],
            m[10],
            m[11],
            m[12],
            m[13],
            m[14],
            m[15],
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{vec, vec::Vec};
    use proptest::prelude::*;

    /// The fixed part of a multicast address record is 20 octets: record
    /// type, aux data len, number of sources & the 16 byte address.
    #[test]
    fn constants() {
        assert_eq!(20, MulticastAddressRecordHeader::LEN);
    }

    proptest! {
        /// `from_slice` must decode every field, return the bytes after the
        /// header as `rest` and report a length error for any short slice.
        #[test]
        fn from_slice(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            num_of_sources in any::<u16>(),
            multicast_address in any::<[u8; 16]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..256usize),
        ) {
            let n_be = num_of_sources.to_be_bytes();
            let mut head = [0u8; MulticastAddressRecordHeader::LEN];
            head[0] = record_type;
            head[1] = aux_data_len;
            head[2] = n_be[0];
            head[3] = n_be[1];
            head[4..20].copy_from_slice(&multicast_address);

            let expected = MulticastAddressRecordHeader {
                record_type: MulticastAddressRecordType(record_type),
                aux_data_len,
                num_of_sources,
                multicast_address,
            };

            // exact length (no trailing bytes)
            {
                let (header, rest) = MulticastAddressRecordHeader::from_slice(&head).unwrap();
                prop_assert_eq!(header, expected);
                prop_assert!(rest.is_empty());
            }

            // with trailing bytes (sources + aux data) returned in `rest`
            {
                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = MulticastAddressRecordHeader::from_slice(&full).unwrap();
                prop_assert_eq!(header, expected);
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // length errors for any slice shorter than LEN
            {
                let buf = [0u8; MulticastAddressRecordHeader::LEN];
                for bad_len in 0..MulticastAddressRecordHeader::LEN {
                    prop_assert_eq!(
                        MulticastAddressRecordHeader::from_slice(&buf[..bad_len]),
                        Err(err::LenError {
                            required_len: MulticastAddressRecordHeader::LEN,
                            len: bad_len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::Mld,
                            layer_start_offset: 0,
                        })
                    );
                }
            }
        }
    }

    proptest! {
        /// `to_bytes` must write the fields at their RFC 9777 offsets, with
        /// the number of sources in network byte order.
        #[test]
        fn to_bytes(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            num_of_sources in any::<u16>(),
            multicast_address in any::<[u8; 16]>(),
        ) {
            let header = MulticastAddressRecordHeader {
                record_type: MulticastAddressRecordType(record_type),
                aux_data_len,
                num_of_sources,
                multicast_address,
            };

            let n_be = num_of_sources.to_be_bytes();
            let mut expected = [0u8; MulticastAddressRecordHeader::LEN];
            expected[0] = record_type;
            expected[1] = aux_data_len;
            expected[2] = n_be[0];
            expected[3] = n_be[1];
            expected[4..20].copy_from_slice(&multicast_address);

            prop_assert_eq!(header.to_bytes(), expected);
        }
    }

    proptest! {
        /// `to_bytes` followed by `from_slice` must return the original
        /// header, with any appended bytes handed back as `rest`.
        #[test]
        fn roundtrip(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            num_of_sources in any::<u16>(),
            multicast_address in any::<[u8; 16]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..256usize),
        ) {
            let original = MulticastAddressRecordHeader {
                record_type: MulticastAddressRecordType(record_type),
                aux_data_len,
                num_of_sources,
                multicast_address,
            };

            // serialize then deserialize: yields the same header and an empty rest.
            {
                let bytes = original.to_bytes();
                let (parsed, rest) = MulticastAddressRecordHeader::from_slice(&bytes).unwrap();
                prop_assert_eq!(parsed, original);
                prop_assert!(rest.is_empty());
            }

            // serialize, append arbitrary suffix bytes, deserialize: same
            // header, suffix returned as `rest`.
            {
                let bytes = original.to_bytes();
                let mut full = vec![];
                full.extend_from_slice(&bytes);
                full.extend_from_slice(&suffix);

                let (parsed, rest) = MulticastAddressRecordHeader::from_slice(&full).unwrap();
                prop_assert_eq!(parsed, original);
                prop_assert_eq!(rest, suffix.as_slice());
            }
        }
    }
}
