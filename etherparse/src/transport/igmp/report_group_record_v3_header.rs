use crate::{err::LenError, igmp::ReportGroupRecordType, *};

/// Header part of an "IGMPv3 Report Group Record".
///
/// The header contains the following parts for the group record:
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Record Type  |  Aux Data Len |     Number of Sources (N)     |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | part of header and this type
/// |                       Multicast Address                       |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                       Source Address [1]                      |
/// +-                                                             -+
/// |                       Source Address [2]                      |
/// +-                                                             -+
/// .                               .                               .
/// .                               .                               .
/// .                               .                               .
/// +-                                                             -+
/// |                       Source Address [N]                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                         Auxiliary Data                        .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportGroupRecordV3Header {
    /// Identifies what type of record
    pub record_type: ReportGroupRecordType,

    /// The Aux Data Len field contains the length of the Auxiliary Data
    /// field in this Group Record, in units of 32-bit words. It may
    /// contain zero, to indicate the absence of any auxiliary data.
    pub aux_data_len: u8,

    /// The Number of Sources (N) field specifies how many source
    /// addresses are present in this Group Record.
    pub num_of_sources: u16,

    /// The Multicast Address field contains the IP multicast address
    /// to which this Group Record pertains.
    pub multicast_address: [u8; 4],
}

impl ReportGroupRecordV3Header {
    /// Number of bytes/octets an [`ReportGroupRecordV3Header`] takes up in serialized form.
    pub const LEN: usize = 8;

    /// Reads an [`ReportGroupRecordV3Header`] from a slice and returns a
    /// tuple containing the resulting header and the unused part of the
    /// slice.
    ///
    /// The "unused part" is the slice that follows the fixed 8 byte
    /// header (i.e. the source addresses and auxiliary data of the
    /// group record).
    ///
    /// # Errors
    ///
    /// * [`err::LenError`] if the slice is shorter than
    ///   [`ReportGroupRecordV3Header::LEN`] (8 bytes).
    pub fn from_slice(slice: &[u8]) -> Result<(ReportGroupRecordV3Header, &[u8]), LenError> {
        if slice.len() < Self::LEN {
            return Err(LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmp,
                layer_start_offset: 0,
            });
        }

        // SAFETY: length checked above to be >= Self::LEN (8).
        let header = unsafe {
            ReportGroupRecordV3Header {
                record_type: ReportGroupRecordType(*slice.get_unchecked(0)),
                aux_data_len: *slice.get_unchecked(1),
                num_of_sources: u16::from_be_bytes([
                    *slice.get_unchecked(2),
                    *slice.get_unchecked(3),
                ]),
                multicast_address: [
                    *slice.get_unchecked(4),
                    *slice.get_unchecked(5),
                    *slice.get_unchecked(6),
                    *slice.get_unchecked(7),
                ],
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
        [
            self.record_type.0,
            self.aux_data_len,
            n[0],
            n[1],
            self.multicast_address[0],
            self.multicast_address[1],
            self.multicast_address[2],
            self.multicast_address[3],
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn constants() {
        assert_eq!(8, ReportGroupRecordV3Header::LEN);
    }

    proptest! {
        #[test]
        fn from_slice(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            num_of_sources in any::<u16>(),
            multicast_address in any::<[u8; 4]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..256usize),
        ) {
            let n_be = num_of_sources.to_be_bytes();
            let head = [
                record_type,
                aux_data_len,
                n_be[0], n_be[1],
                multicast_address[0], multicast_address[1],
                multicast_address[2], multicast_address[3],
            ];

            // exact length (no trailing bytes)
            {
                let (header, rest) = ReportGroupRecordV3Header::from_slice(&head).unwrap();
                prop_assert_eq!(
                    header,
                    ReportGroupRecordV3Header {
                        record_type: ReportGroupRecordType(record_type),
                        aux_data_len,
                        num_of_sources,
                        multicast_address,
                    }
                );
                prop_assert!(rest.is_empty());
            }

            // with trailing bytes (sources + aux data) returned in `rest`
            {
                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = ReportGroupRecordV3Header::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    ReportGroupRecordV3Header {
                        record_type: ReportGroupRecordType(record_type),
                        aux_data_len,
                        num_of_sources,
                        multicast_address,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // length errors for any slice shorter than LEN
            {
                let buf = [0u8; ReportGroupRecordV3Header::LEN];
                for bad_len in 0..ReportGroupRecordV3Header::LEN {
                    prop_assert_eq!(
                        ReportGroupRecordV3Header::from_slice(&buf[..bad_len]),
                        Err(err::LenError {
                            required_len: ReportGroupRecordV3Header::LEN,
                            len: bad_len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::Igmp,
                            layer_start_offset: 0,
                        })
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            num_of_sources in any::<u16>(),
            multicast_address in any::<[u8; 4]>(),
        ) {
            let header = ReportGroupRecordV3Header {
                record_type: ReportGroupRecordType(record_type),
                aux_data_len,
                num_of_sources,
                multicast_address,
            };

            let n_be = num_of_sources.to_be_bytes();
            let expected = [
                record_type,
                aux_data_len,
                n_be[0], n_be[1],
                multicast_address[0], multicast_address[1],
                multicast_address[2], multicast_address[3],
            ];

            prop_assert_eq!(header.to_bytes(), expected);
        }
    }

    proptest! {
        #[test]
        fn roundtrip(
            record_type in any::<u8>(),
            aux_data_len in any::<u8>(),
            num_of_sources in any::<u16>(),
            multicast_address in any::<[u8; 4]>(),
            suffix in proptest::collection::vec(any::<u8>(), 0..256usize),
        ) {
            let original = ReportGroupRecordV3Header {
                record_type: ReportGroupRecordType(record_type),
                aux_data_len,
                num_of_sources,
                multicast_address,
            };

            // serialize then deserialize: yields the same header and an empty rest.
            {
                let bytes = original.to_bytes();
                let (parsed, rest) = ReportGroupRecordV3Header::from_slice(&bytes).unwrap();
                prop_assert_eq!(parsed, original.clone());
                prop_assert!(rest.is_empty());
            }

            // serialize, append arbitrary suffix bytes, deserialize: same
            // header, suffix returned as `rest`.
            {
                let bytes = original.to_bytes();
                let mut full = vec![];
                full.extend_from_slice(&bytes);
                full.extend_from_slice(&suffix);

                let (parsed, rest) = ReportGroupRecordV3Header::from_slice(&full).unwrap();
                prop_assert_eq!(parsed, original);
                prop_assert_eq!(rest, suffix.as_slice());
            }
        }
    }
}
