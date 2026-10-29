use crate::{mld::*, *};

/// A zero-copy slice of an MLD (Multicast Listener Discovery) message,
/// decoded into one variant per message type.
///
/// This mirrors [`MldType`] but keeps the variable-length parts (source
/// address lists & multicast address records) as zero-copy slices instead
/// of copying them. Match on the variant to get typed, compile-time-checked
/// access to the message specific accessors (e.g.
/// `multicast_address_records` is only reachable on
/// [`MldSlice::MulticastListenerReportV2`]).
///
/// # Decoding an MLD message
///
/// MLD is carried within ICMPv6, so an MLD message is decoded from an
/// already parsed [`Icmpv6Slice`]: the ICMPv6 layer owns the type byte, the
/// checksum and bytes 4-7, and [`Icmpv6Slice::payload`] holds everything
/// from byte 8 onwards. All three parts are needed, because the fields at
/// bytes 4-7 are MLD fields (`Maximum Response Delay`/`Maximum Response
/// Code` for queries, `Flags` & `Nr of Mcast Address Records` for the
/// MLDv2 report).
///
/// ```
/// use etherparse::{Icmpv6Slice, MldSlice, icmpv6, mld};
///
/// # // MLDv1 multicast listener report for ff02::1
/// # let mut bytes = [0u8; 24];
/// # bytes[0] = icmpv6::TYPE_MULTICAST_LISTENER_REPORT;
/// # bytes[8] = 0xff;
/// # bytes[9] = 0x02;
/// # bytes[23] = 1;
/// # let icmpv6_bytes = &bytes[..];
/// let icmpv6 = Icmpv6Slice::from_slice(icmpv6_bytes).unwrap();
///
/// // the checksum is part of the ICMPv6 layer and should be verified there
/// // (`icmpv6.is_checksum_valid(source_ip, destination_ip)`).
///
/// // MLD message types are ICMPv6 message types
/// match icmpv6.type_u8() {
///     icmpv6::TYPE_MULTICAST_LISTENER_QUERY
///     | icmpv6::TYPE_MULTICAST_LISTENER_REPORT
///     | icmpv6::TYPE_MULTICAST_LISTENER_REDUCTION
///     | mld::MLDV2_TYPE_MULTICAST_LISTENER_REPORT => {
///         let mld = MldSlice::from_slice(
///             icmpv6.type_u8(),
///             icmpv6.bytes5to8(),
///             icmpv6.payload(),
///         ).unwrap();
///
///         match mld {
///             MldSlice::MulticastListenerReportV1(report) => {
///                 assert_eq!(
///                     report.multicast_address().octets,
///                     [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
///                 );
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// ```
///
/// # Important: Caller must trim to the MLD message length
///
/// For `130` "Multicast Listener Query" messages, the MLD version is
/// determined by message length per [RFC 9777 §8.1](
/// https://datatracker.ietf.org/doc/html/rfc9777#section-8.1):
///
/// * MLDv1 Query: length = 24 octets (so 16 payload octets)
/// * MLDv2 Query: length >= 28 octets (so >= 20 payload octets)
///
/// [`Icmpv6Slice::from_slice`] does not limit the ICMPv6 message to the
/// IPv6 payload length, so the caller **must** trim the input to the exact
/// MLD message boundary (typically derived from the IPv6 payload length)
/// before decoding. If extra trailing bytes are present, a query may be
/// misidentified as MLDv2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MldSlice<'a> {
    /// Multicast Listener Query message (MLDv1, type `130`, 16 payload octets).
    MulticastListenerQuery(MulticastListenerQuerySlice<'a>),

    /// Multicast Listener Query message (MLDv2, type `130`, >= 20 payload
    /// octets) with sources.
    MulticastListenerQueryWithSources(MulticastListenerQueryWithSourcesSlice<'a>),

    /// Multicast Listener Report message (MLDv1, type `131`).
    MulticastListenerReportV1(MulticastListenerReportV1Slice<'a>),

    /// Version 2 Multicast Listener Report message (MLDv2, type `143`)
    /// with multicast address records.
    MulticastListenerReportV2(MulticastListenerReportV2Slice<'a>),

    /// Multicast Listener Done message (MLDv1, type `132`).
    MulticastListenerDone(MulticastListenerDoneSlice<'a>),

    /// Unknown type of MLD message.
    Unknown(MldUnknownSlice<'a>),
}

impl<'a> MldSlice<'a> {
    /// Creates a slice containing an MLD message from the parts of an
    /// ICMPv6 message.
    ///
    /// * `type_u8` is the ICMPv6 type byte ([`Icmpv6Slice::type_u8`]).
    /// * `bytes5to8` are bytes 4-7 of the ICMPv6 header
    ///   ([`Icmpv6Slice::bytes5to8`]), which hold MLD fields.
    /// * `payload` is everything from byte 8 onwards
    ///   ([`Icmpv6Slice::payload`]).
    ///
    /// The ICMPv6 `code` byte is not taken, as it is set to zero by the
    /// sender and ignored by receivers for every MLD message type. The
    /// checksum is part of the ICMPv6 layer and should be verified there
    /// via [`Icmpv6Slice::is_checksum_valid`].
    ///
    /// # Errors
    ///
    /// The function will return an `Err` [`err::LenError`] if the given
    /// payload is too small to contain the fixed part of the message:
    ///
    /// * less than 16 payload bytes for a `131` Multicast Listener Report
    ///   or a `132` Multicast Listener Done message, or
    /// * a payload length other than 16 and below 20 bytes for a `130`
    ///   Multicast Listener Query (which is invalid per RFC 9777).
    ///
    /// For MLDv2 queries the declared source addresses must additionally
    /// be fully contained in the payload.
    ///
    /// The `143` MLDv2 report and unknown types have no minimum payload
    /// length (a report with zero records has an empty payload). The
    /// multicast address records of a `143` report are variable length and
    /// are not validated here; use
    /// [`MulticastListenerReportV2Slice::multicast_address_records`] to
    /// iterate them, which reports length errors lazily.
    #[inline]
    pub fn from_slice(
        type_u8: u8,
        bytes5to8: [u8; 4],
        payload: &'a [u8],
    ) -> Result<MldSlice<'a>, err::LenError> {
        Ok(match type_u8 {
            MLD_TYPE_MULTICAST_LISTENER_QUERY => {
                if payload.len() == MulticastListenerQueryType::PAYLOAD_LEN {
                    // A query with a 16 byte payload (24 byte message) is an
                    // MLDv1 query.
                    // SAFETY: length is exactly
                    //         MulticastListenerQueryType::PAYLOAD_LEN (16).
                    MldSlice::MulticastListenerQuery(unsafe {
                        MulticastListenerQuerySlice::from_slice_unchecked(bytes5to8, payload)
                    })
                } else if payload.len() >= MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN {
                    // A query with a payload of at least 20 bytes (28 byte
                    // message) is an MLDv2 query. Validate that all declared
                    // source addresses (16 bytes each) are actually present.
                    // SAFETY: length checked above to be >= 20, so bytes 18..20 exist.
                    let num_of_sources =
                        usize::from(unsafe { get_unchecked_be_u16(payload.as_ptr().add(18)) });
                    let required_len =
                        MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN + num_of_sources * 16;
                    if payload.len() < required_len {
                        return Err(err::LenError {
                            required_len,
                            len: payload.len(),
                            len_source: LenSource::Slice,
                            layer: err::Layer::Mld,
                            layer_start_offset: 0,
                        });
                    }
                    // SAFETY: length checked to be
                    //         >= MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN (20)
                    //         and to contain all declared source addresses.
                    MldSlice::MulticastListenerQueryWithSources(unsafe {
                        MulticastListenerQueryWithSourcesSlice::from_slice_unchecked(
                            bytes5to8, payload,
                        )
                    })
                } else {
                    // A query with a payload length other then 16 and below
                    // 20 bytes is invalid per RFC 9777.
                    return Err(err::LenError {
                        required_len: if payload.len() < MulticastListenerQueryType::PAYLOAD_LEN {
                            MulticastListenerQueryType::PAYLOAD_LEN
                        } else {
                            MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN
                        },
                        len: payload.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    });
                }
            }
            MLDV1_TYPE_MULTICAST_LISTENER_REPORT => {
                if payload.len() < MulticastListenerReportV1Type::PAYLOAD_LEN {
                    return Err(err::LenError {
                        required_len: MulticastListenerReportV1Type::PAYLOAD_LEN,
                        len: payload.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    });
                }
                // SAFETY: length checked above to be >= 16.
                MldSlice::MulticastListenerReportV1(unsafe {
                    MulticastListenerReportV1Slice::from_slice_unchecked(bytes5to8, payload)
                })
            }
            MLDV1_TYPE_MULTICAST_LISTENER_DONE => {
                if payload.len() < MulticastListenerDoneType::PAYLOAD_LEN {
                    return Err(err::LenError {
                        required_len: MulticastListenerDoneType::PAYLOAD_LEN,
                        len: payload.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    });
                }
                // SAFETY: length checked above to be >= 16.
                MldSlice::MulticastListenerDone(unsafe {
                    MulticastListenerDoneSlice::from_slice_unchecked(bytes5to8, payload)
                })
            }
            // All fixed fields of a v2 report are in `bytes5to8` and the
            // multicast address records are variable length and NOT
            // validated here, so any payload length is accepted.
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT => MldSlice::MulticastListenerReportV2(
                MulticastListenerReportV2Slice::new(bytes5to8, payload),
            ),
            _ => MldSlice::Unknown(MldUnknownSlice::new(type_u8, bytes5to8, payload)),
        })
    }

    /// Decode the message values into an [`MldType`] enum.
    #[inline]
    pub fn mld_type(&self) -> MldType {
        match self {
            MldSlice::MulticastListenerQuery(s) => MldType::MulticastListenerQuery(s.to_header()),
            MldSlice::MulticastListenerQueryWithSources(s) => {
                MldType::MulticastListenerQueryWithSources(s.to_header())
            }
            MldSlice::MulticastListenerReportV1(s) => {
                MldType::MulticastListenerReportV1(s.to_header())
            }
            MldSlice::MulticastListenerReportV2(s) => {
                MldType::MulticastListenerReportV2(s.to_header())
            }
            MldSlice::MulticastListenerDone(s) => MldType::MulticastListenerDone(s.to_header()),
            MldSlice::Unknown(s) => MldType::Unknown(s.to_header()),
        }
    }

    /// Returns the "type" byte value of the ICMPv6 header carrying this
    /// MLD message.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        match self {
            MldSlice::MulticastListenerQuery(_)
            | MldSlice::MulticastListenerQueryWithSources(_) => MLD_TYPE_MULTICAST_LISTENER_QUERY,
            MldSlice::MulticastListenerReportV1(_) => MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
            MldSlice::MulticastListenerReportV2(_) => MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            MldSlice::MulticastListenerDone(_) => MLDV1_TYPE_MULTICAST_LISTENER_DONE,
            MldSlice::Unknown(s) => s.type_u8(),
        }
    }

    /// Returns bytes 4-7 of the ICMPv6 header.
    ///
    /// The meaning of these bytes depends on the message type:
    ///
    /// | Message Type | Bytes 4-5 | Bytes 6-7 |
    /// |---|---|---|
    /// | [`MldSlice::MulticastListenerQuery`] (v1) | Maximum Response Delay | Reserved |
    /// | [`MldSlice::MulticastListenerQueryWithSources`] (v2) | Maximum Response Code | Reserved |
    /// | [`MldSlice::MulticastListenerReportV1`] | Unused | Reserved |
    /// | [`MldSlice::MulticastListenerReportV2`] | Flags | Nr of Mcast Address Records (M) |
    /// | [`MldSlice::MulticastListenerDone`] | Unused | Reserved |
    /// | [`MldSlice::Unknown`] | unknown | unknown |
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        match self {
            MldSlice::MulticastListenerQuery(s) => s.bytes5to8(),
            MldSlice::MulticastListenerQueryWithSources(s) => s.bytes5to8(),
            MldSlice::MulticastListenerReportV1(s) => s.bytes5to8(),
            MldSlice::MulticastListenerReportV2(s) => s.bytes5to8(),
            MldSlice::MulticastListenerDone(s) => s.bytes5to8(),
            MldSlice::Unknown(s) => s.bytes5to8(),
        }
    }

    /// Number of payload bytes/octets taken up by the fixed part of this
    /// message type (the part decoded into [`MldSlice::mld_type`]).
    #[inline]
    pub fn fixed_payload_len(&self) -> usize {
        match self {
            MldSlice::MulticastListenerQuery(_) => MulticastListenerQueryType::PAYLOAD_LEN,
            MldSlice::MulticastListenerQueryWithSources(_) => {
                MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN
            }
            MldSlice::MulticastListenerReportV1(_) => MulticastListenerReportV1Type::PAYLOAD_LEN,
            MldSlice::MulticastListenerReportV2(_) => MulticastListenerReportV2Header::PAYLOAD_LEN,
            MldSlice::MulticastListenerDone(_) => MulticastListenerDoneType::PAYLOAD_LEN,
            MldSlice::Unknown(_) => UnknownHeader::PAYLOAD_LEN,
        }
    }

    /// Returns a slice to the payload bytes not covered by
    /// [`MldSlice::mld_type`].
    ///
    /// The contents depend on the message type:
    ///
    /// | Message Type | Content |
    /// |---|---|
    /// | [`MldSlice::MulticastListenerQuery`] (v1) | Nothing (empty) |
    /// | [`MldSlice::MulticastListenerQueryWithSources`] (v2) | Source Address list |
    /// | [`MldSlice::MulticastListenerReportV1`] | Nothing (empty, unless trailing data) |
    /// | [`MldSlice::MulticastListenerReportV2`] | Multicast Address Records |
    /// | [`MldSlice::MulticastListenerDone`] | Nothing (empty, unless trailing data) |
    /// | [`MldSlice::Unknown`] | The complete ICMPv6 payload |
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match self {
            MldSlice::MulticastListenerQuery(s) => {
                // v1 queries always have a payload of exactly 16 bytes.
                let slice = s.slice();
                // SAFETY: from_slice guarantees exactly 16 bytes.
                unsafe {
                    core::slice::from_raw_parts(
                        slice.as_ptr().add(MulticastListenerQueryType::PAYLOAD_LEN),
                        slice.len() - MulticastListenerQueryType::PAYLOAD_LEN,
                    )
                }
            }
            MldSlice::MulticastListenerQueryWithSources(s) => s.payload(),
            MldSlice::MulticastListenerReportV1(s) => s.payload(),
            MldSlice::MulticastListenerReportV2(s) => s.payload(),
            MldSlice::MulticastListenerDone(s) => s.payload(),
            MldSlice::Unknown(s) => s.payload(),
        }
    }

    /// Returns the slice containing the complete ICMPv6 payload of the MLD
    /// message (everything that was passed to [`MldSlice::from_slice`]).
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        match self {
            MldSlice::MulticastListenerQuery(s) => s.slice(),
            MldSlice::MulticastListenerQueryWithSources(s) => s.slice(),
            MldSlice::MulticastListenerReportV1(s) => s.slice(),
            MldSlice::MulticastListenerReportV2(s) => s.slice(),
            MldSlice::MulticastListenerDone(s) => s.slice(),
            MldSlice::Unknown(s) => s.slice(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    /// Returns a `ff02::<last>` style multicast address.
    fn multicast_addr(last: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xFF;
        addr[1] = 0x02;
        addr[15] = last;
        addr
    }

    /// Returns a `2001::<index>` style source address.
    fn source_addr(index: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = index;
        addr
    }

    /// Builds the 16 byte payload of an MLDv1 message.
    fn v1_payload(multicast_address: [u8; 16]) -> Vec<u8> {
        multicast_address.to_vec()
    }

    /// Builds the payload of an MLDv2 query with the given source addresses.
    fn v2_query_payload(
        multicast_address: [u8; 16],
        raw_byte_16: u8,
        qqic: u8,
        sources: &[[u8; 16]],
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0..16].copy_from_slice(&multicast_address);
        bytes[16] = raw_byte_16;
        bytes[17] = qqic;
        bytes[18..20].copy_from_slice(&(sources.len() as u16).to_be_bytes());
        for source in sources {
            bytes.extend_from_slice(source);
        }
        bytes
    }

    /// Builds a single MLDv2 multicast address record.
    fn record_bytes(
        record_type: u8,
        aux_data_len: u8,
        sources: &[[u8; 16]],
        multicast_address: [u8; 16],
    ) -> Vec<u8> {
        let n = (sources.len() as u16).to_be_bytes();
        let mut bytes = vec![record_type, aux_data_len, n[0], n[1]];
        bytes.extend_from_slice(&multicast_address);
        for source in sources {
            bytes.extend_from_slice(source);
        }
        for _ in 0..aux_data_len {
            bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        }
        bytes
    }

    /// `bytes5to8` of a report with the given flags & record count.
    fn report_v2_bytes5to8(flags: [u8; 2], num_of_records: u16) -> [u8; 4] {
        let n = num_of_records.to_be_bytes();
        [flags[0], flags[1], n[0], n[1]]
    }

    /// `bytes5to8` of a query with the given max response delay/code.
    fn query_bytes5to8(max_response: u16) -> [u8; 4] {
        let m = max_response.to_be_bytes();
        [m[0], m[1], 0, 0]
    }

    /// Query version detection keys off the payload length (RFC 9777
    /// section 8.1), so every length that is neither exactly 16 (MLDv1) nor
    /// at least 20 (MLDv2) must be rejected as too short.
    #[test]
    fn from_slice_query_invalid_payload_length() {
        // any query payload length that is neither 16 nor >= 20 must fail
        for bad_len in 0..MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN {
            if bad_len == MulticastListenerQueryType::PAYLOAD_LEN {
                continue;
            }
            let payload = vec![0u8; bad_len];
            assert_eq!(
                MldSlice::from_slice(
                    MLD_TYPE_MULTICAST_LISTENER_QUERY,
                    query_bytes5to8(0),
                    &payload
                )
                .unwrap_err(),
                err::LenError {
                    required_len: if bad_len < MulticastListenerQueryType::PAYLOAD_LEN {
                        MulticastListenerQueryType::PAYLOAD_LEN
                    } else {
                        MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN
                    },
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Mld,
                    layer_start_offset: 0,
                }
            );
        }
    }

    /// A 16 byte query payload must decode as MLDv1, exposing the max
    /// response delay & multicast address with no payload left over.
    #[test]
    fn from_slice_v1_query() {
        let payload = v1_payload(multicast_addr(0));

        let slice = MldSlice::from_slice(
            MLD_TYPE_MULTICAST_LISTENER_QUERY,
            query_bytes5to8(1000),
            &payload,
        )
        .unwrap();
        assert_eq!(slice.type_u8(), MLD_TYPE_MULTICAST_LISTENER_QUERY);
        assert_eq!(slice.fixed_payload_len(), 16);
        assert_eq!(slice.payload(), &[]);
        assert_eq!(slice.bytes5to8(), [0x03, 0xE8, 0, 0]);
        assert_eq!(slice.slice(), &payload[..]);

        let query = match &slice {
            MldSlice::MulticastListenerQuery(q) => q,
            other => panic!("expected MulticastListenerQuery, got {:?}", other),
        };
        assert_eq!(query.max_response_delay(), 1000);
        assert_eq!(query.multicast_address().octets, multicast_addr(0));

        match slice.mld_type() {
            MldType::MulticastListenerQuery(q) => {
                assert_eq!(q.max_response_delay, 1000);
                assert_eq!(q.multicast_address.octets, multicast_addr(0));
            }
            other => panic!("expected MulticastListenerQuery, got {:?}", other),
        }
    }

    /// A general query carries the unspecified address, which must decode
    /// into a multicast address that reports `is_zero`.
    #[test]
    fn from_slice_v1_general_query() {
        // a general query has a multicast address of zero
        let payload = v1_payload([0u8; 16]);
        let slice = MldSlice::from_slice(
            MLD_TYPE_MULTICAST_LISTENER_QUERY,
            query_bytes5to8(10000),
            &payload,
        )
        .unwrap();
        match slice {
            MldSlice::MulticastListenerQuery(q) => {
                assert!(q.multicast_address().is_zero());
                assert_eq!(q.max_response_delay(), 10000);
            }
            other => panic!("expected MulticastListenerQuery, got {:?}", other),
        }
    }

    /// A query payload of 20 or more bytes must decode as MLDv2, exposing
    /// the byte 16 bit fields, QQIC and the source address list.
    #[test]
    fn from_slice_v2_query() {
        let payload = v2_query_payload(
            multicast_addr(1),
            0x0A, // flags = 0, S = 1, QRV = 2
            125,
            &[source_addr(1)],
        );

        let slice = MldSlice::from_slice(
            MLD_TYPE_MULTICAST_LISTENER_QUERY,
            query_bytes5to8(0x8001), // exponential max response code
            &payload,
        )
        .unwrap();
        assert_eq!(
            slice.fixed_payload_len(),
            MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN
        );
        assert_eq!(slice.payload().len(), 16);
        assert_eq!(slice.type_u8(), MLD_TYPE_MULTICAST_LISTENER_QUERY);

        let query = match &slice {
            MldSlice::MulticastListenerQueryWithSources(q) => q,
            other => panic!(
                "expected MulticastListenerQueryWithSources, got {:?}",
                other
            ),
        };
        assert_eq!(query.max_response_code().0, 0x8001);
        assert_eq!(query.max_response_code().as_millis(), 0x1001 << 3);
        assert_eq!(query.multicast_address().octets, multicast_addr(1));
        assert_eq!(query.raw_byte_16(), 0x0A);
        assert_eq!(query.flags(), 0);
        assert!(query.s_flag());
        assert_eq!(query.qrv().value(), 2);
        assert_eq!(query.qqic(), 125);
        assert_eq!(query.num_of_sources(), 1);
        assert_eq!(query.source_addrs_bytes(), &source_addr(1)[..]);
        assert_eq!(
            query.source_addresses().collect::<Vec<_>>(),
            vec![source_addr(1)]
        );

        match slice.mld_type() {
            MldType::MulticastListenerQueryWithSources(q) => {
                assert_eq!(q.max_response_code.0, 0x8001);
                assert_eq!(q.multicast_address.octets, multicast_addr(1));
                assert_eq!(q.raw_byte_16, 0x0A);
                assert_eq!(q.qqic, 125);
                assert_eq!(q.num_of_sources, 1);
                assert!(q.s_flag());
                assert_eq!(q.qrv().value(), 2);
            }
            other => panic!(
                "expected MulticastListenerQueryWithSources, got {:?}",
                other
            ),
        }
    }

    /// An MLDv2 general query has an empty source list but still a 20 byte
    /// payload, so it must decode as MLDv2 rather than MLDv1.
    #[test]
    fn from_slice_v2_query_no_sources() {
        // A general MLDv2 query carries no sources but still has a >= 20 byte payload.
        let payload = v2_query_payload([0u8; 16], 0, 0, &[]);
        assert_eq!(payload.len(), 20);
        let slice = MldSlice::from_slice(
            MLD_TYPE_MULTICAST_LISTENER_QUERY,
            query_bytes5to8(100),
            &payload,
        )
        .unwrap();
        match slice {
            MldSlice::MulticastListenerQueryWithSources(q) => {
                assert_eq!(q.num_of_sources(), 0);
                assert_eq!(q.source_addrs_bytes(), &[]);
                assert_eq!(q.source_addresses().len(), 0);
                assert!(q.multicast_address().is_zero());
                assert_eq!(q.max_response_code().0, 100);
            }
            other => panic!(
                "expected MulticastListenerQueryWithSources, got {:?}",
                other
            ),
        }
    }

    /// An MLDv1 report must decode into the report variant and expose its
    /// multicast address.
    #[test]
    fn from_slice_v1_report() {
        let payload = v1_payload(multicast_addr(2));

        let slice =
            MldSlice::from_slice(MLDV1_TYPE_MULTICAST_LISTENER_REPORT, [0; 4], &payload).unwrap();
        assert_eq!(slice.type_u8(), MLDV1_TYPE_MULTICAST_LISTENER_REPORT);
        assert_eq!(slice.fixed_payload_len(), 16);
        assert_eq!(slice.payload(), &[]);

        let report = match &slice {
            MldSlice::MulticastListenerReportV1(r) => r,
            other => panic!("expected MulticastListenerReportV1, got {:?}", other),
        };
        assert_eq!(report.multicast_address().octets, multicast_addr(2));
        assert_eq!(report.bytes5to8(), [0; 4]);

        match slice.mld_type() {
            MldType::MulticastListenerReportV1(r) => {
                assert_eq!(r.multicast_address.octets, multicast_addr(2));
            }
            other => panic!("expected MulticastListenerReportV1, got {:?}", other),
        }
    }

    /// A "Multicast Listener Done" must decode into the done variant and
    /// expose its multicast address.
    #[test]
    fn from_slice_done() {
        let payload = v1_payload(multicast_addr(3));

        let slice =
            MldSlice::from_slice(MLDV1_TYPE_MULTICAST_LISTENER_DONE, [0; 4], &payload).unwrap();
        assert_eq!(slice.type_u8(), MLDV1_TYPE_MULTICAST_LISTENER_DONE);
        assert_eq!(slice.fixed_payload_len(), 16);

        let done = match &slice {
            MldSlice::MulticastListenerDone(d) => d,
            other => panic!("expected MulticastListenerDone, got {:?}", other),
        };
        assert_eq!(done.multicast_address().octets, multicast_addr(3));
        assert_eq!(done.bytes5to8(), [0; 4]);

        match slice.mld_type() {
            MldType::MulticastListenerDone(d) => {
                assert_eq!(d.multicast_address.octets, multicast_addr(3));
            }
            other => panic!("expected MulticastListenerDone, got {:?}", other),
        }
    }

    /// Reports & done messages always carry a 16 byte multicast address,
    /// so any shorter payload must be rejected with a length error.
    #[test]
    fn from_slice_v1_report_and_done_too_short() {
        for type_u8 in [
            MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
            MLDV1_TYPE_MULTICAST_LISTENER_DONE,
        ] {
            for bad_len in 0..MulticastListenerReportV1Type::PAYLOAD_LEN {
                let payload = vec![0u8; bad_len];
                assert_eq!(
                    MldSlice::from_slice(type_u8, [0; 4], &payload).unwrap_err(),
                    err::LenError {
                        required_len: MulticastListenerReportV1Type::PAYLOAD_LEN,
                        len: bad_len,
                        len_source: LenSource::Slice,
                        layer: err::Layer::Mld,
                        layer_start_offset: 0,
                    }
                );
            }
        }
    }

    /// An MLDv2 report keeps all of its data in the payload, so
    /// `fixed_payload_len` must be zero and the records must stay available.
    #[test]
    fn from_slice_v2_report() {
        let payload = record_bytes(1, 0, &[], multicast_addr(1));

        let slice = MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0, 0], 1),
            &payload,
        )
        .unwrap();
        assert_eq!(slice.type_u8(), MLDV2_TYPE_MULTICAST_LISTENER_REPORT);
        assert_eq!(slice.fixed_payload_len(), 0);
        assert_eq!(slice.payload().len(), 20);

        let report = match &slice {
            MldSlice::MulticastListenerReportV2(r) => r,
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        };
        assert_eq!(report.num_of_records(), 1);
        assert_eq!(report.flags(), [0, 0]);

        match slice.mld_type() {
            MldType::MulticastListenerReportV2(r) => {
                assert_eq!(r.num_of_records, 1);
                assert_eq!(r.flags, [0, 0]);
            }
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        }
    }

    /// A report with zero records has an empty payload, which must be
    /// accepted and yield an empty record iterator.
    #[test]
    fn from_slice_v2_report_empty_payload() {
        // A report with zero records has an empty ICMPv6 payload.
        let slice = MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0, 0], 0),
            &[],
        )
        .unwrap();
        let report = match &slice {
            MldSlice::MulticastListenerReportV2(r) => r,
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        };
        assert_eq!(report.num_of_records(), 0);
        assert_eq!(report.payload(), &[]);
        assert_eq!(report.multicast_address_records().count(), 0);
    }

    /// The report flags come from bytes 4-5 of the ICMPv6 header, so they
    /// must be readable through both `bytes5to8` and `flags`.
    #[test]
    fn from_slice_v2_report_flags() {
        let slice = MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0x01, 0x02], 0),
            &[],
        )
        .unwrap();
        assert_eq!(slice.bytes5to8(), [0x01, 0x02, 0, 0]);
        match slice {
            MldSlice::MulticastListenerReportV2(r) => {
                assert_eq!(r.flags(), [0x01, 0x02]);
                assert_ne!(
                    0,
                    r.flags()[0] & MulticastListenerReportV2Header::FLAGS_0_EXTENSION_MASK
                );
            }
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        }
    }

    /// An unrecognized type id must decode into the unknown variant, which
    /// keeps the raw bytes 4-7 and hands back the whole payload.
    #[test]
    fn from_slice_unknown_type() {
        let payload = [1u8, 2, 3, 4];

        let slice = MldSlice::from_slice(0xFF, [1, 2, 3, 4], &payload).unwrap();
        assert_eq!(slice.type_u8(), 0xFF);
        assert_eq!(slice.fixed_payload_len(), 0);
        assert_eq!(slice.payload(), &payload);

        let unknown = match &slice {
            MldSlice::Unknown(u) => u,
            other => panic!("expected Unknown, got {:?}", other),
        };
        assert_eq!(unknown.type_u8(), 0xFF);
        assert_eq!(unknown.bytes5to8(), [1, 2, 3, 4]);

        match slice.mld_type() {
            MldType::Unknown(u) => {
                assert_eq!(u.mld_type, 0xFF);
                assert_eq!(u.raw_bytes_4_7, [1, 2, 3, 4]);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    /// An unknown type has no length requirement, so an empty payload must
    /// be accepted.
    #[test]
    fn from_slice_unknown_type_empty_payload() {
        let slice = MldSlice::from_slice(0xFE, [0; 4], &[]).unwrap();
        assert!(matches!(slice, MldSlice::Unknown(_)));
        assert_eq!(slice.payload(), &[]);
    }

    /// Bytes after the fixed part of a message must not be rejected and
    /// must be returned by `payload`.
    #[test]
    fn from_slice_with_trailing_payload() {
        // v1 report with trailing data
        let mut payload = v1_payload(multicast_addr(1));
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let slice =
            MldSlice::from_slice(MLDV1_TYPE_MULTICAST_LISTENER_REPORT, [0; 4], &payload).unwrap();
        assert_eq!(slice.fixed_payload_len(), 16);
        assert_eq!(slice.payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// An MLDv2 query has a single, fixed source list, so a declared count
    /// the payload cannot hold must be rejected up front.
    #[test]
    fn from_slice_v2_query_too_short_sources() {
        // Declares 5 sources but only carries room for 1 -> from_slice
        // must reject the payload as too short.
        let mut payload = v2_query_payload(multicast_addr(1), 0, 0, &[source_addr(1)]);
        payload[18..20].copy_from_slice(&5u16.to_be_bytes());

        assert_eq!(
            MldSlice::from_slice(
                MLD_TYPE_MULTICAST_LISTENER_QUERY,
                query_bytes5to8(0),
                &payload
            )
            .unwrap_err(),
            err::LenError {
                required_len: MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN + 5 * 16,
                len: 36,
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    /// Checks the source list length boundary: a payload holding exactly
    /// the declared sources must be accepted, one byte less rejected.
    #[test]
    fn from_slice_v2_query_exact_sources() {
        // Exactly enough room for the declared sources must be accepted.
        let payload = v2_query_payload(multicast_addr(1), 0, 0, &[source_addr(1), source_addr(2)]);
        assert_eq!(payload.len(), 20 + 2 * 16);

        let slice = MldSlice::from_slice(
            MLD_TYPE_MULTICAST_LISTENER_QUERY,
            query_bytes5to8(0),
            &payload,
        )
        .unwrap();
        assert!(matches!(
            slice,
            MldSlice::MulticastListenerQueryWithSources(_)
        ));

        // One byte short must be rejected.
        assert_eq!(
            MldSlice::from_slice(
                MLD_TYPE_MULTICAST_LISTENER_QUERY,
                query_bytes5to8(0),
                &payload[..payload.len() - 1]
            )
            .unwrap_err(),
            err::LenError {
                required_len: MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN + 2 * 16,
                len: payload.len() - 1,
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
    }

    /// Unlike the query source list, report records are validated lazily,
    /// so an overstated record count must still decode successfully.
    #[test]
    fn from_slice_v2_report_records_not_validated() {
        // Declares 2 records but only provides 1 -> from_slice still
        // succeeds; the records are validated lazily by the iterator.
        let payload = record_bytes(1, 0, &[source_addr(1)], multicast_addr(1));

        let slice = MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0, 0], 2),
            &payload,
        )
        .unwrap();
        assert!(matches!(slice, MldSlice::MulticastListenerReportV2(_)));
    }

    /// A record count larger than the payload must surface as a length
    /// error from the iterator, which then ends instead of repeating it.
    #[test]
    fn multicast_address_records_iter_stops_on_missing_record() {
        let payload = record_bytes(1, 0, &[source_addr(1)], multicast_addr(1));
        // record 2 is missing entirely

        let report = match MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0, 0], 2),
            &payload,
        )
        .unwrap()
        {
            MldSlice::MulticastListenerReportV2(r) => r,
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        };
        let mut iter = report.multicast_address_records();
        // first record parses fine
        assert!(iter.next().unwrap().is_ok());
        // second record is missing entirely -> error
        assert_eq!(
            iter.next().unwrap().unwrap_err(),
            err::LenError {
                required_len: MulticastAddressRecordHeader::LEN,
                len: 0,
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
        // iteration stops after the error
        assert!(iter.next().is_none());
    }

    /// A record declaring more sources than it carries must end iteration
    /// with a length error naming the full required record length.
    #[test]
    fn multicast_address_records_iter_stops_on_short_record() {
        // A single record that declares more sources than it carries.
        let mut payload = record_bytes(1, 0, &[source_addr(1)], multicast_addr(1));
        payload[2..4].copy_from_slice(&2u16.to_be_bytes()); // declares 2 sources

        let report = match MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0, 0], 1),
            &payload,
        )
        .unwrap()
        {
            MldSlice::MulticastListenerReportV2(r) => r,
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        };
        let mut iter = report.multicast_address_records();
        assert_eq!(
            iter.next().unwrap().unwrap_err(),
            err::LenError {
                required_len: MulticastAddressRecordHeader::LEN + 2 * 16,
                len: 36, // bytes available for the record
                len_source: LenSource::Slice,
                layer: err::Layer::Mld,
                layer_start_offset: 0,
            }
        );
        assert!(iter.next().is_none());
    }

    /// Records vary in length, so a well formed report must yield every
    /// record with its own type, address & source list.
    #[test]
    fn multicast_address_records_iter_all_records() {
        let mut payload = record_bytes(1, 0, &[], multicast_addr(1));
        payload.extend_from_slice(&record_bytes(2, 0, &[source_addr(5)], multicast_addr(2)));

        let report = match MldSlice::from_slice(
            MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
            report_v2_bytes5to8([0, 0], 2),
            &payload,
        )
        .unwrap()
        {
            MldSlice::MulticastListenerReportV2(r) => r,
            other => panic!("expected MulticastListenerReportV2, got {:?}", other),
        };
        let records: Vec<_> = report
            .multicast_address_records()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].multicast_address(), multicast_addr(1));
        assert_eq!(records[0].num_of_sources(), 0);
        assert_eq!(
            records[0].record_type(),
            MulticastAddressRecordType::MODE_IS_INCLUDE
        );
        assert_eq!(records[1].multicast_address(), multicast_addr(2));
        assert_eq!(records[1].source_addrs_bytes(), &source_addr(5)[..]);
        assert_eq!(
            records[1].record_type(),
            MulticastAddressRecordType::MODE_IS_EXCLUDE
        );
    }

    /// Decoding an MLD message out of an `Icmpv6Slice` must work for every
    /// message type, and the slice accessors must agree with the ICMPv6
    /// ones.
    #[test]
    fn decode_from_icmpv6_slice() {
        let cases: Vec<(u8, [u8; 4], Vec<u8>)> = vec![
            (
                MLD_TYPE_MULTICAST_LISTENER_QUERY,
                query_bytes5to8(1000),
                v1_payload(multicast_addr(0)),
            ),
            (
                MLD_TYPE_MULTICAST_LISTENER_QUERY,
                query_bytes5to8(1000),
                v2_query_payload(multicast_addr(1), 0x0A, 125, &[source_addr(1)]),
            ),
            (
                MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
                [0; 4],
                v1_payload(multicast_addr(2)),
            ),
            (
                MLDV1_TYPE_MULTICAST_LISTENER_DONE,
                [0; 4],
                v1_payload(multicast_addr(3)),
            ),
            (
                MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
                report_v2_bytes5to8([0, 0], 1),
                record_bytes(1, 0, &[], multicast_addr(4)),
            ),
            (MLDV2_TYPE_MULTICAST_LISTENER_REPORT, [0; 4], vec![]),
            (0xFE, [9, 9, 9, 9], vec![1, 2, 3]),
        ];

        for (type_u8, bytes5to8, payload) in cases {
            // build the complete ICMPv6 message
            let mut icmpv6_bytes = vec![type_u8, 0, 0, 0];
            icmpv6_bytes.extend_from_slice(&bytes5to8);
            icmpv6_bytes.extend_from_slice(&payload);

            let icmpv6 = Icmpv6Slice::from_slice(&icmpv6_bytes).unwrap();
            assert_eq!(icmpv6.type_u8(), type_u8);
            assert_eq!(icmpv6.bytes5to8(), bytes5to8);
            assert_eq!(icmpv6.payload(), &payload[..]);

            let mld = MldSlice::from_slice(icmpv6.type_u8(), icmpv6.bytes5to8(), icmpv6.payload())
                .unwrap();

            assert_eq!(mld.type_u8(), icmpv6.type_u8());
            assert_eq!(mld.bytes5to8(), icmpv6.bytes5to8());
            assert_eq!(mld.slice(), icmpv6.payload());
            assert_eq!(
                mld.payload(),
                &mld.slice()[mld.fixed_payload_len()..],
                "payload mismatch for type {}",
                type_u8
            );
            // mld_type() must round-trip the decoded fields
            assert_eq!(mld.mld_type(), mld.mld_type());
        }
    }

    proptest! {
        /// The common accessors must return exactly what was passed to
        /// `from_slice` for any type id without a length requirement.
        #[test]
        fn accessors(
            type_u8 in any::<u8>(),
            bytes5to8 in any::<[u8; 4]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            // Avoid the types with length requirements / source list
            // validation so that any generated payload is accepted.
            let type_u8 = if [
                MLD_TYPE_MULTICAST_LISTENER_QUERY,
                MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
                MLDV1_TYPE_MULTICAST_LISTENER_DONE,
            ].contains(&type_u8) {
                0xFF
            } else {
                type_u8
            };

            let slice = MldSlice::from_slice(type_u8, bytes5to8, &payload).unwrap();
            prop_assert_eq!(type_u8, slice.type_u8());
            prop_assert_eq!(bytes5to8, slice.bytes5to8());
            prop_assert_eq!(&payload[..], slice.slice());
            prop_assert_eq!(&payload[..], slice.payload());
            prop_assert_eq!(0, slice.fixed_payload_len());
        }
    }

    proptest! {
        /// `Clone`, `PartialEq` & `Debug` must be derived for the enum.
        #[test]
        fn clone_eq_debug(multicast_address in any::<[u8; 16]>()) {
            let payload = v1_payload(multicast_address);
            let slice = MldSlice::from_slice(
                MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
                [0; 4],
                &payload,
            ).unwrap();
            prop_assert_eq!(&slice, &slice.clone());
            let dbg = format!("{:?}", slice);
            prop_assert!(dbg.contains("Slice"), "{}", dbg);
        }
    }

    proptest! {
        /// Round-trip the fields of every variant through the slice and
        /// confirm the decoded `MldType` matches.
        #[test]
        fn mld_type_roundtrip(
            max_response in any::<u16>(),
            multicast_address in any::<[u8; 16]>(),
            raw_byte_16 in any::<u8>(),
            qqic in any::<u8>(),
            report_flags in any::<[u8; 2]>(),
            num_of_records in any::<u16>(),
            unknown_type in any::<u8>().prop_filter(
                "must not be a known MLD type",
                |t| ![
                    MLD_TYPE_MULTICAST_LISTENER_QUERY,
                    MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
                    MLDV1_TYPE_MULTICAST_LISTENER_DONE,
                    MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
                ].contains(t),
            ),
            unknown_bytes5to8 in any::<[u8; 4]>(),
        ) {
            // MLDv1 query
            {
                let payload = v1_payload(multicast_address);
                let slice = MldSlice::from_slice(
                    MLD_TYPE_MULTICAST_LISTENER_QUERY,
                    query_bytes5to8(max_response),
                    &payload,
                ).unwrap();
                prop_assert_eq!(
                    slice.mld_type(),
                    MldType::MulticastListenerQuery(mld::MulticastListenerQueryType {
                        max_response_delay: max_response,
                        multicast_address: multicast_address.into(),
                    })
                );
            }

            // MLDv2 query (no sources, so any declared count of 0 is valid)
            {
                let payload = v2_query_payload(multicast_address, raw_byte_16, qqic, &[]);
                let slice = MldSlice::from_slice(
                    MLD_TYPE_MULTICAST_LISTENER_QUERY,
                    query_bytes5to8(max_response),
                    &payload,
                ).unwrap();
                prop_assert_eq!(
                    slice.mld_type(),
                    MldType::MulticastListenerQueryWithSources(
                        mld::MulticastListenerQueryWithSourcesHeader {
                            max_response_code: mld::MaxResponseCode(max_response),
                            multicast_address: multicast_address.into(),
                            raw_byte_16,
                            qqic,
                            num_of_sources: 0,
                        }
                    )
                );
            }

            // MLDv1 report
            {
                let payload = v1_payload(multicast_address);
                let slice = MldSlice::from_slice(
                    MLDV1_TYPE_MULTICAST_LISTENER_REPORT,
                    [0; 4],
                    &payload,
                ).unwrap();
                prop_assert_eq!(
                    slice.mld_type(),
                    MldType::MulticastListenerReportV1(mld::MulticastListenerReportV1Type {
                        multicast_address: multicast_address.into(),
                    })
                );
            }

            // MLDv1 done
            {
                let payload = v1_payload(multicast_address);
                let slice = MldSlice::from_slice(
                    MLDV1_TYPE_MULTICAST_LISTENER_DONE,
                    [0; 4],
                    &payload,
                ).unwrap();
                prop_assert_eq!(
                    slice.mld_type(),
                    MldType::MulticastListenerDone(mld::MulticastListenerDoneType {
                        multicast_address: multicast_address.into(),
                    })
                );
            }

            // MLDv2 report
            {
                let slice = MldSlice::from_slice(
                    MLDV2_TYPE_MULTICAST_LISTENER_REPORT,
                    report_v2_bytes5to8(report_flags, num_of_records),
                    &[],
                ).unwrap();
                prop_assert_eq!(
                    slice.mld_type(),
                    MldType::MulticastListenerReportV2(mld::MulticastListenerReportV2Header {
                        flags: report_flags,
                        num_of_records,
                    })
                );
            }

            // unknown
            {
                let slice = MldSlice::from_slice(
                    unknown_type,
                    unknown_bytes5to8,
                    &[],
                ).unwrap();
                prop_assert_eq!(
                    slice.mld_type(),
                    MldType::Unknown(mld::UnknownHeader {
                        mld_type: unknown_type,
                        raw_bytes_4_7: unknown_bytes5to8,
                    })
                );
            }
        }
    }
}
