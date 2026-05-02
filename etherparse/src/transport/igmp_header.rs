use arrayvec::ArrayVec;

use crate::{err::LenError, *};

/// A header of an IGMP packet.
///
/// The header contains the static part of an IGMP
/// packet.
///
/// For the following message types the header contains all the data:
///
/// - IGMP v1 & v2 membership query ([`crate::IgmpType::MembershipQuery`])
/// - IGMP v1 membership report ([`crate::IgmpType::MembershipReportV1`])
/// - IGMP v2 membership report ([`crate::IgmpType::MembershipReportV2`])
/// - IGMP v2 & v3 leave group ([`crate::IgmpType::LeaveGroup`])
///
///
/// and for the followng messages only the static part is contained
/// within the header (the variable-length part is in the payload):
///
/// - IGMPv3 membership query ([`crate::IgmpType::MembershipQuery`]):
///   ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
///   |  Type = 0x11  | Max Resp Code |           Checksum            |  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | part of header and
///   |                         Group Address                         |  | this type
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
///   | Flags |S| QRV |     QQIC      |     Number of Sources (N)     |  ↓
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
///   |                       Source Address [1]                      |  |
///   +-                                                             -+  |
///   |                       Source Address [2]                      |  |
///   +-                              .                              -+  | part of payload
///   .                               .                               .  |
///   .                               .                               .  |
///   +-                                                             -+  |
///   |                       Source Address [N]                      |  ↓
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
///   ```
/// - IGMPv3 membership report ([`crate::IgmpType::MembershipReportV3`]):
///   ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
///   |  Type = 0x22  |    Reserved   |           Checksum            |  | part of header &
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | this type
///   |             Flags             |  Number of Group Records (M)  |  ↓
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
///   |                                                               |  |
///   .                                                               .  |
///   .                        Group Record [1]                       .  |
///   .                                                               .  |
///   |                                                               |  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
///   |                                                               |  |
///   .                                                               .  |
///   .                        Group Record [2]                       .  | part of payload
///   .                                                               .  |
///   |                                                               |  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
///   |                               .                               |  |
///   .                               .                               .  |
///   |                               .                               |  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
///   |                                                               |  |
///   .                                                               .  |
///   .                        Group Record [M]                       .  |
///   .                                                               .  |
///   |                                                               |  ↓
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
///   ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgmpHeader {
    /// IGMP message type.
    pub igmp_type: IgmpType,
    /// Checksum in the IGMP header.
    pub checksum: u16,
}

impl IgmpHeader {
    /// Number of bytes/octets an [`IgmpHeader`] takes up at minimum in serialized form.
    pub const MIN_LEN: usize = 8;

    /// Number of bytes/octets an [`IgmpHeader`] takes up maximally in serialized form.
    pub const MAX_LEN: usize = 12;

    /// Constructs an [`IgmpHeader`] with reserved & checksum set to 0.
    #[inline]
    pub fn new(igmp_type: IgmpType) -> IgmpHeader {
        IgmpHeader {
            igmp_type,
            checksum: 0,
        }
    }

    /// Creates an [`IgmpHeader`] with a checksum calculated based on the
    /// given IGMP type and payload.
    ///
    /// Per RFC 1112, RFC 2236 and RFC 9776 the checksum is calculated
    /// over the entire IGMP message (header + payload) with the
    /// checksum field set to zero, even for fields that are unused
    /// (e.g. the "Max Resp Time" / reserved fields in IGMPv1 messages).
    #[inline]
    pub fn with_checksum(igmp_type: IgmpType, payload: &[u8]) -> IgmpHeader {
        let mut result = IgmpHeader::new(igmp_type);
        result.checksum = result.calc_checksum(payload);
        result
    }

    /// Reads an IGMP header from a slice and returns a tuple containing the
    /// resulting header and the unused part of the slice.
    ///
    /// The IGMP message variant is determined by the type byte. For
    /// `0x11` "Membership Query" messages, [RFC 9776 §7.1](
    /// https://datatracker.ietf.org/doc/html/rfc9776#section-7.1) defines
    /// the version distinction by message length:
    ///
    /// * IGMPv1 Query: length = 8 octets AND `Max Resp Code` field is zero.
    /// * IGMPv2 Query: length = 8 octets AND `Max Resp Code` field is non-zero.
    /// * IGMPv3 Query: length >= 12 octets.
    /// * Query Messages of any other length (e.g. 9, 10 or 11 octets)
    ///   MUST be silently ignored. This parser surfaces them as a
    ///   [`err::LenError`] so that callers can make that decision
    ///   explicitly.
    ///
    /// IGMPv1 and IGMPv2 queries are returned as
    /// [`IgmpType::MembershipQuery`] (the `max_response_time` field is
    /// `0` for IGMPv1). IGMPv3 queries are returned as
    /// [`IgmpType::MembershipQueryWithSources`].
    ///
    /// For all other recognized type bytes the fixed 8 byte header is
    /// consumed. The returned slice is the part of the input that
    /// follows the fixed header (e.g. the source addresses of an IGMPv3
    /// query or the group records of an IGMPv3 membership report).
    ///
    /// IGMP type bytes that do not match any of the message types
    /// defined in RFC 1112, RFC 2236 or RFC 9776 are returned as
    /// [`IgmpType::Unknown`] with the raw header bytes preserved.
    ///
    /// # Errors
    ///
    /// * [`err::LenError`] if the slice is too small to contain a
    ///   complete header (less than 8 bytes for any type, or 9-11 bytes
    ///   for a Membership Query).
    pub fn from_slice(slice: &[u8]) -> Result<(IgmpHeader, &[u8]), LenError> {
        if slice.len() < Self::MIN_LEN {
            return Err(LenError {
                required_len: Self::MIN_LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::Igmp,
                layer_start_offset: 0,
            });
        }

        // SAFETY: length checked above to be >= MIN_LEN (8).
        let type_u8 = unsafe { *slice.get_unchecked(0) };
        let max_resp = unsafe { *slice.get_unchecked(1) };
        let checksum =
            u16::from_be_bytes(unsafe { [*slice.get_unchecked(2), *slice.get_unchecked(3)] });
        let group_address: [u8; 4] = unsafe {
            [
                *slice.get_unchecked(4),
                *slice.get_unchecked(5),
                *slice.get_unchecked(6),
                *slice.get_unchecked(7),
            ]
        };

        match type_u8 {
            igmp::IGMP_TYPE_MEMBERSHIP_QUERY => {
                if igmp::MembershipQueryType::LEN == slice.len() {
                    // if the length is bellow 12 bytes fall back to the IGMPv1 or
                    // v2 variant of the query
                    Ok((
                        IgmpHeader {
                            igmp_type: IgmpType::MembershipQuery(igmp::MembershipQueryType {
                                max_response_time: max_resp,
                                group_address: group_address.into(),
                            }),
                            checksum,
                        },
                        // SAFETY: Safe as the slice was previously verified to have at least the length
                        //         Self::MIN_LEN.
                        unsafe {
                            core::slice::from_raw_parts(
                                slice.as_ptr().add(Self::MIN_LEN),
                                slice.len() - Self::MIN_LEN,
                            )
                        },
                    ))
                } else if slice.len() >= igmp::MembershipQueryWithSourcesHeader::LEN {
                    // IGMPv3 query messages additionally contain source addresses
                    // SAFETY: length checked above to be >= igmp::MembershipQueryWithSourcesHeader::LEN (12).
                    let raw_byte_8 = unsafe { *slice.get_unchecked(8) };
                    let qqic = unsafe { *slice.get_unchecked(9) };
                    let num_of_sources = u16::from_be_bytes(unsafe {
                        [*slice.get_unchecked(10), *slice.get_unchecked(11)]
                    });
                    Ok((
                        IgmpHeader {
                            igmp_type: IgmpType::MembershipQueryWithSources(
                                igmp::MembershipQueryWithSourcesHeader {
                                    max_response_code: igmp::MaxResponseCode(max_resp),
                                    group_address: group_address.into(),
                                    raw_byte_8,
                                    qqic,
                                    num_of_sources,
                                },
                            ),
                            checksum,
                        },
                        // SAFETY: Safe as the slice was previously verified to have at least the length
                        //         Self::MIN_LEN.
                        unsafe {
                            core::slice::from_raw_parts(
                                slice
                                    .as_ptr()
                                    .add(igmp::MembershipQueryWithSourcesHeader::LEN),
                                slice.len() - igmp::MembershipQueryWithSourcesHeader::LEN,
                            )
                        },
                    ))
                } else {
                    Err(LenError {
                        required_len: igmp::MembershipQueryWithSourcesHeader::LEN,
                        len: slice.len(),
                        len_source: LenSource::Slice,
                        layer: err::Layer::Igmp,
                        layer_start_offset: 0,
                    })
                }
            }
            igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT => Ok((
                IgmpHeader {
                    igmp_type: IgmpType::MembershipReportV1(igmp::MembershipReportV1Type {
                        group_address: group_address.into(),
                    }),
                    checksum,
                },
                // SAFETY: Safe as the slice was previously verified to have at least the length
                //         Self::MIN_LEN.
                unsafe {
                    core::slice::from_raw_parts(
                        slice.as_ptr().add(Self::MIN_LEN),
                        slice.len() - Self::MIN_LEN,
                    )
                },
            )),
            igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT => Ok((
                IgmpHeader {
                    igmp_type: IgmpType::MembershipReportV2(igmp::MembershipReportV2Type {
                        group_address: group_address.into(),
                    }),
                    checksum,
                },
                // SAFETY: Safe as the slice was previously verified to have at least the length
                //         Self::MIN_LEN.
                unsafe {
                    core::slice::from_raw_parts(
                        slice.as_ptr().add(Self::MIN_LEN),
                        slice.len() - Self::MIN_LEN,
                    )
                },
            )),
            igmp::IGMPV2_TYPE_LEAVE_GROUP => Ok((
                IgmpHeader {
                    igmp_type: IgmpType::LeaveGroup(igmp::LeaveGroupType {
                        group_address: group_address.into(),
                    }),
                    checksum,
                },
                // SAFETY: Safe as the slice was previously verified to have at least the length
                //         Self::MIN_LEN.
                unsafe {
                    core::slice::from_raw_parts(
                        slice.as_ptr().add(Self::MIN_LEN),
                        slice.len() - Self::MIN_LEN,
                    )
                },
            )),
            igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT => {
                // SAFETY: Safe as the slice was previously verified to have at least the length
                //         Self::MIN_LEN (8).
                let flags = unsafe { [*slice.get_unchecked(4), *slice.get_unchecked(5)] };
                let num_of_records = u16::from_be_bytes(unsafe {
                    [*slice.get_unchecked(6), *slice.get_unchecked(7)]
                });
                Ok((
                    IgmpHeader {
                        igmp_type: IgmpType::MembershipReportV3(igmp::MembershipReportV3Header {
                            flags,
                            num_of_records,
                        }),
                        checksum,
                    },
                    // SAFETY: Safe as the slice was previously verified to have at least the length
                    //         Self::MIN_LEN.
                    unsafe {
                        core::slice::from_raw_parts(
                            slice.as_ptr().add(Self::MIN_LEN),
                            slice.len() - Self::MIN_LEN,
                        )
                    },
                ))
            }
            _ => Ok((
                IgmpHeader {
                    igmp_type: IgmpType::Unknown(igmp::UnknownHeader {
                        igmp_type: type_u8,
                        raw_byte_1: max_resp,
                        raw_bytes_4_7: group_address,
                    }),
                    checksum,
                },
                // SAFETY: Safe as the slice was previously verified to have at least the length
                //         Self::MIN_LEN.
                unsafe {
                    core::slice::from_raw_parts(
                        slice.as_ptr().add(Self::MIN_LEN),
                        slice.len() - Self::MIN_LEN,
                    )
                },
            )),
        }
    }

    /// Calculates the IGMP checksum (16-bit one's complement of the
    /// one's complement sum of the entire IGMP message with the checksum
    /// field set to zero).
    ///
    /// `payload` is the part of the IGMP message that comes after the
    /// fixed header part covered by [`IgmpHeader`] (for example the
    /// source addresses of an IGMPv3 membership query or the group
    /// records of an IGMPv3 membership report).
    ///
    /// RFC 1112, RFC 2236 and RFC 9776 specifies that the checksum must be
    /// computed over the whole message even over the bytes that are
    /// otherwise ignored by the receiver (e.g. additional unused bytes after
    /// the header).
    pub fn calc_checksum(&self, payload: &[u8]) -> u16 {
        use IgmpType::*;
        let sum = match &self.igmp_type {
            MembershipQuery(t) => checksum::Sum16BitWords::new()
                .add_2bytes([igmp::IGMP_TYPE_MEMBERSHIP_QUERY, t.max_response_time])
                .add_4bytes(t.group_address.octets),
            MembershipQueryWithSources(t) => checksum::Sum16BitWords::new()
                .add_2bytes([igmp::IGMP_TYPE_MEMBERSHIP_QUERY, t.max_response_code.0])
                .add_4bytes(t.group_address.octets)
                .add_2bytes([t.raw_byte_8, t.qqic])
                .add_2bytes(t.num_of_sources.to_be_bytes()),
            MembershipReportV1(t) => checksum::Sum16BitWords::new()
                .add_2bytes([igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT, 0])
                .add_4bytes(t.group_address.octets),
            MembershipReportV2(t) => checksum::Sum16BitWords::new()
                .add_2bytes([igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT, 0])
                .add_4bytes(t.group_address.octets),
            MembershipReportV3(t) => checksum::Sum16BitWords::new()
                .add_2bytes([igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT, 0])
                .add_2bytes(t.flags)
                .add_2bytes(t.num_of_records.to_be_bytes()),
            LeaveGroup(t) => checksum::Sum16BitWords::new()
                .add_2bytes([igmp::IGMPV2_TYPE_LEAVE_GROUP, 0])
                .add_4bytes(t.group_address.octets),
            Unknown(t) => checksum::Sum16BitWords::new()
                .add_2bytes([t.igmp_type, t.raw_byte_1])
                .add_4bytes(t.raw_bytes_4_7),
        };
        sum.add_slice(payload).ones_complement().to_be()
    }

    /// Length in bytes/octets of this header type.
    #[inline]
    pub const fn header_len(&self) -> usize {
        use IgmpType::*;
        match self.igmp_type {
            MembershipQuery(_) => igmp::MembershipQueryType::LEN,
            MembershipQueryWithSources(_) => igmp::MembershipQueryWithSourcesHeader::LEN,
            MembershipReportV1(_) => igmp::MembershipReportV1Type::LEN,
            MembershipReportV2(_) => igmp::MembershipReportV2Type::LEN,
            MembershipReportV3(_) => igmp::MembershipReportV3Header::LEN,
            LeaveGroup(_) => igmp::LeaveGroupType::LEN,
            Unknown(_) => igmp::UnknownHeader::LEN,
        }
    }

    /// Converts the header to on-the-wire bytes.
    pub fn to_bytes(&self) -> ArrayVec<u8, { Self::MAX_LEN }> {
        use IgmpType::*;
        let c = self.checksum.to_be_bytes();
        match &self.igmp_type {
            MembershipQuery(t) => {
                let mut bytes = ArrayVec::from([
                    igmp::IGMP_TYPE_MEMBERSHIP_QUERY,
                    t.max_response_time,
                    c[0],
                    c[1],
                    t.group_address.octets[0],
                    t.group_address.octets[1],
                    t.group_address.octets[2],
                    t.group_address.octets[3],
                    0,
                    0,
                    0,
                    0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 12.
                unsafe {
                    bytes.set_len(8);
                }
                bytes
            }
            MembershipQueryWithSources(t) => {
                let num_sources_be = t.num_of_sources.to_be_bytes();
                ArrayVec::from([
                    igmp::IGMP_TYPE_MEMBERSHIP_QUERY,
                    t.max_response_code.0,
                    c[0],
                    c[1],
                    t.group_address.octets[0],
                    t.group_address.octets[1],
                    t.group_address.octets[2],
                    t.group_address.octets[3],
                    t.raw_byte_8,
                    t.qqic,
                    num_sources_be[0],
                    num_sources_be[1],
                ])
            }
            MembershipReportV1(t) => {
                let mut bytes = ArrayVec::from([
                    igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT,
                    0, // unused
                    c[0],
                    c[1],
                    t.group_address.octets[0],
                    t.group_address.octets[1],
                    t.group_address.octets[2],
                    t.group_address.octets[3],
                    0,
                    0,
                    0,
                    0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 12.
                unsafe {
                    bytes.set_len(8);
                }
                bytes
            }
            MembershipReportV2(t) => {
                let mut bytes = ArrayVec::from([
                    igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT,
                    0, // "Max Resp Time" field is unused in Membership Report messages
                    c[0],
                    c[1],
                    t.group_address.octets[0],
                    t.group_address.octets[1],
                    t.group_address.octets[2],
                    t.group_address.octets[3],
                    0,
                    0,
                    0,
                    0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 12.
                unsafe {
                    bytes.set_len(8);
                }
                bytes
            }
            MembershipReportV3(t) => {
                let num_recs_be = t.num_of_records.to_be_bytes();
                let mut bytes = ArrayVec::from([
                    igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT,
                    0, // reserved
                    c[0],
                    c[1],
                    t.flags[0],
                    t.flags[1],
                    num_recs_be[0],
                    num_recs_be[1],
                    0,
                    0,
                    0,
                    0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 12.
                unsafe {
                    bytes.set_len(8);
                }
                bytes
            }
            LeaveGroup(t) => {
                let mut bytes = ArrayVec::from([
                    igmp::IGMPV2_TYPE_LEAVE_GROUP,
                    0, // "Max Resp Time" field is unused in leave group messages
                    c[0],
                    c[1],
                    t.group_address.octets[0],
                    t.group_address.octets[1],
                    t.group_address.octets[2],
                    t.group_address.octets[3],
                    0,
                    0,
                    0,
                    0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 12.
                unsafe {
                    bytes.set_len(8);
                }
                bytes
            }
            Unknown(t) => {
                let mut bytes = ArrayVec::from([
                    t.igmp_type,
                    t.raw_byte_1,
                    c[0],
                    c[1],
                    t.raw_bytes_4_7[0],
                    t.raw_bytes_4_7[1],
                    t.raw_bytes_4_7[2],
                    t.raw_bytes_4_7[3],
                    0,
                    0,
                    0,
                    0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 12.
                unsafe {
                    bytes.set_len(8);
                }
                bytes
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use alloc::{format, vec, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn constants() {
        assert_eq!(8, IgmpHeader::MIN_LEN);
        assert_eq!(12, IgmpHeader::MAX_LEN);
    }

    proptest! {
        #[test]
        fn from_slice(
            max_response_time in any::<u8>(),
            max_response_code in any::<u8>(),
            group_address in any::<[u8;4]>(),
            s_flag in any::<bool>(),
            qrv_raw in 0u8..=igmp::Qrv::MAX_U8,
            query_flags in 0u8..=(igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS >> igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_OFFSET_FLAGS),
            qqic in any::<u8>(),
            num_of_sources in any::<u16>(),
            report_flags in any::<[u8;2]>(),
            num_of_records in any::<u16>(),
            checksum in any::<u16>(),
            // arbitrary trailing bytes that should be returned as `rest`
            // for variants whose fixed header consumes only 8 bytes.
            suffix in proptest::collection::vec(any::<u8>(), 0..256usize),
            // an arbitrary unknown IGMP type byte (filtered to exclude
            // the five message types defined in the RFCs).
            unknown_type in any::<u8>().prop_filter(
                "must not be a known IGMP type",
                |t| ![
                    igmp::IGMP_TYPE_MEMBERSHIP_QUERY,
                    igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT,
                    igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT,
                    igmp::IGMPV2_TYPE_LEAVE_GROUP,
                    igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT,
                ].contains(t),
            ),
            unknown_raw_byte_1 in any::<u8>(),
            unknown_raw_bytes_4_7 in any::<[u8;4]>(),
        ) {
            let raw_byte_8 = ((query_flags & igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS) << igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_OFFSET_FLAGS)
                | ((s_flag as u8) << 3)
                | (qrv_raw & 0b111);
            let cs_be = checksum.to_be_bytes();

            // membership query
            {
                let bytes = [
                    igmp::IGMP_TYPE_MEMBERSHIP_QUERY,
                    max_response_time,
                    cs_be[0], cs_be[1],
                    group_address[0], group_address[1],
                    group_address[2], group_address[3],
                ];
                let (header, rest) = IgmpHeader::from_slice(&bytes).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::MembershipQuery(igmp::MembershipQueryType {
                            max_response_time,
                            group_address: group_address.into(),
                        }),
                        checksum,
                    }
                );
                prop_assert!(rest.is_empty());
            }

            // membership query with sources
            {
                let mut head = [0u8; 12];
                head[0] = igmp::IGMP_TYPE_MEMBERSHIP_QUERY;
                head[1] = max_response_code;
                head[2] = cs_be[0];
                head[3] = cs_be[1];
                head[4..8].copy_from_slice(&group_address);
                head[8] = raw_byte_8;
                head[9] = qqic;
                head[10..12].copy_from_slice(&num_of_sources.to_be_bytes());

                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = IgmpHeader::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::MembershipQueryWithSources(
                            igmp::MembershipQueryWithSourcesHeader {
                                max_response_code: igmp::MaxResponseCode(max_response_code),
                                group_address: group_address.into(),
                                raw_byte_8,
                                qqic,
                                num_of_sources,
                            },
                        ),
                        checksum,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // membership report v1
            {
                let head = [
                    igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT,
                    0,
                    cs_be[0], cs_be[1],
                    group_address[0], group_address[1],
                    group_address[2], group_address[3],
                ];
                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = IgmpHeader::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::MembershipReportV1(igmp::MembershipReportV1Type {
                            group_address: group_address.into(),
                        }),
                        checksum,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // membership report v2
            {
                let head = [
                    igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT,
                    0,
                    cs_be[0], cs_be[1],
                    group_address[0], group_address[1],
                    group_address[2], group_address[3],
                ];
                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = IgmpHeader::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::MembershipReportV2(igmp::MembershipReportV2Type {
                            group_address: group_address.into(),
                        }),
                        checksum,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // leave group
            {
                let head = [
                    igmp::IGMPV2_TYPE_LEAVE_GROUP,
                    0,
                    cs_be[0], cs_be[1],
                    group_address[0], group_address[1],
                    group_address[2], group_address[3],
                ];
                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = IgmpHeader::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::LeaveGroup(igmp::LeaveGroupType {
                            group_address: group_address.into(),
                        }),
                        checksum,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // membership report v3
            {
                let nr_be = num_of_records.to_be_bytes();
                let head = [
                    igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT,
                    0,
                    cs_be[0], cs_be[1],
                    report_flags[0], report_flags[1],
                    nr_be[0], nr_be[1],
                ];
                let mut full = Vec::with_capacity(head.len() + suffix.len());
                full.extend_from_slice(&head);
                full.extend_from_slice(&suffix);

                let (header, rest) = IgmpHeader::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::MembershipReportV3(igmp::MembershipReportV3Header {
                            flags: report_flags,
                            num_of_records,
                        }),
                        checksum,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }

            // serialize & deserialize all types
            {
                let cases: [IgmpType; 7] = [
                    IgmpType::MembershipQuery(igmp::MembershipQueryType {
                        max_response_time,
                        group_address: group_address.into(),
                    }),
                    IgmpType::MembershipQueryWithSources(igmp::MembershipQueryWithSourcesHeader {
                        max_response_code: igmp::MaxResponseCode(max_response_code),
                        group_address: group_address.into(),
                        raw_byte_8,
                        qqic,
                        num_of_sources,
                    }),
                    IgmpType::MembershipReportV1(igmp::MembershipReportV1Type {
                        group_address: group_address.into(),
                    }),
                    IgmpType::MembershipReportV2(igmp::MembershipReportV2Type {
                        group_address: group_address.into(),
                    }),
                    IgmpType::MembershipReportV3(igmp::MembershipReportV3Header {
                        flags: report_flags,
                        num_of_records,
                    }),
                    IgmpType::LeaveGroup(igmp::LeaveGroupType {
                        group_address: group_address.into(),
                    }),
                    IgmpType::Unknown(igmp::UnknownHeader {
                        igmp_type: unknown_type,
                        raw_byte_1: unknown_raw_byte_1,
                        raw_bytes_4_7: unknown_raw_bytes_4_7,
                    }),
                ];

                for igmp_type in cases {
                    let original = IgmpHeader { igmp_type, checksum };
                    let bytes = original.to_bytes();
                    let (parsed, rest) = IgmpHeader::from_slice(bytes.as_slice()).unwrap();
                    prop_assert_eq!(parsed, original);
                    prop_assert!(rest.is_empty());
                }
            }

            // length error less then 8 bytes
            {
                let buf = [0u8; IgmpHeader::MIN_LEN];
                for bad_len in 0..IgmpHeader::MIN_LEN {
                    prop_assert_eq!(
                        IgmpHeader::from_slice(&buf[..bad_len]),
                        Err(err::LenError {
                            required_len: IgmpHeader::MIN_LEN,
                            len: bad_len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::Igmp,
                            layer_start_offset: 0,
                        })
                    );
                }
            }

            // length error less then 9-11 bytes (membership query)
            {
                for bad_len in (IgmpHeader::MIN_LEN + 1)..IgmpHeader::MAX_LEN {
                    let mut buf = vec![0u8; bad_len];
                    buf[0] = igmp::IGMP_TYPE_MEMBERSHIP_QUERY;
                    prop_assert_eq!(
                        IgmpHeader::from_slice(&buf),
                        Err(err::LenError {
                            required_len: IgmpHeader::MAX_LEN,
                            len: bad_len,
                            len_source: LenSource::Slice,
                            layer: err::Layer::Igmp,
                            layer_start_offset: 0,
                        })
                    );
                }
            }

            // unknown type is parsed as IgmpType::Unknown (with the raw
            // header bytes preserved) instead of returning an error.
            {
                let bytes = [
                    unknown_type,
                    unknown_raw_byte_1,
                    cs_be[0], cs_be[1],
                    unknown_raw_bytes_4_7[0], unknown_raw_bytes_4_7[1],
                    unknown_raw_bytes_4_7[2], unknown_raw_bytes_4_7[3],
                ];
                let mut full = Vec::with_capacity(bytes.len() + suffix.len());
                full.extend_from_slice(&bytes);
                full.extend_from_slice(&suffix);

                let (header, rest) = IgmpHeader::from_slice(&full).unwrap();
                prop_assert_eq!(
                    header,
                    IgmpHeader {
                        igmp_type: IgmpType::Unknown(igmp::UnknownHeader {
                            igmp_type: unknown_type,
                            raw_byte_1: unknown_raw_byte_1,
                            raw_bytes_4_7: unknown_raw_bytes_4_7,
                        }),
                        checksum,
                    }
                );
                prop_assert_eq!(rest, suffix.as_slice());
            }
        }
    }

    fn assert_rfc_verifies(header: &IgmpHeader, payload: &[u8]) {
        let bytes = header.to_bytes();
        let zero = checksum::Sum16BitWords::new()
            .add_slice(bytes.as_slice())
            .add_slice(payload)
            .ones_complement();
        assert_eq!(
            0, zero,
            "expected one's complement sum to be 0 for header {:?} and payload {:?}, got {:#06x}",
            header, payload, zero
        );
    }

    proptest! {
        #[test]
        fn calc_checksum(
            max_response_time in any::<u8>(),
            max_response_code in any::<u8>(),
            group_address in any::<[u8;4]>(),
            s_flag in any::<bool>(),
            qrv_raw in 0u8..=igmp::Qrv::MAX_U8,
            query_flags in 0u8..=(igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS >> igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_OFFSET_FLAGS),
            qqic in any::<u8>(),
            num_of_sources in any::<u16>(),
            report_flags in any::<[u8;2]>(),
            num_of_records in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024usize),
            unknown_type in any::<u8>().prop_filter(
                "must not be a known IGMP type",
                |t| ![
                    igmp::IGMP_TYPE_MEMBERSHIP_QUERY,
                    igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT,
                    igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT,
                    igmp::IGMPV2_TYPE_LEAVE_GROUP,
                    igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT,
                ].contains(t),
            ),
            unknown_raw_byte_1 in any::<u8>(),
            unknown_raw_bytes_4_7 in any::<[u8;4]>(),
        ) {
            let raw_byte_8 = ((query_flags & igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS) << igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_OFFSET_FLAGS)
                | ((s_flag as u8) << 3)
                | (qrv_raw & 0b111);

            // membership query
            {
                let igmp_type = IgmpType::MembershipQuery(igmp::MembershipQueryType {
                    max_response_time,
                    group_address: group_address.into(),
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([igmp::IGMP_TYPE_MEMBERSHIP_QUERY, max_response_time])
                    .add_4bytes(group_address)
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // membership query with sources
            {
                let igmp_type = IgmpType::MembershipQueryWithSources(igmp::MembershipQueryWithSourcesHeader {
                    max_response_code: igmp::MaxResponseCode(max_response_code),
                    group_address: group_address.into(),
                    raw_byte_8,
                    qqic,
                    num_of_sources,
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([igmp::IGMP_TYPE_MEMBERSHIP_QUERY, max_response_code])
                    .add_4bytes(group_address)
                    .add_2bytes([
                        raw_byte_8,
                        qqic,
                    ])
                    .add_2bytes(num_of_sources.to_be_bytes())
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // membership report v1
            {
                let igmp_type = IgmpType::MembershipReportV1(igmp::MembershipReportV1Type {
                    group_address: group_address.into(),
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT, 0])
                    .add_4bytes(group_address)
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // membership report v2
            {
                let igmp_type = IgmpType::MembershipReportV2(igmp::MembershipReportV2Type {
                    group_address: group_address.into(),
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT, 0])
                    .add_4bytes(group_address)
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // membership report v3
            {
                let igmp_type = IgmpType::MembershipReportV3(igmp::MembershipReportV3Header {
                    flags: report_flags,
                    num_of_records,
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT, 0])
                    .add_2bytes(report_flags)
                    .add_2bytes(num_of_records.to_be_bytes())
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // leave group
            {
                let igmp_type = IgmpType::LeaveGroup(igmp::LeaveGroupType {
                    group_address: group_address.into(),
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([igmp::IGMPV2_TYPE_LEAVE_GROUP, 0])
                    .add_4bytes(group_address)
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // unknown
            {
                let igmp_type = IgmpType::Unknown(igmp::UnknownHeader {
                    igmp_type: unknown_type,
                    raw_byte_1: unknown_raw_byte_1,
                    raw_bytes_4_7: unknown_raw_bytes_4_7,
                });
                let header = IgmpHeader { igmp_type: igmp_type.clone(), checksum: 0 };

                let expected = checksum::Sum16BitWords::new()
                    .add_2bytes([unknown_type, unknown_raw_byte_1])
                    .add_4bytes(unknown_raw_bytes_4_7)
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                prop_assert_eq!(expected, header.calc_checksum(&payload));
                assert_rfc_verifies(&IgmpHeader::with_checksum(igmp_type, &payload), &payload);
            }

            // Hand-rolled IGMPv2 Membership Report example with an externally
            // computed checksum. Verifies that we produce the exact same
            // checksum as the RFC formula applied byte-for-byte.
            //
            // Type = 0x16, Max Resp Time = 0x00, Checksum = 0x0000,
            // Group Address = 224.0.0.1 (0xe0000001)
            //
            // Manual computation:
            //  0x1600 + 0x0000 + 0xe000 + 0x0001 = 0xf601
            //  one's complement = 0x09fe
            // Final wire bytes are big-endian: 0x09, 0xfe.
            {
                let header = IgmpHeader {
                    igmp_type: IgmpType::MembershipReportV2(igmp::MembershipReportV2Type {
                        group_address: [0xe0, 0x00, 0x00, 0x01].into(),
                    }),
                    checksum: 0,
                };
                prop_assert_eq!(header.calc_checksum(&[]).to_be_bytes(), [0x09, 0xfe]);
            }

            // Different payload bytes must yield a different checksum
            // (and both versions still satisfy the RFC verification
            // property when paired with their respective payloads).
            {
                let igmp_type = IgmpType::MembershipReportV3(igmp::MembershipReportV3Header {
                    flags: [0, 0],
                    num_of_records: 1,
                });
                let header_no_payload = IgmpHeader::with_checksum(igmp_type.clone(), &[]);
                let header_with_payload =
                    IgmpHeader::with_checksum(igmp_type, &[0x01, 0x02, 0x03, 0x04]);
                prop_assert_ne!(header_no_payload.checksum, header_with_payload.checksum);
                assert_rfc_verifies(&header_no_payload, &[]);
                assert_rfc_verifies(&header_with_payload, &[0x01, 0x02, 0x03, 0x04]);
            }
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            max_response_time in any::<u8>(),
            max_response_code in any::<u8>(),
            group_address in any::<[u8;4]>(),
            s_flag in any::<bool>(),
            qrv_raw in 0u8..=igmp::Qrv::MAX_U8,
            query_flags in 0u8..=(igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS >> igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_OFFSET_FLAGS),
            qqic in any::<u8>(),
            num_of_sources in any::<u16>(),
            report_flags in any::<[u8;2]>(),
            num_of_records in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024usize),
            unknown_type in any::<u8>().prop_filter(
                "must not be a known IGMP type",
                |t| ![
                    igmp::IGMP_TYPE_MEMBERSHIP_QUERY,
                    igmp::IGMPV1_TYPE_MEMBERSHIP_REPORT,
                    igmp::IGMPV2_TYPE_MEMBERSHIP_REPORT,
                    igmp::IGMPV2_TYPE_LEAVE_GROUP,
                    igmp::IGMPV3_TYPE_MEMBERSHIP_REPORT,
                ].contains(t),
            ),
            unknown_raw_byte_1 in any::<u8>(),
            unknown_raw_bytes_4_7 in any::<[u8;4]>(),
        ) {
            let raw_byte_8 = ((query_flags & igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS) << igmp::MembershipQueryWithSourcesHeader::RAW_BYTE_8_OFFSET_FLAGS)
                | ((s_flag as u8) << 3)
                | (qrv_raw & 0b111);

            // For every IGMP variant, with_checksum must
            //   1) preserve the supplied IgmpType verbatim, and
            //   2) populate the checksum field with calc_checksum's result.
            let cases: [IgmpType; 7] = [
                IgmpType::MembershipQuery(igmp::MembershipQueryType {
                    max_response_time,
                    group_address: group_address.into(),
                }),
                IgmpType::MembershipQueryWithSources(igmp::MembershipQueryWithSourcesHeader {
                    max_response_code: igmp::MaxResponseCode(max_response_code),
                    group_address: group_address.into(),
                    raw_byte_8,
                    qqic,
                    num_of_sources,
                }),
                IgmpType::MembershipReportV1(igmp::MembershipReportV1Type {
                    group_address: group_address.into(),
                }),
                IgmpType::MembershipReportV2(igmp::MembershipReportV2Type {
                    group_address: group_address.into(),
                }),
                IgmpType::MembershipReportV3(igmp::MembershipReportV3Header {
                    flags: report_flags,
                    num_of_records,
                }),
                IgmpType::LeaveGroup(igmp::LeaveGroupType {
                    group_address: group_address.into(),
                }),
                IgmpType::Unknown(igmp::UnknownHeader {
                    igmp_type: unknown_type,
                    raw_byte_1: unknown_raw_byte_1,
                    raw_bytes_4_7: unknown_raw_bytes_4_7,
                }),
            ];

            for igmp_type in cases {
                // type is preserved & checksum equals calc_checksum
                {
                    let header = IgmpHeader::with_checksum(igmp_type.clone(), &payload);
                    prop_assert_eq!(&igmp_type, &header.igmp_type);

                    let zero_checksum_header = IgmpHeader {
                        igmp_type: igmp_type.clone(),
                        checksum: 0,
                    };
                    prop_assert_eq!(
                        zero_checksum_header.calc_checksum(&payload),
                        header.checksum
                    );
                }

                // RFC verification: a header built with with_checksum
                // must produce a one's complement sum of zero over the
                // entire IGMP message (header + payload).
                {
                    let header = IgmpHeader::with_checksum(igmp_type, &payload);
                    assert_rfc_verifies(&header, &payload);
                }
            }
        }
    }
}
