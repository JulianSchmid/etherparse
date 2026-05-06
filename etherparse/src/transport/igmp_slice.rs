use crate::{igmp::*, *};

/// A slice containing an IGMP network packet.
///
/// Struct allows the selective read of fields in the IGMP
/// packet without copying the data.
///
/// # Important: Caller must trim to IGMP message length
///
/// For `0x11` "Membership Query" messages, the IGMP version is
/// determined by message length per [RFC 9776 §7.1](
/// https://datatracker.ietf.org/doc/html/rfc9776#section-7.1):
///
/// * IGMPv1/v2 Query: length = 8 octets
/// * IGMPv3 Query: length >= 12 octets
///
/// The caller **must** trim the input slice to the exact IGMP message
/// boundary (typically derived from the IP payload length) before
/// calling [`IgmpSlice::from_slice`]. If extra trailing bytes are
/// present, a query may be misidentified as IGMPv3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IgmpSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IgmpSlice<'a> {
    /// Creates a slice containing an IGMP packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` [`err::LenError`] if the given
    /// slice is too small to contain a valid IGMP header (minimum 8
    /// bytes), or has a length of 9-11 bytes for a `0x11` Membership
    /// Query (which is invalid per RFC 9776).
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<IgmpSlice<'a>, err::LenError> {
        // Validate by attempting to parse the header. This checks both
        // the minimum length and the 9-11 byte invalid range for queries.
        let _ = IgmpHeader::from_slice(slice)?;
        Ok(IgmpSlice { slice })
    }

    /// Decode the header values into an [`IgmpHeader`] struct.
    #[inline]
    pub fn header(&self) -> IgmpHeader {
        // SAFETY: from_slice already validated the slice, so this cannot fail.
        let (header, _) = IgmpHeader::from_slice(self.slice).unwrap();
        header
    }

    /// Number of bytes/octets that will be converted into an
    /// [`IgmpHeader`] when [`IgmpSlice::header`] gets called.
    #[inline]
    pub fn header_len(&self) -> usize {
        // SAFETY: Safe as from_slice checks that the slice has at least
        // IgmpHeader::MIN_LEN (8) bytes.
        let type_u8 = unsafe { *self.slice.get_unchecked(0) };
        match type_u8 {
            IGMP_TYPE_MEMBERSHIP_QUERY if self.slice.len() >= MembershipQueryWithSourcesHeader::LEN => {
                MembershipQueryWithSourcesHeader::LEN
            }
            _ => IgmpHeader::MIN_LEN,
        }
    }

    /// Decode the header values (excluding the checksum) into an [`IgmpType`] enum.
    #[inline]
    pub fn igmp_type(&self) -> IgmpType {
        self.header().igmp_type
    }

    /// Returns the "type" byte value in the IGMP header.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY: Safe as from_slice checks that the slice has at least
        // IgmpHeader::MIN_LEN (8) bytes.
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the second byte of the IGMP header.
    ///
    /// The meaning of this byte depends on the message type:
    /// - Membership Query: Max Response Time (v1: 0, v2: non-zero)
    /// - Membership Report V3: Reserved (0)
    /// - All other types: unused/reserved
    #[inline]
    pub fn max_resp_code_or_reserved(&self) -> u8 {
        // SAFETY: Safe as from_slice checks that the slice has at least
        // IgmpHeader::MIN_LEN (8) bytes.
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns the "checksum" value in the IGMP header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY: Safe as from_slice checks that the slice has at least
        // IgmpHeader::MIN_LEN (8) bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the bytes from position 4 through 7 in the IGMP header.
    ///
    /// For most message types this is the Group Address. For IGMPv3
    /// Membership Reports, bytes 4-5 are flags and bytes 6-7 are the
    /// Number of Group Records.
    #[inline]
    pub fn bytes4to7(&self) -> [u8; 4] {
        // SAFETY: Safe as from_slice checks that the slice has at least
        // IgmpHeader::MIN_LEN (8) bytes.
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns a slice to the bytes not covered by `.header()`.
    ///
    /// The contents of the payload depend on the message type:
    ///
    /// | Message Type | Payload Content |
    /// |---|---|
    /// | [`IgmpType::MembershipQuery`] (v1/v2) | Nothing (empty) |
    /// | [`IgmpType::MembershipQueryWithSources`] (v3) | Source Address list |
    /// | [`IgmpType::MembershipReportV1`] | Nothing (empty, unless trailing data) |
    /// | [`IgmpType::MembershipReportV2`] | Nothing (empty, unless trailing data) |
    /// | [`IgmpType::MembershipReportV3`] | Group Records |
    /// | [`IgmpType::LeaveGroup`] | Nothing (empty, unless trailing data) |
    /// | [`IgmpType::Unknown`] | Everything after the 8th byte |
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let header_len = self.header_len();
        // SAFETY: Safe as from_slice validated that the slice length is
        // at least header_len.
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(header_len),
                self.slice.len() - header_len,
            )
        }
    }

    /// Returns the slice containing the entire IGMP packet.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec};
    use proptest::prelude::*;

    #[test]
    fn from_slice_too_small() {
        for bad_len in 0..IgmpHeader::MIN_LEN {
            let bytes = [0u8; 8];
            assert_eq!(
                IgmpSlice::from_slice(&bytes[..bad_len]).unwrap_err(),
                err::LenError {
                    required_len: IgmpHeader::MIN_LEN,
                    len: bad_len,
                    len_source: LenSource::Slice,
                    layer: err::Layer::Igmp,
                    layer_start_offset: 0,
                }
            );
        }
    }

    #[test]
    fn from_slice_query_invalid_length() {
        // 9-11 bytes with type 0x11 should fail
        for bad_len in 9..12 {
            let mut bytes = [0u8; 12];
            bytes[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
            assert!(IgmpSlice::from_slice(&bytes[..bad_len]).is_err());
        }
    }

    #[test]
    fn from_slice_v1_query() {
        // 8 bytes, type 0x11, max_resp_time = 0 => v1 query
        let mut bytes = [0u8; 8];
        bytes[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
        bytes[4] = 224;
        bytes[7] = 1;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(slice.max_resp_code_or_reserved(), 0);
        assert_eq!(slice.header_len(), 8);
        assert_eq!(slice.payload(), &[]);

        match slice.igmp_type() {
            IgmpType::MembershipQuery(q) => {
                assert_eq!(q.max_response_time, 0);
                assert_eq!(q.group_address.octets, [224, 0, 0, 1]);
            }
            _ => panic!("expected MembershipQuery"),
        }
    }

    #[test]
    fn from_slice_v2_query() {
        // 8 bytes, type 0x11, max_resp_time != 0 => v2 query
        let mut bytes = [0u8; 8];
        bytes[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
        bytes[1] = 100; // max_resp_time
        bytes[4] = 224;
        bytes[7] = 1;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.max_resp_code_or_reserved(), 100);
        assert_eq!(slice.header_len(), 8);

        match slice.igmp_type() {
            IgmpType::MembershipQuery(q) => {
                assert_eq!(q.max_response_time, 100);
            }
            _ => panic!("expected MembershipQuery"),
        }
    }

    #[test]
    fn from_slice_v3_query() {
        // >= 12 bytes, type 0x11 => v3 query
        let mut bytes = [0u8; 16];
        bytes[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
        bytes[1] = 50; // max_resp_code
        bytes[4] = 224;
        bytes[7] = 1;
        bytes[8] = 0x0A; // flags|S|QRV
        bytes[9] = 125; // QQIC
        bytes[10] = 0;
        bytes[11] = 1; // 1 source

        // 12 bytes header + 4 bytes payload (1 source address)
        let slice = IgmpSlice::from_slice(&bytes[..16]).unwrap();
        assert_eq!(slice.header_len(), MembershipQueryWithSourcesHeader::LEN);
        assert_eq!(slice.payload().len(), 4); // 16 - 12

        match slice.igmp_type() {
            IgmpType::MembershipQueryWithSources(q) => {
                assert_eq!(q.max_response_code.0, 50);
                assert_eq!(q.group_address.octets, [224, 0, 0, 1]);
                assert_eq!(q.raw_byte_8, 0x0A);
                assert_eq!(q.qqic, 125);
                assert_eq!(q.num_of_sources, 1);
            }
            _ => panic!("expected MembershipQueryWithSources"),
        }
    }

    #[test]
    fn from_slice_v1_report() {
        let mut bytes = [0u8; 8];
        bytes[0] = IGMPV1_TYPE_MEMBERSHIP_REPORT;
        bytes[4] = 224;
        bytes[7] = 1;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), IGMPV1_TYPE_MEMBERSHIP_REPORT);
        assert_eq!(slice.header_len(), 8);
        assert_eq!(slice.payload(), &[]);

        match slice.igmp_type() {
            IgmpType::MembershipReportV1(r) => {
                assert_eq!(r.group_address.octets, [224, 0, 0, 1]);
            }
            _ => panic!("expected MembershipReportV1"),
        }
    }

    #[test]
    fn from_slice_v2_report() {
        let mut bytes = [0u8; 8];
        bytes[0] = IGMPV2_TYPE_MEMBERSHIP_REPORT;
        bytes[4] = 224;
        bytes[7] = 2;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), IGMPV2_TYPE_MEMBERSHIP_REPORT);

        match slice.igmp_type() {
            IgmpType::MembershipReportV2(r) => {
                assert_eq!(r.group_address.octets, [224, 0, 0, 2]);
            }
            _ => panic!("expected MembershipReportV2"),
        }
    }

    #[test]
    fn from_slice_v3_report() {
        // type 0x22, 8-byte header + group record payload
        let mut bytes = vec![0u8; 16];
        bytes[0] = IGMPV3_TYPE_MEMBERSHIP_REPORT;
        bytes[1] = 0; // reserved
        // bytes[2..4] = checksum (0)
        bytes[4] = 0; // flags[0]
        bytes[5] = 0; // flags[1]
        bytes[6] = 0; // num_of_records high
        bytes[7] = 1; // num_of_records low = 1
        // group record (8 bytes)
        bytes[8] = 1; // record type (MODE_IS_INCLUDE)
        bytes[9] = 0; // aux data len
        bytes[10] = 0; // num sources high
        bytes[11] = 0; // num sources low
        bytes[12] = 224;
        bytes[13] = 0;
        bytes[14] = 0;
        bytes[15] = 1;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), IGMPV3_TYPE_MEMBERSHIP_REPORT);
        assert_eq!(slice.header_len(), 8);
        assert_eq!(slice.payload().len(), 8);

        match slice.igmp_type() {
            IgmpType::MembershipReportV3(r) => {
                assert_eq!(r.num_of_records, 1);
                assert_eq!(r.flags, [0, 0]);
            }
            _ => panic!("expected MembershipReportV3"),
        }
    }

    #[test]
    fn from_slice_leave_group() {
        let mut bytes = [0u8; 8];
        bytes[0] = IGMPV2_TYPE_LEAVE_GROUP;
        bytes[4] = 224;
        bytes[7] = 1;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), IGMPV2_TYPE_LEAVE_GROUP);

        match slice.igmp_type() {
            IgmpType::LeaveGroup(l) => {
                assert_eq!(l.group_address.octets, [224, 0, 0, 1]);
            }
            _ => panic!("expected LeaveGroup"),
        }
    }

    #[test]
    fn from_slice_unknown_type() {
        let mut bytes = [0u8; 8];
        bytes[0] = 0xFF;
        bytes[1] = 0xAB;
        bytes[4] = 1;
        bytes[5] = 2;
        bytes[6] = 3;
        bytes[7] = 4;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.type_u8(), 0xFF);

        match slice.igmp_type() {
            IgmpType::Unknown(u) => {
                assert_eq!(u.igmp_type, 0xFF);
                assert_eq!(u.raw_byte_1, 0xAB);
                assert_eq!(u.raw_bytes_4_7, [1, 2, 3, 4]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn from_slice_with_trailing_payload() {
        // v1 report with trailing data
        let mut bytes = [0u8; 12];
        bytes[0] = IGMPV1_TYPE_MEMBERSHIP_REPORT;
        bytes[4] = 224;
        bytes[8] = 0xDE;
        bytes[9] = 0xAD;
        bytes[10] = 0xBE;
        bytes[11] = 0xEF;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.header_len(), 8);
        assert_eq!(slice.payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    proptest! {
        #[test]
        fn header_roundtrip(bytes in proptest::collection::vec(any::<u8>(), 8..=8)) {
            // Avoid type 0x11 (query) to sidestep the length-based version detection
            let mut bytes = bytes;
            if bytes[0] == IGMP_TYPE_MEMBERSHIP_QUERY {
                bytes[0] = 0xFF;
            }
            let slice = IgmpSlice::from_slice(&bytes).unwrap();
            let header = slice.header();
            assert_eq!(header.checksum, slice.checksum());
        }
    }

    proptest! {
        #[test]
        fn type_u8_accessor(bytes in any::<[u8; 8]>()) {
            // Avoid 0x11 with exactly 8 bytes -> fine, but avoid invalid 9-11
            let slice_result = IgmpSlice::from_slice(&bytes);
            if let Ok(slice) = slice_result {
                assert_eq!(bytes[0], slice.type_u8());
            }
        }
    }

    proptest! {
        #[test]
        fn checksum_accessor(bytes in any::<[u8; 8]>()) {
            if let Ok(slice) = IgmpSlice::from_slice(&bytes) {
                assert_eq!(
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                    slice.checksum()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn bytes4to7_accessor(bytes in any::<[u8; 8]>()) {
            if let Ok(slice) = IgmpSlice::from_slice(&bytes) {
                assert_eq!(
                    [bytes[4], bytes[5], bytes[6], bytes[7]],
                    slice.bytes4to7()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn slice_accessor(bytes in proptest::collection::vec(any::<u8>(), 8..64)) {
            let mut bytes = bytes;
            // Avoid query type to prevent 9-11 byte rejection
            if bytes[0] == IGMP_TYPE_MEMBERSHIP_QUERY {
                bytes[0] = 0xFF;
            }
            let igmp_slice = IgmpSlice::from_slice(&bytes).unwrap();
            assert_eq!(&bytes[..], igmp_slice.slice());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(bytes in any::<[u8; 12]>()) {
            // Use v3 query type so 12 bytes is valid
            let mut bytes = bytes;
            bytes[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
            let slice = IgmpSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn debug_fmt(bytes in any::<[u8; 8]>()) {
            let mut bytes = bytes;
            if bytes[0] == IGMP_TYPE_MEMBERSHIP_QUERY {
                bytes[0] = 0xFF;
            }
            let slice = IgmpSlice::from_slice(&bytes).unwrap();
            let dbg = format!("{:?}", slice);
            assert!(dbg.starts_with("IgmpSlice"));
        }
    }

    #[test]
    fn payload_v3_query_sources() {
        // 12-byte header + 8 bytes (2 source addresses)
        let mut bytes = [0u8; 20];
        bytes[0] = IGMP_TYPE_MEMBERSHIP_QUERY;
        bytes[1] = 10; // max_resp_code
        bytes[10] = 0;
        bytes[11] = 2; // 2 sources
        // source 1: 10.0.0.1
        bytes[12] = 10;
        bytes[15] = 1;
        // source 2: 10.0.0.2
        bytes[16] = 10;
        bytes[19] = 2;

        let slice = IgmpSlice::from_slice(&bytes).unwrap();
        assert_eq!(slice.header_len(), 12);
        let payload = slice.payload();
        assert_eq!(payload.len(), 8);
        assert_eq!(payload[0], 10); // first byte of source 1
        assert_eq!(payload[3], 1);
        assert_eq!(payload[4], 10); // first byte of source 2
        assert_eq!(payload[7], 2);
    }
}
