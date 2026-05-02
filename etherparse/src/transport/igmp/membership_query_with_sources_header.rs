use crate::igmp::{GroupAddress, MaxResponseCode, Qrv};

/// A membership report message type (IGMPv3 version) with source addresses.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 0x11  | Max Resp Code |           Checksum            |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | part of header and
/// |                         Group Address                         |  | this type
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// | Flags |S| QRV |     QQIC      |     Number of Sources (N)     |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                       Source Address [1]                      |  |
/// +-                                                             -+  |
/// |                       Source Address [2]                      |  |
/// +-                              .                              -+  | part of payload
/// .                               .                               .  |
/// .                               .                               .  |
/// +-                                                             -+  |
/// |                       Source Address [N]                      |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MembershipQueryWithSourcesHeader {
    /// The Max Resp Code field specifies the maximum time allowed before
    /// sending a responding report.
    pub max_response_code: MaxResponseCode,

    /// The group address being queried.
    ///
    /// Set to zero for general queries, to learn which groups
    /// have members on an attached network. Filled for group-specific
    /// queries to learn if a particular group has members on an
    /// attached network.
    ///
    /// For IGMPv1, this field is ignored.
    pub group_address: GroupAddress,

    /// Raw byte containing "flags", "s" & "QRV" (the getters & setters
    /// methods can be used to get & set the different values).
    pub raw_byte_8: u8,

    /// QQIC (Querier's Query Interval Code).
    pub qqic: u8,

    /// Number of source addresses present in the query.
    ///
    /// The actual addresses are seperated into the
    /// payload part of the message.
    pub num_of_sources: u16,
}

impl MembershipQueryWithSourcesHeader {
    /// Number of bytes/octets an [`MembershipQueryWithSourcesHeader`] takes up in serialized form.
    pub const LEN: usize = 12;

    /// Bitmask identifying the "flags" part of [`MembershipQueryWithSourcesHeader::raw_byte_8`].
    pub const RAW_BYTE_8_MASK_FLAGS: u8 = 0b1111_0000;

    /// Bitshift needed to get to the "flags" part of [`MembershipQueryWithSourcesHeader::raw_byte_8`].
    pub const RAW_BYTE_8_OFFSET_FLAGS: u8 = 4;

    /// Bitmask identifying the "s flag" part of [`MembershipQueryWithSourcesHeader::raw_byte_8`].
    pub const RAW_BYTE_8_MASK_S_FLAG: u8 = 0b0000_1000;

    /// Bitmask identifying the "QRV" part of [`MembershipQueryWithSourcesHeader::raw_byte_8`].
    pub const RAW_BYTE_8_MASK_QRV: u8 = 0b0000_0111;

    /// Extracts the "flags" from the `raw_byte_8` field.
    pub fn flags(&self) -> u8 {
        (self.raw_byte_8 & Self::RAW_BYTE_8_MASK_FLAGS) >> Self::RAW_BYTE_8_OFFSET_FLAGS
    }

    /// Sets the "flags" in the `raw_byte_8` field.
    pub fn set_flags(&mut self, value: u8) {
        self.raw_byte_8 = (self.raw_byte_8 & (!Self::RAW_BYTE_8_MASK_FLAGS))
            | ((value << Self::RAW_BYTE_8_OFFSET_FLAGS) & Self::RAW_BYTE_8_MASK_FLAGS);
    }

    /// Extract the S flag (Suppress Router-Side Processing) from
    /// the `raw_byte_8` field.
    pub fn s_flag(&self) -> bool {
        0 != (self.raw_byte_8 & Self::RAW_BYTE_8_MASK_S_FLAG)
    }

    /// Sets the S flag (Suppress Router-Side Processing) in
    /// the `raw_byte_8` field.
    pub fn set_s_flag(&mut self, value: bool) {
        if value {
            self.raw_byte_8 |= Self::RAW_BYTE_8_MASK_S_FLAG;
        } else {
            self.raw_byte_8 &= !Self::RAW_BYTE_8_MASK_S_FLAG;
        }
    }

    /// Extracst the QRV (Querier's Robustness Variable) from
    /// the `raw_byte_8` field.
    pub fn qrv(&self) -> Qrv {
        // SAFETY: Safe as the value is guranteed to been within range
        //         after the mask is applied.
        unsafe { Qrv::new_unchecked(self.raw_byte_8 & Self::RAW_BYTE_8_MASK_QRV) }
    }

    /// Sets the QRV (Querier's Robustness Variable) in
    /// the `raw_byte_8` field.
    pub fn set_qrv(&mut self, value: Qrv) {
        self.raw_byte_8 =
            (self.raw_byte_8 & (!Self::RAW_BYTE_8_MASK_QRV)) | (value.value() & Self::RAW_BYTE_8_MASK_QRV);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn flags_get(raw_byte_8 in any::<u8>()) {
            let header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            prop_assert_eq!(header.flags(), raw_byte_8 >> 4);
        }
    }

    proptest! {
        #[test]
        fn flags_set(
            raw_byte_8 in any::<u8>(),
            value in any::<u8>(),
        ) {
            let mut header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            header.set_flags(value);
            // "flags" (top 4 bits) should match the lower 4 bits of `value`
            prop_assert_eq!(header.flags(), value & 0b0000_1111);
            // bits below the "flags" section must be preserved
            prop_assert_eq!(
                header.raw_byte_8 & !MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS,
                raw_byte_8 & !MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_FLAGS
            );
        }
    }

    proptest! {
        #[test]
        fn flags_roundtrip(
            raw_byte_8 in any::<u8>(),
            value in 0u8..=0b0000_1111,
        ) {
            let mut header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            header.set_flags(value);
            prop_assert_eq!(header.flags(), value);
        }
    }

    proptest! {
        #[test]
        fn s_flag_get(raw_byte_8 in any::<u8>()) {
            let header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            prop_assert_eq!(
                header.s_flag(),
                0 != (raw_byte_8 & MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_S_FLAG)
            );
        }
    }

    proptest! {
        #[test]
        fn s_flag_set(
            raw_byte_8 in any::<u8>(),
            value in any::<bool>(),
        ) {
            let mut header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            header.set_s_flag(value);
            prop_assert_eq!(header.s_flag(), value);
            // all other bits must be preserved
            prop_assert_eq!(
                header.raw_byte_8 & !MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_S_FLAG,
                raw_byte_8 & !MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_S_FLAG
            );
        }
    }

    proptest! {
        #[test]
        fn qrv_get(raw_byte_8 in any::<u8>()) {
            let header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            prop_assert_eq!(
                header.qrv().value(),
                raw_byte_8 & MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_QRV
            );
        }
    }

    proptest! {
        #[test]
        fn qrv_set(
            raw_byte_8 in any::<u8>(),
            value in 0u8..=Qrv::MAX_U8,
        ) {
            let qrv = Qrv::try_new(value).unwrap();
            let mut header = MembershipQueryWithSourcesHeader {
                max_response_code: MaxResponseCode(0),
                group_address: GroupAddress::new([0, 0, 0, 0]),
                raw_byte_8,
                qqic: 0,
                num_of_sources: 0,
            };
            header.set_qrv(qrv);
            prop_assert_eq!(header.qrv().value(), value);
            // bits outside of the QRV section must be preserved
            prop_assert_eq!(
                header.raw_byte_8 & !MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_QRV,
                raw_byte_8 & !MembershipQueryWithSourcesHeader::RAW_BYTE_8_MASK_QRV
            );
        }
    }
}

