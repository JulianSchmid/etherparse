use crate::mld::{MaxResponseCode, MulticastAddress, Qrv};

/// A multicast listener query message type (MLDv2 version) with source addresses.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 130   |      Code     |           Checksum            |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |    Maximum Response Code      |           Reserved            |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  | part of header and
/// +-                                                             -+  | this type
/// |                                                               |  |
/// +-                      Multicast Address                      -+  |
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// | Flags |S| QRV |     QQIC      |     Number of Sources (N)     |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-                      Source Address [1]                     -+  |
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-                                                             -+  | part of payload
/// .                               .                               .  |
/// .                               .                               .  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-                      Source Address [N]                     -+  |
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MulticastListenerQueryWithSourcesHeader {
    /// The Maximum Response Code field specifies the maximum time allowed
    /// before sending a responding report.
    pub max_response_code: MaxResponseCode,

    /// The multicast address being queried.
    ///
    /// Set to zero for general queries, to learn which multicast
    /// addresses have listeners on an attached link. Filled for multicast
    /// address specific & multicast address and source specific queries.
    pub multicast_address: MulticastAddress,

    /// Raw byte containing "flags", "s" & "QRV" (the getters & setters
    /// methods can be used to get & set the different values).
    ///
    /// Named after its position in the ICMPv6 payload (byte 24 of the
    /// complete MLD message).
    pub raw_byte_16: u8,

    /// QQIC (Querier's Query Interval Code).
    pub qqic: u8,

    /// Number of source addresses present in the query.
    ///
    /// The actual addresses are seperated into the
    /// payload part of the message.
    pub num_of_sources: u16,
}

impl MulticastListenerQueryWithSourcesHeader {
    /// Number of bytes/octets the fixed part of an MLDv2 "Multicast
    /// Listener Query" takes up in serialized form (including the 8 byte
    /// ICMPv6 header, excluding the source addresses).
    ///
    /// This is the minimum length [RFC 9777 §8.1](
    /// https://datatracker.ietf.org/doc/html/rfc9777#section-8.1) uses to
    /// identify a query as MLDv2.
    pub const LEN: usize = 28;

    /// Number of bytes/octets of the ICMPv6 payload (the bytes after the 8
    /// byte ICMPv6 header) the fixed part of an MLDv2 "Multicast Listener
    /// Query" takes up (excluding the source addresses).
    pub const PAYLOAD_LEN: usize = Self::LEN - 8;

    /// Bitmask identifying the "flags" part of [`MulticastListenerQueryWithSourcesHeader::raw_byte_16`].
    pub const RAW_BYTE_16_MASK_FLAGS: u8 = 0b1111_0000;

    /// Bitshift needed to get to the "flags" part of [`MulticastListenerQueryWithSourcesHeader::raw_byte_16`].
    pub const RAW_BYTE_16_OFFSET_FLAGS: u8 = 4;

    /// Bitmask identifying the "s flag" part of [`MulticastListenerQueryWithSourcesHeader::raw_byte_16`].
    pub const RAW_BYTE_16_MASK_S_FLAG: u8 = 0b0000_1000;

    /// Bitmask identifying the "QRV" part of [`MulticastListenerQueryWithSourcesHeader::raw_byte_16`].
    pub const RAW_BYTE_16_MASK_QRV: u8 = 0b0000_0111;

    /// Extracts the "flags" from the `raw_byte_16` field.
    pub fn flags(&self) -> u8 {
        (self.raw_byte_16 & Self::RAW_BYTE_16_MASK_FLAGS) >> Self::RAW_BYTE_16_OFFSET_FLAGS
    }

    /// Sets the "flags" in the `raw_byte_16` field.
    pub fn set_flags(&mut self, value: u8) {
        self.raw_byte_16 = (self.raw_byte_16 & (!Self::RAW_BYTE_16_MASK_FLAGS))
            | ((value << Self::RAW_BYTE_16_OFFSET_FLAGS) & Self::RAW_BYTE_16_MASK_FLAGS);
    }

    /// Extract the S flag (Suppress Router-Side Processing) from
    /// the `raw_byte_16` field.
    pub fn s_flag(&self) -> bool {
        0 != (self.raw_byte_16 & Self::RAW_BYTE_16_MASK_S_FLAG)
    }

    /// Sets the S flag (Suppress Router-Side Processing) in
    /// the `raw_byte_16` field.
    pub fn set_s_flag(&mut self, value: bool) {
        if value {
            self.raw_byte_16 |= Self::RAW_BYTE_16_MASK_S_FLAG;
        } else {
            self.raw_byte_16 &= !Self::RAW_BYTE_16_MASK_S_FLAG;
        }
    }

    /// Extracts the QRV (Querier's Robustness Variable) from
    /// the `raw_byte_16` field.
    pub fn qrv(&self) -> Qrv {
        // SAFETY: Safe as the value is guranteed to been within range
        //         after the mask is applied.
        unsafe { Qrv::new_unchecked(self.raw_byte_16 & Self::RAW_BYTE_16_MASK_QRV) }
    }

    /// Sets the QRV (Querier's Robustness Variable) in
    /// the `raw_byte_16` field.
    pub fn set_qrv(&mut self, value: Qrv) {
        self.raw_byte_16 = (self.raw_byte_16 & (!Self::RAW_BYTE_16_MASK_QRV))
            | (value.value() & Self::RAW_BYTE_16_MASK_QRV);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    /// Returns a header with all fields zeroed except `raw_byte_16`, so the
    /// bit field tests below only vary the byte they are checking.
    fn test_header(raw_byte_16: u8) -> MulticastListenerQueryWithSourcesHeader {
        MulticastListenerQueryWithSourcesHeader {
            max_response_code: MaxResponseCode(0),
            multicast_address: MulticastAddress::new([0u8; 16]),
            raw_byte_16,
            qqic: 0,
            num_of_sources: 0,
        }
    }

    /// An MLDv2 query is 28 octets (20 of them payload), and the masks &
    /// offset must describe the Resv/S/QRV layout of byte 16.
    #[test]
    fn constants() {
        assert_eq!(28, MulticastListenerQueryWithSourcesHeader::LEN);
        assert_eq!(20, MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN);
        assert_eq!(
            0b1111_0000,
            MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_FLAGS
        );
        assert_eq!(
            4,
            MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_OFFSET_FLAGS
        );
        assert_eq!(
            0b0000_1000,
            MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_S_FLAG
        );
        assert_eq!(
            0b0000_0111,
            MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_QRV
        );
    }

    proptest! {
        /// `flags` must return the top 4 bits of byte 16.
        #[test]
        fn flags_get(raw_byte_16 in any::<u8>()) {
            let header = test_header(raw_byte_16);
            prop_assert_eq!(header.flags(), raw_byte_16 >> 4);
        }
    }

    proptest! {
        /// `set_flags` must write the lower 4 bits of the argument into the
        /// flags section and leave the S flag & QRV bits untouched.
        #[test]
        fn flags_set(
            raw_byte_16 in any::<u8>(),
            value in any::<u8>(),
        ) {
            let mut header = test_header(raw_byte_16);
            header.set_flags(value);
            // "flags" (top 4 bits) should match the lower 4 bits of `value`
            prop_assert_eq!(header.flags(), value & 0b0000_1111);
            // bits below the "flags" section must be preserved
            prop_assert_eq!(
                header.raw_byte_16 & !MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_FLAGS,
                raw_byte_16 & !MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_FLAGS
            );
        }
    }

    proptest! {
        /// `flags` must return what `set_flags` was given for every value
        /// that fits in the 4 bit field.
        #[test]
        fn flags_roundtrip(
            raw_byte_16 in any::<u8>(),
            value in 0u8..=0b0000_1111,
        ) {
            let mut header = test_header(raw_byte_16);
            header.set_flags(value);
            prop_assert_eq!(header.flags(), value);
        }
    }

    proptest! {
        /// `s_flag` must report the state of the "Suppress Router-Side
        /// Processing" bit of byte 16.
        #[test]
        fn s_flag_get(raw_byte_16 in any::<u8>()) {
            let header = test_header(raw_byte_16);
            prop_assert_eq!(
                header.s_flag(),
                0 != (raw_byte_16 & MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_S_FLAG)
            );
        }
    }

    proptest! {
        /// `set_s_flag` must set & clear the S bit and leave every other
        /// bit of byte 16 untouched.
        #[test]
        fn s_flag_set(
            raw_byte_16 in any::<u8>(),
            value in any::<bool>(),
        ) {
            let mut header = test_header(raw_byte_16);
            header.set_s_flag(value);
            prop_assert_eq!(header.s_flag(), value);
            // all other bits must be preserved
            prop_assert_eq!(
                header.raw_byte_16 & !MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_S_FLAG,
                raw_byte_16 & !MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_S_FLAG
            );
        }
    }

    proptest! {
        /// `qrv` must return the lowest 3 bits of byte 16.
        #[test]
        fn qrv_get(raw_byte_16 in any::<u8>()) {
            let header = test_header(raw_byte_16);
            prop_assert_eq!(
                header.qrv().value(),
                raw_byte_16 & MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_QRV
            );
        }
    }

    proptest! {
        /// `set_qrv` must write the QRV into the lowest 3 bits and leave
        /// the flags & S bit untouched.
        #[test]
        fn qrv_set(
            raw_byte_16 in any::<u8>(),
            value in 0u8..=Qrv::MAX_U8,
        ) {
            let qrv = Qrv::try_new(value).unwrap();
            let mut header = test_header(raw_byte_16);
            header.set_qrv(qrv);
            prop_assert_eq!(header.qrv().value(), value);
            // bits outside of the QRV section must be preserved
            prop_assert_eq!(
                header.raw_byte_16 & !MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_QRV,
                raw_byte_16 & !MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_QRV
            );
        }
    }

    proptest! {
        /// `Clone`, `PartialEq` & `Debug` must be derived and hold for any
        /// byte 16 value.
        #[test]
        fn clone_eq_debug(raw_byte_16 in any::<u8>()) {
            let header = test_header(raw_byte_16);
            prop_assert_eq!(&header, &header.clone());
            let dbg = format!("{:?}", header);
            prop_assert!(
                dbg.starts_with("MulticastListenerQueryWithSourcesHeader"),
                "{}",
                dbg
            );
        }
    }
}
