use crate::mld::*;

/// Zero-copy slice of the ICMPv6 payload of an MLDv2 "Version 2 Multicast
/// Listener Report" (type `143`) containing the list of multicast address
/// records.
///
/// The `Flags` & `Nr of Mcast Address Records (M)` fields are located in
/// the first 8 bytes of the ICMPv6 message and are therefore taken from
/// [`crate::Icmpv6Slice::bytes5to8`] instead of the payload. The complete
/// ICMPv6 payload consists of the multicast address records.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 143   |    Reserved   |           Checksum            |  | ICMPv6 header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | (`bytes5to8`)
/// |             Flags             |Nr of Mcast Address Records (M)|  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// .                                                               .  |
/// .                  Multicast Address Record [1]                 .  |
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .                  Multicast Address Record [2]                 .  | ICMPv6 payload
/// .                                                               .  |
/// |                                                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                               .                               |  |
/// .                               .                               .  |
/// |                               .                               |  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
/// |                                                               |  |
/// .                                                               .  |
/// .                  Multicast Address Record [M]                 .  |
/// .                                                               .  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulticastListenerReportV2Slice<'a> {
    /// Bytes 4-7 of the ICMPv6 header (`Flags` & `Nr of Mcast Address Records`).
    bytes5to8: [u8; 4],
    /// The ICMPv6 payload.
    slice: &'a [u8],
}

impl<'a> MulticastListenerReportV2Slice<'a> {
    /// Creates a slice from the ICMPv6 payload.
    ///
    /// All fields of the fixed part are located in `bytes5to8`, so the
    /// payload may be of any length (including empty, for a report with
    /// zero records).
    #[inline]
    pub(crate) fn new(bytes5to8: [u8; 4], slice: &'a [u8]) -> MulticastListenerReportV2Slice<'a> {
        MulticastListenerReportV2Slice { bytes5to8, slice }
    }

    /// Returns bytes 4-7 of the ICMPv6 header (the `Flags` followed by the
    /// `Nr of Mcast Address Records (M)`).
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        self.bytes5to8
    }

    /// Additional flags (bytes 4-5 of the ICMPv6 header).
    #[inline]
    pub fn flags(&self) -> [u8; 2] {
        [self.bytes5to8[0], self.bytes5to8[1]]
    }

    /// Number of multicast address records declared in the report
    /// ("Nr of Mcast Address Records (M)").
    #[inline]
    pub fn num_of_records(&self) -> u16 {
        u16::from_be_bytes([self.bytes5to8[2], self.bytes5to8[3]])
    }

    /// Decodes the fixed fields into an owned [`MulticastListenerReportV2Header`].
    #[inline]
    pub fn to_header(&self) -> MulticastListenerReportV2Header {
        MulticastListenerReportV2Header {
            flags: self.flags(),
            num_of_records: self.num_of_records(),
        }
    }

    /// Returns an iterator over the multicast address records.
    ///
    /// The iterator yields at most [`MulticastListenerReportV2Slice::num_of_records`]
    /// items and stops early with an [`crate::err::LenError`] if the payload is
    /// shorter than the records claim.
    #[inline]
    pub fn multicast_address_records(&self) -> MulticastAddressRecordSliceIter<'a> {
        MulticastAddressRecordSliceIter::new(self.payload(), self.num_of_records())
    }

    /// Returns the multicast address records (the complete ICMPv6 payload).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns the slice containing the ICMPv6 payload of the MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
