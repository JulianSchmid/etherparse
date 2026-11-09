use crate::{mld::*, *};

/// Zero-copy slice of the ICMPv6 payload of an MLDv1 "Multicast Listener
/// Query" (type `130`, 24 octets total, so exactly 16 payload octets).
///
/// The `Maximum Response Delay` is located in the first 8 bytes of the
/// ICMPv6 message and is therefore taken from
/// [`crate::Icmpv6Slice::bytes5to8`] instead of the payload.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 130   |      Code     |           Checksum            |  | ICMPv6 header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | (`bytes5to8`)
/// |    Maximum Response Delay     |           Reserved            |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-                      Multicast Address                      -+  | ICMPv6 payload
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulticastListenerQuerySlice<'a> {
    /// Bytes 4-7 of the ICMPv6 header (`Maximum Response Delay` & `Reserved`).
    bytes5to8: [u8; 4],
    /// The ICMPv6 payload.
    slice: &'a [u8],
}

impl<'a> MulticastListenerQuerySlice<'a> {
    /// Creates a slice from the ICMPv6 payload without checking that it
    /// contains a valid MLDv1 query.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` is at least
    /// [`MulticastListenerQueryType::PAYLOAD_LEN`] (16) bytes long.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(
        bytes5to8: [u8; 4],
        slice: &'a [u8],
    ) -> MulticastListenerQuerySlice<'a> {
        debug_assert!(slice.len() >= MulticastListenerQueryType::PAYLOAD_LEN);
        MulticastListenerQuerySlice { bytes5to8, slice }
    }

    /// Returns bytes 4-7 of the ICMPv6 header (the `Maximum Response
    /// Delay` followed by the `Reserved` field).
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        self.bytes5to8
    }

    /// The maximum response delay in milliseconds.
    #[inline]
    pub fn max_response_delay(&self) -> u16 {
        u16::from_be_bytes([self.bytes5to8[0], self.bytes5to8[1]])
    }

    /// The multicast address being queried.
    #[inline]
    pub fn multicast_address(&self) -> MulticastAddress {
        // SAFETY: from_slice_unchecked guarantees at least 16 bytes.
        MulticastAddress::new(unsafe { get_unchecked_16_byte_array(self.slice.as_ptr()) })
    }

    /// Decodes the fixed fields into an owned [`MulticastListenerQueryType`].
    #[inline]
    pub fn to_header(&self) -> MulticastListenerQueryType {
        MulticastListenerQueryType {
            max_response_delay: self.max_response_delay(),
            multicast_address: self.multicast_address(),
        }
    }

    /// Returns the slice containing the ICMPv6 payload of the MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
