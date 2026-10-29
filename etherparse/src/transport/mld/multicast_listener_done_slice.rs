use crate::{mld::*, *};

/// Zero-copy slice of the ICMPv6 payload of an MLDv1 "Multicast Listener
/// Done" message (type `132`, 24 octets total, so 16 payload octets).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 132   |      Code     |           Checksum            |  | ICMPv6 header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | (`bytes5to8`)
/// |            Unused             |           Reserved            |  ↓
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
pub struct MulticastListenerDoneSlice<'a> {
    /// Bytes 4-7 of the ICMPv6 header (`Unused` & `Reserved`).
    bytes5to8: [u8; 4],
    /// The ICMPv6 payload.
    slice: &'a [u8],
}

impl<'a> MulticastListenerDoneSlice<'a> {
    /// Creates a slice from the ICMPv6 payload without checking the length.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` is at least
    /// [`MulticastListenerDoneType::PAYLOAD_LEN`] (16) bytes long.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(
        bytes5to8: [u8; 4],
        slice: &'a [u8],
    ) -> MulticastListenerDoneSlice<'a> {
        debug_assert!(slice.len() >= MulticastListenerDoneType::PAYLOAD_LEN);
        MulticastListenerDoneSlice { bytes5to8, slice }
    }

    /// Returns bytes 4-7 of the ICMPv6 header.
    ///
    /// Per [RFC 2710 §3.4 & §3.5](
    /// https://datatracker.ietf.org/doc/html/rfc2710#section-3.4) these
    /// bytes are unused & reserved in a done message and must be set to
    /// zero by the sender and ignored by receivers.
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        self.bytes5to8
    }

    /// The multicast address to which the sender has ceased to listen.
    #[inline]
    pub fn multicast_address(&self) -> MulticastAddress {
        // SAFETY: from_slice_unchecked guarantees at least 16 bytes.
        MulticastAddress::new(unsafe { get_unchecked_16_byte_array(self.slice.as_ptr()) })
    }

    /// Decodes the fixed fields into an owned [`MulticastListenerDoneType`].
    #[inline]
    pub fn to_header(&self) -> MulticastListenerDoneType {
        MulticastListenerDoneType {
            multicast_address: self.multicast_address(),
        }
    }

    /// Returns the bytes after the 16-byte multicast address (usually empty).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY: from_slice_unchecked guarantees at least 16 bytes.
        unsafe {
            core::slice::from_raw_parts(
                self.slice
                    .as_ptr()
                    .add(MulticastListenerDoneType::PAYLOAD_LEN),
                self.slice.len() - MulticastListenerDoneType::PAYLOAD_LEN,
            )
        }
    }

    /// Returns the slice containing the ICMPv6 payload of the MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
