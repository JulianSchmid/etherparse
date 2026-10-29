use crate::{mld::*, *};

/// Zero-copy slice of the ICMPv6 payload of an MLDv2 "Multicast Listener
/// Query" (type `130`, at least 28 octets total, so at least 20 payload
/// octets) including the source address list.
///
/// The `Maximum Response Code` is located in the first 8 bytes of the
/// ICMPv6 message and is therefore taken from
/// [`crate::Icmpv6Slice::bytes5to8`] instead of the payload.
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |  Type = 130   |      Code     |           Checksum            |  | ICMPv6 header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | (`bytes5to8`)
/// |    Maximum Response Code      |           Reserved            |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-                      Multicast Address                      -+  | fixed part of
/// |                                                               |  | the payload
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
/// +-                                                             -+  | variable part of
/// .                               .                               .  | the payload
/// .                               .                               .  |
/// +-                                                             -+  |
/// |                                                               |  |
/// +-                      Source Address [N]                     -+  |
/// |                                                               |  |
/// +-                                                             -+  |
/// |                                                               |  ↓
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  -
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulticastListenerQueryWithSourcesSlice<'a> {
    /// Bytes 4-7 of the ICMPv6 header (`Maximum Response Code` & `Reserved`).
    bytes5to8: [u8; 4],
    /// The ICMPv6 payload.
    slice: &'a [u8],
}

impl<'a> MulticastListenerQueryWithSourcesSlice<'a> {
    /// Creates a slice from the ICMPv6 payload without checking that it
    /// contains a valid MLDv2 query.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `slice` contains the complete
    /// declared payload:
    ///
    /// * at least [`MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN`]
    ///   (20) bytes for the fixed part, and
    /// * additionally `num_of_sources * 16` bytes for the source address
    ///   list, where `num_of_sources` is the `u16` read from bytes 18..20
    ///   of the payload.
    ///
    /// In other words `slice.len()` must be at least
    /// `20 + num_of_sources * 16` so that all source addresses accessed by
    /// [`MulticastListenerQueryWithSourcesSlice::source_addrs_bytes`] are in
    /// bounds.
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(
        bytes5to8: [u8; 4],
        slice: &'a [u8],
    ) -> MulticastListenerQueryWithSourcesSlice<'a> {
        debug_assert!(slice.len() >= MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN);
        // The slice must also be long enough to hold all declared source
        // addresses (16 bytes each). `MldSlice::from_slice` guarantees this.
        debug_assert!(
            slice.len()
                >= MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN
                    + usize::from(u16::from_be_bytes([slice[18], slice[19]])) * 16
        );
        MulticastListenerQueryWithSourcesSlice { bytes5to8, slice }
    }

    /// Returns bytes 4-7 of the ICMPv6 header (the `Maximum Response Code`
    /// followed by the `Reserved` field).
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        self.bytes5to8
    }

    /// The Maximum Response Code field.
    #[inline]
    pub fn max_response_code(&self) -> MaxResponseCode {
        MaxResponseCode(u16::from_be_bytes([self.bytes5to8[0], self.bytes5to8[1]]))
    }

    /// The multicast address being queried.
    #[inline]
    pub fn multicast_address(&self) -> MulticastAddress {
        // SAFETY: from_slice_unchecked guarantees at least 20 bytes.
        MulticastAddress::new(unsafe { get_unchecked_16_byte_array(self.slice.as_ptr()) })
    }

    /// Raw byte containing "flags", "s" & "QRV".
    ///
    /// Named after its position in the ICMPv6 payload (byte 24 of the
    /// complete MLD message).
    #[inline]
    pub fn raw_byte_16(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 20 bytes.
        unsafe { *self.slice.get_unchecked(16) }
    }

    /// Extracts the "flags" from the `raw_byte_16` field.
    #[inline]
    pub fn flags(&self) -> u8 {
        (self.raw_byte_16() & MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_FLAGS)
            >> MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_OFFSET_FLAGS
    }

    /// Extracts the S flag (Suppress Router-Side Processing).
    #[inline]
    pub fn s_flag(&self) -> bool {
        0 != (self.raw_byte_16() & MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_S_FLAG)
    }

    /// Extracts the QRV (Querier's Robustness Variable).
    #[inline]
    pub fn qrv(&self) -> Qrv {
        // SAFETY: the value is guaranteed to be within range after the mask.
        unsafe {
            Qrv::new_unchecked(
                self.raw_byte_16() & MulticastListenerQueryWithSourcesHeader::RAW_BYTE_16_MASK_QRV,
            )
        }
    }

    /// QQIC (Querier's Query Interval Code).
    #[inline]
    pub fn qqic(&self) -> u8 {
        // SAFETY: from_slice_unchecked guarantees at least 20 bytes.
        unsafe { *self.slice.get_unchecked(17) }
    }

    /// Number of source addresses declared in the query.
    #[inline]
    pub fn num_of_sources(&self) -> u16 {
        // SAFETY: from_slice_unchecked guarantees at least 20 bytes.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(18)) }
    }

    /// Decodes the fixed fields into an owned [`MulticastListenerQueryWithSourcesHeader`].
    #[inline]
    pub fn to_header(&self) -> MulticastListenerQueryWithSourcesHeader {
        MulticastListenerQueryWithSourcesHeader {
            max_response_code: self.max_response_code(),
            multicast_address: self.multicast_address(),
            raw_byte_16: self.raw_byte_16(),
            qqic: self.qqic(),
            num_of_sources: self.num_of_sources(),
        }
    }

    /// Returns the raw source address bytes.
    ///
    /// The returned slice contains `num_of_sources * 16` bytes (each 16
    /// consecutive bytes are one IPv6 source address).
    #[inline]
    pub fn source_addrs_bytes(&self) -> &'a [u8] {
        let payload = self.payload();
        let len = usize::from(self.num_of_sources()) * 16;
        // SAFETY: `MldSlice::from_slice` guarantees the payload contains
        // all declared source addresses (num_of_sources * 16 bytes).
        unsafe { core::slice::from_raw_parts(payload.as_ptr(), len) }
    }

    /// Returns an iterator over the source addresses as `[u8; 16]` arrays.
    #[inline]
    pub fn source_addresses(&self) -> impl ExactSizeIterator<Item = [u8; 16]> + 'a {
        self.source_addrs_bytes().chunks_exact(16).map(|c| {
            let mut address = [0u8; 16];
            address.copy_from_slice(c);
            address
        })
    }

    /// Returns the bytes after the 20-byte fixed part of the payload (the
    /// source address list).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY: from_slice_unchecked guarantees at least 20 bytes.
        unsafe {
            core::slice::from_raw_parts(
                self.slice
                    .as_ptr()
                    .add(MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN),
                self.slice.len() - MulticastListenerQueryWithSourcesHeader::PAYLOAD_LEN,
            )
        }
    }

    /// Returns the slice containing the ICMPv6 payload of the MLD message.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
