use crate::{
    err::{Layer, LenError},
    *,
};

/// Slice containing a MACsec header & next ether type (if possible).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MacsecHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> MacsecHeaderSlice<'a> {
    /// Try creating a [`MacSecHeaderSlice`] from a slice containing the
    /// MACsec header & next ether type.
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<MacsecHeaderSlice<'a>, err::macsec::HeaderSliceError> {
        use err::macsec::{HeaderError::*, HeaderSliceError::*};

        if slice.len() < 6 {
            return Err(Len(LenError {
                required_len: 6,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::MacsecHeader,
                layer_start_offset: 0,
            }));
        }

        // SAFETY: Safe as the length was verified to be at least 6.
        let tci_an = unsafe { slice.get_unchecked(0) };

        // validate version
        if 0 != tci_an & 0b1000_0000 {
            return Err(Content(UnexpectedVersion));
        }

        // get the encrypted, changed flag (check if ether_type can be parsed)
        let required_len = 6
            + if 0 != tci_an & 0b1100 { 0 } else { 2 }
            + if 0 != tci_an & 0b10_0000 { 8 } else { 0 };

        if slice.len() < required_len {
            return Err(Len(LenError {
                required_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::MacsecHeader,
                layer_start_offset: 0,
            }));
        }

        Ok(MacsecHeaderSlice {
            // SAFETY: Safe as the length was previously verfied to be at least required_len.
            slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), required_len) },
        })
    }

    /// Slice containing the header & ether type of the next segment
    /// if available.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Raw first byte of the mac sec header (containing TCI & AN).
    #[inline]
    pub fn tci_an_raw(&self) -> u8 {
        // SAFETY: Slice access safe as length of the slice was
        //         verified in the constructor to be at least 6.
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// End station identifier (TCI.ES flag).
    #[inline]
    pub fn endstation_id(&self) -> bool {
        0 != (self.tci_an_raw() & 0b100_0000)
    }

    /// Ethernet passive optical network broadcast flag.
    #[inline]
    pub fn tci_scb(&self) -> bool {
        0 != (self.tci_an_raw() & 0b1_0000)
    }

    /// Encryption flag, which indicates whether the user data is
    /// encryped (true = encrypted, TCI.E flag).
    #[inline]
    pub fn encrypted(&self) -> bool {
        // SAFETY: Slice access safe as length of the slice was
        //         verified in the constructor to be at least 6.
        0 != (self.tci_an_raw() & 0b1000)
    }

    /// Flag for change text, set if the user data is modified.
    #[inline]
    pub fn userdata_changed(&self) -> bool {
        // SAFETY: Slice access safe as length of the slice was
        //         verified in the constructor to be at least 6.
        0 != (self.tci_an_raw() & 0b100)
    }

    /// True if the payload was neither flagged as modified or encrypted.
    #[inline]
    pub fn is_unmodified(&self) -> bool {
        // SAFETY: Slice access safe as length of the slice was
        //         verified in the constructor to be at least 6.
        0 == (self.tci_an_raw() & 0b1100)
    }

    /// Payload type (contains encryption, modifidcation flag as
    /// well as the next ether type if available)
    #[inline]
    pub fn ptype(&self) -> MacsecPType {
        let e = self.encrypted();
        let c = self.userdata_changed();
        if e {
            if c {
                MacsecPType::Encrypted
            } else {
                MacsecPType::EncryptedUnmodified
            }
        } else {
            if c {
                MacsecPType::Modified
            } else {
                if 0 != (self.tci_an_raw() & 0b10_0000) {
                    // SAFETY: Slice access safe as length of the slice was
                    //         verified in the constructor to be at least 16
                    //         if 0b10_0000 is set and and 'c' and 'e' are not
                    //         set in the tci_an_raw.
                    MacsecPType::Unmodified(EtherType(u16::from_be_bytes(unsafe {
                        [*self.slice.get_unchecked(14), *self.slice.get_unchecked(15)]
                    })))
                } else {
                    // SAFETY: Slice access safe as length of the slice was
                    //         verified in the constructor to be at least 8
                    //         if 0b10_0000 is not set and 'c' and 'e' are not
                    //         set in the tci_an_raw.
                    MacsecPType::Unmodified(EtherType(u16::from_be_bytes(unsafe {
                        [*self.slice.get_unchecked(6), *self.slice.get_unchecked(7)]
                    })))
                }
            }
        }
    }

    /// Association number (identifes SAs).
    #[inline]
    pub fn an(&self) -> MacsecAn {
        // SAFETY: MacSecAn conversion safe as bitmasked to only
        //         contain 2 bits.
        unsafe { MacsecAn::new_unchecked(self.tci_an_raw() & 0b11) }
    }

    /// Short length with reserved bits.
    #[inline]
    pub fn short_length(&self) -> MacsecShortLen {
        // SAFETY: Slice access safe as length of the slice was
        //         verified in the constructor to be at least 6.
        //         MacSecSl conversion safe as bitmasked to contain
        //         only 6 bits.
        unsafe { MacsecShortLen::new_unchecked(self.slice.get_unchecked(1) & 0b0011_1111) }
    }

    /// Packet number.
    #[inline]
    pub fn packet_nr(&self) -> u32 {
        // SAFETY: Slice access safe as length of the slice was
        //         verified in the constructor to be at least 6.
        //         MacSecSl conversion safe as bitmasked.
        u32::from_be_bytes(unsafe {
            [
                *self.slice.get_unchecked(2),
                *self.slice.get_unchecked(3),
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
            ]
        })
    }

    /// True if the SCI bit is set in the TCI part of the SecTag header.
    #[inline]
    pub fn sci_present(&self) -> bool {
        0 != (self.tci_an_raw() & 0b10_0000)
    }

    /// Secure channel identifier.
    #[inline]
    pub fn sci(&self) -> Option<u64> {
        if self.sci_present() {
            // SAFETY: Slice access safe as length of the slice was
            //         verified in the constructor to be at least 14
            //         if 0b10_0000 is set in the tci_an_raw.
            Some(u64::from_be_bytes(unsafe {
                [
                    *self.slice.get_unchecked(6),
                    *self.slice.get_unchecked(7),
                    *self.slice.get_unchecked(8),
                    *self.slice.get_unchecked(9),
                    *self.slice.get_unchecked(10),
                    *self.slice.get_unchecked(11),
                    *self.slice.get_unchecked(12),
                    *self.slice.get_unchecked(13),
                ]
            }))
        } else {
            None
        }
    }

    /// Ether type of the data following the sec tag (only
    /// available if not encrypted and userdata is not flagged
    /// as modified).
    #[inline]
    pub fn next_ether_type(&self) -> Option<EtherType> {
        if 0 != self.tci_an_raw() & 0b1100 {
            None
        } else {
            if self.sci_present() {
                // SAFETY: Slice access safe as length of the slice was
                //         verified in the constructor to be at least 16
                //         if 0b10_0000 is set and 0b1100 is not set in
                //         the tci_an_raw.
                Some(EtherType(u16::from_be_bytes(unsafe {
                    [*self.slice.get_unchecked(14), *self.slice.get_unchecked(15)]
                })))
            } else {
                // SAFETY: Slice access safe as length of the slice was
                //         verified in the constructor to be at least 8
                //         if 0b10_0000 is not set and 0b1100 is not set in
                //         the tci_an_raw.
                Some(EtherType(u16::from_be_bytes(unsafe {
                    [*self.slice.get_unchecked(6), *self.slice.get_unchecked(7)]
                })))
            }
        }
    }

    /// Length of the MACsec header (SecTag + next ether type if available).
    #[inline]
    pub fn header_len(&self) -> usize {
        6 + if self.sci_present() { 8 } else { 0 } + if self.is_unmodified() { 2 } else { 0 }
    }

    /// Decodes all MacSecHeader values and returns them as a
    /// [`crate::MacSecHeader`].
    #[inline]
    pub fn to_header(&self) -> MacsecHeader {
        MacsecHeader {
            ptype: self.ptype(),
            endstation_id: self.endstation_id(),
            scb: self.tci_scb(),
            an: self.an(),
            short_len: self.short_length(),
            packet_nr: self.packet_nr(),
            sci: self.sci(),
        }
    }
}
