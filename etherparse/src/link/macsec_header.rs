use crate::*;
use arrayvec::ArrayVec;

/// MACsec SecTag header (present at the start of a
/// packet capsuled with MACsec).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacsecHeader {
    /// Payload type (contains encryption, modifidcation flag as
    /// well as the next ether type if available)
    pub ptype: MacsecPType,

    /// End station identifier (TCI.ES flag).
    pub endstation_id: bool,

    /// Ethernet passive optical network broadcast flag.
    pub scb: bool,

    /// Association number (identifes SAs).
    pub an: MacsecAn,

    /// Short length with reserved bits.
    pub short_len: MacsecShortLen,

    /// Packet number.
    pub packet_nr: u32,

    /// Secure channel identifier.
    pub sci: Option<u64>,
}

impl MacsecHeader {
    /// Minimum length of an MacSec header in bytes/octets.
    pub const MIN_LEN: usize = 6;

    /// Maximum length of an MacSec header (including ether type of payload) in bytes/octets.
    pub const MAX_LEN: usize = 16;

    /// Encryption flag, which indicates whether the user data is
    /// encryped (true = encrypted, TCI.E flag).
    #[inline]
    pub fn encrypted(&self) -> bool {
        use MacsecPType::*;
        matches!(self.ptype, Encrypted | EncryptedUnmodified)
    }

    /// Flag for change text, set if the user data is modified.
    pub fn userdata_changed(&self) -> bool {
        use MacsecPType::*;
        matches!(self.ptype, Encrypted | Modified)
    }

    /// Ether type of the data following the mac sec tag.
    pub fn next_ether_type(&self) -> Option<EtherType> {
        if let MacsecPType::Unmodified(re) = self.ptype {
            Some(re)
        } else {
            None
        }
    }

    /// Try creating a [`MacSecHeaderSlice`] from a slice containing the
    /// MACsec header & next ether type.
    pub fn from_slice(slice: &[u8]) -> Result<MacsecHeader, err::macsec::HeaderSliceError> {
        MacsecHeaderSlice::from_slice(slice).map(|v| v.to_header())
    }

    /// Serialize the mac sec header.
    pub fn to_bytes(&self) -> ArrayVec<u8, { MacsecHeader::MAX_LEN }> {
        // tci-an is composed of:
        //       ---------------------------------------
        //       | v | es | sc | scp | e | c | an | an |
        //       ---------------------------------------
        // bits    8   7    6     5    4   3    2    1
        //
        // - version (0)
        // - es (end station identifier bit)
        // - sc (SCI present bit)
        // - scp (Ethernet passive optical network broadcast bit)
        // - e (encryption bit)
        // - c (user data change bit)
        // - an (Association number) [2 bits]
        let tci_an = (self.an.value() & 0b11)
            | if self.userdata_changed() { 0b100 } else { 0 }
            | if self.encrypted() { 0b1000 } else { 0 }
            | if self.scb { 0b1_0000 } else { 0 }
            | if self.sci.is_some() { 0b10_0000 } else { 0 }
            | if self.endstation_id { 0b100_0000 } else { 0 };
        let pn_be = self.packet_nr.to_be_bytes();
        let sci_be = self.sci.unwrap_or(0).to_be_bytes();
        let et_be = if let MacsecPType::Unmodified(e) = self.ptype {
            e.0
        } else {
            0
        }
        .to_be_bytes();
        let mut result: ArrayVec<u8, { MacsecHeader::MAX_LEN }> = if self.sci.is_some() {
            [
                tci_an,
                self.short_len.value() & 0b0011_1111,
                pn_be[0],
                pn_be[1],
                pn_be[2],
                pn_be[3],
                sci_be[0],
                sci_be[1],
                sci_be[2],
                sci_be[3],
                sci_be[4],
                sci_be[5],
                sci_be[6],
                sci_be[7],
                et_be[0],
                et_be[1],
            ]
        } else {
            [
                tci_an,
                self.short_len.value() & 0b0011_1111,
                pn_be[0],
                pn_be[1],
                pn_be[2],
                pn_be[3],
                et_be[0],
                et_be[1],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        }
        .into();
        // SAFETY: Safe as the maximum size of 16 can not be exceeded.
        unsafe {
            result.set_len(
                6 + if self.sci.is_some() { 8 } else { 0 }
                    + if matches!(self.ptype, MacsecPType::Unmodified(_)) {
                        2
                    } else {
                        0
                    },
            );
        }
        result
    }

    /// Writes a given MACsec header to the current position (SecTag & next
    /// ether type if available).
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length of the MACsec header (SecTag + next ether type if available).
    #[inline]
    pub fn header_len(&self) -> usize {
        6 + if self.sci.is_some() { 8 } else { 0 }
            + if matches!(self.ptype, MacsecPType::Unmodified(_)) {
                2
            } else {
                0
            }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn from_slice_to_bytes(
            header in mac_sec_any()
        ) {
            let bytes = header.to_bytes();
            let actual = MacsecHeader::from_slice(&bytes);
            assert_eq!(actual, Ok(header.clone()));
        }
    }
}
