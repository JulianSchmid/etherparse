use crate::*;
use arrayvec::ArrayVec;

/// MACsec SecTag header (present at the start of a
/// packet capsuled with MACsec).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacSecHeader {
    /// End station identifier (TCI.ES flag).
    pub endstation_id: bool,

    /// Ethernet passive optical network broadcast flag.
    pub tci_scb: bool,

    /// Encryption flag, which indicates whether the user data is
    /// encryped (true = encrypted, TCI.E flag).
    pub encrypted: bool,

    /// Flag for change text, set if the user data is modified.
    pub userdata_changed: bool,

    /// Association number (identifes SAs).
    pub an: MacSecAn,

    /// Short length with reserved bits.
    pub short_length: MacSecSl,

    /// Packet number.
    pub packet_nr: u32,

    /// Secure channel identifier.
    pub sci: Option<u64>,

    /// Ether type of the data following the sec tag.
    pub next_ether_type: Option<EtherType>,
}

impl MacSecHeader {
    /// Minimum length of an MacSec header in bytes/octets.
    pub const MIN_LEN: usize = 6;

    /// Maximum length of an MacSec header (including ether type of payload) in bytes/octets.
    pub const MAX_LEN: usize = 16;

    /// Try creating a [`MacSecHeaderSlice`] from a slice containing the
    /// MACsec header & next ether type.
    pub fn from_slice(slice: &[u8]) -> Result<MacSecHeader, err::macsec::HeaderSliceError> {
        MacSecHeaderSlice::from_slice(slice).map(|v| v.to_header())
    }

    /// Serialize the mac sec header.
    pub fn to_bytes(&self) -> ArrayVec<u8, { MacSecHeader::MAX_LEN }> {
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
            | if self.userdata_changed { 0b100 } else { 0 }
            | if self.encrypted { 0b1000 } else { 0 }
            | if self.tci_scb { 0b1_0000 } else { 0 }
            | if self.sci.is_some() { 0b10_0000 } else { 0 }
            | if self.endstation_id { 0b100_0000 } else { 0 };
        let pn_be = self.packet_nr.to_be_bytes();
        let sci_be = self.sci.unwrap_or(0).to_be_bytes();
        let et_be = self.next_ether_type.unwrap_or(EtherType(0)).0.to_be_bytes();
        let mut result: ArrayVec<u8, { MacSecHeader::MAX_LEN }> = [
            tci_an,
            self.short_length.value(),
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
        .into();
        // SAFETY: Safe as the maximum size of 16 can not be exceeded.
        unsafe {
            result.set_len(
                6 + if self.sci.is_some() { 8 } else { 0 }
                    + if self.next_ether_type.is_some() { 2 } else { 0 },
            );
        }
        result
    }
}
