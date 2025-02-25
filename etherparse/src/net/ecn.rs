#[cfg(test)]
use strum_macros::VariantArray;
/// Code points for explicit congestion notification (ECN) in IPv4 and IPv6 headers.
///
/// Code points are defined in [RFC-3168](https://datatracker.ietf.org/doc/html/rfc3168)
///
/// For reasoning to why there are two code points with the exact same meaning,
/// see [RFC-3168 Section 20.2](https://datatracker.ietf.org/doc/html/rfc3168#section-20.2)
//
// NOTE: This enum COULD be used for the Ipv4Header struct, as ECN in both IPv4 and IPv6 are the
// same. The IPv4 ECN implementation isn't very rusty, and it is named only for IPv4, so this
// will be used for IPv6.
#[repr(u8)]
#[cfg_attr(test, derive(VariantArray))]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Copy)]
pub enum Ecn {
    /// End node is not an ECN capable transport.
    NotEct = 0,
    /// End node is an ECN capable transport.
    EctOne = 1,
    /// End node is an ECN capable transport.
    EctZero = 2,
    /// Congestion is experienced by the router.
    CongestionExperienced = 3,
}

impl Ecn {
    /// ECN is 2 bits.
    pub const MAX: u8 = 0b11;

    /// Write the ECN field to the correct location in the given byte.
    pub const fn write(&self, byte: &mut u8) {
        // Erase the old value.
        *byte &= 0b11111100;
        // Insert the new
        *byte |= *self as u8;
    }

    /// Read from the ECN field in the given byte.
    pub const fn read(byte: &u8) -> Self {
        match *byte & 0b11 {
            0 => Self::NotEct,
            1 => Self::EctOne,
            2 => Self::EctZero,
            3 => Self::CongestionExperienced,
            // This will not happen because the match statement is being bit masked.
            _ => panic!("ECN field is only 2 bits."),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use strum::VariantArray;
    #[test]
    fn each_variant_has_symmetric_conversion() {
        for variant in Ecn::VARIANTS {
            let repr = *variant as u8;
            assert_eq!(*variant, Ecn::read(&repr));
        }
    }

    #[test]
    fn writer_does_not_erase_dscp_fields() {
        let mut start = 0b11111111;
        Ecn::NotEct.write(&mut start);
        assert_eq!(start, 0b1111_1100);
    }

    #[test]
    fn reader_fetches_correct_fields() {
        let start = 0b1010_1011;
        let parsed = Ecn::read(&start);
        assert_eq!(parsed, Ecn::CongestionExperienced);
    }
}
