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
    NotEct = 0b00,
    /// End node is an ECN capable transport.
    EctOne = 0b01,
    /// End node is an ECN capable transport.
    EctZero = 0b10,
    /// Congestion is experienced by the router.
    CongestionExperienced = 0b11,
}

impl Ecn {
    /// ECN is 2 bits.
    pub const MAX: u8 = 0b11;

    /// Write the ECN field to the correct location in the given byte.
    /// # Example
    /// ```
    /// # use etherparse::Ecn;
    /// let mut byte = 0b01010_0_10;
    /// Ecn::CongestionExperienced.write(&mut byte);
    /// assert_eq!(byte, 0b01010_0_11);
    /// ```
    pub const fn write(&self, byte: &mut u8) {
        // Erase the old value.
        *byte &= 0b11111100;
        // Insert the new
        *byte |= *self as u8;
    }

    /// Read from the ECN field in the given byte.
    /// # Example
    /// ```
    /// # use etherparse::Ecn;
    /// let byte = 0b1010_1011;
    /// assert_eq!(Ecn::read(&byte), Ecn::CongestionExperienced);
    /// ```
    pub const fn read(byte: &u8) -> Self {
        match *byte & 0b11 {
            0b00 => Self::NotEct,
            0b01 => Self::EctOne,
            0b10 => Self::EctZero,
            0b11 => Self::CongestionExperienced,
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
}
