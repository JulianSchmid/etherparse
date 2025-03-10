#[cfg(test)]
use strum_macros::VariantArray;
/// Differentiated Services Field Codepoints (DSCP) as established in
/// [RFC-2472](https://datatracker.ietf.org/doc/html/rfc2474) and defined/maintained in the
/// [IANA dscp-registry](https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml)
#[repr(u8)]
#[non_exhaustive]
#[cfg_attr(test, derive(VariantArray))]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Copy)]
pub enum Dscp {
    /// Pool 1
    ///
    /// Class Selectors [RFC-2474](https://datatracker.ietf.org/doc/html/rfc2474)
    // NOTE: Underscore in literals are indicative of their dscp pool.
    ClassSelector0 = 0b_00000_0,
    ClassSelector1 = 0b_00100_0,
    ClassSelector2 = 0b_01000_0,
    ClassSelector3 = 0b_01100_0,
    ClassSelector4 = 0b_10000_0,
    ClassSelector5 = 0b_10100_0,
    ClassSelector6 = 0b_11000_0,
    ClassSelector7 = 0b_11100_0,
    /// Assured Forwarding PHB Groups [RFC-2597](https://datatracker.ietf.org/doc/html/rfc2597)
    AfGroup11 = 0b_00101_0,
    AfGroup12 = 0b_00110_0,
    AfGroup13 = 0b_00111_0,
    AfGroup21 = 0b_01001_0,
    AfGroup22 = 0b_01010_0,
    AfGroup23 = 0b_01011_0,
    AfGroup31 = 0b_01101_0,
    AfGroup32 = 0b_01110_0,
    AfGroup33 = 0b_01111_0,
    AfGroup41 = 0b_10001_0,
    AfGroup42 = 0b_10010_0,
    AfGroup43 = 0b_10011_0,
    /// Expedited Forwarding [RFC-3246](https://datatracker.ietf.org/doc/html/rfc3246)
    ExpeditedForwarding = 0b_10111_0,
    /// Voice admit [RFC-5865](https://datatracker.ietf.org/doc/html/rfc5865)
    VoiceAdmit = 0b_10110_0,
    /// Pool 3
    ///
    /// Lower Effort PHB [RFC-8622](https://datatracker.ietf.org/doc/html/rfc8622)
    LowerEffort = 0b_0000_01,
    // NOTE: NQB was omitted here because it has an expiration in the IANA registry.
}

impl Dscp {
    /// DSCP field is only 6 bits.
    pub const MAX: u8 = 0b111111;

    /// Write this DSCP to a given octet. This ensures the DSCP is located in the correct bit range
    /// of the octet.
    /// # Example
    /// ```
    /// # use etherparse::Dscp;
    /// let mut byte = 0b11111_1_11;
    /// Dscp::ClassSelector1.write(&mut byte);
    /// assert_eq!(byte, 0b00100_0_11);
    /// ```
    pub fn write(&self, byte: &mut u8) {
        Self::write_inner(*self as u8, byte);
    }

    /// Write a raw DSCP value to a given octet.
    ///
    /// This method should be used when using the experimental pool in the DSCP field.
    ///
    /// Errors - When the given raw value is larger than [`Self::MAX`]
    /// # Example
    /// ```
    /// # use etherparse::Dscp;
    /// let mut byte = 0b1111_01_11;
    /// let to_write = 0b0101_11;
    /// Dscp::write_raw(to_write, &mut byte).unwrap();
    /// assert_eq!(byte, 0b0101_11_11);
    /// ```
    ///
    /// ```
    /// # use etherparse::Dscp;
    /// let mut byte = 0b1111_01_11;
    /// let too_big = Dscp::MAX + 1;
    /// assert!(Dscp::write_raw(too_big, &mut byte).is_err());
    /// ```
    pub fn write_raw(raw_value: u8, byte: &mut u8) -> Result<(), DscpError> {
        if raw_value <= Self::MAX {
            Self::write_inner(raw_value, byte);
            Ok(())
        } else {
            Err(DscpError::ValueTooLarge(raw_value))
        }
    }

    /// Extract the raw DSCP field from a given byte.
    ///
    /// This method should be used when using the experimental pool in the DSCP field.
    /// # Example
    /// ```
    /// # use etherparse::Dscp;
    /// let byte = 0b0101_01_11;
    /// assert_eq!(Dscp::read_raw(&byte), 0b0101_01)
    /// ```
    pub const fn read_raw(byte: &u8) -> u8 {
        *byte >> 2
    }

    /// Extract the DSCP variant from a given byte. This method will only return standardized
    /// variants from the IANA DSCP registry.
    ///
    /// # Example
    /// ```
    /// # use etherparse::Dscp;
    /// let byte = 0b00100_0_11;
    /// assert_eq!(Dscp::read(&byte), Ok(Dscp::ClassSelector1));
    /// ```
    pub const fn read(byte: &u8) -> Result<Self, DscpError> {
        let dscp_field = Self::read_raw(byte);
        // match here because `Option::ok_or()` is not `const`
        Self::from_u8(&dscp_field)
    }

    fn write_inner(value: u8, byte: &mut u8) {
        // Erase current dscp field, bits 6-7 are for the ECN field.
        *byte &= 0b00000011;
        // Write new dscp field
        *byte |= (value) << 2;
    }

    // Note: `strum` has a nice FromRepr trait that derives this conversion.
    // But the resulting method is public and I don't want to confuse crate users with it.
    const fn from_u8(value: &u8) -> Result<Self, DscpError> {
        match *value {
            0b_00000_0 => Ok(Self::ClassSelector0),
            0b_00100_0 => Ok(Self::ClassSelector1),
            0b_01000_0 => Ok(Self::ClassSelector2),
            0b_01100_0 => Ok(Self::ClassSelector3),
            0b_10000_0 => Ok(Self::ClassSelector4),
            0b_10100_0 => Ok(Self::ClassSelector5),
            0b_11000_0 => Ok(Self::ClassSelector6),
            0b_11100_0 => Ok(Self::ClassSelector7),
            0b_00101_0 => Ok(Self::AfGroup11),
            0b_00110_0 => Ok(Self::AfGroup12),
            0b_00111_0 => Ok(Self::AfGroup13),
            0b_01001_0 => Ok(Self::AfGroup21),
            0b_01010_0 => Ok(Self::AfGroup22),
            0b_01011_0 => Ok(Self::AfGroup23),
            0b_01101_0 => Ok(Self::AfGroup31),
            0b_01110_0 => Ok(Self::AfGroup32),
            0b_01111_0 => Ok(Self::AfGroup33),
            0b_10001_0 => Ok(Self::AfGroup41),
            0b_10010_0 => Ok(Self::AfGroup42),
            0b_10011_0 => Ok(Self::AfGroup43),
            0b_10111_0 => Ok(Self::ExpeditedForwarding),
            0b_10110_0 => Ok(Self::VoiceAdmit),
            0b_0000_01 => Ok(Self::LowerEffort),

            _ => Err(DscpError::NoStandardAction(*value)),
        }
    }
}

/// Errors that can occur while working with the DSCP field..
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DscpError {
    /// Returned if a u8 does not have a code point in the IANA DSCP registry.
    NoStandardAction(u8),
    /// Returned if a given DSCP is larger than maximum allowed value.
    ValueTooLarge(u8),
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for DscpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl core::fmt::Display for DscpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoStandardAction(val) => {
                write!(
                    f,
                    "There is no standardized DSCP action associated with {val}, check \
                    https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml for a list \
                    of registered DSCP actions."
                )
            }
            Self::ValueTooLarge(val) => {
                write!(
                    f,
                    "Given value ({}) must be less than {} as the field is only 6 bits",
                    val,
                    Dscp::MAX
                )
            }
        }
    }
}

#[cfg(test)]
mod test {

    use strum::VariantArray;

    use super::*;
    #[test]
    fn each_variant_has_symmetric_conversion() {
        // The use of the auto derived VARIANTS const ensures correct maintenance when the enum is
        // modified.
        for variant in Dscp::VARIANTS {
            let repr = *variant as u8;
            assert_eq!(*variant, Dscp::from_u8(&repr).unwrap())
        }
    }
}
