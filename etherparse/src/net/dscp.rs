#[cfg(test)]
use strum_macros::VariantArray;
/// Differentiated Services Field Codepoints (DSCP) as established in
/// [RFC-2472](https://datatracker.ietf.org/doc/html/rfc2474) and defined/maintained in the
/// [IANA dscp-registry](https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml)
#[repr(u8)]
#[cfg_attr(test, derive(VariantArray))]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Copy)]
pub enum Dscp {
    /// Pool 1
    ///
    /// Class Selectors [RFC-2474](https://datatracker.ietf.org/doc/html/rfc2474)
    ClassSelector0 = 0,
    ClassSelector1 = 8,
    ClassSelector2 = 16,
    ClassSelector3 = 24,
    ClassSelector4 = 32,
    ClassSelector5 = 40,
    ClassSelector6 = 48,
    ClassSelector7 = 56,
    /// Assured Forwarding PHB Groups [RFC-2597](https://datatracker.ietf.org/doc/html/rfc2597)
    AfGroup11 = 10,
    AfGroup12 = 12,
    AfGroup13 = 14,
    AfGroup21 = 18,
    AfGroup22 = 20,
    AfGroup23 = 22,
    AfGroup31 = 26,
    AfGroup32 = 28,
    AfGroup33 = 30,
    AfGroup41 = 34,
    AfGroup42 = 36,
    AfGroup43 = 38,
    /// Expedited Forwarding [RFC-3246](https://datatracker.ietf.org/doc/html/rfc3246)
    ExpeditedForwarding = 46,
    /// Voice admit [RFC-5865](https://datatracker.ietf.org/doc/html/rfc5865)
    VoiceAdmit = 44,
    /// Pool 3
    ///
    /// Lower Effort PHB [RFC-8622](https://datatracker.ietf.org/doc/html/rfc8622)
    LowerEffort = 1,
    // NOTE: NQB was omitted here because it has an expiration in the IANA registry.
}

impl Dscp {
    /// DSCP field is only 6 bits.
    pub const MAX: u8 = 0b111111;

    /// Write this DSCP to a given octet. This ensures the DSCP is located in the correct bit range
    /// of the octet.
    pub const fn write(&self, byte: &mut u8) {
        Self::write_inner(*self as u8, byte);
    }

    /// Write a raw DSCP value to a given octet.
    ///
    /// This method should be used when using the experimental pool in the DSCP field.
    ///
    /// Errors - When the given raw value is larger than [`Self::MAX`]
    pub const fn write_raw(raw_value: u8, byte: &mut u8) -> Result<(), DscpError> {
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
    pub const fn read_raw(byte: &u8) -> u8 {
        *byte >> 2
    }

    /// Extract the DSCP variant from a given byte. This method will only return standardized
    /// variants from the IANA DSCP registry.
    pub const fn read(byte: &u8) -> Result<Self, DscpError> {
        let dscp_field = Self::read_raw(byte);
        Self::from_u8(&dscp_field)
    }

    const fn write_inner(value: u8, byte: &mut u8) {
        // Erase current dscp field, bits 6-7 are for the ECN field.
        *byte &= 0b00000011;
        // Write new dscp field
        *byte |= (value) << 2;
    }

    const fn from_u8(value: &u8) -> Result<Self, DscpError> {
        match *value {
            0 => Ok(Self::ClassSelector0),
            8 => Ok(Self::ClassSelector1),
            16 => Ok(Self::ClassSelector2),
            24 => Ok(Self::ClassSelector3),
            32 => Ok(Self::ClassSelector4),
            40 => Ok(Self::ClassSelector5),
            48 => Ok(Self::ClassSelector6),
            56 => Ok(Self::ClassSelector7),
            10 => Ok(Self::AfGroup11),
            12 => Ok(Self::AfGroup12),
            14 => Ok(Self::AfGroup13),
            18 => Ok(Self::AfGroup21),
            20 => Ok(Self::AfGroup22),
            22 => Ok(Self::AfGroup23),
            26 => Ok(Self::AfGroup31),
            28 => Ok(Self::AfGroup32),
            30 => Ok(Self::AfGroup33),
            34 => Ok(Self::AfGroup41),
            36 => Ok(Self::AfGroup42),
            38 => Ok(Self::AfGroup43),
            46 => Ok(Self::ExpeditedForwarding),
            44 => Ok(Self::VoiceAdmit),
            1 => Ok(Self::LowerEffort),

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

    #[test]
    fn writer_does_not_erase_ecn_fields() {
        let mut start = 0b11111111;
        Dscp::ClassSelector0.write(&mut start);
        assert_eq!(start, 0b11);
    }

    #[test]
    fn reader_fetches_correct_fields() {
        let mut start = 48 << 2 | 0b11;
        let parsed = Dscp::read(&mut start).unwrap();
        assert_eq!(parsed, Dscp::ClassSelector6);
    }
}
