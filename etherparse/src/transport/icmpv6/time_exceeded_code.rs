use super::*;

/// Code values for ICMPv6 time exceeded message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeExceededCode {
    /// "hop limit exceeded in transit"
    HopLimitExceeded = 0,
    /// "fragment reassembly time exceeded"
    FragmentReassemblyTimeExceeded = 1,
}

impl TimeExceededCode {
    /// Tries to convert a code [`u8`] value to a [`TimeExceededCode`] value.
    ///
    /// Returns [`None`] in case the code value is not known as a time exceeded code.
    #[inline]
    pub fn from_u8(code_u8: u8) -> Option<TimeExceededCode> {
        use TimeExceededCode::*;
        match code_u8 {
            CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED => Some(HopLimitExceeded),
            CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED => {
                Some(FragmentReassemblyTimeExceeded)
            }
            _ => None,
        }
    }

    /// Returns the [`u8`] value of the code.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        *self as u8
    }
}