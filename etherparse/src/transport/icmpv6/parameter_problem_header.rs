use super::*;

/// ICMPv6 parameter problem header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterProblemHeader {
    /// The code can offer additional informations about what kind of parameter
    /// problem caused the error.
    pub code: ParameterProblemCode,
    /// Identifies the octet offset within the
    /// invoking packet where the error was detected.
    ///
    /// The pointer will point beyond the end of the ICMPv6
    /// packet if the field in error is beyond what can fit
    /// in the maximum size of an ICMPv6 error message.
    pub pointer: u32,
}
