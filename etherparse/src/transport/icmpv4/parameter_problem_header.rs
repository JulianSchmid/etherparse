
/// The header of an ICMPv4 Parameter Problems (contents up to
/// the offending ip header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParameterProblemHeader {
    /// Identifies the octet where an error was detected.
    ///
    /// The value is the pointer pointing to the offending octet in
    /// the offending packet.
    PointerIndicatesError(u8),
    /// Missing a Required Option
    MissingRequiredOption,
    /// Bad Length
    BadLength,
}

impl ParameterProblemHeader {
    /// Tries to convert the code [`u8`] value and pointer to a [`ParameterProblemHeader`] value.
    ///
    /// Returns [`None`] in case the code value is not known as a parameter problem code.
    pub fn from_values(code_u8: u8, pointer: u8) -> Option<ParameterProblemHeader> {
        use super::{*, ParameterProblemHeader::*};
        match code_u8 {
            CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR => {
                Some(PointerIndicatesError(pointer))
            }
            CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION => Some(MissingRequiredOption),
            CODE_PARAMETER_PROBLEM_BAD_LENGTH => Some(BadLength),
            _ => None,
        }
    }
}
