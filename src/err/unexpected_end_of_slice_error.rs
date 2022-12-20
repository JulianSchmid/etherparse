use crate::err::Layer;

/// Error when an unexpected end of a slice is reached even though more data was expected to be present.
#[derive(Debug, Eq, PartialEq)]
pub struct UnexpectedEndOfSliceError {
    /// Expected minimum length of the slice.
    pub expected_min: usize,

    /// Actual length of the slice.
    pub actual: usize,

    /// Layer in which the length was smaller then expected.
    pub layer: Layer,
}
