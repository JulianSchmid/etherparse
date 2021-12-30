/// This modules contains errors that can be caused when slicing or
/// decoding headers and packets via `read` and `from_slice` methods.
///
/// Enums returned as errors by functions decoding & slicing headers 
/// should contain only values that can actually be triggered by the called
/// function (e.g. an UDP parse function should not return an enum with an 
/// TCP parse error that can never be triggered).
///
/// In case you want to use one error type instead you can convert all error
/// types to an [`de::Error`] using the [`de::Error::from`].
///
/// # Error Types & Design
///
/// The errors are split into two categories:
///
/// * Errors that are caused when getting data (e.g. "slice is too short" or an io error)
/// * Errors that are caused because of the read content (e.g. a length field is shorter then the minimum size)
///
/// Functions that can not trigger a content errors will directly return
///
/// * [`de::UnexpectedEndOfSliceError`] (for functions that read data from slices)
/// * [`std::io::Error`] (for `read` functions where data is read from an io::Read source)
///
/// as errors.
///
/// In case content errors can also be triggered one of the following two wrapper
/// types is returned based on the data source:
///
/// * [`de::FromSliceError`] is used when decoding from a slice.
/// * [`de::ReadError`] is used when data is read from an io::Read source.
///
/// These take a content error type as an argument. For example:
///
/// ```
/// # use std::error::Error;
/// # use std::fmt::{Display, Formatter};
/// # use etherparse::error::de::UnexpectedEndOfSliceError;
/// pub enum FromSliceError<T : Error + Display> {
///     UnexpectedEndOfSlice(UnexpectedEndOfSliceError),
///     Content(T)
/// }
/// ```
///
/// Secondly there are error types that indicate issues in
/// the read data:
///
/// * [`de::Ipv4Error`]
/// * [`de::Ipv6Error`]
/// * [`de::IpError`]
pub mod de;