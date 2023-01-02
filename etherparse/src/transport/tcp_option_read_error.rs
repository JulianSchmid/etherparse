use crate::*;

/// Errors that can occour while reading the options of a TCP header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpOptionReadError {
    /// Returned if an option id was read, but there was not enough memory in the options left to completely read it.
    UnexpectedEndOfSlice {
        option_id: u8,
        expected_len: u8,
        actual_len: usize,
    },

    /// Returned if the option as an unexpected size argument (e.g. != 4 for maximum segment size).
    UnexpectedSize { option_id: u8, size: u8 },

    /// Returned if an unknown tcp header option is encountered.
    ///
    /// The first element is the identifier and the slice contains the rest of data left in the options.
    UnknownId(u8),
}

impl std::error::Error for TcpOptionReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl core::fmt::Display for TcpOptionReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use TcpOptionReadError::*;
        match self {
            UnexpectedEndOfSlice {
                option_id,
                expected_len,
                actual_len,
            } => {
                write!(f, "TcpOptionReadError: Not enough memory left in slice to read option of kind {} (expected at least {} bytes, only {} bytes available).", option_id, expected_len, actual_len)
            }
            UnexpectedSize { option_id, size } => {
                write!(f, "TcpOptionReadError: Length value of the option of kind {} had unexpected value {}.", option_id, size)
            }
            UnknownId(id) => {
                write!(
                    f,
                    "TcpOptionReadError: Unknown tcp option kind value {}.",
                    id
                )
            }
        }
    }
}
