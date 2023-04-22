use super::HeaderSerError;

/// Error when writing IPv4 extension headers.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum HeaderWriteError {
    /// IO error encountered while writing.
    Io(std::io::Error),
    /// Data was not serializable because of its content.
    Content(HeaderSerError),
}

#[cfg(feature = "std")]
impl HeaderWriteError {
    /// Returns a reference to the [`std::io::Error`] if the value is an [`HeaderWriteError::Io`].
    pub fn io(&self) -> Option<&std::io::Error> {
        match self {
            HeaderWriteError::Io(err) => Some(err),
            HeaderWriteError::Content(_) => None,
        }
    }

    /// Returns a reference to the [`crate::err:ipv4_exts::HeaderSerError`] if the value is an [`HeaderWriteError::Content`].
    pub fn content(&self) -> Option<&HeaderSerError> {
        match self {
            HeaderWriteError::Io(_) => None,
            HeaderWriteError::Content(err) => Some(err),
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for HeaderWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderWriteError::*;
        match self {
            Io(err) => err.fmt(f),
            Content(err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeaderWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HeaderWriteError::*;
        match self {
            Io(ref err) => Some(err),
            Content(ref err) => Some(err),
        }
    }
}
