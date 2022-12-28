use super::HeaderError;

/// Error when decoding two VLAN headers via a `std::io::Read` source.
#[derive(Debug)]
pub enum HeaderReadError {
    /// Error when an unexpected end of a slice is reached
    /// even though more data was expected to be present.
    Io(std::io::Error),

    /// Error caused by the contents of the header.
    Content(HeaderError),
}

impl HeaderReadError {
    /// Returns the `std::io::Error` value if the `HeaderReadError` is `Io`.
    /// Otherwise `None is returned.
    #[inline]
    pub fn io_error(self) -> Option<std::io::Error> {
        use HeaderReadError::*;
        match self {
            Io(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the `err::double_vlan::HeaderError` value if the `HeaderReadError` is `Content`.
    /// Otherwise `None is returned.
    #[inline]
    pub fn content_error(self) -> Option<HeaderError> {
        use HeaderReadError::*;
        match self {
            Content(value) => Some(value),
            _ => None,
        }
    }
}

impl core::fmt::Display for HeaderReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderReadError::*;
        match self {
            Io(err) => write!(f, "Double VLAN Header IO Error: {}", err),
            Content(value) => value.fmt(f),
        }
    }
}

impl std::error::Error for HeaderReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HeaderReadError::*;
        match self {
            Io(err) => Some(err),
            Content(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{HeaderReadError::*, *};

    #[test]
    fn debug() {
        let err = HeaderError::NonVlanEtherType {
            unexpected_ether_type: 1,
        };
        assert_eq!(
            format!("Content({:?})", err.clone()),
            format!("{:?}", Content(err))
        );
    }

    #[test]
    fn fmt() {
        {
            let err = std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            );
            assert_eq!(
                format!("Double VLAN Header IO Error: {}", err),
                format!("{}", Io(err))
            );
        }
        {
            let err = HeaderError::NonVlanEtherType {
                unexpected_ether_type: 1,
            };
            assert_eq!(format!("{}", &err), format!("{}", Content(err.clone())));
        }
    }

    #[test]
    fn source() {
        use std::error::Error;
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .source()
        .is_some());
        assert!(Content(HeaderError::NonVlanEtherType {
            unexpected_ether_type: 1
        })
        .source()
        .is_some());
    }

    #[test]
    fn io_error() {
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .io_error()
        .is_some());
        assert!(Content(HeaderError::NonVlanEtherType {
            unexpected_ether_type: 1
        })
        .io_error()
        .is_none());
    }

    #[test]
    fn content_error() {
        assert_eq!(
            None,
            Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
            .content_error()
        );
        {
            let err = HeaderError::NonVlanEtherType {
                unexpected_ether_type: 1,
            };
            assert_eq!(Some(err.clone()), Content(err.clone()).content_error());
        }
    }
}
