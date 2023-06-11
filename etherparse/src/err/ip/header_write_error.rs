use crate::err::{ipv4_exts, ipv6_exts};

/// Error when writing IPv4 extension headers.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum HeaderWriteError {
    /// IO error encountered while writing.
    Io(std::io::Error),
    /// IPv4 extensions can not be serialized (e.g. order
    /// is not determinable as headers are never referenced).
    Ipv4Exts(ipv4_exts::ExtsWalkError),
    /// IPv6 extensions can not be serialized (e.g. order
    /// is not determinable as headers are never referenced).
    Ipv6Exts(ipv6_exts::ExtsWalkError),
}

#[cfg(feature = "std")]
impl HeaderWriteError {
    /// Returns a reference to the [`std::io::Error`] if the value is an `Io`.
    pub fn io(&self) -> Option<&std::io::Error> {
        match self {
            HeaderWriteError::Io(err) => Some(err),
            _ => None,
        }
    }

    /// Returns a reference to the [`crate::err::ipv4_exts::ExtsWalkError`]
    /// if the value is an `Ipv4Exts`.
    pub fn ipv4_exts(&self) -> Option<&ipv4_exts::ExtsWalkError> {
        match self {
            HeaderWriteError::Ipv4Exts(err) => Some(err),
            _ => None,
        }
    }

    /// Returns a reference to the [`crate::err::ipv6_exts::ExtsWalkError`]
    /// if the value is an `Ipv6Exts`.
    pub fn ipv6_exts(&self) -> Option<&ipv6_exts::ExtsWalkError> {
        match self {
            HeaderWriteError::Ipv6Exts(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for HeaderWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HeaderWriteError::*;
        match self {
            Io(err) => err.fmt(f),
            Ipv4Exts(err) => err.fmt(f),
            Ipv6Exts(err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeaderWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use HeaderWriteError::*;
        match self {
            Io(ref err) => Some(err),
            Ipv4Exts(ref err) => Some(err),
            Ipv6Exts(ref err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderWriteError::*, *};
    use crate::*;
    use alloc::format;
    use std::error::Error;

    #[test]
    fn io() {
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .io()
        .is_some());
        assert!(Ipv4Exts(ipv4_exts::ExtsWalkError::ExtNotReferenced {
            missing_ext: IpNumber::AUTHENTICATION_HEADER,
        })
        .io()
        .is_none());
    }

    #[test]
    fn ipv4_exts() {
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .ipv4_exts()
        .is_none());
        {
            let err = ipv4_exts::ExtsWalkError::ExtNotReferenced {
                missing_ext: IpNumber::AUTHENTICATION_HEADER,
            };
            assert_eq!(Some(&err), Ipv4Exts(err.clone()).ipv4_exts());
        }
    }

    #[test]
    fn ipv6_exts() {
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .ipv6_exts()
        .is_none());
        {
            let err = ipv6_exts::ExtsWalkError::ExtNotReferenced {
                missing_ext: IpNumber::AUTHENTICATION_HEADER,
            };
            assert_eq!(Some(&err), Ipv6Exts(err.clone()).ipv6_exts());
        }
    }

    #[test]
    fn debug() {
        let err = ipv6_exts::ExtsWalkError::ExtNotReferenced {
            missing_ext: IpNumber::AUTHENTICATION_HEADER,
        };
        assert_eq!(
            format!("Ipv6Exts({:?})", err.clone()),
            format!("{:?}", Ipv6Exts(err))
        );
    }

    #[test]
    fn fmt() {
        {
            let err = std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            );
            assert_eq!(format!("{}", err), format!("{}", Io(err)));
        }
        {
            let err = ipv4_exts::ExtsWalkError::ExtNotReferenced {
                missing_ext: IpNumber::AUTHENTICATION_HEADER,
            };
            assert_eq!(format!("{}", Ipv4Exts(err.clone())), format!("{}", err));
        }
        {
            let err = ipv6_exts::ExtsWalkError::ExtNotReferenced {
                missing_ext: IpNumber::AUTHENTICATION_HEADER,
            };
            assert_eq!(format!("{}", Ipv6Exts(err.clone())), format!("{}", err));
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
        .source()
        .is_some());
        assert!(Ipv4Exts(ipv4_exts::ExtsWalkError::ExtNotReferenced {
            missing_ext: IpNumber::AUTHENTICATION_HEADER,
        })
        .source()
        .is_some());
        assert!(Ipv6Exts(ipv6_exts::ExtsWalkError::ExtNotReferenced {
            missing_ext: IpNumber::AUTHENTICATION_HEADER,
        })
        .source()
        .is_some());
    }
}
