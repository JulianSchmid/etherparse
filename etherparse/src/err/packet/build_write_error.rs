use crate::err::{ipv4_exts, ipv6_exts, ValueTooBigError};

/// Error while writing packet
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum BuildWriteError {
    /// IO error while writing packet.
    Io(std::io::Error),

    /// Error if the length of the payload is too
    /// big to be representable by the length fields.
    PayloadLen(ValueTooBigError<usize>),

    /// Error if the IPv4 extensions can not be serialized
    /// because of internal consistency errors (i.e. a header
    /// is never).
    Ipv4Exts(ipv4_exts::HeaderSerError),

    /// Error if the IPv6 extensions can not be serialized
    /// because of internal consistency errors.
    Ipv6Exts(ipv6_exts::HeaderSerError),

    /// Error if ICMPv6 is packaged in an IPv4 packet (it is undefined
    /// how to calculate the checksum).
    Icmpv6InIpv4,
}

#[cfg(feature = "std")]
impl BuildWriteError {
    /// Returns the [`std::io::Error`] value if the `BuildWriteError` is an `Io`.
    /// Otherwise `None` is returned.
    pub fn io(self) -> Option<std::io::Error> {
        match self {
            BuildWriteError::Io(value) => Some(value),
            _ => None,
        }
    }
    /// Returns the [`crate::err::packet::ValueTooBigError`] value if the
    /// `BuildWriteError` is a `ValueTooBig`. Otherwise `None` is returned.
    pub fn value_too_big(self) -> Option<ValueTooBigError<usize>> {
        match self {
            BuildWriteError::PayloadLen(value) => Some(value),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for BuildWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use BuildWriteError::*;
        match self {
            Io(err) => err.fmt(f),
            PayloadLen(err) => err.fmt(f),
            Ipv4Exts(err) => err.fmt(f),
            Ipv6Exts(err) => err.fmt(f),
            Icmpv6InIpv4 => write!(f, "Error: ICMPv6 can not be combined with an IPv4 headers (checksum can not be calculated)."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use BuildWriteError::*;
        match self {
            Io(ref err) => Some(err),
            PayloadLen(ref err) => Some(err),
            Ipv4Exts(err) => Some(err),
            Ipv6Exts(err) => Some(err),
            Icmpv6InIpv4 => None,
        }
    }
}
