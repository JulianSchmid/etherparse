
/// Code value in an ICMPv4 Redirect message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RedirectCode {
    /// Redirect Datagram for the Network (or subnet)
    RedirectForNetwork = 0,
    /// Redirect Datagram for the Host
    RedirectForHost = 1,
    /// Redirect Datagram for the Type of Service and Network
    RedirectForTypeOfServiceAndNetwork = 2,
    /// Redirect datagrams for the Type of Service and Host
    RedirectForTypeOfServiceAndHost = 3,
}

impl RedirectCode {
    /// Tries to convert a code [`u8`] value to a [`RedirectCode`] value.
    ///
    /// Returns [`None`] in case the code value is not known as a redirect code.
    #[inline]
    pub fn from_u8(code_u8: u8) -> Option<RedirectCode> {
        use crate::icmpv4::{*, RedirectCode::*};
        match code_u8 {
            CODE_REDIRECT_FOR_NETWORK => Some(RedirectForNetwork),
            CODE_REDIRECT_FOR_HOST => Some(RedirectForHost),
            CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK => {
                Some(RedirectForTypeOfServiceAndNetwork)
            }
            CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST => Some(RedirectForTypeOfServiceAndHost),
            _ => None,
        }
    }

    /// Returns the [`u8`] value of the code.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        *self as u8
    }
}