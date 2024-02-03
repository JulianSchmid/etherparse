use crate::*;

/// Deprecated use [`crate::NetSlice`] or [`crate::IpSlice`] instead.
#[cfg(feature = "std")]
#[deprecated(
    since = "0.14.0",
    note = "Deprecated use crate::NetSlice or crate::IpSlice instead"
)]
pub use NetSlice as InternetSlice;

/// Slice containing the network headers & payloads (e.g. IPv4, IPv6, ARP).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetSlice<'a> {
    /// The ipv4 header & the decoded extension headers.
    Ipv4(Ipv4Slice<'a>),
    /// The ipv6 header & the decoded extension headers.
    Ipv6(Ipv6Slice<'a>),
}

impl<'a> NetSlice<'a> {
    /// Returns a reference to ip payload if the net slice contains
    /// an ipv4 or ipv6 slice.
    #[inline]
    pub fn ip_payload_ref(&self) -> Option<&IpPayloadSlice<'a>> {
        match self {
            NetSlice::Ipv4(s) => Some(&s.payload),
            NetSlice::Ipv6(s) => Some(&s.payload),
        }
    }
}

impl<'a> From<IpSlice<'a>> for NetSlice<'a> {
    #[inline]
    fn from(value: IpSlice<'a>) -> NetSlice<'a> {
        match value {
            IpSlice::Ipv4(ipv4) => NetSlice::Ipv4(ipv4),
            IpSlice::Ipv6(ipv6) => NetSlice::Ipv6(ipv6),
        }
    }
}

impl<'a> From<Ipv4Slice<'a>> for NetSlice<'a> {
    #[inline]
    fn from(value: Ipv4Slice<'a>) -> NetSlice<'a> {
        NetSlice::Ipv4(value)
    }
}

impl<'a> From<Ipv6Slice<'a>> for NetSlice<'a> {
    #[inline]
    fn from(value: Ipv6Slice<'a>) -> NetSlice<'a> {
        NetSlice::Ipv6(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use alloc::{format, vec::Vec};

    #[test]
    fn debug() {
        let bytes = Ipv6Header {
            next_header: IpNumber::UDP,
            ..Default::default()
        }
        .to_bytes();
        let s = Ipv6Slice::from_slice(&bytes).unwrap();
        let n = NetSlice::Ipv6(s.clone());
        assert_eq!(format!("{n:?}"), format!("Ipv6({s:?})"));
    }

    #[test]
    fn clone_eq() {
        let bytes = Ipv6Header {
            next_header: IpNumber::UDP,
            ..Default::default()
        }
        .to_bytes();
        let s = NetSlice::Ipv6(Ipv6Slice::from_slice(&bytes).unwrap());
        assert_eq!(s, s.clone())
    }

    #[test]
    fn ip_payload_ref() {
        // ipv4
        {
            let payload = [1, 2, 3, 4];
            let bytes = {
                let mut bytes = Vec::with_capacity(Ipv4Header::MIN_LEN + 4);
                bytes.extend_from_slice(
                    &(Ipv4Header {
                        total_len: Ipv4Header::MIN_LEN_U16 + 4,
                        protocol: IpNumber::UDP,
                        ..Default::default()
                    })
                    .to_bytes(),
                );
                bytes.extend_from_slice(&payload);
                bytes
            };
            let s = NetSlice::Ipv4(Ipv4Slice::from_slice(&bytes).unwrap());
            assert_eq!(
                s.ip_payload_ref(),
                Some(&IpPayloadSlice {
                    ip_number: IpNumber::UDP,
                    fragmented: false,
                    len_source: LenSource::Ipv4HeaderTotalLen,
                    payload: &payload
                })
            );
        }
        // ipv6
        {
            let payload = [1, 2, 3, 4];
            let bytes = {
                let mut bytes = Vec::with_capacity(Ipv6Header::LEN + 4);
                bytes.extend_from_slice(
                    &(Ipv6Header {
                        next_header: IpNumber::UDP,
                        payload_length: 4,
                        ..Default::default()
                    })
                    .to_bytes(),
                );
                bytes.extend_from_slice(&payload);
                bytes
            };
            let s = NetSlice::Ipv6(Ipv6Slice::from_slice(&bytes).unwrap());
            assert_eq!(
                s.ip_payload_ref(),
                Some(&IpPayloadSlice {
                    ip_number: IpNumber::UDP,
                    fragmented: false,
                    len_source: LenSource::Ipv6HeaderPayloadLen,
                    payload: &payload
                })
            );
        }
    }

    #[test]
    fn from() {
        // IpSlice::Ipv4
        {
            let payload = [1, 2, 3, 4];
            let bytes = {
                let mut bytes = Vec::with_capacity(Ipv4Header::MIN_LEN + 4);
                bytes.extend_from_slice(
                    &(Ipv4Header {
                        total_len: Ipv4Header::MIN_LEN_U16 + 4,
                        protocol: IpNumber::UDP,
                        ..Default::default()
                    })
                    .to_bytes(),
                );
                bytes.extend_from_slice(&payload);
                bytes
            };
            let i = Ipv4Slice::from_slice(&bytes).unwrap();
            let actual: NetSlice = IpSlice::Ipv4(i.clone()).into();
            assert_eq!(NetSlice::Ipv4(i.clone()), actual);
        }
        // Ipv4Slice
        {
            let payload = [1, 2, 3, 4];
            let bytes = {
                let mut bytes = Vec::with_capacity(Ipv4Header::MIN_LEN + 4);
                bytes.extend_from_slice(
                    &(Ipv4Header {
                        total_len: Ipv4Header::MIN_LEN_U16 + 4,
                        protocol: IpNumber::UDP,
                        ..Default::default()
                    })
                    .to_bytes(),
                );
                bytes.extend_from_slice(&payload);
                bytes
            };
            let i = Ipv4Slice::from_slice(&bytes).unwrap();
            let actual: NetSlice = i.clone().into();
            assert_eq!(NetSlice::Ipv4(i.clone()), actual);
        }
        // IpSlice::Ipv6
        {
            let payload = [1, 2, 3, 4];
            let bytes = {
                let mut bytes = Vec::with_capacity(Ipv6Header::LEN + 4);
                bytes.extend_from_slice(
                    &(Ipv6Header {
                        next_header: IpNumber::UDP,
                        payload_length: 4,
                        ..Default::default()
                    })
                    .to_bytes(),
                );
                bytes.extend_from_slice(&payload);
                bytes
            };
            let i = Ipv6Slice::from_slice(&bytes).unwrap();
            let actual: NetSlice = i.clone().into();
            assert_eq!(NetSlice::Ipv6(i.clone()), actual);
        }
    }
}
