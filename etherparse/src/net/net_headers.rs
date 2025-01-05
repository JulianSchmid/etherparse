use crate::*;

/// Deprecated use [`crate::NetHeaders`] instead.
#[deprecated(since = "0.14.0", note = "`IpHeader` was renamed to `NetHeaders`")]
pub type IpHeader = NetHeaders;

/// Headers on the network layer (e.g. IP, ARP, ...).
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NetHeaders {
    /// IPv4 header & extension headers.
    Ipv4(Ipv4Header, Ipv4Extensions),
    /// IPv6 header & extension headers.
    Ipv6(Ipv6Header, Ipv6Extensions),
    /// Address Resolution Protocol packet.
    Arp(ArpPacket),
}

impl NetHeaders {
    /// Returns true if the NetHeaders contains either IPv4 or IPv6.
    pub fn is_ip(&self) -> bool {
        use NetHeaders::*;
        matches!(self, Ipv4(_, _) | Ipv6(_, _))
    }

    /// Returns references to the IPv4 header & extensions if the header contains IPv4 values.
    pub fn ipv4_ref(&self) -> Option<(&Ipv4Header, &Ipv4Extensions)> {
        if let NetHeaders::Ipv4(header, exts) = self {
            Some((header, exts))
        } else {
            None
        }
    }

    /// Returns references to the IPv6 header & extensions if the header contains IPv6 values.
    pub fn ipv6_ref(&self) -> Option<(&Ipv6Header, &Ipv6Extensions)> {
        if let NetHeaders::Ipv6(header, exts) = self {
            Some((header, exts))
        } else {
            None
        }
    }

    /// Sets all the next_header fields in the ipv4 & ipv6 header
    /// as well as in all extension headers and returns the ether
    /// type number.
    ///
    /// The given number will be set as the last "next_header" or
    /// protocol number.
    pub fn try_set_next_headers(
        &mut self,
        last_next_header: IpNumber,
    ) -> Result<EtherType, err::net::NetSetNextHeaderError> {
        use NetHeaders::*;
        match self {
            Ipv4(ref mut header, ref mut extensions) => {
                header.protocol = extensions.set_next_headers(last_next_header);
                Ok(EtherType::IPV4)
            }
            Ipv6(ref mut header, ref mut extensions) => {
                header.next_header = extensions.set_next_headers(last_next_header);
                Ok(EtherType::IPV4)
            }
            Arp(_) => Err(err::net::NetSetNextHeaderError::ArpHeader),
        }
    }

    /// Returns the size when the header & extension headers are serialized
    pub fn header_len(&self) -> usize {
        use crate::NetHeaders::*;
        match *self {
            Ipv4(ref header, ref extensions) => header.header_len() + extensions.header_len(),
            Ipv6(_, ref extensions) => Ipv6Header::LEN + extensions.header_len(),
            Arp(ref arp) => arp.packet_len(),
        }
    }
}

impl From<IpHeaders> for NetHeaders {
    #[inline]
    fn from(value: IpHeaders) -> Self {
        match value {
            IpHeaders::Ipv4(h, e) => NetHeaders::Ipv4(h, e),
            IpHeaders::Ipv6(h, e) => NetHeaders::Ipv6(h, e),
        }
    }
}

impl From<ArpPacket> for NetHeaders {
    #[inline]
    fn from(value: ArpPacket) -> Self {
        NetHeaders::Arp(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use alloc::format;

    #[test]
    fn debug() {
        let h = Ipv4Header {
            ..Default::default()
        };
        let e = Ipv4Extensions {
            ..Default::default()
        };
        let n = NetHeaders::Ipv4(h.clone(), e.clone());
        assert_eq!(format!("{n:?}"), format!("Ipv4({h:?}, {e:?})"));
    }

    #[test]
    fn clone_eq() {
        let n = NetHeaders::Ipv4(Default::default(), Default::default());
        assert_eq!(n, n.clone())
    }

    #[test]
    fn ipv4_ref() {
        // ipv4
        {
            let h: Ipv4Header = Default::default();
            let e: Ipv4Extensions = Default::default();
            let s = NetHeaders::Ipv4(h.clone(), e.clone());
            assert_eq!(s.ipv4_ref(), Some((&h, &e)));
        }
        // ipv6
        {
            let h: Ipv6Header = Default::default();
            let e: Ipv6Extensions = Default::default();
            let s = NetHeaders::Ipv6(h.clone(), e.clone());
            assert_eq!(s.ipv4_ref(), None);
        }
    }

    #[test]
    fn ipv6_ref() {
        // ipv4
        {
            let h: Ipv4Header = Default::default();
            let e: Ipv4Extensions = Default::default();
            let s = NetHeaders::Ipv4(h.clone(), e.clone());
            assert_eq!(s.ipv6_ref(), None);
        }
        // ipv6
        {
            let h: Ipv6Header = Default::default();
            let e: Ipv6Extensions = Default::default();
            let s = NetHeaders::Ipv6(h.clone(), e.clone());
            assert_eq!(s.ipv6_ref(), Some((&h, &e)));
        }
    }

    #[test]
    fn header_len() {
        // ipv4
        {
            let h: Ipv4Header = Default::default();
            let e: Ipv4Extensions = Default::default();
            let s = NetHeaders::Ipv4(h.clone(), e.clone());
            assert_eq!(s.header_len(), h.header_len() + e.header_len());
        }
        // ipv6
        {
            let h: Ipv6Header = Default::default();
            let e: Ipv6Extensions = Default::default();
            let s = NetHeaders::Ipv6(h.clone(), e.clone());
            assert_eq!(s.header_len(), h.header_len() + e.header_len());
        }
    }

    #[test]
    fn from() {
        // ipv4
        {
            let h: Ipv4Header = Default::default();
            let e: Ipv4Extensions = Default::default();
            let s = IpHeaders::Ipv4(h.clone(), e.clone());
            let a: NetHeaders = s.clone().into();
            assert_eq!(a, NetHeaders::Ipv4(h.clone(), e.clone()));
        }
        // ipv6
        {
            let h: Ipv6Header = Default::default();
            let e: Ipv6Extensions = Default::default();
            let s = IpHeaders::Ipv6(h.clone(), e.clone());
            let a: NetHeaders = s.clone().into();
            assert_eq!(a, NetHeaders::Ipv6(h.clone(), e.clone()));
        }
    }
}
