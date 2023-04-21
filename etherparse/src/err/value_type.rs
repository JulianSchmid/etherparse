/// Types of values that have a limited allowed value range
/// and can cause an [`crate::err::ValueTooBigError`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ValueType {
    /// VLAN identifier field present in a [`crate::SingleVlanHeader`].
    VlanId,
    /// VLAN PCP (Priority Code Point) field in a [`crate::SingleVlanheader`].
    VlanPcp,
    /// IP Fragment offset present in the IPv4 header and
    /// IPv6 fragmentation header.
    IpFragmentOffset,
    /// IPv4 Header DSCP (Differentiated Services Code Point) field
    /// present in an [`crate::Ipv4Header`].
    Ipv4Dscp,
    /// IPv4 Header ECN (Explicit Congestion Notification) field
    /// present in an [`crate::Ipv4Header`].
    Ipv4Ecn,
    /// IPv6 Header Flow Label field present in [`crate::Ipv6Header`].
    Ipv6FlowLabel,

    Ipv4PayloadLength,
}

impl core::fmt::Display for ValueType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use ValueType::*;
        match self {
            VlanId => write!(f, "VLAN ID"),
            VlanPcp => write!(f, "VLAN PCP (Priority Code Point)"),
            IpFragmentOffset => write!(f, "IP Fragment Offset"),
            Ipv4Dscp => write!(f, "IPv4 DSCP (Differentiated Services Code Point)"),
            Ipv4Ecn => write!(f, "IPv4 ECN (Explicit Congestion Notification)"),
            Ipv6FlowLabel => write!(f, "IPv6 Flow Label"),
            Ipv4PayloadLength => write!(f, "Ipv4Header.payload_len"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::format;

    #[test]
    fn debug() {
        assert_eq!(
            format!("{:?}", ValueType::IpFragmentOffset),
            "IpFragmentOffset"
        );
    }

    #[test]
    fn cmp_partial_cmp() {
        use core::cmp::Ordering;
        let a = ValueType::IpFragmentOffset;
        let b = a;
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Equal));
    }

    #[test]
    fn display() {
        use ValueType::*;

        assert_eq!("VLAN ID", &format!("{}", VlanId));
        assert_eq!("VLAN PCP (Priority Code Point)", &format!("{}", VlanPcp));
        assert_eq!("IP Fragment Offset", &format!("{}", IpFragmentOffset));
        assert_eq!(
            "IPv4 DSCP (Differentiated Services Code Point)",
            &format!("{}", Ipv4Dscp)
        );
        assert_eq!(
            "IPv4 ECN (Explicit Congestion Notification)",
            &format!("{}", Ipv4Ecn)
        );
        assert_eq!("IPv6 Flow Label", &format!("{}", Ipv6FlowLabel));
        assert_eq!("Ipv4Header.payload_len", &format!("{}", Ipv4PayloadLength));
    }
}
