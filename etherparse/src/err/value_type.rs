/// Types of values that have a limited allowed value range
/// and can cause an [`crate::err::ValueTooBigError`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ValueType {
    /// VLAN identifier field present in a [`crate::SingleVlanHeader`].
    VlanId,
    /// IP Fragment offset present in the IPv4 header and
    /// IPv6 fragmentation header.
    IpFragmentOffset,

    Ipv4PayloadLength,
    /// Ipv4 Header DSCP (Differentiated Services Code Point) field
    /// present in an [`crate::Ipv4Header`].
    Ipv4Dscp,
    /// Ipv4 Header ECN (Explicit Congestion Notification) field
    /// present in an [`crate::Ipv4Header`].
    Ipv4Ecn,

    Ipv6FlowLabel,
    /// VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
}

impl core::fmt::Display for ValueType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use ValueType::*;
        match self {
            VlanId => write!(f, "VLAN ID"),
            Ipv4PayloadLength => write!(f, "Ipv4Header.payload_len"),
            Ipv4Dscp => write!(f, "IPv4 Header DSCP (Differentiated Services Code Point)"),
            Ipv4Ecn => write!(f, "IPv4 Header ECN (Explicit Congestion Notification)"),
            IpFragmentOffset => write!(f, "IP Fragment Offset"),
            Ipv6FlowLabel => write!(f, "Ipv6Header.flow_label"),
            VlanTagPriorityCodePoint => write!(f, "SingleVlanHeader.priority_code_point"),
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
        assert_eq!("Ipv4Header.payload_len", &format!("{}", Ipv4PayloadLength));
        assert_eq!(
            "IPv4 Header DSCP (Differentiated Services Code Point)",
            &format!("{}", Ipv4Dscp)
        );
        assert_eq!(
            "IPv4 Header ECN (Explicit Congestion Notification)",
            &format!("{}", Ipv4Ecn)
        );
        assert_eq!("IP Fragment Offset", &format!("{}", IpFragmentOffset));
        assert_eq!("Ipv6Header.flow_label", &format!("{}", Ipv6FlowLabel));
        assert_eq!(
            "SingleVlanHeader.priority_code_point",
            &format!("{}", VlanTagPriorityCodePoint)
        );
    }
}
