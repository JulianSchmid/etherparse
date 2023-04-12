/// Types of values that have a limited allowed value range
/// and can cause an [`crate::err::ValueTooBigError`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ValueType {
    /// IP Fragment offset present in the IPv4 header and 
    /// IPv6 fragmentation header.
    IpFragmentOffset,

    Ipv4PayloadLength,
    Ipv4Dscp,
    Ipv4Ecn,
    
    Ipv6FlowLabel,
    /// VlanTaggingHeader.priority_code_point
    VlanTagPriorityCodePoint,
    /// VlanTaggingHeader.vlan_identifier
    VlanTagVlanId,
}

impl core::fmt::Display for ValueType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use ValueType::*;
        match self {
            Ipv4PayloadLength => write!(f, "Ipv4Header.payload_len"),
            Ipv4Dscp => write!(f, "Ipv4Header.differentiated_services_code_point"),
            Ipv4Ecn => write!(f, "Ipv4Header.explicit_congestion_notification"),
            IpFragmentOffset => write!(f, "IP fragment offset"),
            Ipv6FlowLabel => write!(f, "Ipv6Header.flow_label"),
            VlanTagPriorityCodePoint => write!(f, "SingleVlanHeader.priority_code_point"),
            VlanTagVlanId => write!(f, "SingleVlanHeader.vlan_identifier"),
        }
    }
}

#[cfg(test)]
mod test {
    use std::format;
    use super::*;

    #[test]
    fn debug() {
        assert_eq!(
            format!("{:?}", ValueType::IpFragmentOffset),
            "IpFragmentOffset"
        );
    }

    #[test]
    fn display() {
        use ValueType::*;
    
        assert_eq!("Ipv4Header.payload_len", &format!("{}", Ipv4PayloadLength));
        assert_eq!(
            "Ipv4Header.differentiated_services_code_point",
            &format!("{}", Ipv4Dscp)
        );
        assert_eq!(
            "Ipv4Header.explicit_congestion_notification",
            &format!("{}", Ipv4Ecn)
        );
        assert_eq!(
            "IP fragment offset",
            &format!("{}", IpFragmentOffset)
        );
        assert_eq!("Ipv6Header.flow_label", &format!("{}", Ipv6FlowLabel));
        assert_eq!(
            "SingleVlanHeader.priority_code_point",
            &format!("{}", VlanTagPriorityCodePoint)
        );
        assert_eq!(
            "SingleVlanHeader.vlan_identifier",
            &format!("{}", VlanTagVlanId)
        );
    }
}