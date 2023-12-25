use crate::*;

/// IEEE 802.1Q VLAN Tagging Header (can be single or double tagged).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanHeader {
    /// IEEE 802.1Q VLAN Tagging Header
    Single(SingleVlanHeader),
    /// IEEE 802.1Q double VLAN Tagging Header
    Double(DoubleVlanHeader),
}

impl VlanHeader {
    /// All ether types that identify a vlan header.
    pub const VLAN_ETHER_TYPES: [EtherType; 3] = [
        ether_type::VLAN_TAGGED_FRAME,
        ether_type::PROVIDER_BRIDGING,
        ether_type::VLAN_DOUBLE_TAGGED_FRAME,
    ];

    /// Write the IEEE 802.1Q VLAN single or double tagging header
    #[cfg(feature = "std")]
    #[inline]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        use VlanHeader::*;
        match &self {
            Single(header) => header.write(writer),
            Double(header) => header.write(writer),
        }
    }

    /// Returns the ether type of the next header after the vlan header(s).
    #[inline]
    pub fn next_header(&self) -> EtherType {
        match self {
            VlanHeader::Single(s) => s.ether_type,
            VlanHeader::Double(d) => d.inner.ether_type,
        }
    }

    /// Length of the serialized header(s) in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        use VlanHeader::*;
        match &self {
            Single(_) => SingleVlanHeader::LEN,
            Double(_) => DoubleVlanHeader::LEN,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    #[test]
    fn constants() {
        use ether_type::*;
        use VlanHeader as V;

        assert_eq!(3, V::VLAN_ETHER_TYPES.len());
        assert_eq!(VLAN_TAGGED_FRAME, V::VLAN_ETHER_TYPES[0]);
        assert_eq!(PROVIDER_BRIDGING, V::VLAN_ETHER_TYPES[1]);
        assert_eq!(VLAN_DOUBLE_TAGGED_FRAME, V::VLAN_ETHER_TYPES[2]);
    }

    proptest! {
        #[test]
        fn clone_eq(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single eq
            {
                let value = VlanHeader::Single(single.clone());
                assert_eq!(value, value.clone());
            }
            // double
            {
                let value = VlanHeader::Double(double);
                assert_eq!(value, value.clone());
            }
        }
    }

    proptest! {
        #[test]
        fn dbg(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let value = VlanHeader::Single(single.clone());
                assert_eq!(
                    &format!(
                        "Single({:?})",
                        single
                    ),
                    &format!("{:?}", value)
                );
            }
            // double
            {
                let value = VlanHeader::Double(double.clone());
                assert_eq!(
                    &format!(
                        "Double({:?})",
                        double
                    ),
                    &format!("{:?}", value)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            assert_eq!(
                SingleVlanHeader::LEN,
                VlanHeader::Single(single.clone()).header_len()
            );
            // double
            assert_eq!(
                DoubleVlanHeader::LEN,
                VlanHeader::Double(double.clone()).header_len()
            );
        }
    }

    proptest! {
        #[test]
        fn write(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let expected = {
                    let mut buffer = Vec::with_capacity(single.header_len());
                    single.write(&mut buffer).unwrap();
                    buffer
                };
                let actual = {
                    let mut buffer = Vec::with_capacity(single.header_len());
                    VlanHeader::Single(single.clone()).write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(expected, actual);
            }

            // double
            {
                let expected = {
                    let mut buffer = Vec::with_capacity(double.header_len());
                    double.write(&mut buffer).unwrap();
                    buffer
                };
                let actual = {
                    let mut buffer = Vec::with_capacity(double.header_len());
                    VlanHeader::Double(double.clone()).write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(expected, actual);
            }
        }
    }
}
