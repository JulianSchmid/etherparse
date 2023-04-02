use crate::*;

/// A slice containing a single or double vlan header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanSlice<'a> {
    SingleVlan(SingleVlanHeaderSlice<'a>),
    DoubleVlan(DoubleVlanHeaderSlice<'a>),
}

impl<'a> VlanSlice<'a> {
    /// Decode all the fields and copy the results to a VlanHeader struct
    #[inline]
    pub fn to_header(&self) -> VlanHeader {
        use crate::VlanHeader::*;
        use crate::VlanSlice::*;
        match self {
            SingleVlan(value) => Single(value.to_header()),
            DoubleVlan(value) => Double(value.to_header()),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{test_gens::*, *};
    use alloc::format;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn to_header(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let raw = single.to_bytes().unwrap();
                let slice = VlanSlice::SingleVlan(
                    SingleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(
                    slice.to_header(),
                    VlanHeader::Single(single)
                );
            }

            // double
            {
                let raw = double.to_bytes().unwrap();
                let slice = VlanSlice::DoubleVlan(
                    DoubleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(
                    slice.to_header(),
                    VlanHeader::Double(double)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn debug(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let raw = single.to_bytes().unwrap();
                let s = SingleVlanHeaderSlice::from_slice(&raw).unwrap();
                assert_eq!(
                    format!("{:?}", VlanSlice::SingleVlan(s.clone())),
                    format!("SingleVlan({:?})", s)
                );
            }

            // double
            {
                let raw = double.to_bytes().unwrap();
                let d = DoubleVlanHeaderSlice::from_slice(&raw).unwrap();
                assert_eq!(
                    format!("{:?}", VlanSlice::DoubleVlan(d.clone())),
                    format!("DoubleVlan({:?})", d)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let raw = single.to_bytes().unwrap();
                let s = VlanSlice::SingleVlan(
                    SingleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(s.clone(), s);
            }

            // double
            {
                let raw = double.to_bytes().unwrap();
                let d = VlanSlice::DoubleVlan(
                    DoubleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(d.clone(), d);
            }
        }
    }
}
