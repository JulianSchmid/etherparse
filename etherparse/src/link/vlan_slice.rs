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
