use crate::*;

/// A slice containing the link layer extension header (currently only Ethernet II and
/// SLL are supported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkExtSlice<'a> {
    /// Slice containing a VLAN header & payload.
    Vlan(SingleVlanSlice<'a>),
}

impl<'a> LinkExtSlice<'a> {
    /// Returns the header length of the link extension.
    pub fn header_len(&self) -> usize {
        match self {
            LinkExtSlice::Vlan(s) => s.header_len(),
        }
    }

    /// Convert the header part of the link extension into a [`LinkExtHeader`].
    pub fn to_header(&self) -> LinkExtHeader {
        match self {
            LinkExtSlice::Vlan(s) => LinkExtHeader::Vlan(s.to_header()),
        }
    }

    /// Return the payload of the link extensions.
    pub fn payload(&self) -> EtherPayloadSlice<'a> {
        match self {
            LinkExtSlice::Vlan(s) => s.payload(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_gens::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug_clone_eq(ref vlan in vlan_single_any()) {
            let bytes = vlan.to_bytes();
            let e = SingleVlanSlice::from_slice(&bytes).unwrap();
            let slice = LinkExtSlice::Vlan(
                e.clone()
            );

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(
                format!("{:?}", slice),
                format!("Vlan({:?})", e),
            );
        }
    }

    proptest! {
        #[test]
        fn header_len(ref vlan in vlan_single_any()) {
            let bytes = vlan.to_bytes();
            let e = SingleVlanSlice::from_slice(&bytes).unwrap();
            let slice = LinkExtSlice::Vlan(
                e.clone()
            );
            assert_eq!(slice.header_len(), e.header_len());
        }
    }

    proptest! {
        #[test]
        fn to_header(ref vlan in vlan_single_any()) {
            let bytes = vlan.to_bytes();
            let e = SingleVlanSlice::from_slice(&bytes).unwrap();
            let slice = LinkExtSlice::Vlan(
                e.clone()
            );
            assert_eq!(slice.to_header(), LinkExtHeader::Vlan(e.to_header()));
        }
    }

    proptest! {
        #[test]
        fn payload(ref vlan in vlan_single_any()) {
            let payload = [1,2,3,4];
            let mut bytes = Vec::with_capacity(SingleVlanHeader::LEN + 4);
            bytes.extend_from_slice(&vlan.to_bytes());
            bytes.extend_from_slice(&payload);
            let e = SingleVlanSlice::from_slice(&bytes).unwrap();
            let slice = LinkExtSlice::Vlan(
                e.clone()
            );
            assert_eq!(slice.payload(), EtherPayloadSlice{ ether_type: vlan.ether_type, payload: &payload });
        }
    }
}
