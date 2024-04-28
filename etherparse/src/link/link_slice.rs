use crate::*;

/// A slice containing the link layer header (currently only Ethernet II is supported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkSlice<'a> {
    /// A slice containing an Ethernet II header.
    Ethernet2(Ethernet2Slice<'a>),

    /// Ether payload without header.
    EtherPayload(EtherPayloadSlice<'a>),
}

impl<'a> LinkSlice<'a> {
    /// Convert the link slice to a header (currently just the
    /// ethernet2 header as this is the only value it can take).
    pub fn to_header(&self) -> Option<LinkHeader> {
        use LinkSlice::*;
        match self {
            Ethernet2(slice) => Some(LinkHeader::Ethernet2(slice.to_header())),
            EtherPayload(_) => None,
        }
    }

    /// Returns the link layer payload (slice + ether type number).
    pub fn payload(&self) -> EtherPayloadSlice<'a> {
        use LinkSlice::*;
        match self {
            Ethernet2(s) => s.payload().clone(),
            EtherPayload(p) => p.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug_clone_eq(ref eth in ethernet_2_unknown()) {
            let bytes = eth.to_bytes();
            let e = Ethernet2Slice::from_slice_without_fcs(&bytes).unwrap();
            let slice = LinkSlice::Ethernet2(
                e.clone()
            );

            // clone & eq
            assert_eq!(slice.clone(), slice);

            // debug
            assert_eq!(
                format!("{:?}", slice),
                format!("Ethernet2({:?})", e),
            );
        }
    }

    proptest! {
        #[test]
        fn to_header(ref eth in ethernet_2_unknown()) {
            {
                let bytes = eth.to_bytes();
                let slice = LinkSlice::Ethernet2(
                    Ethernet2Slice::from_slice_without_fcs(&bytes).unwrap()
                );
                assert_eq!(
                    slice.to_header(),
                    Some(LinkHeader::Ethernet2(eth.clone()))
                );
            }
            {
                let slice = LinkSlice::EtherPayload(EtherPayloadSlice {
                    ether_type: ether_type::IPV4,
                    payload: &[]
                });
                assert_eq!(
                    slice.to_header(),
                    None
                );
            }
        }
    }

    proptest! {
        #[test]
        fn payload(ref eth in ethernet_2_unknown()) {
            let p = [1,2,3,4];
            {
                let mut bytes = Vec::with_capacity(Ethernet2Header::LEN + p.len());
                bytes.extend_from_slice(&eth.to_bytes());
                bytes.extend_from_slice(&p);
                let slice = LinkSlice::Ethernet2(
                    Ethernet2Slice::from_slice_without_fcs(&bytes).unwrap()
                );
                assert_eq!(
                    slice.payload(),
                    EtherPayloadSlice{ ether_type: eth.ether_type, payload: &p }
                );
            }
            {
                let p = [1,2,3,4];
                let slice = LinkSlice::EtherPayload(EtherPayloadSlice {
                    ether_type: eth.ether_type,
                    payload: &p
                });
                assert_eq!(
                    slice.payload(),
                    EtherPayloadSlice{ ether_type: eth.ether_type, payload: &p }
                );
            }
        }
    }
}
