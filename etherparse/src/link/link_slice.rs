use crate::*;

/// A slice containing the link layer header (currently only Ethernet II is supported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkSlice<'a> {
    /// A slice containing an Ethernet II header.
    Ethernet2(Ethernet2HeaderSlice<'a>),
}

impl<'a> LinkSlice<'a> {
    /// Convert the link slice to a header (currently just the
    /// ethernet2 header as this is the only value it can take).
    pub fn to_header(&self) -> Ethernet2Header {
        use LinkSlice::*;
        match self {
            Ethernet2(slice) => slice.to_header(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use alloc::format;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn debug_clone_eq(ref eth in ethernet_2_unknown()) {
            let bytes = eth.to_bytes();
            let e = Ethernet2HeaderSlice::from_slice(&bytes).unwrap();
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
            let bytes = eth.to_bytes();
            let slice = LinkSlice::Ethernet2(
                Ethernet2HeaderSlice::from_slice(&bytes).unwrap()
            );

            // clone & eq
            assert_eq!(
                slice.to_header(),
                *eth
            );
        }
    }
}
