pub mod ethernet;
pub mod vlan_tagging;

use super::*;

mod link_slice {
    use super::*;

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
