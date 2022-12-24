use crate::*;
use core::slice::from_raw_parts;

/// A slice containing an double vlan header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> DoubleVlanHeaderSlice<'a> {
    /// Creates a double header slice from a slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<DoubleVlanHeaderSlice<'a>, ReadError> {
        // check length
        use crate::ReadError::*;
        if slice.len() < DoubleVlanHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(err::UnexpectedEndOfSliceError {
                expected_min_len: DoubleVlanHeader::SERIALIZED_SIZE,
                actual_len: slice.len(),
                layer: err::Layer::VlanHeader,
            }));
        }

        // create slice
        let result = DoubleVlanHeaderSlice {
            // SAFETY:
            // Safe as the slice length is checked is before to have
            // at least the length of DoubleVlanHeader::SERIALIZED_SIZE (8)
            slice: unsafe { from_raw_parts(slice.as_ptr(), DoubleVlanHeader::SERIALIZED_SIZE) },
        };

        use ether_type::*;

        //check that outer ethertype is matching
        match result.outer().ether_type() {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                //all done
                Ok(result)
            }
            value => Err(DoubleVlanOuterNonVlanEtherType(value)),
        }
    }

    /// Returns the slice containing the double vlan header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns a slice with the outer vlan header
    #[inline]
    pub fn outer(&self) -> SingleVlanHeaderSlice<'a> {
        // SAFETY:
        // Safe as the constructor checks that the slice has the length
        // of DoubleVlanHeader::SERIALIZED_SIZE (8) and the
        // SingleVlanHeader::SERIALIZED_SIZE has a size of 4.
        unsafe {
            SingleVlanHeaderSlice::from_slice_unchecked(from_raw_parts(
                self.slice.as_ptr(),
                SingleVlanHeader::SERIALIZED_SIZE,
            ))
        }
    }

    /// Returns a slice with the inner vlan header.
    #[inline]
    pub fn inner(&self) -> SingleVlanHeaderSlice<'a> {
        // SAFETY:
        // Safe as the constructor checks that the slice has the length
        // of DoubleVlanHeader::SERIALIZED_SIZE (8) and the
        // SingleVlanHeader::SERIALIZED_SIZE has a size of 4.
        unsafe {
            SingleVlanHeaderSlice::from_slice_unchecked(from_raw_parts(
                self.slice.as_ptr().add(SingleVlanHeader::SERIALIZED_SIZE),
                SingleVlanHeader::SERIALIZED_SIZE,
            ))
        }
    }

    /// Decode all the fields and copy the results to a DoubleVlanHeader struct
    pub fn to_header(&self) -> DoubleVlanHeader {
        DoubleVlanHeader {
            outer: self.outer().to_header(),
            inner: self.inner().to_header(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{*, test_gens::*};
    use proptest::prelude::*;
    use assert_matches::assert_matches;

    proptest! {
        #[test]
        fn from_slice(
            input in vlan_double_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20),
            ether_type_non_vlan in any::<u16>().prop_filter(
                "ether_type must not be a vlan ether type",
                |v| !VlanHeader::VLAN_ETHER_TYPES.iter().any(|&x| v == &x)
            )
        ) {
            {
                // serialize
                let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len() + dummy_data.len());
                input.write(&mut buffer).unwrap();
                buffer.extend(&dummy_data[..]);

                // normal
                {
                    let slice = DoubleVlanHeaderSlice::from_slice(&buffer).unwrap();
                    assert_eq!(slice.slice(), &buffer[..8]);
                }

                // slice length to small
                for len in 0..8 {
                    assert_eq!(
                        DoubleVlanHeaderSlice::from_slice(&buffer[..len])
                            .unwrap_err()
                            .unexpected_end_of_slice()
                            .unwrap(),
                        err::UnexpectedEndOfSliceError{
                            expected_min_len: 8,
                            actual_len: len,
                            layer:  err::Layer::VlanHeader
                        }
                    );
                }
            }

            // bad outer ether type
            {
                let mut bad_outer = input.clone();
                bad_outer.outer.ether_type = ether_type_non_vlan;
                assert_matches!(
                    DoubleVlanHeaderSlice::from_slice(&bad_outer.to_bytes().unwrap())
                        .unwrap_err(),
                    ReadError::DoubleVlanOuterNonVlanEtherType(_)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in vlan_double_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = DoubleVlanHeaderSlice::from_slice(&bytes).unwrap();

            assert_eq!(input.outer, slice.outer().to_header());
            assert_eq!(input.inner, slice.inner().to_header());
        }
    }

    proptest! {
        #[test]
        fn to_header(input in vlan_double_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = DoubleVlanHeaderSlice::from_slice(&bytes).unwrap();

            assert_eq!(
                DoubleVlanHeader{
                    outer: input.outer,
                    inner: input.inner,
                },
                slice.to_header()
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in vlan_double_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = DoubleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in vlan_double_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = DoubleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(
                &format!(
                    "DoubleVlanHeaderSlice {{ slice: {:?} }}",
                    slice.slice(),
                ),
                &format!("{:?}", slice)
            );
        }
    }
}
