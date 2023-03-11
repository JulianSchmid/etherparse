use crate::*;
use core::slice::from_raw_parts;

///A slice containing a single vlan header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleVlanHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> SingleVlanHeaderSlice<'a> {
    ///Creates a vlan header slice from a slice.
    #[inline]
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<SingleVlanHeaderSlice<'a>, err::UnexpectedEndOfSliceError> {
        //check length
        if slice.len() < SingleVlanHeader::LEN {
            return Err(err::UnexpectedEndOfSliceError {
                expected_min_len: SingleVlanHeader::LEN,
                actual_len: slice.len(),
                layer: err::Layer::VlanHeader,
            });
        }

        //all done
        Ok(SingleVlanHeaderSlice::<'a> {
            // SAFETY:
            // Safe as the slice length is checked beforehand to have
            // at least the length of SingleVlanHeader::LEN (4)
            slice: unsafe { from_raw_parts(slice.as_ptr(), SingleVlanHeader::LEN) },
        })
    }

    /// Converts the given slice into a vlan header slice WITHOUT any
    /// checks to ensure that the data present is an vlan header or that the
    /// slice length is matching the header length.
    ///
    /// If you are not sure what this means, use [`SingleVlanHeaderSlice::from_slice`]
    /// instead.
    ///
    /// # Safety
    ///
    /// The caller must ensured that the given slice has the length of
    /// [`SingleVlanHeader::LEN`]
    #[inline]
    pub(crate) unsafe fn from_slice_unchecked(slice: &[u8]) -> SingleVlanHeaderSlice {
        SingleVlanHeaderSlice { slice }
    }

    /// Returns the slice containing the single vlan header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the "priority_code_point" field from the slice. This is a 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    #[inline]
    pub fn priority_code_point(&self) -> u8 {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe { *self.slice.get_unchecked(0) >> 5 }
    }

    /// Read the "drop_eligible_indicator" flag from the slice. Indicates that the frame may be dropped under the presence of congestion.
    #[inline]
    pub fn drop_eligible_indicator(&self) -> bool {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe { 0 != (*self.slice.get_unchecked(0) & 0x10) }
    }

    /// Reads the 12 bits "vland identifier" field from the slice.
    #[inline]
    pub fn vlan_identifier(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Slice len checked in constructor to be at least 4.
            unsafe {
                [
                    *self.slice.get_unchecked(0) & 0xf,
                    *self.slice.get_unchecked(1),
                ]
            },
        )
    }

    /// Read the "Tag protocol identifier" field from the slice. Refer to the "EtherType" for a list of possible supported values.
    #[inline]
    pub fn ether_type(&self) -> u16 {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Decode all the fields and copy the results to a SingleVlanHeader struct
    #[inline]
    pub fn to_header(&self) -> SingleVlanHeader {
        SingleVlanHeader {
            priority_code_point: self.priority_code_point(),
            drop_eligible_indicator: self.drop_eligible_indicator(),
            vlan_identifier: self.vlan_identifier(),
            ether_type: self.ether_type(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{test_gens::*, *};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn from_slice(
            input in vlan_single_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len() + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // normal
            {
                let slice = SingleVlanHeaderSlice::from_slice(&buffer).unwrap();
                assert_eq!(slice.slice(), &buffer[..4]);
            }

            // slice length to small
            for len in 0..4 {
                assert_eq!(
                    SingleVlanHeaderSlice::from_slice(&buffer[..len])
                        .unwrap_err(),
                    err::UnexpectedEndOfSliceError{
                        expected_min_len: 4,
                        actual_len: len,
                        layer:  err::Layer::VlanHeader
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in vlan_single_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = SingleVlanHeaderSlice::from_slice(&bytes).unwrap();

            assert_eq!(input.priority_code_point, slice.priority_code_point());
            assert_eq!(input.drop_eligible_indicator, slice.drop_eligible_indicator());
            assert_eq!(input.vlan_identifier, slice.vlan_identifier());
            assert_eq!(input.ether_type, slice.ether_type());
        }
    }

    proptest! {
        #[test]
        fn to_header(input in vlan_single_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = SingleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in vlan_single_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = SingleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in vlan_single_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = SingleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(
                &format!(
                    "SingleVlanHeaderSlice {{ slice: {:?} }}",
                    slice.slice(),
                ),
                &format!("{:?}", slice)
            );
        }
    }
}
