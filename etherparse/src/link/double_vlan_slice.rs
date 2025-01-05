use crate::{err::*, *};

/// Slice containing a VLAN header & payload.
#[derive(Clone, Eq, PartialEq)]
pub struct DoubleVlanSlice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> DoubleVlanSlice<'a> {
    /// Try creating a [`DoubleVlanSlice`] from a slice containing the
    /// VLAN header & payload.
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<DoubleVlanSlice<'a>, err::double_vlan::HeaderSliceError> {
        use err::double_vlan::{HeaderError::*, HeaderSliceError::*};

        // check length
        if slice.len() < DoubleVlanHeader::LEN {
            return Err(Len(LenError {
                required_len: DoubleVlanHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::VlanHeader,
                layer_start_offset: 0,
            }));
        }

        // create slice
        let result = DoubleVlanSlice { slice };

        // check that outer ethertype is matching
        use ether_type::*;
        match result.outer().ether_type() {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => Ok(result),
            value => Err(Content(NonVlanEtherType {
                unexpected_ether_type: value,
            })),
        }
    }

    /// Returns the slice containing the VLAN header and payload.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Outer VLAN header & payload (includes header of inner vlan header).
    #[inline]
    pub fn outer(&self) -> SingleVlanSlice {
        SingleVlanSlice { slice: self.slice }
    }

    /// Inner VLAN header & payload.
    #[inline]
    pub fn inner(&self) -> SingleVlanSlice {
        SingleVlanSlice {
            slice: unsafe {
                // SAFETY: Safe as "from_slice" verified the slice length
                // to be DoubleVlanHeader::LEN (aka 2*SingleVlanHeader::LEN).
                core::slice::from_raw_parts(
                    self.slice.as_ptr().add(SingleVlanHeader::LEN),
                    self.slice.len() - SingleVlanHeader::LEN,
                )
            },
        }
    }

    /// Decode all the fields and copy the results to a DoubleVlanHeader struct
    #[inline]
    pub fn to_header(&self) -> DoubleVlanHeader {
        DoubleVlanHeader {
            outer: self.outer().to_header(),
            inner: self.inner().to_header(),
        }
    }

    /// Returns the slice containing the payload & ether type
    /// identifying it's content type after bother VLAN headers.
    #[inline]
    pub fn payload(&self) -> EtherPayloadSlice<'a> {
        EtherPayloadSlice {
            ether_type: self.inner().ether_type(),
            payload: self.payload_slice(),
        }
    }

    /// Returns the slice containing the payload after both
    /// VLAN headers.
    pub fn payload_slice(&self) -> &'a [u8] {
        unsafe {
            // SAFETY:
            // Safe as the contructor checks that the slice has
            // at least the length of DoubleVlanHeader::LEN (8).
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(DoubleVlanHeader::LEN),
                self.slice.len() - DoubleVlanHeader::LEN,
            )
        }
    }

    /// Length of the VLAN header in bytes (equal to
    /// [`crate::DoubleVlanHeader::LEN`]).
    #[inline]
    pub const fn header_len(&self) -> usize {
        DoubleVlanHeader::LEN
    }
}

impl core::fmt::Debug for DoubleVlanSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DoubleVlanSlice")
            .field("outer", &self.outer().to_header())
            .field("inner", &self.inner().to_header())
            .field("payload", &self.payload())
            .finish()
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
        fn debug_clone_eq(
            vlan in vlan_double_any()
        ) {
            let payload: [u8;8] = [1,2,3,4,5,6,7,8];
            let mut data = Vec::with_capacity(
                vlan.header_len() +
                payload.len()
            );
            data.extend_from_slice(&vlan.to_bytes());
            data.extend_from_slice(&payload);

            // decode packet
            let slice = DoubleVlanSlice::from_slice(&data).unwrap();

            // check debug output
            prop_assert_eq!(
                format!("{:?}", slice),
                format!(
                    "DoubleVlanSlice {{ outer: {:?}, inner: {:?}, payload: {:?} }}",
                    slice.outer().to_header(),
                    slice.inner().to_header(),
                    slice.payload(),
                )
            );
            prop_assert_eq!(slice.clone(), slice);
        }
    }

    proptest! {
        #[test]
        fn getters(vlan in vlan_double_any()) {
            let payload: [u8;8] = [1,2,3,4,5,6,7,8];
            let mut data = Vec::with_capacity(
                vlan.header_len() +
                payload.len()
            );
            data.extend_from_slice(&vlan.to_bytes());
            data.extend_from_slice(&payload);

            let slice = DoubleVlanSlice::from_slice(&data).unwrap();
            assert_eq!(&data, slice.slice());
            assert_eq!(&data, slice.outer().slice());
            assert_eq!(vlan.outer, slice.outer().to_header());
            assert_eq!(&data[SingleVlanHeader::LEN..], slice.inner().slice());
            assert_eq!(vlan.inner, slice.inner().to_header());
            assert_eq!(vlan, slice.to_header());
            assert_eq!(
                EtherPayloadSlice{
                    ether_type: vlan.inner.ether_type,
                    payload: &payload
                },
                slice.payload()
            );
            assert_eq!(&payload, slice.payload_slice());
            assert_eq!(DoubleVlanHeader::LEN, slice.header_len());
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            vlan in vlan_double_any(),
            ether_type_non_vlan in ether_type_any().prop_filter(
                "ether_type must not be a vlan ether type",
                |v| !VlanHeader::VLAN_ETHER_TYPES.iter().any(|&x| v == &x)
            )
        ) {
            use err::double_vlan::{HeaderError::*, HeaderSliceError::*};

            let payload: [u8;10] = [1,2,3,4,5,6,7,8,9,10];
            let data = {
                let mut data = Vec::with_capacity(
                    vlan.header_len() +
                    payload.len()
                );
                data.extend_from_slice(&vlan.to_bytes());
                data.extend_from_slice(&payload);
                data
            };

            // normal decode
            {
                let slice = DoubleVlanSlice::from_slice(&data).unwrap();
                assert_eq!(slice.to_header(), vlan);
                assert_eq!(slice.payload_slice(), &payload);
            }

            // length error
            for len in 0..DoubleVlanHeader::LEN {
                assert_eq!(
                    DoubleVlanSlice::from_slice(&data[..len]).unwrap_err(),
                    Len(LenError{
                        required_len: DoubleVlanHeader::LEN,
                        len,
                        len_source: LenSource::Slice,
                        layer: Layer::VlanHeader,
                        layer_start_offset: 0
                    })
                );
            }

            // mismatching outer ether type
            {
                let mut bad_data = data.clone();
                let e_be = ether_type_non_vlan.0.to_be_bytes();
                bad_data[2] = e_be[0];
                bad_data[3] = e_be[1];
                assert_eq!(
                    DoubleVlanSlice::from_slice(&bad_data).unwrap_err(),
                    Content(NonVlanEtherType{
                        unexpected_ether_type: ether_type_non_vlan,
                    })
                );
            }
        }
    }
}
