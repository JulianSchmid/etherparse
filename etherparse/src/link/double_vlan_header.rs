use crate::*;

/// IEEE 802.1Q double VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeader {
    /// The outer vlan tagging header
    pub outer: SingleVlanHeader,
    /// The inner vlan tagging header
    pub inner: SingleVlanHeader,
}

impl DoubleVlanHeader {
    /// Serialized size of two VLAN headers in bytes/octets.
    pub const LEN: usize = 8;

    #[deprecated(since = "0.14.0", note = "Use `DoubleVlanHeader::LEN` instead")]
    pub const SERIALIZED_SIZE: usize = DoubleVlanHeader::LEN;

    /// Read an DoubleVlanHeader from a slice and return the header & unused parts of the slice.
    #[deprecated(since = "0.10.1", note = "Use SingleVlanHeader::from_slice instead.")]
    #[inline]
    pub fn read_from_slice(
        slice: &[u8],
    ) -> Result<(DoubleVlanHeader, &[u8]), err::double_vlan::HeaderSliceError> {
        DoubleVlanHeader::from_slice(slice)
    }

    /// Read an DoubleVlanHeader from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(
        slice: &[u8],
    ) -> Result<(DoubleVlanHeader, &[u8]), err::double_vlan::HeaderSliceError> {
        Ok((
            DoubleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[DoubleVlanHeader::LEN..],
        ))
    }

    /// Read a double tagging header from the given source
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<DoubleVlanHeader, err::double_vlan::HeaderReadError> {
        use err::double_vlan::{HeaderError::*, HeaderReadError::*};

        let outer = SingleVlanHeader::read(reader).map_err(Io)?;

        use crate::ether_type::{PROVIDER_BRIDGING, VLAN_DOUBLE_TAGGED_FRAME, VLAN_TAGGED_FRAME};
        //check that outer ethertype is matching
        match outer.ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                Ok(DoubleVlanHeader {
                    outer,
                    inner: SingleVlanHeader::read(reader).map_err(Io)?,
                })
            }
            value => Err(Content(NonVlanEtherType {
                unexpected_ether_type: value,
            })),
        }
    }

    /// Write the double IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        self.outer.write(writer)?;
        self.inner.write(writer)
    }

    /// Length of the serialized headers in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        8
    }

    /// Returns the serialized form of the headers or an value error in case
    /// the headers contain values that are outside of range.
    #[inline]
    pub fn to_bytes(&self) -> Result<[u8; 8], ValueError> {
        let outer = self.outer.to_bytes()?;
        let inner = self.inner.to_bytes()?;
        Ok([
            outer[0], outer[1], outer[2], outer[3], inner[0], inner[1], inner[2], inner[3],
        ])
    }
}

impl Default for DoubleVlanHeader {
    fn default() -> Self {
        DoubleVlanHeader {
            outer: SingleVlanHeader {
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0,
                ether_type: ether_type::VLAN_TAGGED_FRAME,
            },
            inner: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{test_gens::*, *};
    use proptest::prelude::*;
    use std::io::{Cursor, ErrorKind};

    #[test]
    fn constants() {
        assert_eq!(8, DoubleVlanHeader::LEN);
    }

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
            use err::double_vlan::{HeaderError::*, HeaderSliceError::*};

            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len() + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // normal
            {
                let (result, rest) = DoubleVlanHeader::from_slice(&buffer).unwrap();
                assert_eq!(result, input);
                assert_eq!(rest, &buffer[8..]);
            }
            #[allow(deprecated)]
            {
                let (result, rest) = DoubleVlanHeader::read_from_slice(&buffer).unwrap();
                assert_eq!(result, input);
                assert_eq!(rest, &buffer[8..]);
            }

            // slice length to small
            for len in 0..8 {
                assert_eq!(
                    DoubleVlanHeader::from_slice(&buffer[..len])
                        .unwrap_err(),
                    UnexpectedEndOfSlice(err::SliceLenError{
                        expected_min_len: 8,
                        actual_len: len,
                        layer:  err::Layer::VlanHeader
                    })
                );
            }

            // bad outer ether type
            {
                let mut bad_outer = input.clone();
                bad_outer.outer.ether_type = ether_type_non_vlan;
                let bytes = bad_outer.to_bytes().unwrap();
                assert_eq!(
                    DoubleVlanHeader::from_slice(&bytes)
                        .unwrap_err(),
                    Content(NonVlanEtherType{
                        unexpected_ether_type: ether_type_non_vlan,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn read(
            input in vlan_double_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20),
            ether_type_non_vlan in any::<u16>().prop_filter(
                "ether_type must not be a vlan ether type",
                |v| !VlanHeader::VLAN_ETHER_TYPES.iter().any(|&x| v == &x)
            )
        ) {
            use err::double_vlan::HeaderError::*;

            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len() + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // normal
            {
                let mut cursor = Cursor::new(&buffer);
                let result = DoubleVlanHeader::read(&mut cursor).unwrap();
                assert_eq!(result, input);
                assert_eq!(8, cursor.position());
            }

            // outer & inner error
            for len in 0..8 {
                let mut cursor = Cursor::new(&buffer[0..len]);
                assert_eq!(
                    DoubleVlanHeader::read(&mut cursor)
                    .unwrap_err()
                    .io_error()
                    .unwrap()
                    .kind(),
                    ErrorKind::UnexpectedEof
                );
            }

            // bad outer ether type
            {
                let mut bad_outer = input.clone();
                bad_outer.outer.ether_type = ether_type_non_vlan;
                let bytes = bad_outer.to_bytes().unwrap();
                let mut cursor = Cursor::new(&bytes);
                assert_eq!(
                    DoubleVlanHeader::read(&mut cursor)
                        .unwrap_err()
                        .content_error()
                        .unwrap(),
                    NonVlanEtherType{
                        unexpected_ether_type: ether_type_non_vlan,
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write_and_to_bytes(input in vlan_double_any()) {
            // normal write
            {
                let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len());
                input.write(&mut buffer).unwrap();
                assert_eq!(&buffer[..], &input.to_bytes().unwrap());
                {
                    let inner_bytes = input.inner.to_bytes().unwrap();
                    let outer_bytes = input.outer.to_bytes().unwrap();
                    assert_eq!(
                        input.to_bytes().unwrap(),
                        [
                            outer_bytes[0],
                            outer_bytes[1],
                            outer_bytes[2],
                            outer_bytes[3],
                            inner_bytes[0],
                            inner_bytes[1],
                            inner_bytes[2],
                            inner_bytes[3],
                        ]
                    );
                }
            }

            // bad value outer
            {
                let mut bad_input = input.clone();
                bad_input.outer.priority_code_point = 0b1000;

                let mut buffer: Vec<u8> = Vec::new();
                let expected = ValueError::U8TooLarge{
                    value: bad_input.outer.priority_code_point,
                    max: 0b111,
                    field: ErrorField::VlanTagPriorityCodePoint
                };

                assert_eq!(
                    bad_input
                        .write(&mut buffer)
                        .unwrap_err()
                        .value_error()
                        .unwrap(),
                    expected
                );
                assert_eq!(
                    bad_input
                        .to_bytes()
                        .unwrap_err(),
                    expected
                );
            }

            // bad value inner
            {
                let mut bad_input = input.clone();
                bad_input.inner.priority_code_point = 0b1000;

                let mut buffer: Vec<u8> = Vec::new();
                let expected = ValueError::U8TooLarge{
                    value: bad_input.inner.priority_code_point,
                    max: 0b111,
                    field: ErrorField::VlanTagPriorityCodePoint
                };

                assert_eq!(
                    bad_input
                        .write(&mut buffer)
                        .unwrap_err()
                        .value_error()
                        .unwrap(),
                    expected
                );
                assert_eq!(
                    bad_input
                        .to_bytes()
                        .unwrap_err(),
                    expected
                );
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(input in vlan_double_any()) {
            assert_eq!(8, input.header_len());
        }
    }

    #[test]
    fn default() {
        let actual: DoubleVlanHeader = Default::default();
        assert_eq!(actual.outer, {
            let mut outer: SingleVlanHeader = Default::default();
            outer.ether_type = ether_type::VLAN_TAGGED_FRAME;
            outer
        });
        assert_eq!(actual.inner, Default::default());
    }

    proptest! {
        #[test]
        fn clone_eq(input in vlan_double_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in vlan_double_any()) {
            assert_eq!(
                &format!(
                    "DoubleVlanHeader {{ outer: {:?}, inner: {:?} }}",
                    input.outer,
                    input.inner,
                ),
                &format!("{:?}", input)
            );
        }
    }
}
