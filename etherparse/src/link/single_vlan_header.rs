use crate::*;

/// IEEE 802.1Q VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SingleVlanHeader {
    /// A 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub priority_code_point: u8,
    /// Indicate that the frame may be dropped under the presence of congestion.
    pub drop_eligible_indicator: bool,
    /// 12 bits vland identifier.
    pub vlan_identifier: u16,
    /// "Tag protocol identifier": Type id of content after this header. Refer to the "EtherType" for a list of possible supported values.
    pub ether_type: u16,
}

impl SingleVlanHeader {
    /// Serialized size of an VLAN header in bytes/octets.
    pub const LEN: usize = 4;

    #[deprecated(since = "0.14.0", note = "Use `SingleVlanHeader::LEN` instead")]
    pub const SERIALIZED_SIZE: usize = SingleVlanHeader::LEN;

    /// Read an SingleVlanHeader from a slice and return the header & unused parts of the slice.
    #[deprecated(since = "0.10.1", note = "Use SingleVlanHeader::from_slice instead.")]
    #[inline]
    pub fn read_from_slice(
        slice: &[u8],
    ) -> Result<(SingleVlanHeader, &[u8]), err::SliceLenError> {
        SingleVlanHeader::from_slice(slice)
    }

    /// Read an SingleVlanHeader from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(
        slice: &[u8],
    ) -> Result<(SingleVlanHeader, &[u8]), err::SliceLenError> {
        Ok((
            SingleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[SingleVlanHeader::LEN..],
        ))
    }

    /// Read an SingleVlanHeader from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 4]) -> SingleVlanHeader {
        SingleVlanHeader {
            priority_code_point: (bytes[0] >> 5) & 0b0000_0111u8,
            drop_eligible_indicator: 0 != (bytes[0] & 0b0001_0000u8),
            vlan_identifier: u16::from_be_bytes([bytes[0] & 0b0000_1111u8, bytes[1]]),
            ether_type: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }

    /// Read a IEEE 802.1Q VLAN tagging header
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<SingleVlanHeader, io::Error> {
        let buffer = {
            let mut buffer: [u8; SingleVlanHeader::LEN] = [0; SingleVlanHeader::LEN];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(
            // SAFETY: Safe as the buffer has the exact size of an vlan header.
            unsafe { SingleVlanHeaderSlice::from_slice_unchecked(&buffer) }.to_header(),
        )
    }

    /// Write the IEEE 802.1Q VLAN tagging header
    #[inline]
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()?)?;
        Ok(())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        4
    }

    /// Returns the serialized form of the header or an value error in case
    /// the header values are outside of range.
    #[inline]
    pub fn to_bytes(&self) -> Result<[u8; 4], ValueError> {
        use crate::ErrorField::*;
        // check value ranges
        max_check_u8(self.priority_code_point, 0x7, VlanTagPriorityCodePoint)?;
        max_check_u16(self.vlan_identifier, 0xfff, VlanTagVlanId)?;

        // serialize
        let id_be = self.vlan_identifier.to_be_bytes();
        let eth_type_be = self.ether_type.to_be_bytes();
        Ok([
            (if self.drop_eligible_indicator {
                id_be[0] | 0x10
            } else {
                id_be[0]
            } | (self.priority_code_point << 5)),
            id_be[1],
            eth_type_be[0],
            eth_type_be[1],
        ])
    }
}

#[cfg(test)]
mod test {
    use crate::{test_gens::*, *};
    use proptest::prelude::*;
    use std::io::{Cursor, ErrorKind};

    #[test]
    fn constants() {
        assert_eq!(4, SingleVlanHeader::LEN);
    }

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
                let (result, rest) = SingleVlanHeader::from_slice(&buffer).unwrap();
                assert_eq!(result, input);
                assert_eq!(rest, &buffer[4..]);
            }
            #[allow(deprecated)]
            {
                let (result, rest) = SingleVlanHeader::read_from_slice(&buffer).unwrap();
                assert_eq!(result, input);
                assert_eq!(rest, &buffer[4..]);
            }

            // slice length to small
            for len in 0..4 {
                assert_eq!(
                    SingleVlanHeader::from_slice(&buffer[..len])
                        .unwrap_err(),
                    err::SliceLenError{
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
        fn from_bytes(input in vlan_single_any()) {
            let actual = SingleVlanHeader::from_bytes(
                input.to_bytes().unwrap()
            );
            assert_eq!(actual, input);
        }
    }

    proptest! {
        #[test]
        fn read(
            input in vlan_single_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len() + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // normal
            {
                let mut cursor = Cursor::new(&buffer);
                let result = SingleVlanHeader::read(&mut cursor).unwrap();
                assert_eq!(result, input);
                assert_eq!(4, cursor.position());
            }

            // unexpexted eof
            for len in 0..4 {
                let mut cursor = Cursor::new(&buffer[0..len]);
                assert_eq!(
                    SingleVlanHeader::read(&mut cursor)
                    .unwrap_err()
                    .kind(),
                    ErrorKind::UnexpectedEof
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write_and_to_bytes(input in vlan_single_any()) {
            // normal write
            {
                let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len());
                input.write(&mut buffer).unwrap();
                assert_eq!(&buffer[..], &input.to_bytes().unwrap());
                {
                    let id_be = input.vlan_identifier.to_be_bytes();
                    let eth_type_be = input.ether_type.to_be_bytes();
                    assert_eq!(
                        input.to_bytes().unwrap(),
                        [
                            (
                                id_be[0] | if input.drop_eligible_indicator {
                                    0x10
                                } else {
                                    0
                                } | (input.priority_code_point << 5)
                            ),
                            id_be[1],
                            eth_type_be[0],
                            eth_type_be[1]
                        ]
                    );
                }
            }

            // priority_code_point: outside of range error
            {
                let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len());
                for i in 1..=0b0001_1111u8 {
                    let mut bad_input = input.clone();
                    bad_input.priority_code_point |= i << 3;
                    let expected = ValueError::U8TooLarge{
                        value: bad_input.priority_code_point,
                        max: 0b111,
                        field: ErrorField::VlanTagPriorityCodePoint
                    };
                    assert_eq!(
                        expected,
                        bad_input.write(&mut buffer)
                            .unwrap_err()
                            .value_error()
                            .unwrap()
                    );
                    assert_eq!(
                        expected,
                        bad_input.to_bytes()
                            .unwrap_err()
                    );
                }
            }

            // vlan_identifier: outside of range error
            {
                let mut buffer: Vec<u8> = Vec::with_capacity(input.header_len());
                for i in 1..=0b1111u16 {
                    let mut bad_input = input.clone();
                    bad_input.vlan_identifier |= i << 12;
                    let expected = ValueError::U16TooLarge{
                        value: bad_input.vlan_identifier,
                        max: 0b1111_1111_1111,
                        field: ErrorField::VlanTagVlanId
                    };
                    assert_eq!(
                        expected,
                        bad_input.write(&mut buffer)
                            .unwrap_err()
                            .value_error()
                            .unwrap()
                    );
                    assert_eq!(
                        expected,
                        bad_input.to_bytes()
                            .unwrap_err()
                    );
                }
            }

            // unexpected eof
            for len in 0..4 {
                let mut buffer = [0u8;4];
                let mut cursor = Cursor::new(&mut buffer[..len]);
                assert!(
                    input.write(&mut cursor)
                        .unwrap_err()
                        .io_error()
                        .is_some()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(input in vlan_single_any()) {
            assert_eq!(4, input.header_len());
        }
    }

    #[test]
    fn default() {
        let actual: SingleVlanHeader = Default::default();
        assert_eq!(0, actual.priority_code_point);
        assert_eq!(false, actual.drop_eligible_indicator);
        assert_eq!(0, actual.vlan_identifier);
        assert_eq!(0, actual.ether_type);
    }

    proptest! {
        #[test]
        fn clone_eq(input in vlan_single_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in vlan_single_any()) {
            assert_eq!(
                &format!(
                    "SingleVlanHeader {{ priority_code_point: {}, drop_eligible_indicator: {}, vlan_identifier: {}, ether_type: {} }}",
                    input.priority_code_point,
                    input.drop_eligible_indicator,
                    input.vlan_identifier,
                    input.ether_type,
                ),
                &format!("{:?}", input)
            );
        }
    }
}
