use super::super::*;

use std::io::{Cursor, ErrorKind};
use proptest::prelude::*;

mod vlan_header {
    use super::*;

    #[test]
    fn constants() {
        use ether_type::*;
        use VlanHeader as V;

        assert_eq!(3, V::VLAN_ETHER_TYPES.len());
        assert_eq!(VLAN_TAGGED_FRAME,        V::VLAN_ETHER_TYPES[0]);
        assert_eq!(PROVIDER_BRIDGING,        V::VLAN_ETHER_TYPES[1]);
        assert_eq!(VLAN_DOUBLE_TAGGED_FRAME, V::VLAN_ETHER_TYPES[2]);
    }

    proptest!{
        #[test]
        fn clone_eq(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single eq
            {
                let value = VlanHeader::Single(single.clone());
                assert_eq!(value, value.clone());
            }
            // double
            {
                let value = VlanHeader::Double(double);
                assert_eq!(value, value.clone());
            }
        }
    }

    proptest!{
        #[test]
        fn dbg(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let value = VlanHeader::Single(single.clone());
                assert_eq!(
                    &format!(
                        "Single({:?})",
                        single
                    ),
                    &format!("{:?}", value)
                );
            }
            // double
            {
                let value = VlanHeader::Double(double.clone());
                assert_eq!(
                    &format!(
                        "Double({:?})",
                        double
                    ),
                    &format!("{:?}", value)
                );
            }
        }
    }

    proptest!{
        #[test]
        fn header_len(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            assert_eq!(
                SingleVlanHeader::SERIALIZED_SIZE,
                VlanHeader::Single(single.clone()).header_len()
            );
            // double
            assert_eq!(
                DoubleVlanHeader::SERIALIZED_SIZE,
                VlanHeader::Double(double.clone()).header_len()
            );
        }
    }

    proptest!{
        #[test]
        fn write(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let expected = {
                    let mut buffer = Vec::with_capacity(single.header_len());
                    single.write(&mut buffer).unwrap();
                    buffer
                };
                let actual = {
                    let mut buffer = Vec::with_capacity(single.header_len());
                    VlanHeader::Single(single.clone()).write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(expected, actual);
            }

            // double
            {
                let expected = {
                    let mut buffer = Vec::with_capacity(double.header_len());
                    double.write(&mut buffer).unwrap();
                    buffer
                };
                let actual = {
                    let mut buffer = Vec::with_capacity(double.header_len());
                    VlanHeader::Double(double.clone()).write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(expected, actual);
            }
        }
    }
}

mod vlan_slice {
    use super::*;

    proptest!{
        #[test]
        fn to_header(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let raw = single.to_bytes().unwrap();
                let slice = VlanSlice::SingleVlan(
                    SingleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(
                    slice.to_header(),
                    VlanHeader::Single(single)
                );
            }

            // double
            {
                let raw = double.to_bytes().unwrap();
                let slice = VlanSlice::DoubleVlan(
                    DoubleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(
                    slice.to_header(),
                    VlanHeader::Double(double)
                );
            }
        }
    }

    proptest!{
        #[test]
        fn debug(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let raw = single.to_bytes().unwrap();
                let s = SingleVlanHeaderSlice::from_slice(&raw).unwrap();
                assert_eq!(
                    format!("{:?}", VlanSlice::SingleVlan(s.clone())),
                    format!("SingleVlan({:?})", s)
                );
            }

            // double
            {
                let raw = double.to_bytes().unwrap();
                let d = DoubleVlanHeaderSlice::from_slice(&raw).unwrap();
                assert_eq!(
                    format!("{:?}", VlanSlice::DoubleVlan(d.clone())),
                    format!("DoubleVlan({:?})", d)
                );
            }
        }
    }

    proptest!{
        #[test]
        fn clone_eq(
            single in vlan_single_any(),
            double in vlan_double_any(),
        ) {
            // single
            {
                let raw = single.to_bytes().unwrap();
                let s = VlanSlice::SingleVlan(
                    SingleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(s.clone(), s);
            }

            // double
            {
                let raw = double.to_bytes().unwrap();
                let d = VlanSlice::DoubleVlan(
                    DoubleVlanHeaderSlice::from_slice(&raw).unwrap()
                );
                assert_eq!(d.clone(), d);
            }
        }
    }
}

mod single_vlan_header {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(4, SingleVlanHeader::SERIALIZED_SIZE);
    }

    proptest!{
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
                    UnexpectedEndOfSliceError { expected_min_len: 4 }
                );
            }
        }
    }

    proptest!{
        #[test]
        fn from_bytes(input in vlan_single_any()) {
            let actual = SingleVlanHeader::from_bytes(
                input.to_bytes().unwrap()
            );
            assert_eq!(actual, input);
        }
    }

    proptest!{
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

    proptest!{
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
                let mut writer = TestWriter::with_max_size(len);
                assert_eq!(
                    ErrorKind::UnexpectedEof,
                    input.write(&mut writer)
                        .unwrap_err()
                        .io_error()
                        .unwrap()
                        .kind()
                );
            }
        }
    }

    proptest!{
        #[test]
        fn header_len(input in vlan_single_any()) {
            assert_eq!(4, input.header_len());
        }
    }

    #[test]
    fn default() {
        let actual : SingleVlanHeader = Default::default();
        assert_eq!(0, actual.priority_code_point);
        assert_eq!(false, actual.drop_eligible_indicator);
        assert_eq!(0, actual.vlan_identifier);
        assert_eq!(0, actual.ether_type);
    }

    proptest!{
        #[test]
        fn clone_eq(input in vlan_single_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest!{
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

mod double_vlan_header {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(8, DoubleVlanHeader::SERIALIZED_SIZE);
    }

    proptest!{
        #[test]
        fn from_slice(
            input in vlan_double_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20),
            ether_type_non_vlan in any::<u16>().prop_filter(
                "ether_type must not be a vlan ether type",
                |v| !VlanHeader::VLAN_ETHER_TYPES.iter().any(|&x| v == &x)
            )
        ) {
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
                        .unwrap_err()
                        .unexpected_end_of_slice_min_expected_size()
                        .unwrap(),
                    8
                );
            }

            // bad outer ether type
            {
                let mut bad_outer = input.clone();
                bad_outer.outer.ether_type = ether_type_non_vlan;
                let bytes = bad_outer.to_bytes().unwrap();
                assert_matches!(
                    DoubleVlanHeader::from_slice(&bytes)
                        .unwrap_err(),
                    ReadError::DoubleVlanOuterNonVlanEtherType(_)
                );
            }
        }
    }

    proptest!{
        #[test]
        fn read(
            input in vlan_double_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20),
            ether_type_non_vlan in any::<u16>().prop_filter(
                "ether_type must not be a vlan ether type",
                |v| !VlanHeader::VLAN_ETHER_TYPES.iter().any(|&x| v == &x)
            )
        ) {
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
                assert_matches!(
                    DoubleVlanHeader::read(&mut cursor)
                        .unwrap_err(),
                    ReadError::DoubleVlanOuterNonVlanEtherType(_)
                );
            }
        }
    }

    proptest!{
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

    proptest!{
        #[test]
        fn header_len(input in vlan_double_any()) {
            assert_eq!(8, input.header_len());
        }
    }

    #[test]
    fn default() {
        let actual : DoubleVlanHeader = Default::default();
        assert_eq!(
            actual.outer,
            {
                let mut outer : SingleVlanHeader = Default::default();
                outer.ether_type = ether_type::VLAN_TAGGED_FRAME;
                outer
            }
        );
        assert_eq!(actual.inner, Default::default());
    }

    proptest!{
        #[test]
        fn clone_eq(input in vlan_double_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest!{
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

mod single_vlan_header_slice {
    use super::*;

    proptest!{
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
                        .unwrap_err()
                        .expected_min_len,
                    4
                );
            }
        }
    }

    proptest!{
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

    proptest!{
        #[test]
        fn to_header(input in vlan_single_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = SingleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }

    proptest!{
        #[test]
        fn clone_eq(input in vlan_single_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = SingleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest!{
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

mod double_vlan_header_slice {
    use super::*;

    proptest!{
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
                            .unexpected_end_of_slice_min_expected_size()
                            .unwrap(),
                        8
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

    proptest!{
        #[test]
        fn getters(input in vlan_double_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = DoubleVlanHeaderSlice::from_slice(&bytes).unwrap();

            assert_eq!(input.outer, slice.outer().to_header());
            assert_eq!(input.inner, slice.inner().to_header());
        }
    }

    proptest!{
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

    proptest!{
        #[test]
        fn clone_eq(input in vlan_double_any()) {
            let bytes = input.to_bytes().unwrap();
            let slice = DoubleVlanHeaderSlice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest!{
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
