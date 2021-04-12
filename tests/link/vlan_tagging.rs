use super::super::*;

use std::io::Cursor;
use proptest::prelude::*;

#[test]
fn vlan_ether_types() {
    use ether_type::*;
    use crate::VlanHeader as V;
    assert_eq!(3, V::VLAN_ETHER_TYPES.len());
    assert_eq!(VLAN_TAGGED_FRAME,        V::VLAN_ETHER_TYPES[0]);
    assert_eq!(PROVIDER_BRIDGING,        V::VLAN_ETHER_TYPES[1]);
    assert_eq!(VLAN_DOUBLE_TAGGED_FRAME, V::VLAN_ETHER_TYPES[2]);
}

proptest!{
    #[test]
    fn single_vlan_read(ref header in vlan_single_any()) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(SingleVlanHeader::SERIALIZED_SIZE);
        header.write(&mut buffer).unwrap();
        assert_eq!(4, buffer.len());

        //deserialize with read
        {
            let mut cursor = Cursor::new(&buffer);
            let result = SingleVlanHeader::read(&mut cursor).unwrap();
            assert_eq!(4, cursor.position());

            //check equivalence
            assert_eq!(header, &result);
        }

        //deserialize with read_from_slice
        {
            let result = SingleVlanHeader::read_from_slice(&buffer[..]).unwrap();

            //check equivalence
            assert_eq!(header, &result.0);
            assert_eq!(&buffer[SingleVlanHeader::SERIALIZED_SIZE..], result.1);
        }

        // slice version from_slice
        {
            let slice = SingleVlanHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(slice.clone(), slice);
            assert_eq!(slice.slice(), &buffer[..]);
            assert_eq!(slice.priority_code_point(), header.priority_code_point);
            assert_eq!(slice.drop_eligible_indicator(), header.drop_eligible_indicator);
            assert_eq!(slice.vlan_identifier(), header.vlan_identifier);
            assert_eq!(slice.ether_type(), header.ether_type);

            //check that the to_header results in the same as the input
            assert_eq!(&slice.to_header(), header);
        }
    }
}

#[test]
fn single_vlan_read_and_write_length_error() {

    use ReadError::*;

    let header = SingleVlanHeader {
        ether_type: EtherType::Ipv4 as u16,
        priority_code_point: 2,
        drop_eligible_indicator: true,
        vlan_identifier: 1234,
    };

    // error if a complete write is not possible
    for len in 0..SingleVlanHeader::SERIALIZED_SIZE {
        let mut writer = TestWriter::with_max_size(len);
        assert_eq!(
            writer.error_kind(),
            header.write(&mut writer).unwrap_err().io_error().unwrap().kind()
        );
    }

    // error check for unexpected eof
    let buffer = {
        let mut buffer = Vec::with_capacity(SingleVlanHeader::SERIALIZED_SIZE);
        header.write(&mut buffer).unwrap();
        buffer
    };
    for len in 0..SingleVlanHeader::SERIALIZED_SIZE {
        // read
        assert_matches!(
            SingleVlanHeader::read(&mut Cursor::new(&buffer[..len])),
            Err(_)
        );
        
        // read_from_slice
        assert_matches!(
            SingleVlanHeader::read_from_slice(&buffer[..len]),
            Err(UnexpectedEndOfSlice(SingleVlanHeader::SERIALIZED_SIZE))
        );

        // from_slice
        assert_matches!(
            SingleVlanHeaderSlice::from_slice(&buffer[..len]), 
            Err(UnexpectedEndOfSlice(SingleVlanHeader::SERIALIZED_SIZE))
        );
    }
}

#[test]
fn single_vlan_write() {
    use crate::WriteError::ValueError;
    use crate::ValueError::*;
    use crate::ErrorField::*;
    fn base() -> SingleVlanHeader {
        SingleVlanHeader {
            ether_type: EtherType::Ipv4 as u16,
            priority_code_point: 2,
            drop_eligible_indicator: true,
            vlan_identifier: 1234,
        }
    }

    fn test_write(input: &SingleVlanHeader) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::new();
        let result = input.write(&mut buffer);
        assert_eq!(0, buffer.len());
        result
    }

    //priority_code_point
    assert_matches!(test_write(&{
                        let mut value = base();
                        value.priority_code_point = 8;
                        value
                    }),
                    Err(ValueError(U8TooLarge{value: 8, max: 7, field: VlanTagPriorityCodePoint})));

    //vlan_identifier
    assert_matches!(test_write(&{
                        let mut value = base();
                        value.vlan_identifier = 0x1000;
                        value
                    }),
                    Err(ValueError(U16TooLarge{value: 0x1000, max: 0xFFF, field: VlanTagVlanId})));
}

proptest!{
    #[test]
    fn double_vlan_header_read_write(
        ref outer_base in vlan_single_any(),
        ref inner in vlan_single_any()
    ) {

        for outer_ether_type in &VlanHeader::VLAN_ETHER_TYPES {

            let header = DoubleVlanHeader {
                outer: {
                    let mut outer = outer_base.clone();
                    outer.ether_type = *outer_ether_type;
                    outer
                },
                inner: inner.clone()
            };
            let buffer = {
                let mut buffer = Vec::<u8>::with_capacity(DoubleVlanHeader::SERIALIZED_SIZE);
                header.write(&mut buffer).unwrap();
                buffer
            };
            
            //read
            assert_eq!(
                header,
                DoubleVlanHeader::read(&mut Cursor::new(&buffer)).unwrap(),
            );
        
            //read_from_slice
            {
                let result = DoubleVlanHeader::read_from_slice(&buffer).unwrap();
                assert_eq!(result.0, header);
                assert_eq!(result.1, &buffer[buffer.len()..]);
            }

            //from_slice
            {
                let slice = DoubleVlanHeaderSlice::from_slice(&buffer).unwrap();

                assert_eq!(slice.clone(), slice);

                assert_eq!(slice.slice(), &buffer[..]);

                assert_eq!(slice.outer().slice(), &buffer[..SingleVlanHeader::SERIALIZED_SIZE]);
                assert_eq!(slice.outer().priority_code_point(), header.outer.priority_code_point);
                assert_eq!(slice.outer().drop_eligible_indicator(), header.outer.drop_eligible_indicator);
                assert_eq!(slice.outer().vlan_identifier(), header.outer.vlan_identifier);
                assert_eq!(slice.outer().ether_type(), header.outer.ether_type);

                assert_eq!(slice.inner().slice(), &buffer[SingleVlanHeader::SERIALIZED_SIZE..SingleVlanHeader::SERIALIZED_SIZE*2]);
                assert_eq!(slice.inner().priority_code_point(), header.inner.priority_code_point);
                assert_eq!(slice.inner().drop_eligible_indicator(), header.inner.drop_eligible_indicator);
                assert_eq!(slice.inner().vlan_identifier(), header.inner.vlan_identifier);
                assert_eq!(slice.inner().ether_type(), header.inner.ether_type);

                //check that the to_header results in the same as the input
                assert_eq!(slice.to_header(), header);
            }
        }
    }
}

#[test]
fn double_vlan_header_read_and_write_length_error() {
    use crate::ether_type::*;
    use ReadError::*;

    for ether_type in &VlanHeader::VLAN_ETHER_TYPES {
        let header = DoubleVlanHeader {
            outer: SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0,
                ether_type: *ether_type
            },
            inner: SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0,
                ether_type: IPV4
            }
        };

        // check that an error is triggered if not enough memory for the write
        // is availible
        for len in 0..DoubleVlanHeader::SERIALIZED_SIZE {
            let mut writer = TestWriter::with_max_size(len);
            assert_eq!(
                writer.error_kind(),
                header.write(&mut writer).unwrap_err().io_error().unwrap().kind()
            );
        }

        // check that a length error is written for every too small length
        let buffer = {
            let mut buffer = Vec::<u8>::with_capacity(DoubleVlanHeader::SERIALIZED_SIZE);
            header.write(&mut buffer).unwrap();
            buffer
        };
        for len in 0..DoubleVlanHeader::SERIALIZED_SIZE {
            // read
            assert_matches!(
                DoubleVlanHeader::read(&mut Cursor::new(&buffer[..len])),
                Err(IoError(_))
            );

            // read_from_slice
            assert_matches!(
                DoubleVlanHeader::read_from_slice(&buffer[..len]),
                Err(UnexpectedEndOfSlice(DoubleVlanHeader::SERIALIZED_SIZE))
            );

            // from_slice
            assert_matches!(
                DoubleVlanHeaderSlice::from_slice(&buffer[..len]),
                Err(UnexpectedEndOfSlice(DoubleVlanHeader::SERIALIZED_SIZE))
            );
        }
    }
}

proptest!{
    #[test]
    fn double_vlan_header_read_error_ether_type(
        ref outer_base in vlan_single_any(),
        ref inner in vlan_single_any()
    ) {
        use crate::ether_type::*;
        use ReadError::*;

        let header = DoubleVlanHeader {
            outer: {
                let mut outer = outer_base.clone();
                outer.ether_type = IPV4; // some ethertype not associated with a vlan header
                outer
            },
            inner: inner.clone()
        };
        let buffer = {
            let mut buffer = Vec::<u8>::with_capacity(DoubleVlanHeader::SERIALIZED_SIZE);
            header.write(&mut buffer).unwrap();
            buffer
        };

        // read
        assert_matches!(
            DoubleVlanHeader::read(&mut Cursor::new(&buffer)), 
            Err(DoubleVlanOuterNonVlanEtherType(IPV4))
        );

        // read_from_slice
        assert_matches!(
            DoubleVlanHeader::read_from_slice(&buffer),
            Err(DoubleVlanOuterNonVlanEtherType(IPV4))
        );

        // from_slice
        assert_matches!(
            DoubleVlanHeaderSlice::from_slice(&buffer), 
            Err(DoubleVlanOuterNonVlanEtherType(IPV4))
        );
    }
}

#[test]
fn default() {
    let v: DoubleVlanHeader = Default::default();
    assert_eq!(v.outer.priority_code_point, 0);
    assert_eq!(v.outer.drop_eligible_indicator, false);
    assert_eq!(v.outer.vlan_identifier, 0);
    assert_eq!(v.outer.ether_type, ether_type::VLAN_TAGGED_FRAME);

    assert_eq!(v.inner.priority_code_point, 0);
    assert_eq!(v.inner.drop_eligible_indicator, false);
    assert_eq!(v.inner.vlan_identifier, 0);
    assert_eq!(v.inner.ether_type, 0);
}

#[test]
fn dbg_eq_clone() {
    // double header & single header
    let double = DoubleVlanHeader{
        outer: SingleVlanHeader{
            priority_code_point: 0,
            drop_eligible_indicator: false,
            vlan_identifier: 0x123,
            ether_type: ether_type::VLAN_TAGGED_FRAME
        },
        inner: SingleVlanHeader{
            priority_code_point: 0,
            drop_eligible_indicator: false,
            vlan_identifier: 0x123,
            ether_type: 0x12
        }
    };
    assert_eq!(double.outer, double.outer.clone());
    println!("{:?}", double.outer);

    assert_eq!(double, double.clone());
    println!("{:?}", double);

    // vlan header
    use crate::VlanHeader::*;
    {
        let s = Single(double.inner.clone());
        assert_eq!(s, s.clone());
        println!("{:?}", s);
    }
    {
        let d = Double(double.clone());
        assert_eq!(d, d.clone());
        println!("{:?}", d.clone());
    }

    //slice
    {
        let mut buffer = Vec::<u8>::with_capacity(DoubleVlanHeader::SERIALIZED_SIZE);
        double.write(&mut buffer).unwrap();
        let slice = DoubleVlanHeaderSlice::from_slice(&buffer).unwrap();

        assert_eq!(slice.inner(), slice.inner().clone());
        println!("{:?}", slice.inner().clone());

        assert_eq!(slice, slice.clone());
        println!("{:?}", slice.clone());
    }
}
