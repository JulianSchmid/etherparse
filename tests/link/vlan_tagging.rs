use etherparse::*;

#[test]
fn vlan_print() {
    use crate::VlanHeader::*;
    println!("{:?}", 
         Single(SingleVlanHeader{
            priority_code_point: 0,
            drop_eligible_indicator: false,
            vlan_identifier: 0x123,
            ether_type: 0x12
        }));
    println!("{:?}",
        Double(DoubleVlanHeader{
            outer: SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0x123,
                ether_type: 0x12
            },
            inner: SingleVlanHeader{
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0x123,
                ether_type: 0x12
            }
    }));
}

#[test]
fn vlan_header_read() {
    use std::io::Cursor;
    
    let input = SingleVlanHeader {
        ether_type: EtherType::Ipv4 as u16,
        priority_code_point: 2,
        drop_eligible_indicator: true,
        vlan_identifier: 1234,
    };

    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(4);
    input.write(&mut buffer).unwrap();
    assert_eq!(4, buffer.len());

    //deserialize with read
    {
        let mut cursor = Cursor::new(&buffer);
        let result = SingleVlanHeader::read(&mut cursor).unwrap();
        assert_eq!(4, cursor.position());

        //check equivalence
        assert_eq!(input, result);
    }

    //deserialize with read_from_slice
    {
        let result = SingleVlanHeader::read_from_slice(&buffer[..]).unwrap();

        //check equivalence
        assert_eq!(input, result.0);
        assert_eq!(&buffer[SingleVlanHeader::SERIALIZED_SIZE..], result.1);
    }

    //eof with read_from_slice
    assert_matches!(
        SingleVlanHeader::read_from_slice(&buffer[..(buffer.len() - 1)]),
        Err(ReadError::UnexpectedEndOfSlice(SingleVlanHeader::SERIALIZED_SIZE))
    );
}

#[test]
fn vlan_header_write() {
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

#[test]
fn double_vlan_header_read_write() {
    //normal package
    {
        const IN: DoubleVlanHeader = DoubleVlanHeader {
            outer: SingleVlanHeader {
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0x321,
                ether_type: EtherType::VlanTaggedFrame as u16
            },
            inner: SingleVlanHeader {
                priority_code_point: 1,
                drop_eligible_indicator: false,
                vlan_identifier: 0x456,
                ether_type: EtherType::Ipv4 as u16
            }
        };

        //write
        let mut buffer = Vec::<u8>::new();
        IN.write(&mut buffer).unwrap();

        //read
        {
            use std::io::Cursor;
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(DoubleVlanHeader::read(&mut cursor).unwrap(), IN);
        }
        //read_from_slice
        {
            let result = DoubleVlanHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(result.0, IN);
            assert_eq!(result.1, &buffer[buffer.len()..]);
        }

        //read_from_slice unexpected eos
        assert_matches!(
            DoubleVlanHeader::read_from_slice(&buffer[..(buffer.len() - 1)]),
            Err(ReadError::UnexpectedEndOfSlice(DoubleVlanHeader::SERIALIZED_SIZE))
        );
        
    }
    //check that an error is thrown if the outer header contains an invalid id
    {
        const IN: DoubleVlanHeader = DoubleVlanHeader {
            outer: SingleVlanHeader {
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0x321,
                ether_type: 1 //invalid
            },
            inner: SingleVlanHeader {
                priority_code_point: 1,
                drop_eligible_indicator: false,
                vlan_identifier: 0x456,
                ether_type: EtherType::Ipv4 as u16
            }
        };

        //write it
        let mut buffer = Vec::<u8>::new();
        IN.write(&mut buffer).unwrap();

        //read 
        {
            use std::io::Cursor;
            let mut cursor = Cursor::new(&buffer);
            assert_matches!(DoubleVlanHeader::read(&mut cursor), 
                            Err(ReadError::VlanDoubleTaggingUnexpectedOuterTpid(1)));
        }

        //read_from_slice
        {
            assert_matches!(
                DoubleVlanHeader::read_from_slice(&buffer),
                Err(ReadError::VlanDoubleTaggingUnexpectedOuterTpid(1))
            );
        }

        //DoubleVlanHeaderSlice::from_slice
        {
            assert_matches!(
                DoubleVlanHeaderSlice::from_slice(&buffer), 
                Err(ReadError::VlanDoubleTaggingUnexpectedOuterTpid(1))
            );
        }
    }
}

#[test]
fn single_from_slice() {
    let input = SingleVlanHeader {
        ether_type: EtherType::Ipv4 as u16,
        priority_code_point: 2,
        drop_eligible_indicator: true,
        vlan_identifier: 1234,
    };

    //write it
    let mut buffer = Vec::<u8>::new();
    input.write(&mut buffer).unwrap();

    //check that a too small slice results in an error
    use self::ReadError::UnexpectedEndOfSlice;
    assert_matches!(
        SingleVlanHeaderSlice::from_slice(&buffer[..3]), 
        Err(UnexpectedEndOfSlice(SingleVlanHeader::SERIALIZED_SIZE))
    );

    //check that all fields are read correctly
    let slice = SingleVlanHeaderSlice::from_slice(&buffer).unwrap();
    assert_eq!(slice.clone(), slice);
    assert_eq!(slice.slice(), &buffer[..]);
    assert_eq!(slice.priority_code_point(), input.priority_code_point);
    assert_eq!(slice.drop_eligible_indicator(), input.drop_eligible_indicator);
    assert_eq!(slice.vlan_identifier(), input.vlan_identifier);
    assert_eq!(slice.ether_type(), input.ether_type);

    //check that the to_header results in the same as the input
    assert_eq!(slice.to_header(), input);
}

#[test]
fn double_from_slice() {
    let input = DoubleVlanHeader {
        outer: SingleVlanHeader {
            ether_type: EtherType::VlanTaggedFrame as u16,
            priority_code_point: 2,
            drop_eligible_indicator: true,
            vlan_identifier: 1234,
        },
        inner: SingleVlanHeader {
            ether_type: EtherType::Ipv6 as u16,
            priority_code_point: 7,
            drop_eligible_indicator: false,
            vlan_identifier: 4095,
        }
    };

    //write it
    let mut buffer = Vec::<u8>::new();
    input.write(&mut buffer).unwrap();

    //check that a too small slice results in an error
    use self::ReadError::UnexpectedEndOfSlice;
    assert_matches!(
        DoubleVlanHeaderSlice::from_slice(&buffer[..7]),
        Err(UnexpectedEndOfSlice(DoubleVlanHeader::SERIALIZED_SIZE))
    );

    let slice = DoubleVlanHeaderSlice::from_slice(&buffer).unwrap();

    assert_eq!(slice.clone(), slice);

    assert_eq!(slice.slice(), &buffer[..]);

    assert_eq!(slice.outer().slice(), &buffer[..SingleVlanHeader::SERIALIZED_SIZE]);
    assert_eq!(slice.outer().priority_code_point(), input.outer.priority_code_point);
    assert_eq!(slice.outer().drop_eligible_indicator(), input.outer.drop_eligible_indicator);
    assert_eq!(slice.outer().vlan_identifier(), input.outer.vlan_identifier);
    assert_eq!(slice.outer().ether_type(), input.outer.ether_type);

    assert_eq!(slice.inner().slice(), &buffer[SingleVlanHeader::SERIALIZED_SIZE..SingleVlanHeader::SERIALIZED_SIZE*2]);
    assert_eq!(slice.inner().priority_code_point(), input.inner.priority_code_point);
    assert_eq!(slice.inner().drop_eligible_indicator(), input.inner.drop_eligible_indicator);
    assert_eq!(slice.inner().vlan_identifier(), input.inner.vlan_identifier);
    assert_eq!(slice.inner().ether_type(), input.inner.ether_type);

    //check that the to_header results in the same as the input
    assert_eq!(slice.to_header(), input);
}
