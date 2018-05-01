use etherparse::*;

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
    buffer.write_vlan_tagging_header(&input).unwrap();
    assert_eq!(4, buffer.len());

    //deserialize
    let mut cursor = Cursor::new(&buffer);
    let result = cursor.read_vlan_tagging_header().unwrap();
    assert_eq!(4, cursor.position());

    //check equivalence
    assert_eq!(input, result);
}

#[test]
fn vlan_header_write() {
    use WriteError::ValueError;
    use ValueError::*;
    use ErrorField::*;
    fn base() -> SingleVlanHeader {
        SingleVlanHeader {
            ether_type: EtherType::Ipv4 as u16,
            priority_code_point: 2,
            drop_eligible_indicator: true,
            vlan_identifier: 1234,
        }
    };

    fn test_write(input: &SingleVlanHeader) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::new();
        let result = buffer.write_vlan_tagging_header(input);
        assert_eq!(0, buffer.len());
        result
    };

    //priority_code_point
    assert_matches!(test_write(&{
                        let mut value = base();
                        value.priority_code_point = 4;
                        value
                    }),
                    Err(ValueError(U8TooLarge{value: 4, max: 3, field: VlanTagPriorityCodePoint})));

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

        //write it
        let mut buffer = Vec::<u8>::new();
        IN.write(&mut buffer).unwrap();

        //read it
        use std::io::Cursor;
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(DoubleVlanHeader::read(&mut cursor), Ok(IN));
    }
    //check that an error is thrown if the 
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

        //read it
        use std::io::Cursor;
        let mut cursor = Cursor::new(&buffer);
        assert_matches!(DoubleVlanHeader::read(&mut cursor), 
                        Err(ReadError::VlanDoubleTaggingUnexpectedOuterTpid(1)));
    }
}
