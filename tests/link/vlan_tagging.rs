use etherparse::*;

#[test]
fn read_write() {
    use std::io::Cursor;
    
    let input = VlanTaggingHeader {
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
fn write_errors() {
    use WriteError::ValueError;
    use ValueError::*;
    use ErrorField::*;
    fn base() -> VlanTaggingHeader {
        VlanTaggingHeader {
            ether_type: EtherType::Ipv4 as u16,
            priority_code_point: 2,
            drop_eligible_indicator: true,
            vlan_identifier: 1234,
        }
    };

    fn test_write(input: &VlanTaggingHeader) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::new();
        let result = buffer.write_vlan_tagging_header(input);
        assert_eq!(0, buffer.len());
        result
    };

    //priority_code_point
    match test_write(&{
        let mut value = base();
        value.priority_code_point = 4;
        value
    }) {
        Err(ValueError(U8TooLarge{value: 4, max: 3, field: VlanTagPriorityCodePoint})) => {}, //all good
        value => assert!(false, format!("Expected a range error but received {:?}", value))
    }

    //vlan_identifier
    match test_write(&{
        let mut value = base();
        value.vlan_identifier = 0x1000;
        value
    }) {
        Err(ValueError(U16TooLarge{value: 0x1000, max: 0xFFF, field: VlanTagVlanId})) => {}, //all good
        value => assert!(false, format!("Expected a range error but received {:?}", value))
    }
}
