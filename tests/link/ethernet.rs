use super::super::*;

#[test]
fn ether_type_convert() {
    use crate::EtherType::*;

    assert_eq!(0x0800, Ipv4 as u16);
    assert_eq!(0x86dd, Ipv6 as u16);
    assert_eq!(0x0806, Arp as u16);
    assert_eq!(0x0842, WakeOnLan as u16);
    assert_eq!(0x8100, VlanTaggedFrame as u16);
    assert_eq!(0x88A8, ProviderBridging as u16);
    assert_eq!(0x9100, VlanDoubleTaggedFrame as u16);

    assert_eq!(EtherType::from_u16(0x0800), Some(Ipv4));
    assert_eq!(EtherType::from_u16(0x86dd), Some(Ipv6));
    assert_eq!(EtherType::from_u16(0x0806), Some(Arp));
    assert_eq!(EtherType::from_u16(0x0842), Some(WakeOnLan));
    assert_eq!(EtherType::from_u16(0x8100), Some(VlanTaggedFrame));
    assert_eq!(EtherType::from_u16(0x88A8), Some(ProviderBridging));
    assert_eq!(EtherType::from_u16(0x9100), Some(VlanDoubleTaggedFrame));
    assert_eq!(EtherType::from_u16(0x1234), None);
}

#[test]
fn ether_type_u16_constants() {
    use crate::EtherType::*;
    use crate::ether_type::*;
    let pairs = &[
        (Ipv4, IPV4),
        (Ipv6, IPV6),
        (Arp, ARP),
        (WakeOnLan, WAKE_ON_LAN),
        (VlanTaggedFrame, VLAN_TAGGED_FRAME),
        (ProviderBridging, PROVIDER_BRIDGING),
        (VlanDoubleTaggedFrame, VLAN_DOUBLE_TAGGED_FRAME)
    ];

    for (enum_value, constant) in pairs {
        assert_eq!(enum_value.clone() as u16, *constant);
    }
}

proptest! {
    #[test]
    fn read_write(ref input in ethernet_2_any()) {
        use std::io::Cursor;
        
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        assert_eq!(14, buffer.len());

        //read
        {
            //deserialize
            let result = Ethernet2Header::read(&mut Cursor::new(&buffer)).unwrap();
        
            //check equivalence
            assert_eq!(input, &result);
        }

        //read_from_slice
        {
            //deserialize
            let result = Ethernet2Header::read_from_slice(&buffer[..]).unwrap();
        
            //check equivalence
            assert_eq!(input, &result.0);
            assert_eq!(&buffer[Ethernet2Header::SERIALIZED_SIZE..], result.1);
        }

        //read_from_slice (eos error)
        {
            assert_matches!(
                Ethernet2Header::read_from_slice(&buffer[..(buffer.len()-1)]),
                Err(ReadError::UnexpectedEndOfSlice(Ethernet2Header::SERIALIZED_SIZE))
            );
        }
    }
}

/// Test to check that errors during write are correctly forwarded
#[test]
fn write_io_error() {
    let header = Ethernet2Header{
        source: [1,2,3,4,5,6],
        destination: [7,8,9,10,11,12],
        ether_type: ether_type::IPV4,
    };

    // iterate through all to small sizes to ensure all parts
    // forward the errors
    for len in 0..Ethernet2Header::SERIALIZED_SIZE {
        let mut writer = TestWriter::with_max_size(len);
        assert_eq!(
            writer.error_kind(),
            header.write(&mut writer).unwrap_err().kind()
        );
    }
}

/// Test to check that errors during read are correctly forwarded
#[test]
fn read_io_error() {
    let buffer = {
        let mut buffer: [u8;Ethernet2Header::SERIALIZED_SIZE] = [
            0;Ethernet2Header::SERIALIZED_SIZE
        ];
        Ethernet2Header{
            source: [1,2,3,4,5,6],
            destination: [7,8,9,10,11,12],
            ether_type: ether_type::IPV4,
        }.write_to_slice(&mut buffer).unwrap();
        buffer
    };

    // iterate through all to small sizes to ensure all parts
    // forward the errors
    for len in 0..Ethernet2Header::SERIALIZED_SIZE {
        use std::io::Cursor;
        assert_eq!(
            true,
            Ethernet2Header::read(
                &mut Cursor::new(&buffer[..len])
            ).is_err()
        );
    }
}

proptest! {
    #[test]
    fn write_to_slice(ref input in ethernet_2_any()) {
        use self::WriteError::*;

        //error check
        assert_matches!(
            input.write_to_slice(&mut [0; Ethernet2Header::SERIALIZED_SIZE - 1]),
            Err(SliceTooSmall(Ethernet2Header::SERIALIZED_SIZE))
        );

        //write & read
        let mut buffer: [u8; Ethernet2Header::SERIALIZED_SIZE + 2] = Default::default();
        let result = input.write_to_slice(&mut buffer).unwrap();
        
        assert_eq!(result.len(), 2);
        assert_eq!(
            input,
            &Ethernet2Header::read_from_slice(&buffer).unwrap().0
        );
    }
}

proptest! {
    #[test]
    fn from_slice(ref input in ethernet_2_any()) {

        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        assert_eq!(14, buffer.len());

        //check that a too small slice results in an error
        use crate::ReadError::*;
        assert_matches!(
            Ethernet2HeaderSlice::from_slice(&buffer[..13]), 
            Err(UnexpectedEndOfSlice(Ethernet2Header::SERIALIZED_SIZE))
        );

        //check if the header slice is reading the correct values
        let slice = Ethernet2HeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(input.destination, slice.destination());
        assert_eq!(input.source, slice.source());
        assert_eq!(input.ether_type, slice.ether_type());

        //check that the to header method also returns the original struct
        assert_eq!(input, &slice.to_header());
        assert_eq!(&buffer[..], slice.slice());

        //clone check
        assert_eq!(slice, slice.clone());
    }
}

proptest! {
    #[test]
    fn dbg(ref input in ethernet_2_any()) {
        println!("{:?}", input);
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        let slice = Ethernet2HeaderSlice::from_slice(&buffer).unwrap();
        println!("{:?}", slice);
    }
}