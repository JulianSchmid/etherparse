use etherparse::*;

#[test]
fn ether_type_convert() {
    use EtherType::*;

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
fn read_write() {
    use std::io::Cursor;
    
    let input = Ethernet2Header{
        destination: [1,2,3,4,5,6],
        source: [10,11,12,13,14,15],
        ether_type: 0x0800
    };

    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(14);
    input.write(&mut buffer).unwrap();
    assert_eq!(14, buffer.len());

    //deserialize
    let result = Ethernet2Header::read(&mut Cursor::new(&buffer)).unwrap();
    
    //check equivalence
    assert_eq!(input, result);

    
}

#[test]
fn from_slice() {
    let input = Ethernet2Header{
        destination: [1,2,3,4,5,6],
        source: [10,11,12,13,14,15],
        ether_type: 0x0800
    };

    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(14);
    input.write(&mut buffer).unwrap();
    assert_eq!(14, buffer.len());

    //check that a too small slice results in an error
    use ReadError::*;
    assert_matches!(Slice::<Ethernet2Header>::from_slice(&buffer[..13]), Err(IoError(_)));

    //check if the header slice is reading the correct values
    let slice = Slice::<Ethernet2Header>::from_slice(&buffer).unwrap();
    assert_eq!(input.destination, slice.destination());
    assert_eq!(input.source, slice.source());
    assert_eq!(input.ether_type, slice.ether_type());
}