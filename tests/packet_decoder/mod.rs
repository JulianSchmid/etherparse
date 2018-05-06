use etherparse::*;

#[test]
fn ipv4_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let headers = PacketHeaders::decode(&mut buffer).unwrap();

    assert_matches!(headers.ethernet, Some(_));
    assert_matches!(headers.vlan, None);
    assert_matches!(headers.ip, Some(IpHeader::Version4(_)));
    assert_matches!(headers.transport, Some(_));
    assert_eq!(headers.rest.len(), 4);
}

#[test]
fn ipv6_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv6([0;16], [1;16], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let headers = PacketHeaders::decode(&mut buffer).unwrap();

    assert_matches!(headers.ethernet, Some(_));
    assert_matches!(headers.vlan, None);
    assert_matches!(headers.ip, Some(IpHeader::Version6(_)));
    assert_matches!(headers.transport, Some(_));
    assert_eq!(headers.rest.len(), 4);//&buffer[buffer.len()-4..]);
}

#[test]
fn ipv4_single_vlan_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .single_vlan(12)
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let headers = PacketHeaders::decode(&mut buffer).unwrap();

    assert_matches!(headers.ethernet, Some(_));
    assert_matches!(headers.vlan, Some(VlanHeader::Single(_)));
    assert_matches!(headers.ip, Some(IpHeader::Version4(_)));
    assert_matches!(headers.transport, Some(_));
    assert_eq!(headers.rest.len(), 4);
}

#[test]
fn ipv4_double_vlan_udp() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .double_vlan(12, 13)
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    let headers = PacketHeaders::decode(&mut buffer).unwrap();

    assert_matches!(headers.ethernet, Some(_));
    assert_matches!(headers.vlan, Some(VlanHeader::Double(_)));
    assert_matches!(headers.ip, Some(IpHeader::Version4(_)));
    assert_matches!(headers.transport, Some(_));
    assert_eq!(headers.rest.len(), 4);
}

#[test]
fn ipv4_unknown() {
    let mut buffer = Vec::new();
    PacketBuilder::ethernet2([0;6], [0;6])
                  .ipv4([1,2,3,4], [5,6,7,8], 1)
                  .udp(1,2)
                  .write(&mut buffer, &[4,3,2,1]).unwrap();

    //change protocol type to something that is not known
    let protocol_index = buffer.len() 
                         - 4 //payload
                         - UdpHeader::SERIALIZED_SIZE // udp header
                         - Ipv4Header::SERIALIZED_SIZE // ipv4 header
                         + 9; //offset to protocol field

    buffer[protocol_index] = 122; //Simple Multicast Protocol (deprecated)

    let headers = PacketHeaders::decode(&mut buffer).unwrap();

    assert_matches!(headers.ethernet, Some(_));
    assert_matches!(headers.vlan, None);
    assert_matches!(headers.ip, Some(IpHeader::Version4(_)));
    assert_matches!(headers.transport, None);
    assert_eq!(headers.rest.len(), 4 + UdpHeader::SERIALIZED_SIZE);
}