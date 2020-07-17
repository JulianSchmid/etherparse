use super::super::*;

#[test]
fn traffic_class() {
    let dummy_data = [
        0,1,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0,
    ];
    let ext = Ipv6ExtensionHeader::read_from_slice(&dummy_data);
    let frag = Ipv6FragmentHeader::read_from_slice(&dummy_data);
    let auth = IpAuthenticationHeader::read_from_slice(&dummy_data);

    assert_eq!();

    // Q: instead of having an array, should I insert a bunch of optionals?
    // + queries are O(1)
    // - does allow "illegal" packets with mutliple authentification & fragmentation headers
    //      - are they illegal?
    // - header order not preserved

}