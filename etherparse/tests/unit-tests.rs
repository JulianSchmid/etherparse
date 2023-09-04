extern crate etherparse;
use etherparse::*;

pub use etherparse_proptest_generators::*;

mod packet_decoder;
mod transport;

#[test]
fn test_debug_write() {
    //slice
    {
        let input = Ethernet2Header {
            destination: [1, 2, 3, 4, 5, 6],
            source: [10, 11, 12, 13, 14, 15],
            ether_type: 0x0800.into(),
        };

        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        println!("{:?}", Ethernet2HeaderSlice::from_slice(&buffer));
    }
    //PacketHeaders
    {
        let dummy = vec![1, 2, 3, 4];
        let value = PacketHeaders {
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &dummy[..],
        };
        println!("{:?}", value);
    }
}
