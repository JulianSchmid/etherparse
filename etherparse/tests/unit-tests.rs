extern crate etherparse;
use etherparse::*;

pub use etherparse_proptest_generators::*;

mod internet;
mod packet_builder;
mod packet_decoder;
mod packet_filter;
mod packet_slicing;
mod transport;
use proptest::prelude::*;
mod packet_compositions;
mod test_writer;
use test_writer::*;

#[test]
fn test_eq() {
    assert_eq!(
        err::ValueType::Ipv4PayloadLength,
        err::ValueType::Ipv4PayloadLength
    );
    assert_ne!(err::ValueType::Ipv4PayloadLength, err::ValueType::Ipv4Dscp);
}

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
