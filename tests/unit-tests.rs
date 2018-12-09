extern crate etherparse;
use etherparse::*;

extern crate byteorder;

#[macro_use]
extern crate assert_matches;

#[macro_use]
extern crate proptest;

use std::io;

mod link;
mod internet;
mod transport;
mod packet_builder;
mod packet_filter;
mod proptest_generators;
pub use crate::proptest_generators::*;
mod packet_compositions;

#[test]
fn test_debug_write() {
    //slice
    {
        let input = Ethernet2Header{
            destination: [1,2,3,4,5,6],
            source: [10,11,12,13,14,15],
            ether_type: 0x0800
        };

        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        println!("{:?}", Ethernet2HeaderSlice::from_slice(&buffer));
    }
    //read error
    {
        use crate::ReadError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            VlanDoubleTaggingUnexpectedOuterTpid(0),
            IpUnsupportedVersion(0),
            Ipv4UnexpectedVersion(0),
            Ipv4HeaderLengthBad(0),
            Ipv6UnexpectedVersion(0),
            Ipv6TooManyHeaderExtensions,
            TcpDataOffsetTooSmall(0)
        ].iter() {
            println!("{:?}", value);
        }
    }
    //write error
    {
        use crate::ValueError::Ipv4OptionsLengthBad;
        use crate::WriteError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            ValueError(Ipv4OptionsLengthBad(0))
        ].iter() {
            println!("{:?}", value);
        }
    }
    //value error
    {
        use crate::ValueError::*;
        for value in [
            Ipv4OptionsLengthBad(0),
            Ipv4PayloadAndOptionsLengthTooLarge(0),
            Ipv6PayloadLengthTooLarge(0),
            UdpPayloadLengthTooLarge(0),
            U8TooLarge{value: 0, max: 0, field: ErrorField::Ipv4Ecn},
            U16TooLarge{value: 0, max: 0, field: ErrorField::Ipv4Ecn},
            U32TooLarge{value: 0, max: 0, field: ErrorField::Ipv4Ecn}
        ].iter() {
            println!("{:?}", value);
        }
    }
    //error field
    {
        use crate::ErrorField::*;
        for value in [
            Ipv4HeaderLength,
            Ipv4Dscp,
            Ipv4Ecn,
            Ipv4FragmentsOffset,
            Ipv6FlowLabel,
            VlanTagPriorityCodePoint,
            VlanTagVlanId,
            TcpDataOffset
        ].iter() {
            println!("{:?}", value);
        }
    }
    //PacketHeaders
    {
        let dummy = vec![1,2,3,4];
        let value = PacketHeaders{
            link: None,
            vlan: None,
            ip: None,
            transport: None,
            payload: &dummy[..]
        };
        println!("{:?}", value);
    }
}

#[test]
fn test_io_error_to_write_error() {
    assert_matches!(WriteError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
                    WriteError::IoError(_));
}

#[test]
fn test_io_error_to_read_error() {
    assert_matches!(ReadError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
                    ReadError::IoError(_));
}

