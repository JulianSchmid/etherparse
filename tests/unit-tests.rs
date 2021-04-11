extern crate etherparse;
use etherparse::*;

extern crate byteorder;

#[macro_use]
extern crate assert_matches;

extern crate proptest;

use std::io;

mod errors;
mod link;
mod internet;
mod transport;
mod packet_builder;
mod packet_filter;
mod packet_slicing;
mod proptest_generators;
pub use crate::proptest_generators::*;
use proptest::prelude::*;
mod packet_compositions;
mod test_writer;
use test_writer::*;
mod test_reader;
use test_reader::*;

#[test]
fn test_eq() {
    assert_eq!(ErrorField::Ipv4PayloadLength, ErrorField::Ipv4PayloadLength);
    assert_ne!(ErrorField::Ipv4PayloadLength, ErrorField::Ipv4Dscp);
}

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
            UnexpectedEndOfSlice(0),
            DoubleVlanOuterNonVlanEtherType(0),
            IpUnsupportedVersion(0),
            Ipv4UnexpectedVersion(0),
            Ipv4HeaderLengthBad(0),
            Ipv4TotalLengthTooSmall(0),
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
            ValueError(Ipv4OptionsLengthBad(0)),
            SliceTooSmall(0)
        ].iter() {
            println!("{:?}", value);
        }
    }
    //value error
    {
        use crate::ValueError::*;
        for value in [
            Ipv4OptionsLengthBad(0),
            Ipv4PayloadLengthTooLarge(0),
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
            Ipv4PayloadLength,
            Ipv4Dscp,
            Ipv4Ecn,
            Ipv4FragmentsOffset,
            Ipv6FlowLabel,
            VlanTagPriorityCodePoint,
            VlanTagVlanId
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
            /*ip_extensions: [
                None, None, None, None, None,
                None, None, None, None, None,
                None, None
            ],*/
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

mod read_error {

    #[test]
    fn add_slice_offset() {
        use super::*;
        assert_matches!(
            ReadError::UnexpectedEndOfSlice(2).add_slice_offset(3),
            ReadError::UnexpectedEndOfSlice(5)
        );
        assert_matches!(
            ReadError::DoubleVlanOuterNonVlanEtherType(2).add_slice_offset(3),
            ReadError::DoubleVlanOuterNonVlanEtherType(2)
        );
    }

    #[test]
    fn io_error() {
        use super::*;
        assert_eq!(
            std::io::ErrorKind::Other,
            ReadError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
            .io_error().unwrap().kind()
        );
        assert!(
            ReadError::UnexpectedEndOfSlice(0)
            .io_error().is_none()
        );
    }

    #[test]
    fn unexpected_end_of_slice_min_expected_size() {
        use super::*;
        assert!(
            ReadError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
            .unexpected_end_of_slice_min_expected_size().is_none()
        );
        assert_eq!(
            123,
            ReadError::UnexpectedEndOfSlice(123)
            .unexpected_end_of_slice_min_expected_size().unwrap()
        );
    }
}

mod write_error {
    #[test]
    fn io_error() {
        use super::*;
        assert_eq!(
            std::io::ErrorKind::Other,
            WriteError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
            .io_error().unwrap().kind()
        );
        assert!(
            WriteError::ValueError(ValueError::TcpLengthTooLarge(0))
            .io_error().is_none()
        );
    }

    #[test]
    fn value_error() {
        use super::*;
        assert!(
            WriteError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
            .value_error().is_none()
        );
        assert_eq!(
            Some(ValueError::TcpLengthTooLarge(0)),
            WriteError::ValueError(ValueError::TcpLengthTooLarge(0))
            .value_error()
        );
    }
}
