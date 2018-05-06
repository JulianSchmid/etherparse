extern crate etherparse;
use etherparse::*;

#[cfg(test)] #[macro_use]
extern crate assert_matches;

use std::io;

mod link;
mod internet;
mod transport;
mod packet_builder;
mod packet_decoder;

#[test]
fn test_debug_write() {
    //read error
    {
        use ReadError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            VlanDoubleTaggingUnexpectedOuterTpid(0),
            IpUnsupportedVersion(0),
            Ipv4UnexpectedVersion(0),
            Ipv6UnexpectedVersion(0),
            Ipv6TooManyHeaderExtensions
        ].iter() {
            println!("{:?}", value);
        }
    }
    //write error
    {
        use ValueError::Ipv4OptionsLengthBad;
        use WriteError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            ValueError(Ipv4OptionsLengthBad(0))
        ].iter() {
            println!("{:?}", value);
        }
    }
    //value error
    {
        use ValueError::*;
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
        use ErrorField::*;
        for value in [
            Ipv4HeaderLength,
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