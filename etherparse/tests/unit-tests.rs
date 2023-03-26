extern crate etherparse;
use etherparse::*;

use assert_matches::assert_matches;

pub use etherparse_proptest_generators::*;

mod checksum;
mod errors;
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
    assert_eq!(ErrorField::Ipv4PayloadLength, ErrorField::Ipv4PayloadLength);
    assert_ne!(ErrorField::Ipv4PayloadLength, ErrorField::Ipv4Dscp);
}

#[test]
fn test_debug_write() {
    //slice
    {
        let input = Ethernet2Header {
            destination: [1, 2, 3, 4, 5, 6],
            source: [10, 11, 12, 13, 14, 15],
            ether_type: 0x0800,
        };

        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(14);
        input.write(&mut buffer).unwrap();
        println!("{:?}", Ethernet2HeaderSlice::from_slice(&buffer));
    }
    //write error
    {
        use crate::ValueError::Ipv4OptionsLengthBad;
        use crate::WriteError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            ValueError(Ipv4OptionsLengthBad(0)),
            SliceTooSmall(0),
        ]
        .iter()
        {
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
            U8TooLarge {
                value: 0,
                max: 0,
                field: ErrorField::Ipv4Ecn,
            },
            U16TooLarge {
                value: 0,
                max: 0,
                field: ErrorField::Ipv4Ecn,
            },
            U32TooLarge {
                value: 0,
                max: 0,
                field: ErrorField::Ipv4Ecn,
            },
        ]
        .iter()
        {
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
            VlanTagVlanId,
        ]
        .iter()
        {
            println!("{:?}", value);
        }
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

#[test]
fn test_io_error_to_write_error() {
    assert_matches!(
        WriteError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
        WriteError::IoError(_)
    );
}

mod write_error {
    #[test]
    fn io_error() {
        use super::*;
        assert_eq!(
            std::io::ErrorKind::Other,
            WriteError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
                .io_error()
                .unwrap()
                .kind()
        );
        assert!(WriteError::ValueError(ValueError::TcpLengthTooLarge(0))
            .io_error()
            .is_none());
    }

    #[test]
    fn value_error() {
        use super::*;
        assert!(
            WriteError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
                .value_error()
                .is_none()
        );
        assert_eq!(
            Some(ValueError::TcpLengthTooLarge(0)),
            WriteError::ValueError(ValueError::TcpLengthTooLarge(0)).value_error()
        );
    }
}
