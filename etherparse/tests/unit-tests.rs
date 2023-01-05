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
    //read error
    {
        use crate::ReadError::*;
        for value in [
            IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
            SliceLen(err::SliceLenError {
                expected_min_len: 0,
                actual_len: 0,
                layer: err::Layer::Icmpv4,
            }),
            IpHeader(err::ip::HeaderError::UnsupportedIpVersion { version_number: 0 }),
            Ipv4Header(err::ipv4::HeaderError::UnexpectedVersion { version_number: 0 }),
            Ipv6Header(err::ipv6::HeaderError::UnexpectedVersion { version_number: 0 }),
            TcpHeader(err::tcp::HeaderError::DataOffsetTooSmall { data_offset: 1 }),
        ]
        .iter()
        {
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

#[test]
fn test_io_error_to_read_error() {
    assert_matches!(
        ReadError::from(std::io::Error::new(std::io::ErrorKind::Other, "oh no!")),
        ReadError::IoError(_)
    );
}

mod read_error {

    #[test]
    fn add_slice_offset() {
        use super::*;
        assert_eq!(
            ReadError::SliceLen(err::SliceLenError {
                expected_min_len: 1,
                actual_len: 2,
                layer: err::Layer::Icmpv4,
            })
            .add_slice_offset(3)
            .slice_len()
            .unwrap(),
            err::SliceLenError {
                expected_min_len: 4,
                actual_len: 5,
                layer: err::Layer::Icmpv4,
            }
        );
        assert_matches!(
            ReadError::UnexpectedLenOfSlice {
                expected: 7,
                actual: 10
            }
            .add_slice_offset(2),
            ReadError::UnexpectedLenOfSlice {
                expected: 9,
                actual: 12
            }
        );
        {
            use err::ipv4::HeaderError::UnexpectedVersion;
            assert_matches!(
                ReadError::Ipv4Header(UnexpectedVersion { version_number: 0 }).add_slice_offset(3),
                ReadError::Ipv4Header(UnexpectedVersion { version_number: 0 })
            );
        }
    }

    #[test]
    fn io_error() {
        use super::*;
        assert_eq!(
            std::io::ErrorKind::Other,
            ReadError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
                .io_error()
                .unwrap()
                .kind()
        );
        assert!(ReadError::IpHeader(err::ip::HeaderError::UnsupportedIpVersion { version_number: 0 }).io_error().is_none());
    }

    #[test]
    fn unexpected_end_of_slice_min_expected_size() {
        use super::*;
        assert!(
            ReadError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
                .slice_len()
                .is_none()
        );
        {
            let err = err::SliceLenError {
                expected_min_len: 1,
                actual_len: 2,
                layer: err::Layer::Icmpv4,
            };
            assert_eq!(
                err.clone(),
                ReadError::SliceLen(err.clone())
                    .slice_len()
                    .unwrap()
            );
        }
    }
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
