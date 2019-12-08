use super::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn read_error_display(
        arg_u8 in any::<u8>(),
        arg_u16 in any::<u16>(),
        arg_usize in any::<usize>()
    ) { //arg_u16 in any::<u16>()

        use super::ReadError::*;

        //IoError
        {
            let custom_error = std::io::Error::new(std::io::ErrorKind::Other, "some error");
            assert_eq!(
                &format!("{}", custom_error),
                &format!("{}", IoError(custom_error))
            );
        }

        //UnexpectedEndOfSlice
        assert_eq!(
            &format!("ReadError: Unexpected end of slice. The given slice contained less then minimum required {} bytes.", arg_usize),
            &format!("{}", UnexpectedEndOfSlice(arg_usize))
        );

        //VlanDoubleTaggingUnexpectedOuterTpid
        assert_eq!(
            &format!("ReadError: Expected a double vlan header, but the outer tpid {} is a non vlan header tpid.", arg_u16),
            &format!("{}", VlanDoubleTaggingUnexpectedOuterTpid(arg_u16))
        );

        //IpUnsupportedVersion
        assert_eq!(
            &format!("ReadError: Unsupported IP version number. The IP header contained the unsupported version number {}.", arg_u8),
            &format!("{}", IpUnsupportedVersion(arg_u8))
        );

        //Ipv4UnexpectedVersion
        assert_eq!(
            &format!("ReadError: Unexpected IP version number. Expected an IPv4 Header but the header contained the version number {}.", arg_u8),
            &format!("{}", Ipv4UnexpectedVersion(arg_u8))
        );

        //Ipv4HeaderLengthBad
        assert_eq!(
            &format!("ReadError: Bad IPv4 header length. The header length value {} in the IPv4 header is smaller then the ipv4 header.", arg_u8),
            &format!("{}", Ipv4HeaderLengthBad(arg_u8))
        );

        //Ipv4TotalLengthTooSmall
        assert_eq!(
            &format!("ReadError: Bad IPv4 total length. The total length value {} in the IPv4 header is smaller then the ipv4 header itself.", arg_u16),
            &format!("{}", Ipv4TotalLengthTooSmall(arg_u16))
        );

        //Ipv6UnexpectedVersion
        assert_eq!(
            &format!("ReadError: Unexpected IP version number. Expected an IPv6 Header but the header contained the version number {}.", arg_u8),
            &format!("{}", Ipv6UnexpectedVersion(arg_u8))
        );

        //Ipv6TooManyHeaderExtensions
        assert_eq!(
            &format!("ReadError: Too many IPv6 header extensions. There are more then 7 extension headers present, this not supported."),
            &format!("{}", Ipv6TooManyHeaderExtensions)
        );

        //TcpDataOffsetTooSmall
        assert_eq!(
            &format!("ReadError: TCP data offset too small. The data offset value {} in the tcp header is smaller then the tcp header itself.", arg_u8),
            &format!("{}", TcpDataOffsetTooSmall(arg_u8))
        );
    }
}

/// Check that only for std::io::Error a source is returned
#[test]
fn read_error_source() {
    use super::ReadError::*;
    use std::error::Error;

    assert_matches!(
        IoError(std::io::Error::new(std::io::ErrorKind::Other, "some error")).source(), 
        Some(_)
    );

    let none_values = [
        UnexpectedEndOfSlice(0),
        VlanDoubleTaggingUnexpectedOuterTpid(0),
        IpUnsupportedVersion(0),
        Ipv4UnexpectedVersion(0),
        Ipv4HeaderLengthBad(0),
        Ipv4TotalLengthTooSmall(0),
        Ipv6UnexpectedVersion(0),
        Ipv6TooManyHeaderExtensions,
        TcpDataOffsetTooSmall(0),
    ];

    for value in &none_values {
        assert_matches!(value.source(), None);
    }
}
