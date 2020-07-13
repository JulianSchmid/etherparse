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

        //IpAuthenticationHeaderTooSmallPayloadLength
        assert_eq!(
            &format!("ReadError: Authentication header payload size is smaller then 1 ({}) which is smaller then the minimum size of the header.", arg_u8),
            &format!("{}", IpAuthenticationHeaderTooSmallPayloadLength(arg_u8))
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

/// Check the write error display fmt generate the expected strings
#[test]
fn write_error_display() {

    use WriteError::{IoError, SliceTooSmall};
    use ValueError::Ipv4OptionsLengthBad;

    //IoError
    {
        let custom_error = std::io::Error::new(std::io::ErrorKind::Other, "some error");
        assert_eq!(
            &format!("{}", custom_error),
            &format!("{}", IoError(custom_error))
        );
    }

    //ValueError
    {
        let value_error = Ipv4OptionsLengthBad(0);
        assert_eq!(
            &format!("ValueError: {}", value_error),
            &format!("{}", WriteError::ValueError(value_error))
        );
    }

    //SliceTooSmall
    {
        let size = 1234;
        assert_eq!(
            &format!("SliceTooSmall: The slice given to write to is too small (required to be at least {} bytes large)", size),
            &format!("{}", SliceTooSmall(size))
        );
    }
}

/// Check the write error display fmt generate the expected strings
#[test]
fn write_error_source() {
    use super::WriteError::{IoError, SliceTooSmall};
    use std::error::Error;

    assert_matches!(
        IoError(std::io::Error::new(std::io::ErrorKind::Other, "some error")).source(),
        Some(_)
    );

    assert_matches!(
        WriteError::ValueError(ValueError::Ipv4OptionsLengthBad(0)).source(),
        Some(_)
    );

    assert_matches!(
        SliceTooSmall(0).source(),
        None
    );
}

/// Check that all values return None as source
#[test]
fn value_error_source() {
    use ValueError::*;
    use std::error::Error;

    let none_values = [
        Ipv4OptionsLengthBad(0),
        Ipv4PayloadLengthTooLarge(0),
        Ipv6PayloadLengthTooLarge(0),
        Ipv6ExtensionDataTooLarge(0),
        IpAuthenticationHeaderBadIcvLength(0),
        UdpPayloadLengthTooLarge(0),
        TcpLengthTooLarge(0),
        U8TooLarge{ value:0, max:0, field:ErrorField::Ipv4Dscp },
        U16TooLarge{ value:0, max:0, field:ErrorField::Ipv4Dscp },
        U32TooLarge{ value:0, max:0, field:ErrorField::Ipv4Dscp },
    ];

    for value in &none_values {
        assert_matches!(value.source(), None);
    }
}

proptest! {
    #[test]
    fn value_error_display(
        value_u8 in any::<u8>(),
        max_u8 in any::<u8>(),
        value_u16 in any::<u16>(),
        max_u16 in any::<u16>(),
        value_u32 in any::<u32>(),
        max_u32 in any::<u32>(),
        arg_usize in any::<usize>(),
        field in error_field_any()
    ) {
        use ValueError::*;

        //Ipv4OptionsLengthBad
        assert_eq!(
            &format!("Bad IPv4 'options_len'. The IPv4 options length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 40 bytes.", arg_usize),
            &format!("{}", Ipv4OptionsLengthBad(arg_usize))
        );

        //Ipv4PayloadLengthTooLarge
        assert_eq!(
            &format!("IPv4 'total_legnth' too large. The IPv4 header and payload have a larger size ({} bytes) than can be be represented by the 'total_legnth' field in the IPv4 header.", arg_usize),
            &format!("{}", Ipv4PayloadLengthTooLarge(arg_usize))
        );

        //Ipv6PayloadLengthTooLarge
        assert_eq!(
            &format!("IPv6 'payload_length' too large. The IPv6 header block & payload size ({} bytes) is larger then what can be be represented by the 'payload_length' field in the IPv6 header.", arg_usize),
            &format!("{}", Ipv6PayloadLengthTooLarge(arg_usize))
        );

        //Ipv6ExtensionDataTooLarge
        assert_eq!(
            &format!("IPv6 extensions header 'data' are too large. The data size ({} bytes) is larger then what can be be represented by the 'extended header size' field in an IPv6 extension header.", arg_usize),
            &format!("{}", Ipv6ExtensionDataTooLarge(arg_usize))
        );

        //IpAuthenticationHeaderBadIcvLength
        assert_eq!(
            &format!("IP authentication header 'raw_icv' value has a length ({} bytes) is either not a multiple of 4 bytes or bigger then the maximum of 1016 bytes.", arg_usize),
            &format!("{}", IpAuthenticationHeaderBadIcvLength(arg_usize))
        );

        //UdpPayloadLengthTooLarge
        assert_eq!(
            &format!("UDP 'length' too large. The UDP length ({} bytes) is larger then what can be be represented by the 'length' field in the UDP header.", arg_usize),
            &format!("{}", UdpPayloadLengthTooLarge(arg_usize))
        );

        //TcpLengthTooLarge
        assert_eq!(
            &format!("TCP length too large. The TCP packet length ({} bytes) is larger then what is supported.", arg_usize),
            &format!("{}", TcpLengthTooLarge(arg_usize))
        );

        //U8TooLarge
        assert_eq!(
            &format!("The value {} of the field '{}' is larger then the allowed maximum of {}.", value_u8, field, max_u8),
            &format!("{}", U8TooLarge{
                value: value_u8,
                max: max_u8,
                field: field.clone()
            })
        );

        //U16TooLarge
        assert_eq!(
            &format!("The value {} of the field '{}' is larger then the allowed maximum of {}.", value_u16, field, max_u16),
            &format!("{}", U16TooLarge{
                value: value_u16,
                max: max_u16,
                field: field.clone()
            })
        );

        //U32TooLarge
        assert_eq!(
            &format!("The value {} of the field '{}' is larger then the allowed maximum of {}.", value_u32, field, max_u32),
            &format!("{}", U32TooLarge{
                value: value_u32,
                max: max_u32,
                field: field.clone()
            })
        );
    }
}

#[test]
fn error_field_display() {
    use ErrorField::*;

    assert_eq!("Ipv4Header.payload_len", &format!("{}", Ipv4PayloadLength));
    assert_eq!("Ipv4Header.differentiated_services_code_point", &format!("{}", Ipv4Dscp));
    assert_eq!("Ipv4Header.explicit_congestion_notification", &format!("{}", Ipv4Ecn));
    assert_eq!("Ipv4Header.fragments_offset", &format!("{}", Ipv4FragmentsOffset));
    assert_eq!("Ipv6Header.flow_label", &format!("{}", Ipv6FlowLabel));
    assert_eq!("Ipv6FragmentHeader.fragment_offset", &format!("{}", Ipv6FragmentOffset));
    assert_eq!("SingleVlanHeader.priority_code_point", &format!("{}", VlanTagPriorityCodePoint));
    assert_eq!("SingleVlanHeader.vlan_identifier", &format!("{}", VlanTagVlanId));
}
