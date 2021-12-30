use super::super::*;
use proptest::prelude::*;

use std::error::Error;
use crate::error::de;

/// Tests for the struct `error::de::UnexpectedEndOfSliceError`
mod unexpected_end_of_slice {
    use super::*;
    proptest! {
        #[test]
        fn display(
            expected_min_len in any::<usize>(),
            actual_len in any::<usize>(),
        ) {
            assert_eq!(
                &format!("UnexpectedEndOfSliceError: Unexpected end of slice. The given slice contained less then minimum required {} bytes.", expected_min_len),
                &format!(
                    "{}",
                    UnexpectedEndOfSliceError{
                        expected_min_len,
                        actual_len,
                    }
                )
            );
        }
    }

    proptest! {
        #[test]
        fn debug(
            expected_min_len in any::<usize>(),
            actual_len in any::<usize>(),
        ) {
            assert_eq!(
                &format!("UnexpectedEndOfSliceError {{ expected_min_len: {}, actual_len: {} }}", expected_min_len, actual_len),
                &format!(
                    "{:?}",
                    UnexpectedEndOfSliceError{
                        expected_min_len,
                        actual_len,
                    }
                )
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            expected_min_len in any::<usize>(),
            actual_len in any::<usize>(),
        ) {
            let value = UnexpectedEndOfSliceError{
                expected_min_len,
                actual_len,
            };
            assert_eq!(value.clone(), value);
        }
    }

    proptest! {
        #[test]
        fn error_source(
            expected_min_len in any::<usize>(),
            actual_len in any::<usize>(),
        ) {
            assert!(
                UnexpectedEndOfSliceError{
                    expected_min_len,
                    actual_len,
                }.source().is_none()
            );
        }
    }

    #[test]
    fn add_slice_offset() {
        let base = UnexpectedEndOfSliceError{
            expected_min_len: 1,
            actual_len: 0,
        };
        assert_eq!(
            UnexpectedEndOfSliceError{
                expected_min_len: 4,
                actual_len: 3,
            },
            base.clone().add_slice_offset(3),
        );
        // check the original value is not modified
        assert_eq!(1, base.expected_min_len);
    }
}

mod ipv4_error {
    use super::*;

    proptest! {
        #[test]
        fn display(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
        ) {
            use de::Ipv4Error::*;

            //Ipv4UnexpectedVersion
            assert_eq!(
                &format!("de::Ipv4Error: Unexpected IP version number. Expected an IPv4 Header but the header contained the version number {}.", arg_u8),
                &format!("{}", Ipv4UnexpectedVersion(arg_u8))
            );

            //Ipv4HeaderLengthBad
            assert_eq!(
                &format!("de::Ipv4Error: Bad IPv4 header length. The header length value {} in the IPv4 header is smaller then the ipv4 header.", arg_u8),
                &format!("{}", Ipv4HeaderLengthBad(arg_u8))
            );

            //Ipv4TotalLengthTooSmall
            assert_eq!(
                &format!("de::Ipv4Error: Bad IPv4 total length. The total length value {} in the IPv4 header is smaller then the ipv4 header itself.", arg_u16),
                &format!("{}", Ipv4TotalLengthTooSmall(arg_u16))
            );
        }
    }

    proptest! {
        #[test]
        fn debug(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
        ) {
            use Ipv4Error::*;

            //UnexpectedVersion
            assert_eq!(
                &format!("UnexpectedVersion({})", arg_u8),
                &format!("{:?}", UnexpectedVersion(arg_u8))
            );

            //HeaderLengthBad
            assert_eq!(
                &format!("HeaderLengthBad({})", arg_u8),
                &format!("{:?}", HeaderLengthBad(arg_u8))
            );

            //TotalLengthTooSmall
            assert_eq!(
                &format!("TotalLengthTooSmall({})", arg_u16),
                &format!("{:?}", TotalLengthTooSmall(arg_u16))
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
        ) {
            use de::Ipv4Error::*;
            let values = [
                UnexpectedVersion(arg_u8),
                HeaderLengthBad(arg_u8),
                TotalLengthTooSmall(arg_u16),
            ];
            for value in values {
                assert_eq!(value.clone(), value);
            }
        }
    }

    proptest! {
        #[test]
        fn error_source(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
        ) {
            use Ipv4Error::*;
            let values = [
                UnexpectedVersion(arg_u8),
                HeaderLengthBad(arg_u8),
                TotalLengthTooSmall(arg_u16),
            ];
            for value in values {
                assert!(value.source().is_none());
            }
        }
    }
}

mod ipv4_total_length_smaller_than_ihl_error {

    proptest! {
        #[test]
        fn debug(
            header_length in any::<u16>(),
            total_length in any::<u16>(),
        ) {
            assert_eq!(
                &format!("Ipv4TotalLengthSmallerThanIhlError{{ header_length: {}, total_length: {} }}", header_length, total_length),
                &format!(
                    "{:?}",
                    Ipv4TotalLengthSmallerThanIhlError{
                        header_length,
                        total_length,
                    },
                )
            );

        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            header_length in any::<u16>(),
            total_length in any::<u16>(),
        ) {
            use error::de::Ipv4TotalLengthSmallerThanIhlError;

            let value = Ipv4TotalLengthSmallerThanIhlError{
                header_length,
                total_length,
            };
            assert_eq!(value.clone(), value);
        }
    }

}

mod ipv6_error {
    use super::*;

    proptest! {
        #[test]
        fn display(
            arg_u8 in any::<u8>(),
        ) {
            use de::Ipv6Error::*;

            // Ipv6UnexpectedVersion
            assert_eq!(
                &format!("de::Ipv6Error: Unexpected IP version number. Expected an IPv6 Header but the header contained the version number {}.", arg_u8),
                &format!("{}", Ipv6UnexpectedVersion(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn debug(
            arg_u8 in any::<u8>(),
        ) {
            use Ipv6Error::*;

            // UnexpectedIpVersion
            assert_eq!(
                &format!("UnexpectedIpVersion({})", arg_u8),
                &format!("{:?}", UnexpectedIpVersion(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            arg_u8 in any::<u8>(),
        ) {
            use de::Ipv6Error::*;
            let values = [
                UnexpectedIpVersion(arg_u8),
            ];
            for value in values {
                assert_eq!(value.clone(), value);
            }
        }
    }

    proptest! {
        #[test]
        fn error_source(
            arg_u8 in any::<u8>(),
        ) {
            use Ipv6Error::*;
            let values = [
                UnexpectedIpVersion(arg_u8),
            ];
            for value in values {
                assert!(value.source().is_none());
            }
        }
    }
}

mod ipv_error {
    use super::*;

    proptest! {
        #[test]
        fn display(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
            arg2_u16 in any::<u16>(),
        ) {
            use de::IpError::*;

            // UnsupportedIpVersion
            assert_eq!(
                &format!("de::IpError: Unsupported IP version number {} found in IP header (only 4 & 6 are supported).", arg_u8),
                &format!("{}", UnsupportedIpVersion(arg_u8))
            );

            // Ipv4IhlTooSmall
            assert_eq!(
                &format!("de::IpError: The 'ihl' (Internet Header length) field in the IPv4 header has a value of '{}' which is smaller then minimum size of an IPv4 header (5).", arg_u8),
                &format!("{}", Ipv4IhlTooSmall(arg_u8))
            );

            // Ipv4TotalLengthSmallerThanIhl
            assert_eq!(
                &format!("de::IpError: The IPv4 'total_length' of {} octets is smaller then the length of {} octets the header itself (based on ihl).", arg_u16, arg2_u16),
                &format!(
                    "{}",
                    Ipv4TotalLengthSmallerThanIhl(
                        Ipv4TotalLengthSmallerThanIhlError {
                            header_length: arg2_u16,
                            total_length: arg_u16,
                        }
                    )
                )
            );
        }
    }

    proptest! {
        #[test]
        fn debug(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
            arg2_u16 in any::<u16>(),
        ) {
            use IpError::*;

            // UnsupportedIpVersion
            assert_eq!(
                &format!("UnsupportedIpVersion({})", arg_u8),
                &format!("{:?}", UnsupportedIpVersion(arg_u8))
            );

            // Ipv4IhlTooSmall
            assert_eq!(
                &format!("Ipv4IhlTooSmall({})", arg_u8),
                &format!("{:?}", Ipv4IhlTooSmall(arg_u8))
            );

            // Ipv4TotalLengthSmallerThanIhl
            {
                let inner = Ipv4TotalLengthSmallerThanIhlError{
                    header_length: arg2_u16,
                    total_length: arg_u16,
                };
                assert_eq!(
                    &format!("Ipv4TotalLengthSmallerThanIhl({:?})", inner),
                    &format!("{:?}", Ipv4TotalLengthSmallerThanIhl(inner.clone()))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
        ) {
            use de::IpError::*;
            let values = [
                UnsupportedIpVersion(arg_u8),
                Ipv4IhlTooSmall(arg_u8),
                Ipv4TotalLengthSmallerThanIhl(
                    Ipv4TotalLengthSmallerThanIhlError {
                        header_length: arg2_u16,
                        total_length: arg_u16,
                    }
                )
            ];
            for value in values {
                assert_eq!(value.clone(), value);
            }
        }
    }

    proptest! {
        #[test]
        fn error_source(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
        ) {
            use IpError::*;
            let values = [
                UnsupportedIpVersion(arg_u8),
                Ipv4IhlTooSmall(arg_u8),
                Ipv4TotalLengthSmallerThanIhl(
                    Ipv4TotalLengthSmallerThanIhlError {
                        header_length: arg2_u16,
                        total_length: arg_u16,
                    }
                )
            ];
            for value in values {
                assert!(value.source().is_none());
            }
        }
    }
}
