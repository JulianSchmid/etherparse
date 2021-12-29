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
