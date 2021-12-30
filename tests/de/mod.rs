use super::*;
use proptest::prelude::*;

use std::error::Error;
use etherparse::de;

/// Tests for the struct `de::UnexpectedEndOfSliceError`
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
            arg2_u16 in any::<u16>(),
        ) {
            use de::Ipv4Error::*;

            // Ipv4UnexpectedVersion
            assert_eq!(
                &format!("de::Ipv4Error: Unexpected IP version number. Expected an IPv4 Header but the header contained the version number {}.", arg_u8),
                &format!("{}", UnexpectedIpVersion(arg_u8))
            );

            // IhlTooSmall
            assert_eq!(
                &format!("de::Ipv4Error: The 'ihl' (Internet Header length) field in the IPv4 header has a value of '{}' which is smaller then minimum size of an IPv4 header (5).", arg_u8),
                &format!("{}", IhlTooSmall(arg_u8))
            );

            // TotalLengthSmallerThanIhl
            assert_eq!(
                &format!("de::Ipv4Error: The IPv4 'total_length' of {} octets is smaller then the length of {} octets the header itself (based on ihl).", arg2_u16, arg_u16),
                &format!(
                    "{}",
                    TotalLengthSmallerThanIhl(
                        de::Ipv4TotalLengthSmallerThanIhlError {
                            header_length: arg_u16,
                            total_length: arg2_u16,
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
            use de::Ipv4Error::*;

            // UnexpectedIpVersion
            assert_eq!(
                &format!("UnexpectedIpVersion({})", arg_u8),
                &format!("{:?}", UnexpectedIpVersion(arg_u8))
            );

            // IhlTooSmall
            assert_eq!(
                &format!("IhlTooSmall({})", arg_u8),
                &format!("{:?}", IhlTooSmall(arg_u8))
            );

            // TotalLengthSmallerThanIhl
            {
                let inner = de::Ipv4TotalLengthSmallerThanIhlError{
                    header_length: arg2_u16,
                    total_length: arg_u16,
                };
                assert_eq!(
                    &format!("TotalLengthSmallerThanIhl({:?})", inner),
                    &format!("{:?}", TotalLengthSmallerThanIhl(inner))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            arg_u8 in any::<u8>(),
            arg_u16 in any::<u16>(),
            arg2_u16 in any::<u16>(),
        ) {
            use de::Ipv4Error::*;
            let values = [
                UnexpectedIpVersion(arg_u8),
                IhlTooSmall(arg_u8),
                TotalLengthSmallerThanIhl(
                    de::Ipv4TotalLengthSmallerThanIhlError{
                        header_length: arg2_u16,
                        total_length: arg_u16,
                    }
                ),
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
            arg2_u16 in any::<u16>(),
        ) {
            use de::Ipv4Error::*;
            let values = [
                UnexpectedIpVersion(arg_u8),
                IhlTooSmall(arg_u8),
                TotalLengthSmallerThanIhl(
                    de::Ipv4TotalLengthSmallerThanIhlError{
                        header_length: arg2_u16,
                        total_length: arg_u16,
                    }
                ),
            ];
            for value in values {
                assert!(value.source().is_none());
            }
        }
    }
}

mod ipv4_total_length_smaller_than_ihl_error {
    use super::*;

    proptest! {
        #[test]
        fn debug(
            header_length in any::<u16>(),
            total_length in any::<u16>(),
        ) {
            assert_eq!(
                &format!("Ipv4TotalLengthSmallerThanIhlError {{ header_length: {}, total_length: {} }}", header_length, total_length),
                &format!(
                    "{:?}",
                    de::Ipv4TotalLengthSmallerThanIhlError{
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
            let value = de::Ipv4TotalLengthSmallerThanIhlError{
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
                &format!("{}", UnexpectedIpVersion(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn debug(
            arg_u8 in any::<u8>(),
        ) {
            use de::Ipv6Error::*;

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
            use de::Ipv6Error::*;
            let values = [
                UnexpectedIpVersion(arg_u8),
            ];
            for value in values {
                assert!(value.source().is_none());
            }
        }
    }
}

mod ip_error {
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
                        de::Ipv4TotalLengthSmallerThanIhlError {
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
            use de::IpError::*;

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
                let inner = de::Ipv4TotalLengthSmallerThanIhlError{
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
            arg2_u16 in any::<u16>(),
        ) {
            use de::IpError::*;
            let values = [
                UnsupportedIpVersion(arg_u8),
                Ipv4IhlTooSmall(arg_u8),
                Ipv4TotalLengthSmallerThanIhl(
                    de::Ipv4TotalLengthSmallerThanIhlError {
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
            arg2_u16 in any::<u16>(),
        ) {
            use de::IpError::*;
            let values = [
                UnsupportedIpVersion(arg_u8),
                Ipv4IhlTooSmall(arg_u8),
                Ipv4TotalLengthSmallerThanIhl(
                    de::Ipv4TotalLengthSmallerThanIhlError {
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

mod ipv4_exts_error {
    use super::*;
    
    #[test]
    fn display() {
        use de::Ipv4ExtsError::*;
        use de::IpAuthError::*;

        // Auth
        assert_eq!(
            "de::IpAuthError: Authentication header payload size is 0 which is smaller then the minimum size of the header (1 is the minimum allowed value).",
            &format!("{}", Auth(HeaderLengthZero))
        );
    }

    #[test]
    fn debug() {
        use de::Ipv4ExtsError::*;
        use de::IpAuthError::*;

        // Auth
        assert_eq!(
            &format!("Auth({:?})", HeaderLengthZero),
            &format!("{:?}", Auth(HeaderLengthZero))
        );
    }

    #[test]
    fn clone_eq() {
        use de::Ipv4ExtsError::*;
        use de::IpAuthError::*;

        let values = [
            Auth(HeaderLengthZero),
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn error_source() {
        use de::Ipv4ExtsError::*;
        use de::IpAuthError::*;

        let some_values = [
            Auth(HeaderLengthZero),
        ];
        for value in some_values {
            assert!(value.source().is_some());
        }
    }
}

mod ipv6_exts_error {
    use super::*;
    
    #[test]
    fn display() {
        use de::Ipv6ExtsError::*;
        use de::IpAuthError::*;

        // HopByHopHeaderNotAtStart
        assert_eq!(
            "de::Ipv6ExtsError: Encountered an IPv6 hop-by-hop header somwhere else then directly after the IPv6 header. This is not allowed according to RFC 8200.",
            &format!("{}", HopByHopHeaderNotAtStart)
        );

        // Auth
        assert_eq!(
            "de::IpAuthError: Authentication header payload size is 0 which is smaller then the minimum size of the header (1 is the minimum allowed value).",
            &format!("{}", Auth(HeaderLengthZero))
        );
    }

    #[test]
    fn debug() {
        use de::Ipv6ExtsError::*;
        use de::IpAuthError::*;

        assert_eq!(
            "HopByHopHeaderNotAtStart",
            &format!("{:?}", HopByHopHeaderNotAtStart)
        );

        // Auth
        assert_eq!(
            &format!("Auth({:?})", HeaderLengthZero),
            &format!("{:?}", Auth(HeaderLengthZero))
        );
    }

    #[test]
    fn clone_eq() {
        use de::Ipv6ExtsError::*;
        use de::IpAuthError::*;

        let values = [
            HopByHopHeaderNotAtStart,
            Auth(HeaderLengthZero),
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn error_source() {
        use de::Ipv6ExtsError::*;
        use de::IpAuthError::*;

        {
            let some_values = [
                Auth(HeaderLengthZero),
            ];
            for value in some_values {
                assert!(value.source().is_some());
            }
        }
        {
            let none_values = [
                HopByHopHeaderNotAtStart,
            ];
            for value in none_values {
                assert!(value.source().is_none());
            }
        }
    }
}

mod ip_auth_error {
    use super::*;
    
    #[test]
    fn display() {
        use de::IpAuthError::*;

        // HeaderLengthZero
        assert_eq!(
            "de::IpAuthError: Authentication header payload size is 0 which is smaller then the minimum size of the header (1 is the minimum allowed value).",
            &format!("{}", HeaderLengthZero)
        );
    }

    #[test]
    fn debug() {
        use de::IpAuthError::*;

        // HeaderLengthZero
        assert_eq!(
            "HeaderLengthZero",
            &format!("{:?}", HeaderLengthZero)
        );
    }

    #[test]
    fn clone_eq() {
        use de::IpAuthError::*;
        let values = [
            HeaderLengthZero,
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn error_source() {
        use de::IpAuthError::*;
        let values = [
            HeaderLengthZero,
        ];
        for value in values {
            assert!(value.source().is_none());
        }
    }
}
