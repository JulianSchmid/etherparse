use super::*;
use proptest::prelude::*;

use std::error::Error;
use etherparse::de;

/// Tests for the enum `de::Error`
mod error {
    use super::*;

    proptest! {
        #[test]
        fn display(
            arg_u8 in any::<u8>(),
            arg1_u16 in any::<u16>(),
            arg2_u16 in any::<u16>(),
            arg1_usize in any::<usize>(),
            arg2_usize in any::<usize>(),
        ) {
            use de::Error::*;
            {
                let inner = UnexpectedEndOfSliceError{
                    expected_min_len: arg1_usize,
                    actual_len: arg2_usize,
                };
                assert_eq!(
                    &format!("{}", inner),
                    &format!("{}", UnexpectedEndOfSlice(inner))
                );
            }
            {
                let inner = std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "some error"
                );
                assert_eq!(
                    &format!("{}", inner),
                    &format!("{}", IoError(inner))
                );
            }
            assert_eq!(
                &format!("{}", de::IpError::UnsupportedIpVersion(arg_u8)),
                &format!("{}", UnsupportedIpVersion(arg_u8))
            );
            assert_eq!(
                &format!("{}", de::Ipv4Error::UnexpectedIpVersion(arg_u8)),
                &format!("{}", Ipv4UnexpectedIpVersion(arg_u8))
            );
            assert_eq!(
                &format!("{}", de::Ipv6Error::UnexpectedIpVersion(arg_u8)),
                &format!("{}", Ipv6UnexpectedIpVersion(arg_u8))
            );
            assert_eq!(
                &format!("{}", de::Ipv4Error::IhlTooSmall(arg_u8)),
                &format!("{}", Ipv4IhlTooSmall(arg_u8))
            );
            {
                let inner = de::Ipv4TotalLengthSmallerThanIhlError {
                    header_length: arg1_u16,
                    total_length: arg2_u16,
                };
                assert_eq!(
                    &format!("{}", de::Ipv4Error::TotalLengthSmallerThanIhl(inner.clone())),
                    &format!("{}", Ipv4TotalLengthSmallerThanIhl(inner))
                );
            }
            assert_eq!(
                &format!("{}", de::IpAuthError::HeaderLengthZero),
                &format!("{}", IpAuthHeaderLengthZero)
            );
            assert_eq!(
                &format!("{}", de::Ipv6ExtsError::HopByHopHeaderNotAtStart),
                &format!("{}", Ipv6HopByHopHeaderNotAtStart)
            );
            assert_eq!(
                &format!("{}", de::TcpError::DataOffsetTooSmall(arg_u8)),
                &format!("{}", TcpDataOffsetTooSmall(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn debug(
            arg_u8 in any::<u8>(),
            arg1_u16 in any::<u16>(),
            arg2_u16 in any::<u16>(),
            arg1_usize in any::<usize>(),
            arg2_usize in any::<usize>(),
        ) {
            use de::Error::*;
            {
                let inner = UnexpectedEndOfSliceError{
                    expected_min_len: arg1_usize,
                    actual_len: arg2_usize,
                };
                assert_eq!(
                    &format!("UnexpectedEndOfSlice({:?})", inner),
                    &format!("{:?}", UnexpectedEndOfSlice(inner))
                );
            }
            {
                let inner = std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "some error"
                );
                assert_eq!(
                    &format!("IoError({:?})", inner),
                    &format!("{:?}", IoError(inner))
                );
            }
            assert_eq!(
                &format!("UnsupportedIpVersion({})", arg_u8),
                &format!("{:?}", UnsupportedIpVersion(arg_u8))
            );
            assert_eq!(
                &format!("Ipv4UnexpectedIpVersion({})", arg_u8),
                &format!("{:?}", Ipv4UnexpectedIpVersion(arg_u8))
            );
            assert_eq!(
                &format!("Ipv6UnexpectedIpVersion({})", arg_u8),
                &format!("{:?}", Ipv6UnexpectedIpVersion(arg_u8))
            );
            assert_eq!(
                &format!("Ipv4IhlTooSmall({})", arg_u8),
                &format!("{:?}", Ipv4IhlTooSmall(arg_u8))
            );
            {
                let inner = de::Ipv4TotalLengthSmallerThanIhlError {
                    header_length: arg1_u16,
                    total_length: arg2_u16,
                };
                assert_eq!(
                    &format!("Ipv4TotalLengthSmallerThanIhl({:?})", inner),
                    &format!("{:?}", Ipv4TotalLengthSmallerThanIhl(inner))
                );
            }
            assert_eq!(
                "IpAuthHeaderLengthZero",
                &format!("{:?}", IpAuthHeaderLengthZero)
            );
            assert_eq!(
                "Ipv6HopByHopHeaderNotAtStart",
                &format!("{:?}", Ipv6HopByHopHeaderNotAtStart),
            );
            assert_eq!(
                &format!("TcpDataOffsetTooSmall({})", arg_u8),
                &format!("{:?}", TcpDataOffsetTooSmall(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn error_source(
            arg_u8 in any::<u8>(),
            arg1_u16 in any::<u16>(),
            arg2_u16 in any::<u16>(),
            arg1_usize in any::<usize>(),
            arg2_usize in any::<usize>(),
        ) {
            use de::Error::*;
            {
                let some_values = [
                    UnexpectedEndOfSlice(
                        de::UnexpectedEndOfSliceError{
                            expected_min_len: arg1_usize,
                            actual_len: arg2_usize,
                        }
                    ),
                    IoError(
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "some error"
                        )
                    )
                ];
                for value in some_values {
                    assert!(value.source().is_some());
                }
            }
            {
                let none_values = [
                    UnsupportedIpVersion(arg_u8),
                    Ipv4UnexpectedIpVersion(arg_u8),
                    Ipv6UnexpectedIpVersion(arg_u8),
                    Ipv4IhlTooSmall(arg_u8),
                    Ipv4TotalLengthSmallerThanIhl(
                        de::Ipv4TotalLengthSmallerThanIhlError {
                            header_length: arg1_u16,
                            total_length: arg2_u16,
                        }
                    ),
                    IpAuthHeaderLengthZero,
                    Ipv6HopByHopHeaderNotAtStart,
                    TcpDataOffsetTooSmall(arg_u8)
                ];
                for value in none_values {
                    assert!(value.source().is_none());
                }
            }
        }
    }

    #[test]
    fn from_io_error() {
        assert_matches!(
            de::Error::from(
                std::io::Error::new(std::io::ErrorKind::Other, "some error")
            ),
            de::Error::IoError(_)
        );
    }

    #[test]
    fn from_unexpected_end_of_slice_error() {
        assert_matches!(
            de::Error::from(
                de::UnexpectedEndOfSliceError{
                    expected_min_len: 1,
                    actual_len: 2,
                }
            ),
            de::Error::UnexpectedEndOfSlice(
                de::UnexpectedEndOfSliceError{
                    expected_min_len: 1,
                    actual_len: 2,
                }
            )
        );
    }

    #[test]
    fn from_slice_error() {
        assert_matches!(
            de::Error::from(
                de::FromSliceError::Content(
                    de::IpAuthError::HeaderLengthZero
                )
            ),
            de::Error::IpAuthHeaderLengthZero
        );
    }

    #[test]
    fn from_read_error() {
        assert_matches!(
            de::Error::from(
                de::ReadError::Content(
                    de::IpAuthError::HeaderLengthZero
                )
            ),
            de::Error::IpAuthHeaderLengthZero
        );
    }

    #[test]
    fn from_ip_error() {
        assert_matches!(
            de::Error::from(
                de::IpError::UnsupportedIpVersion(5)
            ),
            de::Error::UnsupportedIpVersion(5)
        );
    }

    #[test]
    fn from_ipv4_error() {
        assert_matches!(
            de::Error::from(
                de::Ipv4Error::IhlTooSmall(1)
            ),
            de::Error::Ipv4IhlTooSmall(1)
        );
    }

    #[test]
    fn from_ipv6_error() {
        assert_matches!(
            de::Error::from(
                de::Ipv6Error::UnexpectedIpVersion(2)
            ),
            de::Error::Ipv6UnexpectedIpVersion(2)
        );
    }

    #[test]
    fn from_ipv4_exts_error() {
        use de::Ipv4ExtsError::*;
        use de::IpAuthError::*;
        assert_matches!(
            de::Error::from(
                Auth(HeaderLengthZero)
            ),
            de::Error::IpAuthHeaderLengthZero
        );
    }

    #[test]
    fn from_ipv6_exts_error() {
        use de::Ipv6ExtsError::*;
        assert_matches!(
            de::Error::from(
                HopByHopHeaderNotAtStart
            ),
            de::Error::Ipv6HopByHopHeaderNotAtStart
        );
    }

    #[test]
    fn from_ip_auth_error() {
        assert_matches!(
            de::Error::from(
                de::IpAuthError::HeaderLengthZero
            ),
            de::Error::IpAuthHeaderLengthZero
        );
    }

    #[test]
    fn from_tcp_error() {
        assert_matches!(
            de::Error::from(
                de::TcpError::DataOffsetTooSmall(123)
            ),
            de::Error::TcpDataOffsetTooSmall(123)
        );
    }
}

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

    proptest! {
        #[test]
        fn de_error(
            expected_min_len in any::<usize>(),
            actual_len in any::<usize>(),
        ) {
            use de::Error;
            assert_matches!(
                UnexpectedEndOfSliceError{
                    expected_min_len,
                    actual_len,
                }.de_error(),
                Error::UnexpectedEndOfSlice(_)
            );
        }
    }
}

mod from_slice_error {
    use super::*;

    #[test]
    fn display() {
        use de::FromSliceError::*;
        use de::IpAuthError::*;

        // UnexpectedEndOfSlice
        {
            let value = UnexpectedEndOfSliceError{
                expected_min_len: 4,
                actual_len: 3,
            };
            assert_eq!(
                &format!("{}", value),
                &format!("{}", de::FromSliceError::<de::IpAuthError>::UnexpectedEndOfSlice(value))
            );
        }

        // Content
        assert_eq!(
            &format!("{}", HeaderLengthZero),
            &format!("{}", Content(HeaderLengthZero))
        );
    }

    #[test]
    fn debug() {
        use de::{FromSliceError, IpAuthError};
        use de::FromSliceError::*;
        use de::IpAuthError::*;

        // UnexpectedEndOfSlice
        {
            let value = UnexpectedEndOfSliceError{
                expected_min_len: 4,
                actual_len: 3,
            };
            assert_eq!(
                &format!("UnexpectedEndOfSlice({:?})", value),
                &format!(
                    "{:?}",
                    FromSliceError::<IpAuthError>::UnexpectedEndOfSlice(value)
                )
            );
        }

        // Content
        assert_eq!(
            &format!("Content({:?})", HeaderLengthZero),
            &format!("{:?}", Content(HeaderLengthZero))
        );
    }

    #[test]
    fn clone_eq() {
        use de::FromSliceError::*;
        use de::IpAuthError::*;

        let values = [
            Content(HeaderLengthZero),
            UnexpectedEndOfSlice(
                UnexpectedEndOfSliceError{
                    expected_min_len: 4,
                    actual_len: 3,
                }
            )
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn error_source() {
        use de::FromSliceError::*;
        use de::IpAuthError::*;

        let some_values = [
            Content(HeaderLengthZero),
            UnexpectedEndOfSlice(
                UnexpectedEndOfSliceError{
                    expected_min_len: 4,
                    actual_len: 3,
                }
            )
        ];
        for value in some_values {
            assert!(value.source().is_some());
        }
    }

    #[test]
    fn from_unexpected_end_of_slice_error() {
        use de::{FromSliceError, IpAuthError};
        let value = UnexpectedEndOfSliceError{
            expected_min_len: 4,
            actual_len: 3,
        };
        assert_eq!(
            FromSliceError::<IpAuthError>::from(value.clone()),
            FromSliceError::<IpAuthError>::UnexpectedEndOfSlice(
                value
            )
        );
    }

    #[test]
    fn de_error() {
        use de::{FromSliceError, Error, IpAuthError};
        use de::FromSliceError::*;
        use de::IpAuthError::*;

        // UnexpectedEndOfSlice
        assert_matches!(
            FromSliceError::<IpAuthError>::UnexpectedEndOfSlice(
                UnexpectedEndOfSliceError{
                    expected_min_len: 4,
                    actual_len: 3,
                }
            ).de_error(),
            Error::UnexpectedEndOfSlice(
                UnexpectedEndOfSliceError{
                    expected_min_len: 4,
                    actual_len: 3,
                }
            )
        );

        // Content
        assert_matches!(
            Content(HeaderLengthZero).de_error(),
            Error::IpAuthHeaderLengthZero
        );
    }
}

mod read_error {
    use super::*;

    #[test]
    fn display() {
        use de::ReadError::*;
        use de::IpAuthError::*;

        // IoError
        {
            let inner = std::io::Error::new(std::io::ErrorKind::Other, "some error");
            assert_eq!(
                &format!("{}", inner),
                &format!(
                    "{}",
                    de::ReadError::<de::IpAuthError>::IoError(
                        inner
                    )
                )
            );
        }

        // Content
        assert_eq!(
            &format!("{}", HeaderLengthZero),
            &format!("{}", Content(HeaderLengthZero))
        );
    }

    #[test]
    fn debug() {
        use de::ReadError::*;
        use de::IpAuthError::*;

        // IoError
        {
            let inner = std::io::Error::new(std::io::ErrorKind::Other, "some error");
            assert_eq!(
                &format!("IoError({:?})", inner),
                &format!(
                    "{:?}",
                    de::ReadError::<de::IpAuthError>::IoError(
                        inner
                    )
                )
            );
        }

        // Content
        assert_eq!(
            &format!("Content({:?})", HeaderLengthZero),
            &format!("{:?}", Content(HeaderLengthZero))
        );
    }

    #[test]
    fn source() {
        use de::ReadError::*;
        use de::IpAuthError::*;

        let some_values = [
            IoError(
                std::io::Error::new(std::io::ErrorKind::Other, "some error")
            ),
            Content(HeaderLengthZero)
        ];

        for value in some_values {
            assert!(value.source().is_some());
        }
    }

    #[test]
    fn de_error() {
        use de::ReadError::*;
        use de::IpAuthError::*;
        use de::Error;

        // IoError
        assert_matches!(
            de::ReadError::<de::IpAuthError>::IoError(
                std::io::Error::new(std::io::ErrorKind::Other, "some error")
            ).de_error(),
            Error::IoError(_)
        );

        // Content
        assert_matches!(
            Content(HeaderLengthZero).de_error(),
            Error::IpAuthHeaderLengthZero
        );
    }

    #[test]
    fn from_io_error() {
        assert_matches!(
            de::ReadError::<std::io::Error>::from(
                std::io::Error::new(std::io::ErrorKind::Other, "some error")
            ),
            de::ReadError::IoError(_)
        );
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

    #[test]
    fn de_error() {
        use de::Ipv4Error::*;
        use de::Error;

        // UnexpectedIpVersion
        assert_matches!(
            UnexpectedIpVersion(123).de_error(),
            Error::Ipv4UnexpectedIpVersion(123)
        );

        // IhlTooSmall
        assert_matches!(
            IhlTooSmall(2).de_error(),
            Error::Ipv4IhlTooSmall(2)
        );

        // TotalLengthSmallerThanIhl
        assert_matches!(
            TotalLengthSmallerThanIhl(
                de::Ipv4TotalLengthSmallerThanIhlError{
                    header_length: 12,
                    total_length: 34,
                }
            ).de_error(),
            Error::Ipv4TotalLengthSmallerThanIhl(
                de::Ipv4TotalLengthSmallerThanIhlError{
                    header_length: 12,
                    total_length: 34,
                }
            )
        );
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

    #[test]
    fn de_error() {
        use de::Ipv6Error::*;
        use de::Error;

        // UnexpectedIpVersion
        assert_matches!(
            UnexpectedIpVersion(123).de_error(),
            Error::Ipv6UnexpectedIpVersion(123)
        );
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
        
            // Ipv4Exts
            {
                use de::Ipv4ExtsError::*;
                use de::IpAuthError::*;
                assert_eq!(
                    &format!("{}", Ipv4Exts(Auth(HeaderLengthZero))),
                    &format!("{}", Auth(HeaderLengthZero))
                );
            }

            // Ipv6Exts
            {
                use de::Ipv6ExtsError::*;
                assert_eq!(
                    &format!("{}", Ipv6Exts(HopByHopHeaderNotAtStart)),
                    &format!("{}", HopByHopHeaderNotAtStart)
                );
            }
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

            // Ipv4Exts
            {
                use de::Ipv4ExtsError::*;
                use de::IpAuthError::*;
                assert_eq!(
                    &format!("{:?}", Ipv4Exts(Auth(HeaderLengthZero))),
                    &format!("Ipv4Exts({:?})", Auth(HeaderLengthZero))
                );
            }

            // Ipv6Exts
            {
                use de::Ipv6ExtsError::*;
                assert_eq!(
                    &format!("{:?}", Ipv6Exts(HopByHopHeaderNotAtStart)),
                    &format!("Ipv6Exts({:?})", HopByHopHeaderNotAtStart)
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
            use de::Ipv4ExtsError::Auth;
            use de::IpAuthError::HeaderLengthZero;
            use de::Ipv6ExtsError::HopByHopHeaderNotAtStart;

            let values = [
                UnsupportedIpVersion(arg_u8),
                Ipv4IhlTooSmall(arg_u8),
                Ipv4TotalLengthSmallerThanIhl(
                    de::Ipv4TotalLengthSmallerThanIhlError {
                        header_length: arg2_u16,
                        total_length: arg_u16,
                    }
                ),
                Ipv4Exts(Auth(HeaderLengthZero)),
                Ipv6Exts(HopByHopHeaderNotAtStart),
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
            {
                
                let none_values = [
                    UnsupportedIpVersion(arg_u8),
                    Ipv4IhlTooSmall(arg_u8),
                    Ipv4TotalLengthSmallerThanIhl(
                        de::Ipv4TotalLengthSmallerThanIhlError {
                            header_length: arg2_u16,
                            total_length: arg_u16,
                        }
                    )
                ];
                for value in none_values {
                    assert!(value.source().is_none());
                }
            }
            {
                use de::Ipv4ExtsError::Auth;
                use de::IpAuthError::HeaderLengthZero;
                use de::Ipv6ExtsError::HopByHopHeaderNotAtStart;
                let some_values = [
                    Ipv4Exts(Auth(HeaderLengthZero)),
                    Ipv6Exts(HopByHopHeaderNotAtStart),
                ];
                for value in some_values {
                    assert!(value.source().is_some());
                }
            }
        }
    }

    #[test]
    fn de_error() {
        use de::IpError::*;
        use de::Error;

        // UnsupportedIpVersion
        assert_matches!(
            UnsupportedIpVersion(123).de_error(),
            Error::UnsupportedIpVersion(123)
        );

        // Ipv4IhlTooSmall
        assert_matches!(
            Ipv4IhlTooSmall(12).de_error(),
            Error::Ipv4IhlTooSmall(12)
        );

        // Ipv4TotalLengthSmallerThanIhl
        assert_matches!(
            Ipv4TotalLengthSmallerThanIhl(
                de::Ipv4TotalLengthSmallerThanIhlError {
                    header_length: 23,
                    total_length: 45,
                }
            ).de_error(),
            Error::Ipv4TotalLengthSmallerThanIhl(
                de::Ipv4TotalLengthSmallerThanIhlError {
                    header_length: 23,
                    total_length: 45,
                }
            )
        );

        // Ipv4Exts
        {
            use de::Ipv4ExtsError::*;
            use de::IpAuthError::*;
            assert_matches!(
                Ipv4Exts(Auth(HeaderLengthZero)).de_error(),
                Error::IpAuthHeaderLengthZero
            );
        }

        // Ipv6Exts
        {
            use de::Ipv6ExtsError::*;
            assert_matches!(
                Ipv6Exts(HopByHopHeaderNotAtStart).de_error(),
                Error::Ipv6HopByHopHeaderNotAtStart
            );
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

    #[test]
    fn de_error() {
        use de::Ipv4ExtsError::*;
        use de::IpAuthError::*;
        use de::Error;

        // Auth
        assert_matches!(
            Auth(HeaderLengthZero).de_error(),
            Error::IpAuthHeaderLengthZero
        );
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

    #[test]
    fn de_error() {
        use de::Ipv6ExtsError::*;
        use de::IpAuthError::*;
        use de::Error;

        // HopByHopHeaderNotAtStart
        assert_matches!(
            HopByHopHeaderNotAtStart.de_error(),
            Error::Ipv6HopByHopHeaderNotAtStart
        );

        // Auth
        assert_matches!(
            Auth(HeaderLengthZero).de_error(),
            Error::IpAuthHeaderLengthZero
        );
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

    #[test]
    fn de_error() {
        use de::IpAuthError::*;
        use de::Error;

        // HeaderLengthZero
        assert_matches!(
            HeaderLengthZero.de_error(),
            Error::IpAuthHeaderLengthZero
        );
    }
}


mod tcp_error {
    use super::*;

    proptest! {
        #[test]
        fn display(arg_u8 in any::<u8>()) {
            use de::TcpError::*;

            // DataOffsetTooSmall
            assert_eq!(
                &format!("de::TcpError: TCP data offset too small. The data offset value {} in the tcp header is smaller then the tcp header itself.", arg_u8),
                &format!("{}", DataOffsetTooSmall(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn debug(arg_u8 in any::<u8>()) {
            use de::TcpError::*;

            // DataOffsetTooSmall
            assert_eq!(
                &format!("DataOffsetTooSmall({})", arg_u8),
                &format!("{:?}", DataOffsetTooSmall(arg_u8))
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(arg_u8 in any::<u8>()) {
            use de::TcpError::*;
            let values = [
                DataOffsetTooSmall(arg_u8),
            ];
            for value in values {
                assert_eq!(value.clone(), value);
            }
        }
    }

    proptest! {
        #[test]
        fn error_source(arg_u8 in any::<u8>()) {
            use de::TcpError::*;
            let values = [
                DataOffsetTooSmall(arg_u8),
            ];
            for value in values {
                assert!(value.source().is_none());
            }
        }
    }

    #[test]
    fn de_error() {
        use de::TcpError::*;
        use de::Error;

        // DataOffsetTooSmall
        assert_matches!(
            DataOffsetTooSmall(123).de_error(),
            Error::TcpDataOffsetTooSmall(123)
        );
    }
}
