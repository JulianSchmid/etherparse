use super::super::*;

use crate::ReadError::UnexpectedEndOfSlice;
use crate::ip_number::*;
use std::io::Cursor;

pub mod header {
    use super::*;

    #[test]
    fn read_from_slice() {
        let auth_header = IpAuthenticationHeader::new(
            UDP,
            0,
            0,
            &[]
        ).unwrap();

        let buffer = {
            let mut buffer = Vec::with_capacity(auth_header.header_len());
            auth_header.write(&mut buffer).unwrap();
            buffer.push(1);
            buffer.push(2);
            buffer
        };

        // no auth header
        {
            let (header, next, rest) = Ipv4Extensions::read_from_slice(
                TCP,
                &buffer
            ).unwrap();
            assert!(header.auth.is_none());
            assert_eq!(TCP, next);
            assert_eq!(rest, &buffer);
        }

        // with auth header
        {
            let (actual, next, rest) = Ipv4Extensions::read_from_slice(
                AUTH,
                &buffer
            ).unwrap();
            assert_eq!(actual.auth.unwrap(), auth_header);
            assert_eq!(UDP, next);
            assert_eq!(rest, &buffer[auth_header.header_len()..]);
        }
        
        // too small
        {
            let err = Ipv4Extensions::read_from_slice(
                AUTH,
                &buffer[..auth_header.header_len() - 1]
            ).unwrap_err();
            const AUTH_HEADER_LEN: usize = 12;
            assert_matches!(
                err,
                UnexpectedEndOfSlice(AUTH_HEADER_LEN)
            );
        }
    }
    proptest! {
        #[test]
        fn read(auth in ip_authentication_any()) {
            // None
            {
                let mut cursor = Cursor::new(&[]);
                let (actual, next) = Ipv4Extensions::read(&mut cursor, UDP).unwrap();
                assert_eq!(next, UDP);
                assert_eq!(
                    actual,
                    Ipv4Extensions{
                        auth: None,
                    }
                );
            }

            // Some sucessfull
            {
                let buffer = {
                    let mut buffer = Vec::with_capacity(auth.header_len());
                    auth.write(&mut buffer).unwrap();
                    buffer.push(1);
                    buffer
                };
                let mut cursor = Cursor::new(&buffer);
                let (actual, next) = Ipv4Extensions::read(&mut cursor, AUTH).unwrap();
                assert_eq!(auth.header_len(), cursor.position() as usize);
                assert_eq!(next, auth.next_header);
                assert_eq!(
                    actual,
                    Ipv4Extensions{
                        auth: Some(auth.clone()),
                    }
                );
            }

            // Some error
            {
                let mut cursor = Cursor::new(&[]);
                let err = Ipv4Extensions::read(&mut cursor, AUTH).unwrap_err();
                assert_matches!(
                    err,
                    ReadError::IoError(_)
                );
            }
        }
    }

    #[test]
    fn write() {
        // None
        {
            let mut buffer = Vec::new();
            Ipv4Extensions{
                auth: None,
            }.write(&mut buffer, UDP).unwrap();
            assert_eq!(0, buffer.len());
        }

        // Some
        let auth_header = IpAuthenticationHeader::new(
            UDP,
            0,
            0,
            &[]
        ).unwrap();
        {
            let mut buffer = Vec::with_capacity(auth_header.header_len());
            Ipv4Extensions{
                auth: Some(auth_header.clone()),
            }.write(&mut buffer, AUTH).unwrap();
            let (read_header, _) = IpAuthenticationHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(auth_header, read_header);
        }

        // Some bad start number
        {
            let mut buffer = Vec::new();
            let err = Ipv4Extensions{
                auth: Some(auth_header.clone()),
            }.write(&mut buffer, UDP).unwrap_err();
            assert_matches!(
                err,
                WriteError::ValueError(
                    ValueError::Ipv4ExtensionNotReferenced(
                        IpNumber::AuthenticationHeader
                    )
                )
            );
        }

        // Some: Write error
        {
            let mut writer = TestWriter::with_max_size(
                auth_header.header_len() - 1
            );
            let err = Ipv4Extensions{
                auth: Some(auth_header.clone()),
            }.write(&mut writer, AUTH).unwrap_err();
            assert_eq!(
                std::io::ErrorKind::UnexpectedEof,
                err.io_error().unwrap().kind()
            );
        }
    }

    #[test]
    fn header_len() {
        // None
        assert_eq!(
            0,
            Ipv4Extensions{
                auth: None,
            }.header_len()
        );

        // Some
        {
            let auth = IpAuthenticationHeader::new(
                UDP,
                0,
                0,
                &[]
            ).unwrap();
            assert_eq!(
                auth.header_len(),
                Ipv4Extensions{
                    auth: Some(auth),
                }.header_len()
            );
        }
        // Some with paylaod
        {
            let auth = IpAuthenticationHeader::new(
                UDP,
                0,
                0,
                &[ 1, 2, 3, 4 ]
            ).unwrap();
            assert_eq!(
                auth.header_len(),
                Ipv4Extensions{
                    auth: Some(auth),
                }.header_len()
            );
        }
    }

    #[test]
    fn set_next_headers() {
        // None
        {
            let mut exts = Ipv4Extensions{
                auth: None,
            };
            assert_eq!(UDP, exts.set_next_headers(UDP));
        }

        // Some
        {
            let mut exts = Ipv4Extensions{
                auth: Some(
                    IpAuthenticationHeader::new(
                        TCP,
                        0,
                        0,
                        &[]
                    ).unwrap()
                ),
            };
            assert_eq!(TCP, exts.auth.as_ref().unwrap().next_header);
            // change from TCP to UDP
            let re = exts.set_next_headers(UDP);
            assert_eq!(AUTH, re);
            assert_eq!(UDP, exts.auth.as_ref().unwrap().next_header);
        }
    }

    proptest! {
        #[test]
        fn debug(auth in ip_authentication_any()) {
            // None
            assert_eq!(
                &format!("Ipv4Extensions {{ auth: {:?} }}", Option::<IpAuthenticationHeader>::None),
                &format!(
                    "{:?}",
                    Ipv4Extensions {
                        auth: None,
                    }
                )
            );

            // Some
            assert_eq!(
                &format!("Ipv4Extensions {{ auth: {:?} }}", Some(auth.clone())),
                &format!(
                    "{:?}",
                    Ipv4Extensions {
                        auth: Some(auth.clone()),
                    }
                )
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(auth in ip_authentication_any()) {
            // None
            {
                let header = Ipv4Extensions{
                    auth: None,
                };
                assert_eq!(
                    header.clone(),
                    Ipv4Extensions{
                        auth: None,
                    }
                );
            }
            
            // Some
            {
                let header = Ipv4Extensions{
                    auth: Some(auth.clone()),
                };
                assert_eq!(
                    header.clone(),
                    Ipv4Extensions{
                        auth: Some(auth.clone()),
                    }
                );
            }
        }
    }
} // mod header

mod slice {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(auth in ip_authentication_any()) {
            // None
            {
                let buffer = [1,2,3,4];
                let (slice, next, rest) = Ipv4ExtensionsSlice::from_slice(UDP, &buffer).unwrap();
                assert_eq!(
                    slice,
                    Ipv4ExtensionsSlice{
                        auth: None,
                    }
                );
                assert_eq!(next, UDP);
                assert_eq!(rest, &buffer);
            }

            // Some
            {
                let buffer = {
                    let mut buffer = Vec::with_capacity(auth.header_len());
                    auth.write(&mut buffer).unwrap();
                    // add some data to check the returned rest slice is correct
                    // and not just nothing
                    buffer.push(1);
                    buffer
                };
                let (slice, next, rest) = Ipv4ExtensionsSlice::from_slice(AUTH, &buffer).unwrap();
                assert_eq!(
                    slice,
                    Ipv4ExtensionsSlice{
                        auth: Some(
                            IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap()
                        ),
                    }
                );
                assert_eq!(next, auth.next_header);
                assert_eq!(rest, &buffer[auth.header_len()..]);
            }

            // Error unexpected end of slice
            {
                let err = Ipv4ExtensionsSlice::from_slice(AUTH, &[]).unwrap_err();
                const AUTH_HEADER_LEN: usize = 12;
                assert_matches!(
                    err,
                    UnexpectedEndOfSlice(AUTH_HEADER_LEN)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn to_header(auth in ip_authentication_any()) {
            // None
            assert_eq!(
                Ipv4ExtensionsSlice{
                    auth: None,
                }.to_header(),
                Ipv4Extensions{
                    auth: None,
                }
            );

            // Some
            {
                let buffer = {
                    let mut buffer = Vec::with_capacity(auth.header_len());
                    auth.write(&mut buffer).unwrap();
                    buffer
                };
                let slice = Ipv4ExtensionsSlice{
                    auth: Some(
                        IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap()
                    ),
                };
                assert_eq!(
                    slice.to_header(),
                    Ipv4Extensions{
                        auth: Some(auth.clone()),
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn debug(auth in ip_authentication_any()) {
            // None
            assert_eq!(
                &format!("Ipv4ExtensionsSlice {{ auth: {:?} }}", Option::<IpAuthenticationHeader>::None),
                &format!(
                    "{:?}",
                    Ipv4ExtensionsSlice {
                        auth: None,
                    }
                )
            );

            // Some
            let buffer = {
                let mut buffer = Vec::with_capacity(auth.header_len());
                auth.write(&mut buffer).unwrap();
                buffer
            };
            let auth_slice = IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                &format!("Ipv4ExtensionsSlice {{ auth: {:?} }}", Some(auth_slice.clone())),
                &format!(
                    "{:?}",
                    Ipv4ExtensionsSlice {
                        auth: Some(auth_slice.clone()),
                    }
                )
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(auth in ip_authentication_any()) {
            // None
            {
                let header = Ipv4ExtensionsSlice{
                    auth: None,
                };
                assert_eq!(
                    header.clone(),
                    Ipv4ExtensionsSlice{
                        auth: None,
                    }
                );
            }
            
            // Some
            {
                let buffer = {
                    let mut buffer = Vec::with_capacity(auth.header_len());
                    auth.write(&mut buffer).unwrap();
                    buffer
                };
                let auth_slice = IpAuthenticationHeaderSlice::from_slice(&buffer).unwrap();
                let slice = Ipv4ExtensionsSlice {
                    auth: Some(auth_slice.clone()),
                };
                assert_eq!(
                    slice.clone(),
                    Ipv4ExtensionsSlice{
                        auth: Some(auth_slice.clone()),
                    }
                );
            }
        }
    }
}