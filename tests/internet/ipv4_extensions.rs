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

    #[test]
    fn read() {
        // TODO
    }

    #[test]
    fn write() {
        // TODO
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
        // TODO
    }

} // mod header

mod slice {
    #[test]
    fn from_slice() {
        // TODO
    }

    #[test]
    fn to_header() {
        // TODO
    }
}