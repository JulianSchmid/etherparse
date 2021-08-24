use super::super::*;

use crate::ReadError::UnexpectedEndOfSlice;
use crate::ip_number::*;
use std::io::Cursor;

pub mod header {
    use super::*;

    #[test]
    fn read_from_slice() {
        // no extension headers filled
        {
            let some_data = [1,2,3,4];
            let actual = Ipv6Extensions::read_from_slice(UDP, &some_data).unwrap();
            assert_eq!(actual.0, Default::default());
            assert_eq!(actual.1, UDP);
            assert_eq!(actual.2, &some_data);
        }

        // all extension headers filled
        {
            // TODO

            // idear:
            //  - hop by hop is always first
            //  [
            //      - Destination Options header (note 1)
            //      - Routing header
            //      - Fragment header
            //      - Authentication header (note 2)
            //      - Encapsulating Security Payload header (note 2)
            //  ]
            //  - Destination Options header (note 3)

        }

        // duplicate headers early abort
        // TODO

        // error: hop-by-hop not at start
        // TODO
    }

    #[test]
    fn read() {
        // no extension headers filled
        {
            let mut cursor = Cursor::new(&[]);
            let actual = Ipv6Extensions::read(&mut cursor, UDP).unwrap();
            assert_eq!(actual.0, Default::default());
            assert_eq!(actual.1, UDP);
            assert_eq!(0, cursor.position());
        }

        // all extension headers filled
        // TODO

        // duplicate headers early abort
        // TODO

        // error: hop-by-hop not at start
        // TODO
    }

    #[test]
    fn write() {
        // no extension headers filled
        {
            let exts : Ipv6Extensions = Default::default();
            let mut buffer = Vec::new();
            exts.write(&mut buffer, UDP).unwrap();
            assert_eq!(0, buffer.len());
        }

        // all extension headers filled
        // TODO

        // duplicate headers early abort
        // TODO

        // error: hop-by-hop not at start
        // TODO
    }

    proptest!{
        #[test]
        fn header_len(
            hop_by_hop_options in ipv6_raw_extension_any(),
            destination_options in ipv6_raw_extension_any(),
            routing in ipv6_raw_extension_any(),
            fragment in ipv6_fragment_any(),
            auth in ip_authentication_any(),
            final_destination_options in ipv6_raw_extension_any()
        ) {
            // None
            {
                let exts : Ipv6Extensions = Default::default();
                assert_eq!(0, exts.header_len());
            }

            // All filled
            {
                let exts = Ipv6Extensions{
                    hop_by_hop_options: Some(hop_by_hop_options.clone()),
                    destination_options: Some(destination_options.clone()),
                    routing: Some(
                        Ipv6RoutingExtensions{
                            routing: routing.clone(),
                            final_destination_options: Some(final_destination_options.clone()),
                        }
                    ),
                    fragment: Some(fragment.clone()),
                    auth: Some(auth.clone()),
                };
                assert_eq!(
                    exts.header_len(),
                    (
                        hop_by_hop_options.header_len() +
                        destination_options.header_len() +
                        routing.header_len() +
                        final_destination_options.header_len() +
                        fragment.header_len() +
                        auth.header_len()
                    )
                );
            }

            // Routing without final destination options
            {
                let exts = Ipv6Extensions{
                    hop_by_hop_options: Some(hop_by_hop_options.clone()),
                    destination_options: Some(destination_options.clone()),
                    routing: Some(
                        Ipv6RoutingExtensions{
                            routing: routing.clone(),
                            final_destination_options: None,
                        }
                    ),
                    fragment: Some(fragment.clone()),
                    auth: Some(auth.clone()),
                };
                assert_eq!(
                    exts.header_len(),
                    (
                        hop_by_hop_options.header_len() +
                        destination_options.header_len() +
                        routing.header_len() +
                        fragment.header_len() +
                        auth.header_len()
                    )
                );
            }
        }
    }

    #[test]
    fn set_next_headers() {
        // TODO
    }

    #[test]
    fn next_header() {
        // TODO
    }

    #[test]
    fn debug() {
        // TODO
    }

    #[test]
    fn clone_eq() {
        // TODO
    }

    #[test]
    fn default() {
        let a : Ipv6Extensions = Default::default();
        assert_eq!(a.hop_by_hop_options, None);
        assert_eq!(a.destination_options, None);
        assert_eq!(a.routing, None);
        assert_eq!(a.fragment, None);
        assert_eq!(a.auth, None);
    }
}

pub mod slice {
    use super::*;
    
    #[test]
    fn from_slice() {
        // no extension headers filled
        {
            let some_data = [1,2,3,4];
            let actual = Ipv6ExtensionsSlice::from_slice(UDP, &some_data).unwrap();
            assert_eq!(actual.0.is_fragmenting_payload(), false);
            assert_eq!(actual.0.first_header(), None);
            assert_eq!(actual.0.slice().len(), 0);
            assert_eq!(actual.1, UDP);
            assert_eq!(actual.2, &some_data);
        }

        // all extension headers filled
        // TODO

        // duplicate headers early abort
        // TODO

        // error: hop-by-hop not at start
        // TODO
    }

    #[test]
    fn is_fragmenting_payload() {
        // TODO
    }

    #[test]
    fn debug() {
        // TODO
    }

    #[test]
    fn clone_eq() {
        // TODO
    }

    #[test]
    fn default() {
        let a : Ipv6ExtensionsSlice = Default::default();
        assert_eq!(a.is_fragmenting_payload(), false);
        assert_eq!(a.first_header(), None);
        assert_eq!(a.slice().len(), 0);
    }
}

pub mod slice_iter {
    #[test]
    fn into_iter() {
        // TODO
    }

    #[test]
    fn next() {
        // TODO 
    }

    #[test]
    fn debug() {
        // TODO
    }

    #[test]
    fn clone_eq() {
        // TODO
    }
}