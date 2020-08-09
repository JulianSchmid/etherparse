pub mod udp;
pub mod tcp;

mod transport_header {
    use super::super::*;
    use std::slice;
    use std::io::Cursor;

    #[test]
    fn udp() {
        let udp: UdpHeader = Default::default();
        assert_eq!(Some(udp.clone()), TransportHeader::Udp(udp).udp());
        assert_eq!(None, TransportHeader::Tcp(Default::default()).udp());
    }
    #[test]
    fn mut_udp() {
        let udp: UdpHeader = Default::default();
        assert_eq!(Some(&mut udp.clone()), TransportHeader::Udp(udp).mut_udp());
        assert_eq!(None, TransportHeader::Tcp(Default::default()).mut_udp());
    }
    #[test]
    fn tcp() {
        let tcp: TcpHeader = Default::default();
        assert_eq!(Some(tcp.clone()), TransportHeader::Tcp(tcp).tcp());
        assert_eq!(None, TransportHeader::Udp(Default::default()).tcp());
    }
    #[test]
    fn mut_tcp() {
        let tcp: TcpHeader = Default::default();
        assert_eq!(Some(&mut tcp.clone()), TransportHeader::Tcp(tcp).mut_tcp());
        assert_eq!(None, TransportHeader::Udp(Default::default()).mut_tcp());
    }
    proptest! {
        #[test]
        fn header_size_tcp(ref input in tcp_any()) {
            assert_eq!(TransportHeader::Tcp(input.clone()).header_len(), 
                       input.header_len() as usize);
        }
        
    }
    proptest! {
        #[test]
        fn header_size_udp(ref input in udp_any()) {
            assert_eq!(TransportHeader::Udp(input.clone()).header_len(), 
                       UdpHeader::SERIALIZED_SIZE);
        }
    }
    proptest! {
        #[test]
        fn update_checksum_ipv4_udp(ref ip_header in ipv4_with(ip_number::UDP),
                                    ref udp_header in udp_any())
        {
            //ok case
            {
                let mut transport = TransportHeader::Udp(udp_header.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv4(&ip_header, &payload).unwrap();
                assert_eq!(transport.udp().unwrap().checksum, 
                           udp_header.calc_checksum_ipv4(&ip_header, &payload).unwrap());
            }
            //error case
            {
                let mut transport = TransportHeader::Udp(udp_header.clone());
                let len = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1;
                let tcp_payload = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        len
                    )
                };
                assert_eq!(Err(ValueError::UdpPayloadLengthTooLarge(len)), transport.update_checksum_ipv4(&ip_header, &tcp_payload));
            }
        }
    }
    proptest! {
        #[test]
        fn update_checksum_ipv4_tcp(ref ip_header in ipv4_with(ip_number::TCP),
                                    ref tcp_header in tcp_any())
        {
            //ok case
            {
                let mut transport = TransportHeader::Tcp(tcp_header.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv4(&ip_header, &payload).unwrap();
                assert_eq!(transport.tcp().unwrap().checksum, 
                           tcp_header.calc_checksum_ipv4(&ip_header, &payload).unwrap());
            }
            //error case
            {
                let mut transport = TransportHeader::Tcp(tcp_header.clone());
                let len = (std::u16::MAX - tcp_header.header_len()) as usize + 1;
                let tcp_payload = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        len
                    )
                };
                assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), transport.update_checksum_ipv4(&ip_header, &tcp_payload));
            }
        }
    }
    proptest! {
        #[test]
        #[cfg(target_pointer_width = "64")] 
        fn update_checksum_ipv6_udp(ref ip_header in ipv6_with(ip_number::UDP),
                                    ref udp_header in udp_any())
        {
            //ok case
            {
                let mut transport = TransportHeader::Udp(udp_header.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv6(&ip_header, &payload).unwrap();
                assert_eq!(transport.udp().unwrap().checksum, 
                           udp_header.calc_checksum_ipv6(&ip_header, &payload).unwrap());
            }
            //error case
            {
                let mut transport = TransportHeader::Udp(udp_header.clone());
                let len = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1;
                let payload = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        len
                    )
                };
                assert_eq!(Err(ValueError::UdpPayloadLengthTooLarge(len)), transport.update_checksum_ipv6(&ip_header, &payload));
            }
        }
    }
    proptest! {
        #[test]
        #[cfg(target_pointer_width = "64")] 
        fn update_checksum_ipv6_tcp(ref ip_header in ipv6_with(ip_number::TCP),
                                    ref tcp_header in tcp_any())
        {
            //ok case
            {
                let mut transport = TransportHeader::Tcp(tcp_header.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv6(&ip_header, &payload).unwrap();
                assert_eq!(transport.tcp().unwrap().checksum, 
                           tcp_header.calc_checksum_ipv6(&ip_header, &payload).unwrap());
            }
            //error case
            {
                let mut transport = TransportHeader::Tcp(tcp_header.clone());
                let len = (std::u32::MAX - tcp_header.header_len() as u32) as usize + 1;
                let tcp_payload = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        len
                    )
                };
                assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), transport.update_checksum_ipv6(&ip_header, &tcp_payload));
            }
        }
    }
    proptest! {
        #[test]
        fn write_udp(ref input in udp_any()) {
            //write
            {
                let result_input = {
                    let mut buffer = Vec::new();
                    input.write(&mut buffer).unwrap();
                    buffer
                };
                let result_transport = {
                    let mut buffer = Vec::new();
                    TransportHeader::Udp(input.clone()).write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(result_input, result_transport);
            }
            //trigger an error
            {
                let mut a: [u8;0] = [];
                assert_matches!(TransportHeader::Udp(input.clone()).write(&mut Cursor::new(&mut a[..])),
                                Err(WriteError::IoError(_)));
            }
        }
    }
    proptest! {
        #[test]
        fn write_tcp(ref input in tcp_any()) {
            //write
            {
                let result_input = {
                    let mut buffer = Vec::new();
                    input.write(&mut buffer).unwrap();
                    buffer
                };
                let result_transport = {
                    let mut buffer = Vec::new();
                    TransportHeader::Tcp(input.clone()).write(&mut buffer).unwrap();
                    buffer
                };
                assert_eq!(result_input, result_transport);
            }
            //trigger an error
            {
                let mut a: [u8;0] = [];
                assert_matches!(TransportHeader::Tcp(input.clone()).write(&mut Cursor::new(&mut a[..])),
                                Err(WriteError::IoError(_)));
            }
        }
    }
}