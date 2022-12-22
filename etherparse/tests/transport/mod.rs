pub mod icmp;
pub mod icmpv4;
pub mod icmpv6;
pub mod tcp;
pub mod udp;

mod transport_header {
    use super::super::*;
    use std::io::Cursor;
    use std::slice;

    proptest! {
        #[test]
        fn debug(
            tcp in tcp_any(),
            udp in udp_any(),
            icmpv4 in icmpv4_header_any(),
            icmpv6 in icmpv6_header_any(),
        ) {
            use TransportHeader::*;
            assert_eq!(
                format!("Udp({:?})", udp),
                format!("{:?}", Udp(udp.clone())),
            );
            assert_eq!(
                format!("Tcp({:?})", tcp),
                format!("{:?}", Tcp(tcp.clone())),
            );
            assert_eq!(
                format!("Icmpv4({:?})", icmpv4),
                format!("{:?}", Icmpv4(icmpv4.clone())),
            );
            assert_eq!(
                format!("Icmpv6({:?})", icmpv6),
                format!("{:?}", Icmpv6(icmpv6.clone())),
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            tcp in tcp_any(),
            udp in udp_any(),
            icmpv4 in icmpv4_header_any(),
            icmpv6 in icmpv6_header_any(),
        ) {
            use TransportHeader::*;
            let values = [
                Udp(udp),
                Tcp(tcp),
                Icmpv4(icmpv4),
                Icmpv6(icmpv6),
            ];
            for value in values {
                assert_eq!(value.clone(), value);
            }
        }
    }

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
        fn icmpv4(icmpv4 in icmpv4_header_any()) {
            assert_eq!(Some(icmpv4.clone()), TransportHeader::Icmpv4(icmpv4).icmpv4());
            assert_eq!(None, TransportHeader::Udp(Default::default()).icmpv4());
        }
    }
    proptest! {
        #[test]
        fn mut_icmpv4(icmpv4 in icmpv4_header_any()) {
            assert_eq!(Some(&mut icmpv4.clone()), TransportHeader::Icmpv4(icmpv4).mut_icmpv4());
            assert_eq!(None, TransportHeader::Udp(Default::default()).mut_icmpv4());
        }
    }
    proptest! {
        #[test]
        fn icmpv6(icmpv6 in icmpv6_header_any()) {
            assert_eq!(Some(icmpv6.clone()), TransportHeader::Icmpv6(icmpv6).icmpv6());
            assert_eq!(None, TransportHeader::Udp(Default::default()).icmpv6());
        }
    }
    proptest! {
        #[test]
        fn mut_icmpv6(icmpv6 in icmpv6_header_any()) {
            assert_eq!(Some(&mut icmpv6.clone()), TransportHeader::Icmpv6(icmpv6).mut_icmpv6());
            assert_eq!(None, TransportHeader::Udp(Default::default()).mut_icmpv6());
        }
    }
    proptest! {
        #[test]
        fn header_size(
            udp in udp_any(),
            tcp in tcp_any(),
            icmpv4 in icmpv4_header_any(),
            icmpv6 in icmpv6_header_any(),
        ) {
            assert_eq!(
                TransportHeader::Udp(udp).header_len(),
                UdpHeader::SERIALIZED_SIZE
            );
            assert_eq!(
                TransportHeader::Tcp(tcp.clone()).header_len(),
                tcp.header_len() as usize
            );
            assert_eq!(
                TransportHeader::Icmpv4(icmpv4.clone()).header_len(),
                icmpv4.header_len()
            );
            assert_eq!(
                TransportHeader::Icmpv6(icmpv6.clone()).header_len(),
                icmpv6.header_len()
            );
        }
    }
    proptest! {
        #[test]
        fn update_checksum_ipv4(
            ipv4 in ipv4_any(),
            udp in udp_any(),
            tcp in tcp_any(),
            icmpv4 in icmpv4_header_any(),
            icmpv6 in icmpv6_header_any(),
        ) {
            use TransportHeader::*;

            // udp
            {
                // ok case
                {
                    let mut transport = Udp(udp.clone());
                    let payload = Vec::new();
                    transport.update_checksum_ipv4(&ipv4, &payload).unwrap();
                    assert_eq!(transport.udp().unwrap().checksum,
                               udp.calc_checksum_ipv4(&ipv4, &payload).unwrap());
                }
                // error case
                {
                    let mut transport = Udp(udp.clone());
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
                    assert_eq!(Err(ValueError::UdpPayloadLengthTooLarge(len)), transport.update_checksum_ipv4(&ipv4, &tcp_payload));
                }
            }
            // tcp
            {
                //ok case
                {
                    let mut transport = Tcp(tcp.clone());
                    let payload = Vec::new();
                    transport.update_checksum_ipv4(&ipv4, &payload).unwrap();
                    assert_eq!(transport.tcp().unwrap().checksum,
                               tcp.calc_checksum_ipv4(&ipv4, &payload).unwrap());
                }
                //error case
                {
                    let mut transport = Tcp(tcp.clone());
                    let len = (std::u16::MAX - tcp.header_len()) as usize + 1;
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
                    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), transport.update_checksum_ipv4(&ipv4, &tcp_payload));
                }
            }

            // icmpv4
            {
                let mut transport = Icmpv4(icmpv4.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv4(&ipv4, &payload).unwrap();
                assert_eq!(
                    transport.icmpv4().unwrap().checksum,
                    icmpv4.icmp_type.calc_checksum(&payload)
                );
            }

            // icmpv6 (error)
            assert_eq!(
                Icmpv6(icmpv6).update_checksum_ipv4(&ipv4, &[]),
                Err(ValueError::Icmpv6InIpv4)
            );
        }
    }

    proptest! {
        #[test]
        #[cfg(target_pointer_width = "64")]
        fn update_checksum_ipv6(
            ipv6 in ipv6_any(),
            udp in udp_any(),
            tcp in tcp_any(),
            icmpv4 in icmpv4_header_any(),
            icmpv6 in icmpv6_header_any(),
        ) {
            use TransportHeader::*;

            // udp
            {
                //ok case
                {
                    let mut transport = Udp(udp.clone());
                    let payload = Vec::new();
                    transport.update_checksum_ipv6(&ipv6, &payload).unwrap();
                    assert_eq!(transport.udp().unwrap().checksum,
                               udp.calc_checksum_ipv6(&ipv6, &payload).unwrap());
                }
                //error case
                {
                    let mut transport = Udp(udp.clone());
                    let len = (std::u32::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1;
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
                    assert_eq!(
                        Err(ValueError::UdpPayloadLengthTooLarge(len)),
                        transport.update_checksum_ipv6(&ipv6, &payload)
                    );
                }
            }
            // tcp
            {
                //ok case
                {
                    let mut transport = Tcp(tcp.clone());
                    let payload = Vec::new();
                    transport.update_checksum_ipv6(&ipv6, &payload).unwrap();
                    assert_eq!(transport.tcp().unwrap().checksum,
                               tcp.calc_checksum_ipv6(&ipv6, &payload).unwrap());
                }
                //error case
                {
                    let mut transport = Tcp(tcp.clone());
                    let len = (std::u32::MAX - tcp.header_len() as u32) as usize + 1;
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
                    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), transport.update_checksum_ipv6(&ipv6, &tcp_payload));
                }
            }

            // icmpv4
            {
                let mut transport = Icmpv4(icmpv4.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv6(&ipv6, &payload).unwrap();
                assert_eq!(
                    transport.icmpv4().unwrap().checksum,
                    icmpv4.icmp_type.calc_checksum(&payload)
                );
            }

            // icmpv6
            {
                // normal case
                {
                    let mut transport = Icmpv6(icmpv6.clone());
                    let payload = Vec::new();
                    transport.update_checksum_ipv6(&ipv6, &payload).unwrap();
                    assert_eq!(
                        transport.icmpv6().unwrap().checksum,
                        icmpv6.icmp_type.calc_checksum(ipv6.source, ipv6.destination, &payload).unwrap()
                    );
                }

                // error case
                {
                    let mut transport = Icmpv6(icmpv6.clone());
                    // SAFETY: In case the error is not triggered
                    //         a segmentation fault will be triggered.
                    let too_big_slice = unsafe {
                        //NOTE: The pointer must be initialized with a non null value
                        //      otherwise a key constraint of slices is not fullfilled
                        //      which can lead to crashes in release mode.
                        use std::ptr::NonNull;
                        std::slice::from_raw_parts(
                            NonNull::<u8>::dangling().as_ptr(),
                            (std::u32::MAX - 7) as usize
                        )
                    };
                    assert_matches!(
                        transport.update_checksum_ipv6(&ipv6, too_big_slice),
                        Err(ValueError::Ipv6PayloadLengthTooLarge(_))
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn write(
            udp in udp_any(),
            tcp in tcp_any(),
            icmpv4 in icmpv4_header_any(),
            icmpv6 in icmpv6_header_any(),
        ) {
            // udp
            {
                //write
                {
                    let result_input = {
                        let mut buffer = Vec::new();
                        udp.write(&mut buffer).unwrap();
                        buffer
                    };
                    let result_transport = {
                        let mut buffer = Vec::new();
                        TransportHeader::Udp(udp.clone()).write(&mut buffer).unwrap();
                        buffer
                    };
                    assert_eq!(result_input, result_transport);
                }
                //trigger an error
                {
                    let mut a: [u8;0] = [];
                    assert_matches!(TransportHeader::Udp(udp.clone()).write(&mut Cursor::new(&mut a[..])),
                                    Err(WriteError::IoError(_)));
                }
            }
            // tcp
            {
                //write
                {
                    let result_input = {
                        let mut buffer = Vec::new();
                        tcp.write(&mut buffer).unwrap();
                        buffer
                    };
                    let result_transport = {
                        let mut buffer = Vec::new();
                        TransportHeader::Tcp(tcp.clone()).write(&mut buffer).unwrap();
                        buffer
                    };
                    assert_eq!(result_input, result_transport);
                }
                //trigger an error
                {
                    let mut a: [u8;0] = [];
                    assert_matches!(TransportHeader::Tcp(tcp.clone()).write(&mut Cursor::new(&mut a[..])),
                                    Err(WriteError::IoError(_)));
                }
            }

            // icmpv4
            {
                // normal write
                {
                    let result_input = {
                        let mut buffer = Vec::new();
                        icmpv4.write(&mut buffer).unwrap();
                        buffer
                    };
                    let result_transport = {
                        let mut buffer = Vec::new();
                        TransportHeader::Icmpv4(icmpv4.clone()).write(&mut buffer).unwrap();
                        buffer
                    };
                    assert_eq!(result_input, result_transport);
                }

                // error during write
                {
                    let mut a: [u8;0] = [];
                    assert_matches!(
                        TransportHeader::Icmpv4(icmpv4.clone()).write(&mut Cursor::new(&mut a[..])),
                        Err(WriteError::IoError(_))
                    );
                }
            }

            // icmpv6
            {
                // normal write
                {
                    let result_input = {
                        let mut buffer = Vec::new();
                        icmpv6.write(&mut buffer).unwrap();
                        buffer
                    };
                    let result_transport = {
                        let mut buffer = Vec::new();
                        TransportHeader::Icmpv6(icmpv6.clone()).write(&mut buffer).unwrap();
                        buffer
                    };
                    assert_eq!(result_input, result_transport);
                }

                // error during write
                {
                    let mut a: [u8;0] = [];
                    assert_matches!(
                        TransportHeader::Icmpv6(icmpv6.clone()).write(&mut Cursor::new(&mut a[..])),
                        Err(WriteError::IoError(_))
                    );
                }
            }
        }
    }
}
