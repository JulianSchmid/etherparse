pub mod udp;
pub mod tcp;

mod transport_header {
    use super::super::*;
    use std::slice;

    #[test]
    fn udp() {
        let udp: UdpHeader = Default::default();
        assert_eq!(Some(udp.clone()), TransportHeader::Udp(udp).udp());
        assert_eq!(None, TransportHeader::Tcp(Default::default()).udp());
    }

    #[test]
    fn tcp() {
        let tcp: TcpHeader = Default::default();
        assert_eq!(Some(tcp.clone()), TransportHeader::Tcp(tcp).tcp());
        assert_eq!(None, TransportHeader::Udp(Default::default()).tcp());
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
        fn update_checksum_ipv4_udp(ref ip_header in ipv4_with(IpTrafficClass::Udp as u8),
                                    ref udp_header in udp_any())
        {
            //ok case
            {
                let mut transport = TransportHeader::Udp(udp_header.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv4(&ip_header.0, &payload).unwrap();
                assert_eq!(transport.udp().unwrap().checksum, 
                           udp_header.calc_checksum_ipv4(&ip_header.0, &payload).unwrap());
            }
            //error case
            {
                let mut transport = TransportHeader::Udp(udp_header.clone());
                let len = (std::u16::MAX as usize) - UdpHeader::SERIALIZED_SIZE + 1;
                let tcp_payload = unsafe {
                    slice::from_raw_parts(0x0 as *const u8, len)
                };
                assert_eq!(Err(ValueError::UdpPayloadLengthTooLarge(len)), transport.update_checksum_ipv4(&ip_header.0, &tcp_payload));
            }
        }
    }
    proptest! {
        #[test]
        fn update_checksum_ipv4_tcp(ref ip_header in ipv4_with(IpTrafficClass::Tcp as u8),
                                    ref tcp_header in tcp_any())
        {
            //ok case
            {
                let mut transport = TransportHeader::Tcp(tcp_header.clone());
                let payload = Vec::new();
                transport.update_checksum_ipv4(&ip_header.0, &payload).unwrap();
                assert_eq!(transport.tcp().unwrap().checksum, 
                           tcp_header.calc_checksum_ipv4(&ip_header.0, &payload).unwrap());
            }
            //error case
            {
                let mut transport = TransportHeader::Tcp(tcp_header.clone());
                let len = (std::u16::MAX - tcp_header.header_len()) as usize + 1;
                let tcp_payload = unsafe {
                    slice::from_raw_parts(0x0 as *const u8, len)
                };
                assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), transport.update_checksum_ipv4(&ip_header.0, &tcp_payload));
            }
        }
    }
    proptest! {
        #[test]
        #[cfg(target_pointer_width = "64")] 
        fn update_checksum_ipv6_udp(ref ip_header in ipv6_with(IpTrafficClass::Udp as u8),
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
                    slice::from_raw_parts(0x0 as *const u8, len)
                };
                assert_eq!(Err(ValueError::UdpPayloadLengthTooLarge(len)), transport.update_checksum_ipv6(&ip_header, &payload));
            }
        }
    }
    proptest! {
        #[test]
        #[cfg(target_pointer_width = "64")] 
        fn update_checksum_ipv6_tcp(ref ip_header in ipv6_with(IpTrafficClass::Tcp as u8),
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
                    slice::from_raw_parts(0x0 as *const u8, len)
                };
                assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), transport.update_checksum_ipv6(&ip_header, &tcp_payload));
            }
        }
    }
}