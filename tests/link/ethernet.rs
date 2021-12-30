use super::super::*;

use std::io::{Cursor, ErrorKind};

mod ether_type {
    use super::*;

    #[test]
    fn to_u16() {
        use crate::EtherType::*;
        assert_eq!(0x0800, Ipv4 as u16);
        assert_eq!(0x86dd, Ipv6 as u16);
        assert_eq!(0x0806, Arp as u16);
        assert_eq!(0x0842, WakeOnLan as u16);
        assert_eq!(0x8100, VlanTaggedFrame as u16);
        assert_eq!(0x88A8, ProviderBridging as u16);
        assert_eq!(0x9100, VlanDoubleTaggedFrame as u16);
    }

    #[test]
    fn from_u16() {
        use crate::EtherType::*;
        assert_eq!(EtherType::from_u16(0x0800), Some(Ipv4));
        assert_eq!(EtherType::from_u16(0x86dd), Some(Ipv6));
        assert_eq!(EtherType::from_u16(0x0806), Some(Arp));
        assert_eq!(EtherType::from_u16(0x0842), Some(WakeOnLan));
        assert_eq!(EtherType::from_u16(0x8100), Some(VlanTaggedFrame));
        assert_eq!(EtherType::from_u16(0x88A8), Some(ProviderBridging));
        assert_eq!(EtherType::from_u16(0x9100), Some(VlanDoubleTaggedFrame));
        assert_eq!(EtherType::from_u16(0x1234), None);
    }

    #[test]
    fn constants() {
        use crate::EtherType::*;
        use crate::ether_type::*;
        let pairs = &[
            (Ipv4, IPV4),
            (Ipv6, IPV6),
            (Arp, ARP),
            (WakeOnLan, WAKE_ON_LAN),
            (VlanTaggedFrame, VLAN_TAGGED_FRAME),
            (ProviderBridging, PROVIDER_BRIDGING),
            (VlanDoubleTaggedFrame, VLAN_DOUBLE_TAGGED_FRAME)
        ];

        for (enum_value, constant) in pairs {
            assert_eq!(enum_value.clone() as u16, *constant);
        }
    }

    #[test]
    fn dbg() {
        use crate::EtherType::*;
        let pairs = &[
            (Ipv4, "Ipv4"),
            (Ipv6, "Ipv6"),
            (Arp, "Arp"),
            (WakeOnLan, "WakeOnLan"),
            (VlanTaggedFrame, "VlanTaggedFrame"),
            (ProviderBridging, "ProviderBridging"),
            (VlanDoubleTaggedFrame, "VlanDoubleTaggedFrame")
        ];

        for (enum_value, str_value) in pairs {
            assert_eq!(
                str_value,
                &format!("{:?}", enum_value)
            );
        }
    }

    #[test]
    fn clone_eq() {
        use crate::EtherType::*;
        let values = &[
            Ipv4,
            Ipv6,
            Arp,
            WakeOnLan,
            VlanTaggedFrame,
            ProviderBridging,
            VlanDoubleTaggedFrame,
        ];

        // clone
        for v in values {
            assert_eq!(v, &v.clone());
        }

        // eq
        for (a_pos, a) in values.iter().enumerate() {
            for (b_pos, b) in values.iter().enumerate() {
                assert_eq!(
                    a_pos == b_pos, 
                    a == b
                );
                assert_eq!(
                    a_pos != b_pos, 
                    a != b
                );
            }
        }
    }
}

mod ethernet2_header {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(
            input in ethernet_2_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(14 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let (result, rest) = Ethernet2Header::from_slice(&buffer[..]).unwrap();
                assert_eq!(input, result);
                assert_eq!(&buffer[14..], rest);
            }
            #[allow(deprecated)]
            {
                let (result, rest) = Ethernet2Header::read_from_slice(&buffer[..]).unwrap();
                assert_eq!(input, result);
                assert_eq!(&buffer[14..], rest);
            }

            // call with not enough data in the slice
            for len in 0..=13 {
                assert_eq!(
                    Ethernet2Header::from_slice(&buffer[0..len]),
                    Err(UnexpectedEndOfSliceError{ expected_min_len: 14, actual_len: len })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_bytes(input in ethernet_2_any()) {
            assert_eq!(
                input,
                Ethernet2Header::from_bytes(input.to_bytes())
            );
        }
    }

    proptest! {
        #[test]
        fn read(
            input in ethernet_2_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // normal read
            let mut buffer = Vec::with_capacity(14 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let mut cursor = Cursor::new(&buffer);
                let result = Ethernet2Header::read(&mut cursor).unwrap();
                assert_eq!(input, result);
                assert_eq!(cursor.position(), 14);
            }

            // unexpected eof
            for len in 0..=13 {
                let mut cursor = Cursor::new(&buffer[0..len]);
                assert_eq!(
                    Ethernet2Header::read(&mut cursor)
                    .unwrap_err()
                    .kind(),
                    ErrorKind::UnexpectedEof
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write_to_slice(input in ethernet_2_any()) {
            // normal write
            {
                let mut buffer: [u8;14] = [0;14];
                input.write_to_slice(&mut buffer).unwrap();
                assert_eq!(buffer, input.to_bytes());
            }
            // len to small
            for len in 0..14 {
                let mut buffer: [u8;14] = [0;14];
                assert_eq!(
                    input.write_to_slice(&mut buffer[..len])
                        .unwrap_err()
                        .slice_too_small_size()
                        .unwrap(),
                    Ethernet2Header::SERIALIZED_SIZE
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write(input in ethernet_2_any()) {
            // successfull write
            {
                let mut buffer: Vec<u8> = Vec::with_capacity(14);
                input.write(&mut buffer).unwrap();
                assert_eq!(&buffer[..], &input.to_bytes());
            }

            // not enough memory for write (unexpected eof)
            for len in 0..8 {
                let mut writer = TestWriter::with_max_size(len);
                assert_eq!(
                    ErrorKind::UnexpectedEof,
                    input.write(&mut writer).unwrap_err().kind()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(input in ethernet_2_any()) {
            assert_eq!(input.header_len(), 14);
        }
    }

    proptest! {
        #[test]
        fn to_bytes(input in ethernet_2_any()) {
            let ether_type_be = input.ether_type.to_be_bytes();
            assert_eq!(
                input.to_bytes(),
                [
                    input.destination[0],
                    input.destination[1],
                    input.destination[2],
                    input.destination[3],
                    input.destination[4],
                    input.destination[5],
                    input.source[0],
                    input.source[1],
                    input.source[2],
                    input.source[3],
                    input.source[4],
                    input.source[5],
                    ether_type_be[0],
                    ether_type_be[1],
                ]
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in ethernet_2_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in ethernet_2_any()) {
            assert_eq!(
                &format!(
                    "Ethernet2Header {{ source: {:?}, destination: {:?}, ether_type: {} }}",
                    input.source,
                    input.destination,
                    input.ether_type
                ),
                &format!("{:?}", input)
            );
        }
    }
}

mod ethernet2_header_slice {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(
            input in ethernet_2_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(14 + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let result = Ethernet2HeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(&buffer[..14], result.slice());
            }

            // call with not enough data in the slice
            for len in 0..=13 {
                assert_eq!(
                    Ethernet2HeaderSlice::from_slice(&buffer[0..len]).unwrap_err(),
                    UnexpectedEndOfSliceError {
                        expected_min_len: Ethernet2Header::SERIALIZED_SIZE,
                        actual_len: len,
                    }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in ethernet_2_any()) {
            let buffer = input.to_bytes();
            let slice = Ethernet2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input.destination, slice.destination());
            assert_eq!(input.source, slice.source());
            assert_eq!(input.ether_type, slice.ether_type());
        }
    }

    proptest! {
        #[test]
        fn to_header(input in ethernet_2_any()) {
            let buffer = input.to_bytes();
            let slice = Ethernet2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in ethernet_2_any()) {
            let buffer = input.to_bytes();
            let slice = Ethernet2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in ethernet_2_any()) {
            let buffer = input.to_bytes();
            let slice = Ethernet2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                &format!(
                    "Ethernet2HeaderSlice {{ slice: {:?} }}",
                    slice.slice()
                ),
                &format!("{:?}", slice)
            );
        }
    }
}
