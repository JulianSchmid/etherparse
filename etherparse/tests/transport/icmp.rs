use super::super::*;
use proptest::prelude::*;

mod icmp_echo_header {
    use super::*;

    proptest! {
        #[test]
        fn to_bytes(
            id in any::<u16>(),
            seq in any::<u16>()
        ) {
            let id_bytes = id.to_be_bytes();
            let seq_bytes = seq.to_be_bytes();
            assert_eq!(
                IcmpEchoHeader{ id, seq }.to_bytes(),
                [
                    id_bytes[0], id_bytes[1],
                    seq_bytes[0], seq_bytes[1]
                ]
            );
        }

        #[test]
        fn from_bytes(
            bytes in any::<[u8;4]>()
        ) {
            assert_eq!(
                IcmpEchoHeader::from_bytes(bytes),
                IcmpEchoHeader {
                    id: u16::from_be_bytes([bytes[0], bytes[1]]),
                    seq: u16::from_be_bytes([bytes[2], bytes[3]])
                }
            );
        }

        #[test]
        fn clone_eq(
            id in any::<u16>(),
            seq in any::<u16>()
        ) {
            let value = IcmpEchoHeader{ id, seq };
            assert_eq!(value.clone(), value);
        }

        #[test]
        fn debug(
            id in any::<u16>(),
            seq in any::<u16>()
        ) {
            assert_eq!(
                format!("{:?}", IcmpEchoHeader{ id, seq }),
                format!("IcmpEchoHeader {{ id: {:?}, seq: {:?} }}", id, seq)
            );
        }
    }
}
