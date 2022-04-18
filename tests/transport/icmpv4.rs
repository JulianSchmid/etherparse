use super::super::*;
use proptest::prelude::*;

use etherparse::icmpv4::*;

#[test]
fn constants() {
    // icmp type numbers according to
    // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
    assert_eq!(TYPE_ECHO_REPLY, 0);
    assert_eq!(TYPE_DEST_UNREACH, 3);
    assert_eq!(TYPE_SOURCE_QUENCH, 4);
    assert_eq!(TYPE_REDIRECT, 5);
    assert_eq!(TYPE_ALTERNATE_HOST_ADDRESS, 6);
    assert_eq!(TYPE_ECHO_REQUEST, 8);
    assert_eq!(TYPE_ROUTER_ADVERTISEMENT, 9);
    assert_eq!(TYPE_ROUTER_SOLICITATION, 10);
    assert_eq!(TYPE_TIME_EXCEEDED, 11);
    assert_eq!(TYPE_PARAMETER_PROBLEM, 12);
    assert_eq!(TYPE_TIMESTAMP, 13);
    assert_eq!(TYPE_TIMESTAMP_REPLY, 14);
    assert_eq!(TYPE_INFO_REQUEST, 15);
    assert_eq!(TYPE_INFO_REPLY, 16);
    assert_eq!(TYPE_ADDRESS, 17);
    assert_eq!(TYPE_ADDRESSREPLY, 18);

    // destination unreachable code numbers according to
    // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
    assert_eq!(0, CODE_DST_UNREACH_NET);
    assert_eq!(1, CODE_DST_UNREACH_HOST);
    assert_eq!(2, CODE_DST_UNREACH_PROTOCOL);
    assert_eq!(3, CODE_DST_UNREACH_PORT);
    assert_eq!(4, CODE_DST_UNREACH_NEED_FRAG);
    assert_eq!(5, CODE_DST_UNREACH_SOURCE_ROUTE_FAILED);
    assert_eq!(6, CODE_DST_UNREACH_NET_UNKNOWN);
    assert_eq!(7, CODE_DST_UNREACH_HOST_UNKNOWN);
    assert_eq!(8, CODE_DST_UNREACH_ISOLATED);
    assert_eq!(9, CODE_DST_UNREACH_NET_PROHIB);
    assert_eq!(10, CODE_DST_UNREACH_HOST_PROHIB);
    assert_eq!(11, CODE_DST_UNREACH_TOS_NET);
    assert_eq!(12, CODE_DST_UNREACH_TOS_HOST);
    assert_eq!(13, CODE_DST_UNREACH_FILTER_PROHIB);
    assert_eq!(14, CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION);
    assert_eq!(15, CODE_DST_UNREACH_PRECEDENCE_CUTOFF);

    // redirect code numbers according to
    // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-5
    assert_eq!(0, CODE_REDIRECT_FOR_NETWORK);
    assert_eq!(1, CODE_REDIRECT_FOR_HOST);
    assert_eq!(2, CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK);
    assert_eq!(3, CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST);

    // time exceeded code numbers according to
    // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-11
    assert_eq!(0, CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT);
    assert_eq!(1, CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED);

    // parameter problem code numbers according to
    // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-12
    assert_eq!(0, CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR);
    assert_eq!(1, CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION);
    assert_eq!(2, CODE_PARAMETER_PROBLEM_BAD_LENGTH);
}

mod dest_unreachable_header {
    use super::*;

    fn conversion_values(next_hop_mtu: u16) -> [(u8, DestUnreachableHeader); 16] {
        use DestUnreachableHeader::*;
        [
            (CODE_DST_UNREACH_NET, Network),
            (CODE_DST_UNREACH_HOST, Host),
            (CODE_DST_UNREACH_PROTOCOL, Protocol),
            (CODE_DST_UNREACH_PORT, Port),
            (CODE_DST_UNREACH_NEED_FRAG, FragmentationNeeded{ next_hop_mtu }),
            (CODE_DST_UNREACH_SOURCE_ROUTE_FAILED, SourceRouteFailed),
            (CODE_DST_UNREACH_NET_UNKNOWN, NetworkUnknown),
            (CODE_DST_UNREACH_HOST_UNKNOWN, HostUnknown),
            (CODE_DST_UNREACH_ISOLATED, Isolated),
            (CODE_DST_UNREACH_NET_PROHIB, NetworkProhibited),
            (CODE_DST_UNREACH_HOST_PROHIB, HostProhibited),
            (CODE_DST_UNREACH_TOS_NET, TosNetwork),
            (CODE_DST_UNREACH_TOS_HOST, TosHost),
            (CODE_DST_UNREACH_FILTER_PROHIB, FilterProhibited),
            (CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION, HostPrecedenceViolation),
            (CODE_DST_UNREACH_PRECEDENCE_CUTOFF, PrecedenceCutoff),
        ]
    }

    proptest! {
        #[test]
        fn from_values(
            next_hop_mtu in any::<u16>(),
        ) {
            // valid values
            {
                let valid_values = conversion_values(next_hop_mtu);
                for t in valid_values {
                    assert_eq!(Some(t.1), DestUnreachableHeader::from_values(t.0, next_hop_mtu));
                }
            }
            // invalid values
            for code_u8 in 16u8..=u8::MAX {
                assert_eq!(None, DestUnreachableHeader::from_values(code_u8, next_hop_mtu));
            }
        }
    }

    proptest! {
        #[test]
        fn code_u8(
            next_hop_mtu in any::<u16>(),
        ) {
            let valid_values = conversion_values(next_hop_mtu);
            for t in valid_values {
                assert_eq!(t.0, t.1.code_u8());
            }
        }
    }

    #[test]
    fn clone_eq() {
        use DestUnreachableHeader::*;
        let values = [
            Network,
            Host,
            Protocol,
            Port,
            FragmentationNeeded { next_hop_mtu: 0 },
            SourceRouteFailed,
            NetworkUnknown,
            HostUnknown,
            Isolated,
            NetworkProhibited,
            HostProhibited,
            TosNetwork,
            TosHost,
            FilterProhibited,
            HostPrecedenceViolation,
            PrecedenceCutoff,
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn debug() {
        use DestUnreachableHeader::*;
        let tests = [
            ("Network", Network),
            ("Host", Host),
            ("Protocol", Protocol),
            ("Port", Port),
            (
                "FragmentationNeeded { next_hop_mtu: 0 }",
                FragmentationNeeded { next_hop_mtu: 0 },
            ),
            ("SourceRouteFailed", SourceRouteFailed),
            ("NetworkUnknown", NetworkUnknown),
            ("HostUnknown", HostUnknown),
            ("Isolated", Isolated),
            ("NetworkProhibited", NetworkProhibited),
            ("HostProhibited", HostProhibited),
            ("TosNetwork", TosNetwork),
            ("TosHost", TosHost),
            ("FilterProhibited", FilterProhibited),
            ("HostPrecedenceViolation", HostPrecedenceViolation),
            ("PrecedenceCutoff", PrecedenceCutoff),
        ];
        for t in tests {
            assert_eq!(t.0, format!("{:?}", t.1));
        }
    }
}

mod redirect_code {
    use super::*;
    use etherparse::icmpv4::RedirectCode::*;

    #[test]
    fn from_u8() {
        let tests = [
            (CODE_REDIRECT_FOR_NETWORK, RedirectForNetwork),
            (CODE_REDIRECT_FOR_HOST, RedirectForHost),
            (CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK, RedirectForTypeOfServiceAndNetwork),
            (CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST, RedirectForTypeOfServiceAndHost),
        ];
        for t in tests {
            assert_eq!(Some(t.1), RedirectCode::from_u8(t.0));
        }
        for code_u8 in 4..=u8::MAX {
            assert_eq!(None, RedirectCode::from_u8(code_u8));
        }
    }

    #[test]
    fn code_u8() {
        let tests = [
            (CODE_REDIRECT_FOR_NETWORK, RedirectForNetwork),
            (CODE_REDIRECT_FOR_HOST, RedirectForHost),
            (CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK, RedirectForTypeOfServiceAndNetwork),
            (CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST, RedirectForTypeOfServiceAndHost),
        ];
        for t in tests {
            assert_eq!(t.1.code_u8(), t.0);
        }
    }

    #[test]
    fn clone_eq() {
        let tests = [
            RedirectForNetwork,
            RedirectForHost,
            RedirectForTypeOfServiceAndNetwork,
            RedirectForTypeOfServiceAndHost,
        ];
        for t in tests {
            assert_eq!(t.clone(), t);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            ("RedirectForNetwork", RedirectForNetwork),
            ("RedirectForHost", RedirectForHost),
            ("RedirectForTypeOfServiceAndNetwork", RedirectForTypeOfServiceAndNetwork),
            ("RedirectForTypeOfServiceAndHost", RedirectForTypeOfServiceAndHost),
        ];
        for t in tests {
            assert_eq!(t.0, format!("{:?}", t.1));
        }
    }
}

mod redirect_header {
    use super::*;
    use etherparse::icmpv4::RedirectCode::*;

    #[test]
    fn clone_eq() {
        let v = RedirectHeader{
            code: RedirectForNetwork,
            gateway_internet_address: [0;4],
        };
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn debug() {
        let v = RedirectHeader{
            code: RedirectForNetwork,
            gateway_internet_address: [0;4],
        };
        assert_eq!(
            format!("{:?}", v),
            format!(
                "RedirectHeader {{ code: {:?}, gateway_internet_address: {:?} }}",
                v.code,
                v.gateway_internet_address
            )
        );
    }
}

mod time_exceeded_code {
    use super::*;
    use etherparse::icmpv4::TimeExceededCode::*;

    #[test]
    fn from_u8() {
        assert_eq!(
            TimeExceededCode::from_u8(CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT),
            Some(TtlExceededInTransit)
        );
        assert_eq!(
            TimeExceededCode::from_u8(CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED),
            Some(FragmentReassemblyTimeExceeded)
        );

        for code_u8 in 2..=u8::MAX {
            assert_eq!(None, TimeExceededCode::from_u8(code_u8));
        }
    }

    #[test]
    fn code_u8() {
        assert_eq!(TtlExceededInTransit.code_u8(), CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT);
        assert_eq!(FragmentReassemblyTimeExceeded.code_u8(), CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED);
    }

    #[test]
    fn debug() {
        let values = [
            ("TtlExceededInTransit", TtlExceededInTransit),
            ("FragmentReassemblyTimeExceeded", FragmentReassemblyTimeExceeded),
        ];
        for (expected, input) in values {
            assert_eq!(expected, format!("{:?}", input));
        }
    }

    #[test]
    fn clone_eq() {
        let values = [
            TtlExceededInTransit,
            FragmentReassemblyTimeExceeded,
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }
}

mod timestamp_message {
    use super::*;
    #[test]
    fn constants() {
        assert_eq!(20, TimestampMessage::SERIALIZED_SIZE);
    }

    proptest!{
        #[test]
        fn from_bytes(bytes in any::<[u8;16]>()) {
            assert_eq!(
                TimestampMessage::from_bytes(bytes),
                TimestampMessage{
                    id: u16::from_be_bytes([bytes[0], bytes[1]]),
                    seq: u16::from_be_bytes([bytes[2], bytes[3]]),
                    originate_timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                    receive_timestamp: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                    transmit_timestamp: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
                }
            );
        }
    }

    #[test]
    fn clone_eq() {
        let v = TimestampMessage {
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn debug() {
        let v = TimestampMessage {
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        assert_eq!(
            format!("{:?}", v),
            format!(
                "TimestampMessage {{ id: {:?}, seq: {:?}, originate_timestamp: {:?}, receive_timestamp: {:?}, transmit_timestamp: {:?} }}",
                v.id,
                v.seq,
                v.originate_timestamp,
                v.receive_timestamp,
                v.transmit_timestamp,
            )
        );
    }
}

mod parameter_problem_header {
    use super::*;
    use ParameterProblemHeader::*;

    proptest!{
        #[test]
        fn from_values(pointer in any::<u8>()) {
            {
                let tests = [
                    (CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR, PointerIndicatesError(pointer)),
                    (CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION, MissingRequiredOption),
                    (CODE_PARAMETER_PROBLEM_BAD_LENGTH, BadLength),
                ];
                for t in tests {
                    assert_eq!(Some(t.1), ParameterProblemHeader::from_values(t.0, pointer));
                }
            }
            for code_u8 in 3..=u8::MAX {
                assert_eq!(None, ParameterProblemHeader::from_values(code_u8, pointer));
            }
        }
    }

    #[test]
    fn clone_eq() {
        let tests = [
            PointerIndicatesError(0),
            MissingRequiredOption,
            BadLength,
        ];
        for t in tests {
            assert_eq!(t.clone(), t);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            ("PointerIndicatesError(0)", PointerIndicatesError(0)),
            ("MissingRequiredOption", MissingRequiredOption),
            ("BadLength", BadLength),
        ];
        for t in tests {
            assert_eq!(t.0, format!("{:?}", t.1));
        }
    }
}

mod icmpv4_type {
    use super::*;
    use Icmpv4Type::*;

    #[test]
    fn header_len() {
        let dummy_ts = TimestampMessage{
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        let dummy_echo = IcmpEchoHeader{
            id: 0,
            seq: 0,
        };
        let dummy_redirect = RedirectHeader{
            code: RedirectCode::RedirectForNetwork,
            gateway_internet_address: [0;4],
        };
        let tests = [
            (8, Unknown{type_u8: 0, code_u8: 0, bytes5to8: [0;4]}),
            (8, EchoReply(dummy_echo)),
            (8, DestinationUnreachable(DestUnreachableHeader::Network)),
            (8, Redirect(dummy_redirect)),
            (8, EchoRequest(dummy_echo)),
            (8, TimeExceeded(TimeExceededCode::TtlExceededInTransit)),
            (8, ParameterProblem(ParameterProblemHeader::BadLength)),
            (20, TimestampRequest(dummy_ts.clone())),
            (20, TimestampReply(dummy_ts)),
        ];
        for t in tests {
            assert_eq!(t.0, t.1.header_len());
        }
    }

    #[test]
    fn fixed_payload_size() {
        use Icmpv4Type::*;

        let dummy_ts = TimestampMessage{
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        let dummy_echo = IcmpEchoHeader{
            id: 0,
            seq: 0,
        };
        let dummy_redirect = RedirectHeader{
            code: RedirectCode::RedirectForNetwork,
            gateway_internet_address: [0;4],
        };
        let tests = [
            (None, Unknown{type_u8: 0, code_u8: 0, bytes5to8: [0;4]}),
            (None, EchoReply(dummy_echo)),
            (None, DestinationUnreachable(DestUnreachableHeader::Network)),
            (None, Redirect(dummy_redirect)),
            (None, EchoRequest(dummy_echo)),
            (None, TimeExceeded(TimeExceededCode::TtlExceededInTransit)),
            (None, ParameterProblem(ParameterProblemHeader::BadLength)),
            (Some(0), TimestampRequest(dummy_ts.clone())),
            (Some(0), TimestampReply(dummy_ts)),
        ];
        for t in tests {
            assert_eq!(t.0, t.1.fixed_payload_size());
        }
    }

    proptest!{
        #[test]
        fn calc_checksum(
            dest_unreach_code_u8 in 0u8..=15,
            next_hop_mtu in any::<u16>(),
            redirect_code_u8 in 0u8..=3,
            gateway_internet_address in any::<[u8;4]>(),
            time_exceeded_code_u8 in 0u8..=1,
            id in any::<u16>(),
            seq in any::<u16>(),
            originate_timestamp in any::<u32>(),
            receive_timestamp in any::<u32>(),
            transmit_timestamp in any::<u32>(),
            param_problem_code_u8 in 0u8..=2,
            pointer in any::<u8>(),
            unknown_type_u8 in any::<u8>(),
            unknown_code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            let ts = TimestampMessage{
                id,
                seq,
                originate_timestamp,
                receive_timestamp,
                transmit_timestamp,
            };
            let echo = IcmpEchoHeader{
                id,
                seq,
            };
            let redirect = RedirectHeader{
                code: RedirectCode::from_u8(redirect_code_u8).unwrap(),
                gateway_internet_address,
            };
            let dest_unreach = DestUnreachableHeader::from_values(dest_unreach_code_u8, next_hop_mtu).unwrap();
            let param_prob = ParameterProblemHeader::from_values(param_problem_code_u8, pointer).unwrap();
            let values = [
                Unknown {
                    type_u8: unknown_type_u8,
                    code_u8: unknown_code_u8,
                    bytes5to8: bytes5to8,
                },
                EchoReply(echo.clone()),
                DestinationUnreachable(dest_unreach),
                Redirect(redirect),
                EchoRequest(echo),
                TimeExceeded(TimeExceededCode::from_u8(time_exceeded_code_u8).unwrap()),
                ParameterProblem(param_prob),
                TimestampRequest(ts.clone()),
                TimestampReply(ts),
            ];
            
            for t in values {
                let bytes = Icmpv4Header{
                    icmp_type: t.clone(),
                    checksum: 0, // use zero so the checksum calculation from the bytes works
                }.to_bytes();
                let expected = etherparse::checksum::Sum16BitWords::new()
                    .add_slice(bytes.as_ref())
                    .add_slice(&payload)
                    .ones_complement()
                    .to_be();
                assert_eq!(expected, t.calc_checksum(&payload));
            }
        }
    }

    #[test]
    fn clone_eq() {
        let dummy_ts = TimestampMessage{
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        let dummy_echo = IcmpEchoHeader{
            id: 0,
            seq: 0,
        };
        let dummy_redirect = RedirectHeader{
            code: RedirectCode::RedirectForNetwork,
            gateway_internet_address: [0;4],
        };
        let tests = [
            Unknown{type_u8: 0, code_u8: 0, bytes5to8: [0;4]},
            EchoReply(dummy_echo),
            DestinationUnreachable(DestUnreachableHeader::Network),
            Redirect(dummy_redirect),
            EchoRequest(dummy_echo),
            TimeExceeded(TimeExceededCode::TtlExceededInTransit),
            ParameterProblem(ParameterProblemHeader::BadLength),
            TimestampRequest(dummy_ts.clone()),
            TimestampReply(dummy_ts),
        ];
        for t in tests {
            assert_eq!(t.clone(), t);
        }
    }

    #[test]
    fn debug() {
        let dummy_ts = TimestampMessage{
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        let dummy_echo = IcmpEchoHeader{
            id: 0,
            seq: 0,
        };

        assert_eq!(
            format!("{:?}", Unknown{type_u8: 0, code_u8: 0, bytes5to8: [0;4]}),
            format!(
                "Unknown {{ type_u8: {:?}, code_u8: {:?}, bytes5to8: {:?} }}",
                0u8, 0u8, [0u8;4]
            )
        );
        assert_eq!(
            format!("{:?}", EchoReply(dummy_echo)),
            format!("EchoReply({:?})", dummy_echo)
        );
        assert_eq!(
            format!("{:?}", DestinationUnreachable(DestUnreachableHeader::Network)),
            format!("DestinationUnreachable({:?})", DestUnreachableHeader::Network)
        );
        {
            let dummy_redirect = RedirectHeader{
                code: RedirectCode::RedirectForNetwork,
                gateway_internet_address: [0;4],
            };
            assert_eq!(
                format!("{:?}", Redirect(dummy_redirect.clone())),
                format!("Redirect({:?})", dummy_redirect)
            );
        }
        assert_eq!(
            format!("{:?}", EchoRequest(dummy_echo)),
            format!("EchoRequest({:?})", dummy_echo)
        );
        assert_eq!(
            format!("{:?}", TimeExceeded(TimeExceededCode::TtlExceededInTransit)),
            format!("TimeExceeded({:?})", TimeExceededCode::TtlExceededInTransit)
        );
        assert_eq!(
            format!("{:?}", ParameterProblem(ParameterProblemHeader::BadLength)),
            format!("ParameterProblem({:?})", ParameterProblemHeader::BadLength)
        );
        assert_eq!(
            format!("{:?}", TimestampRequest(dummy_ts.clone())),
            format!("TimestampRequest({:?})", dummy_ts)
        );
         assert_eq!(
            format!("{:?}", TimestampReply(dummy_ts.clone())),
            format!("TimestampReply({:?})", dummy_ts)
        );
    }
}

mod icmpv4_header {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(8, Icmpv4Header::MIN_SERIALIZED_SIZE);
        assert_eq!(20, Icmpv4Header::MAX_SERIALIZED_SIZE);
    }

    proptest!{
        #[test]
        fn header_len(
            checksum in any::<u16>(),
            icmpv4_type in icmpv4_type_any()
        ) {
            let header = Icmpv4Header{
                icmp_type: icmpv4_type.clone(),
                checksum,
            };
            assert_eq!(header.header_len(), icmpv4_type.header_len());
        }
    }

    proptest!{
        #[test]
        fn fixed_payload_size(
            checksum in any::<u16>(),
            icmpv4_type in icmpv4_type_any()
        ) {
            let header = Icmpv4Header{
                icmp_type: icmpv4_type.clone(),
                checksum,
            };
            assert_eq!(header.fixed_payload_size(), icmpv4_type.fixed_payload_size());
        }
    }

    proptest!{
        #[test]
        fn new(icmpv4_type in icmpv4_type_any()) {
            assert_eq!(
                Icmpv4Header {
                    icmp_type: icmpv4_type.clone(),
                    checksum: 0,
                },
                Icmpv4Header::new(icmpv4_type)
            );
        }
    }

    proptest!{
        #[test]
        fn write(
            icmpv4_type in icmpv4_type_any(),
            checksum in any::<u16>(),
        ) {
            let header = Icmpv4Header {
                icmp_type: icmpv4_type.clone(),
                checksum,
            };

            // normal write
            {
                let bytes = header.to_bytes();
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();
                assert_eq!(&bytes[..], &buffer[..]);
            }

            // error case
            for bad_len in 0..icmpv4_type.header_len() {
                let mut writer = TestWriter::with_max_size(bad_len);
                header.write(&mut writer).unwrap_err();
            }
        }
    }

    proptest!{
        #[test]
        fn update_checksum(
            icmpv4_type in icmpv4_type_any(),
            checksum in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let mut header = Icmpv4Header {
                icmp_type: icmpv4_type.clone(),
                checksum,
            };
            header.update_checksum(&payload);
            assert_eq!(header.checksum, icmpv4_type.calc_checksum(&payload));
        }
    }

    proptest!{
        #[test]
        fn from_slice(
            icmpv4_type in icmpv4_type_any(),
            checksum in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            use Icmpv4Type::*;

            // ok case
            let header = Icmpv4Header {
                icmp_type: icmpv4_type.clone(),
                checksum: checksum,
            };
            let buffer = {
                let mut buffer = Vec::with_capacity(header.header_len() + payload.len());
                buffer.extend_from_slice(&header.to_bytes());
                
                match icmpv4_type {
                    // skip the payoad for the timestamp request (those don't have a payload)
                    TimestampRequest(_) | TimestampReply(_) => {},
                    _ => {
                        buffer.extend_from_slice(&[0u8;36]);
                    }
                }
                buffer
            };
            {
                let (actual, rest) = Icmpv4Header::from_slice(&buffer).unwrap();
                assert_eq!(actual, header);
                assert_eq!(rest, &buffer[header.header_len()..]);
            }

            // error case
            for bad_len in 0..header.header_len() {
                assert_matches!(
                    Icmpv4Header::from_slice(&buffer[..bad_len]),
                    Err(_)
                );
            }
        }
    }

    proptest!{
        #[test]
        #[rustfmt::skip]
        fn to_bytes(
            checksum in any::<u16>(),
            next_hop_mtu in any::<u16>(),
            redirect_code_u8 in 0u8..=3,
            gateway_internet_address in any::<[u8;4]>(),
            time_exceeded_code_u8 in 0u8..=1,
            id in any::<u16>(),
            seq in any::<u16>(),
            originate_timestamp in any::<u32>(),
            receive_timestamp in any::<u32>(),
            transmit_timestamp in any::<u32>(),
            pointer in any::<u8>(),
            unknown_type_u8 in any::<u8>(),
            unknown_code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use Icmpv4Type::*;
            use arrayvec::ArrayVec;

            let ts = TimestampMessage{
                id,
                seq,
                originate_timestamp,
                receive_timestamp,
                transmit_timestamp,
            };
            let ts_bytes = {
                let id_be = id.to_be_bytes();
                let seq_be = seq.to_be_bytes();
                let ot = originate_timestamp.to_be_bytes();
                let rt = receive_timestamp.to_be_bytes();
                let tt = transmit_timestamp.to_be_bytes();
                [
                    0, 0, 0, 0,
                    id_be[0], id_be[1], seq_be[0], seq_be[1],
                    ot[0], ot[1], ot[2], ot[3],
                    rt[0], rt[1], rt[2], rt[3],
                    tt[0], tt[1], tt[2], tt[3],
                ]
            };
            let echo = IcmpEchoHeader{
                id,
                seq,
            };
            let redirect = RedirectHeader{
                code: RedirectCode::from_u8(redirect_code_u8).unwrap(),
                gateway_internet_address,
            };

            // test values with no need for subtests
            let random_values = [
                (
                    Unknown {
                        type_u8: unknown_type_u8,
                        code_u8: unknown_code_u8,
                        bytes5to8: bytes5to8,
                    },
                    8,
                    [
                        unknown_type_u8, unknown_code_u8, 0, 0,
                        bytes5to8[0], bytes5to8[1], bytes5to8[2], bytes5to8[3],
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                    ],
                ),
                (
                    EchoReply(echo.clone()),
                    8,
                    {
                        let id_be = id.to_be_bytes();
                        let seq_be = seq.to_be_bytes();
                        [
                            TYPE_ECHO_REPLY, 0, 0, 0,
                            id_be[0], id_be[1], seq_be[0], seq_be[1],
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                        ]
                    }
                ),
                
                (
                    Redirect(redirect),
                    8,
                    {
                        let gip = gateway_internet_address;
                        [
                            TYPE_REDIRECT, redirect_code_u8, 0, 0,
                            gip[0], gip[1], gip[2], gip[3],
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                        ]
                    },
                ),
                (
                    EchoRequest(echo.clone()),
                    8,
                    {
                        let id_be = id.to_be_bytes();
                        let seq_be = seq.to_be_bytes();
                        [
                            TYPE_ECHO_REQUEST, 0, 0, 0,
                            id_be[0], id_be[1], seq_be[0], seq_be[1],
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                        ]
                    }
                ),
                (
                    TimeExceeded(TimeExceededCode::from_u8(time_exceeded_code_u8).unwrap()),
                    8,
                    [
                        TYPE_TIME_EXCEEDED, time_exceeded_code_u8, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                    ],
                ),
                (
                    TimestampRequest(ts.clone()),
                    20,
                    {
                        let mut b = ts_bytes;
                        b[0] = TYPE_TIMESTAMP;
                        b
                    }
                ),
                (
                    TimestampReply(ts),
                    20,
                    {
                        let mut b = ts_bytes;
                        b[0] = TYPE_TIMESTAMP_REPLY;
                        b
                    }
                ),
            ];
            
            for t in random_values {
                let actual = Icmpv4Header{
                    icmp_type: t.0.clone(),
                    checksum,
                }.to_bytes();

                let mut expected = ArrayVec::from(t.2);
                unsafe {
                    expected.set_len(t.1)
                }
                let checksum_be = checksum.to_be_bytes();
                expected[2] = checksum_be[0];
                expected[3] = checksum_be[1];
                assert_eq!(expected, actual);
            }

            // destination unreachable
            {
                use DestUnreachableHeader::*;
                let tests = [
                    (CODE_DST_UNREACH_NET, [0;2], Network),
                    (CODE_DST_UNREACH_HOST, [0;2], Host),
                    (CODE_DST_UNREACH_PROTOCOL, [0;2], Protocol),
                    (CODE_DST_UNREACH_PORT, [0;2], Port),
                    (CODE_DST_UNREACH_NEED_FRAG, next_hop_mtu.to_be_bytes(), FragmentationNeeded{ next_hop_mtu }),
                    (CODE_DST_UNREACH_SOURCE_ROUTE_FAILED, [0;2], SourceRouteFailed),
                    (CODE_DST_UNREACH_NET_UNKNOWN, [0;2], NetworkUnknown),
                    (CODE_DST_UNREACH_HOST_UNKNOWN, [0;2], HostUnknown),
                    (CODE_DST_UNREACH_ISOLATED, [0;2], Isolated),
                    (CODE_DST_UNREACH_NET_PROHIB, [0;2], NetworkProhibited),
                    (CODE_DST_UNREACH_HOST_PROHIB, [0;2], HostProhibited),
                    (CODE_DST_UNREACH_TOS_NET, [0;2], TosNetwork),
                    (CODE_DST_UNREACH_TOS_HOST, [0;2], TosHost),
                    (CODE_DST_UNREACH_FILTER_PROHIB, [0;2], FilterProhibited),
                    (CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION, [0;2], HostPrecedenceViolation),
                    (CODE_DST_UNREACH_PRECEDENCE_CUTOFF, [0;2], PrecedenceCutoff),
                ];
                for t in tests {
                    let checksum_be = checksum.to_be_bytes();
                    let mut expected = ArrayVec::from([
                        TYPE_DEST_UNREACH, t.0, checksum_be[0], checksum_be[1],
                        0, 0, t.1[0], t.1[1],
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]);
                    unsafe {
                        expected.set_len(8);
                    }
                    let actual = Icmpv4Header{
                        icmp_type: DestinationUnreachable(t.2.clone()),
                        checksum,
                    }.to_bytes();
                    assert_eq!(expected, actual);
                }
            }

            // parameter problem
            {
                use ParameterProblemHeader::*;
                let tests = [
                    (CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR, pointer, PointerIndicatesError(pointer)),
                    (CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION, 0, MissingRequiredOption),
                    (CODE_PARAMETER_PROBLEM_BAD_LENGTH, 0, BadLength),
                ];
                for t in tests {
                    let checksum_be = checksum.to_be_bytes();
                    let mut expected = ArrayVec::from([
                        TYPE_PARAMETER_PROBLEM, t.0, checksum_be[0], checksum_be[1],
                        t.1, 0, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]);
                    unsafe {
                        expected.set_len(8);
                    }
                    let actual = Icmpv4Header{
                        icmp_type: ParameterProblem(t.2.clone()),
                        checksum,
                    }.to_bytes();
                    assert_eq!(expected, actual);
                }
            }
        }
    }

    #[test]
    fn clone_eq() {
        use Icmpv4Type::*;
        let header = Icmpv4Header {
            icmp_type: ParameterProblem(ParameterProblemHeader::BadLength),
            checksum: 0,
        };
        assert_eq!(header.clone(), header);
    }

    #[test]
    fn debug() {
        use Icmpv4Type::*;
        let header = Icmpv4Header {
            icmp_type: ParameterProblem(ParameterProblemHeader::BadLength),
            checksum: 0,
        };
        assert_eq!(
            format!("{:?}", header),
            format!("Icmpv4Header {{ icmp_type: {:?}, checksum: {:?} }}", header.icmp_type, header.checksum)
        );
    }
}

mod icmpv4_slice {
    use super::*;

    #[test]
    fn from_slice() {
        use ReadError::*;

        // normal case
        {
            let bytes = [0u8;8];
            let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice.slice(), &bytes);
        }

        // smaller then min size error
        for bad_len in 0..8 {
            let bytes = [0u8;8];
            assert_matches!(
                Icmpv4Slice::from_slice(&bytes[..bad_len]),
                Err(UnexpectedEndOfSlice(Icmpv4Header::MIN_SERIALIZED_SIZE))
            );
        }

        // timestamp tests
        for ts_type_u8 in [TYPE_TIMESTAMP, TYPE_TIMESTAMP_REPLY] {
            let bytes = {
                let mut bytes = [0u8;26];
                bytes[0] = ts_type_u8;
                bytes
            };

            // valid timestamps
            {
                let slice = Icmpv4Slice::from_slice(&bytes[..20]).unwrap();
                assert_eq!(slice.slice(), &bytes[..20]);
            }

            // too short timestamps
            for bad_len in 8..20 {
                assert_matches!(
                    Icmpv4Slice::from_slice(&bytes[..bad_len]),
                    Err(UnexpectedLenOfSlice{
                        expected: TimestampMessage::SERIALIZED_SIZE,
                        actual: _
                    })
                );
            }

            // too large timestamps
            for bad_len in 21..26 {
                assert_matches!(
                    Icmpv4Slice::from_slice(&bytes[..bad_len]),
                    Err(UnexpectedLenOfSlice{
                        expected: TimestampMessage::SERIALIZED_SIZE,
                        actual: _
                    })
                );
            }

            // timestamp with a non zero code
            for code_u8 in 1..=u8::MAX {
                let mut bytes = [0u8;20];
                bytes[0] = ts_type_u8;
                bytes[1] = code_u8;
                let slice = Icmpv4Slice::from_slice(&bytes[..8]).unwrap();
                assert_eq!(slice.slice(), &bytes[..8]);
            }
        }
    }

    proptest!{
        #[test]
        fn header(bytes in any::<[u8;20]>()) {
            let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
            assert_eq!(
                Icmpv4Header {
                    icmp_type: slice.icmp_type(),
                    checksum: slice.checksum(),
                },
                slice.header()
            );
        }
    }

    #[test]
    fn header_len() {
        use Icmpv4Type::*;
        let dummy_ts = TimestampMessage{
            id: 0,
            seq: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
        };
        let dummy_echo = IcmpEchoHeader{
            id: 0,
            seq: 0,
        };
        let dummy_redirect = RedirectHeader{
            code: RedirectCode::RedirectForNetwork,
            gateway_internet_address: [0;4],
        };
        let tests = [
            (Unknown{type_u8: u8::MAX, code_u8: 0, bytes5to8: [0;4]}),
            (EchoReply(dummy_echo)),
            (DestinationUnreachable(DestUnreachableHeader::Network)),
            (Redirect(dummy_redirect)),
            (EchoRequest(dummy_echo)),

            (TimeExceeded(TimeExceededCode::TtlExceededInTransit)),
            (ParameterProblem(ParameterProblemHeader::BadLength)),
            (TimestampRequest(dummy_ts.clone())),
            // check that a non zero code value return 8
            (Unknown{type_u8: TYPE_TIMESTAMP, code_u8: 1, bytes5to8: [0;4]}),
            (TimestampReply(dummy_ts)),
            // check that a non zero code value return 8
            (Unknown{type_u8: TYPE_TIMESTAMP_REPLY, code_u8: 1, bytes5to8: [0;4]}),
        ];
        for t in tests {
            assert_eq!(
                t.header_len(),
                Icmpv4Slice::from_slice(
                    &Icmpv4Header::new(t).to_bytes()
                ).unwrap().header_len()
            );
        }
    }

    proptest!{
        #[test]
        fn icmp_type(base_bytes in any::<[u8;20]>()) {

            use Icmpv4Type::*;

            let gen_bytes = |type_u8: u8, code_u8: u8| -> [u8;20] {
                let mut bytes = base_bytes;
                bytes[0] = type_u8;
                bytes[1] = code_u8;
                bytes
            };

            let assert_unknown = |type_u8: u8, code_u8: u8| {
                let bytes = gen_bytes(type_u8, code_u8);
                let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                assert_eq!(
                    slice.icmp_type(),
                    Unknown{
                        type_u8,
                        code_u8,
                        bytes5to8: slice.bytes5to8(),
                    }
                );
            };

            // unknown types
            for type_u8 in 0..=u8::MAX{
                match type_u8 {
                    TYPE_ECHO_REPLY | TYPE_DEST_UNREACH | TYPE_REDIRECT |
                    TYPE_ECHO_REQUEST | TYPE_TIME_EXCEEDED | TYPE_PARAMETER_PROBLEM |
                    TYPE_TIMESTAMP | TYPE_TIMESTAMP_REPLY => {},
                    type_u8 => {
                        assert_unknown(type_u8, base_bytes[1]);
                    }
                }
            }

            // echo reply
            {
                // matching code
                {
                    let bytes = gen_bytes(TYPE_ECHO_REPLY, 0);
                    let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                    assert_eq!(
                        slice.icmp_type(),
                        EchoReply(IcmpEchoHeader::from_bytes(slice.bytes5to8()))
                    );
                }

                // unknown code
                for unknow_code in 1..=u8::MAX {
                    assert_unknown(TYPE_ECHO_REPLY, unknow_code);
                }
            }

            // destination unreachable
            {
                use DestUnreachableHeader::*;
                // trivial code values
                {
                    let trivial_tests = [
                        (CODE_DST_UNREACH_NET, Network),
                        (CODE_DST_UNREACH_HOST, Host),
                        (CODE_DST_UNREACH_PROTOCOL, Protocol),
                        (CODE_DST_UNREACH_PORT, Port),
                        // need frag skipped as contains an additional value
                        (CODE_DST_UNREACH_SOURCE_ROUTE_FAILED, SourceRouteFailed),
                        (CODE_DST_UNREACH_NET_UNKNOWN, NetworkUnknown),
                        (CODE_DST_UNREACH_HOST_UNKNOWN, HostUnknown),
                        (CODE_DST_UNREACH_ISOLATED, Isolated),
                        (CODE_DST_UNREACH_NET_PROHIB, NetworkProhibited),
                        (CODE_DST_UNREACH_HOST_PROHIB, HostProhibited),
                        (CODE_DST_UNREACH_TOS_NET, TosNetwork),
                        (CODE_DST_UNREACH_TOS_HOST, TosHost),
                        (CODE_DST_UNREACH_FILTER_PROHIB, FilterProhibited),
                        (CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION, HostPrecedenceViolation),
                        (CODE_DST_UNREACH_PRECEDENCE_CUTOFF, PrecedenceCutoff),
                    ];

                    for (code_u8, expected) in trivial_tests {
                        let bytes = gen_bytes(TYPE_DEST_UNREACH, code_u8);
                        let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                        assert_eq!(
                            slice.icmp_type(),
                            DestinationUnreachable(expected)
                        );
                    }
                }

                // need frag
                {
                    let bytes = gen_bytes(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NEED_FRAG);
                    let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                    assert_eq!(
                        slice.icmp_type(),
                        DestinationUnreachable(FragmentationNeeded {
                            next_hop_mtu: u16::from_be_bytes([bytes[6], bytes[7]])
                        })
                    );
                }

                // unknown codes
                for unknow_code in 16..=u8::MAX {
                    assert_unknown(TYPE_ECHO_REPLY, unknow_code);
                }
            }

            // redirect
            {
                use RedirectCode::*;
                // known codes
                {
                    let trivial_tests = [
                        (CODE_REDIRECT_FOR_NETWORK, RedirectForNetwork),
                        (CODE_REDIRECT_FOR_HOST, RedirectForHost),
                        (CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK, RedirectForTypeOfServiceAndNetwork),
                        (CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST, RedirectForTypeOfServiceAndHost),
                    ];

                    for (code_u8, expected) in trivial_tests {
                        let bytes = gen_bytes(TYPE_REDIRECT, code_u8);
                        let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                        assert_eq!(
                            slice.icmp_type(),
                            Redirect(RedirectHeader{
                                code: expected,
                                gateway_internet_address: slice.bytes5to8(),
                            })
                        );
                    }
                }

                // unknown codes
                for unknow_code in 4..=u8::MAX {
                    assert_unknown(TYPE_REDIRECT, unknow_code);
                }
            }

            // echo request
            {
                // matching code
                {
                    let bytes = gen_bytes(TYPE_ECHO_REQUEST, 0);
                    let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                    assert_eq!(
                        slice.icmp_type(),
                        EchoRequest(IcmpEchoHeader::from_bytes(slice.bytes5to8()))
                    );
                }

                // unknown code
                for unknow_code in 1..=u8::MAX {
                    assert_unknown(TYPE_ECHO_REQUEST, unknow_code);
                }
            }

            // time exceeded
            {
                use TimeExceededCode::*;
                // known codes
                {
                    let trivial_tests = [
                        (CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT, TtlExceededInTransit),
                        (CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED, FragmentReassemblyTimeExceeded),
                    ];

                    for (code_u8, expected) in trivial_tests {
                        let bytes = gen_bytes(TYPE_TIME_EXCEEDED, code_u8);
                        let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                        assert_eq!(
                            slice.icmp_type(),
                            TimeExceeded(expected)
                        );
                    }
                }

                // unknown code
                for unknow_code in 2..=u8::MAX {
                    assert_unknown(TYPE_TIME_EXCEEDED, unknow_code);
                }
            }

            // parameter porblem
            {
                use ParameterProblemHeader::*;
                // trivial code values
                {
                    let trivial_tests = [
                        (CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION, MissingRequiredOption),
                        (CODE_PARAMETER_PROBLEM_BAD_LENGTH, BadLength),
                    ];

                    for (code_u8, expected) in trivial_tests {
                        let bytes = gen_bytes(TYPE_PARAMETER_PROBLEM, code_u8);
                        let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                        assert_eq!(
                            slice.icmp_type(),
                            ParameterProblem(expected)
                        );
                    }
                }

                // with pointer
                {
                    let bytes = gen_bytes(TYPE_PARAMETER_PROBLEM, CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR);
                    let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                    assert_eq!(
                        slice.icmp_type(),
                        ParameterProblem(PointerIndicatesError(bytes[4]))
                    );
                }

                // unknown codes
                for unknow_code in 3..=u8::MAX {
                    assert_unknown(TYPE_PARAMETER_PROBLEM, unknow_code);
                }
            }

            // timestamp
            {
                // matching code
                {
                    let bytes = gen_bytes(TYPE_TIMESTAMP, 0);
                    let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                    assert_eq!(
                        slice.icmp_type(),
                        TimestampRequest(TimestampMessage::from_bytes([
                            bytes[4], bytes[5], bytes[6], bytes[7],
                            bytes[8], bytes[9], bytes[10], bytes[11],
                            bytes[12], bytes[13], bytes[14], bytes[15],
                            bytes[16], bytes[17], bytes[18], bytes[19],
                        ]))
                    );
                }

                // unknown code
                for unknow_code in 1..=u8::MAX {
                    assert_unknown(TYPE_TIMESTAMP, unknow_code);
                }
            }

            // timestamp reply
            {
                // matching code
                {
                    let bytes = gen_bytes(TYPE_TIMESTAMP_REPLY, 0);
                    let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
                    assert_eq!(
                        slice.icmp_type(),
                        TimestampReply(TimestampMessage::from_bytes([
                            bytes[4], bytes[5], bytes[6], bytes[7],
                            bytes[8], bytes[9], bytes[10], bytes[11],
                            bytes[12], bytes[13], bytes[14], bytes[15],
                            bytes[16], bytes[17], bytes[18], bytes[19],
                        ]))
                    );
                }

                // unknown code
                for unknow_code in 1..=u8::MAX {
                    assert_unknown(TYPE_TIMESTAMP_REPLY, unknow_code);
                }
            }
        }
    }

    proptest!{
        #[test]
        fn type_u8(bytes in any::<[u8;20]>()) {
            assert_eq!(
                bytes[0],
                Icmpv4Slice::from_slice(&bytes).unwrap().type_u8(),
            );
        }
    }

    proptest!{
        #[test]
        fn code_u8(bytes in any::<[u8;20]>()) {
            assert_eq!(
                bytes[1],
                Icmpv4Slice::from_slice(&bytes).unwrap().code_u8(),
            );
        }
    }

    proptest!{
        #[test]
        fn checksum(bytes in any::<[u8;20]>()) {
            assert_eq!(
                u16::from_be_bytes([bytes[2], bytes[3]]),
                Icmpv4Slice::from_slice(&bytes).unwrap().checksum(),
            );
        }
    }

    proptest!{
        #[test]
        fn bytes5to8(bytes in any::<[u8;20]>()) {
            assert_eq!(
                [bytes[4], bytes[5], bytes[6], bytes[7]],
                Icmpv4Slice::from_slice(&bytes).unwrap().bytes5to8(),
            );
        }
    }

    proptest!{
        #[test]
        fn payload(
            payload in proptest::collection::vec(any::<u8>(), 8..26)
        ) {
            use Icmpv4Type::*;
            let dummy_ts = TimestampMessage{
                id: 0,
                seq: 0,
                originate_timestamp: 0,
                receive_timestamp: 0,
                transmit_timestamp: 0,
            };
            let dummy_echo = IcmpEchoHeader{
                id: 0,
                seq: 0,
            };
            let dummy_redirect = RedirectHeader{
                code: RedirectCode::RedirectForNetwork,
                gateway_internet_address: [0;4],
            };
            // tests with variable payloads
            {
                let var_tests = [
                    Unknown{type_u8: 0, code_u8: 0, bytes5to8: [0;4]},
                    EchoReply(dummy_echo),
                    DestinationUnreachable(DestUnreachableHeader::Network),
                    Redirect(dummy_redirect),
                    EchoRequest(dummy_echo),
                    TimeExceeded(TimeExceededCode::TtlExceededInTransit),
                    ParameterProblem(ParameterProblemHeader::BadLength),
                    // timestamps with non-zero code values
                    Unknown{type_u8: TYPE_TIMESTAMP, code_u8: 1, bytes5to8: [0;4]},
                    Unknown{type_u8: TYPE_TIMESTAMP_REPLY, code_u8: 1, bytes5to8: [0;4]},
                ];
                for t in var_tests {

                    let mut bytes = Vec::with_capacity(t.header_len() + payload.len());
                    Icmpv4Header::new(t.clone()).write(&mut bytes).unwrap();
                    bytes.extend_from_slice(&payload);

                    assert_eq!(
                        &payload[..],
                        Icmpv4Slice::from_slice(&bytes).unwrap().payload()
                    );
                }
            }
            // tests with fixed payload sizes
            {
                let fixed_tests = [
                    (0, TimestampRequest(dummy_ts.clone())),
                    (0, TimestampReply(dummy_ts)),
                ];
                for t in fixed_tests {
                    let mut bytes = Vec::with_capacity(t.1.header_len() + t.0);
                    Icmpv4Header::new(t.1.clone()).write(&mut bytes).unwrap();
                    bytes.extend_from_slice(&payload[..t.0]);

                    assert_eq!(
                        &payload[..t.0],
                        Icmpv4Slice::from_slice(&bytes).unwrap().payload()
                    );
                }
            }
        }
    }

    proptest!{
        #[test]
        fn slice(bytes in proptest::collection::vec(any::<u8>(), 20..1024)) {
            let slice = if bytes[0] == TYPE_TIMESTAMP || bytes[0] == TYPE_TIMESTAMP_REPLY {
                &bytes[..20]
            } else {
                &bytes[..]
            };
            assert_eq!(
                slice,
                Icmpv4Slice::from_slice(slice).unwrap().slice(),
            );
        }
    }

    proptest!{
        #[test]
        fn clone_eq(bytes in any::<[u8;20]>()) {
            let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest!{
        #[test]
        fn debug(bytes in any::<[u8;20]>()) {
            let slice = Icmpv4Slice::from_slice(&bytes).unwrap();
            assert_eq!(
                format!("{:?}", slice),
                format!("Icmpv4Slice {{ slice: {:?} }}", &bytes[..])
            );
        }
    }
}

mod icmpv4_regression {
    use super::*;

    #[test]
    fn icmp4_echo_marshall_unmarshall() {
        let icmp4 = Icmpv4Header {
            icmp_type: Icmpv4Type::EchoRequest(IcmpEchoHeader { seq: 1, id: 2 }),
            checksum: 0,
        };
        // serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        icmp4.write(&mut buffer).unwrap();
        let (new_icmp4, rest) = Icmpv4Header::from_slice(&buffer).unwrap();
        assert_eq!(icmp4, new_icmp4);
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn ip4_echo_marshall_unmarshall() {
        let builder = PacketBuilder::ipv4(
            [192, 168, 1, 1], //source ip
            [192, 168, 1, 2], //desitionation ip
            20,
        ) //time to life
        .icmp4_echo_request(1, 2);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

        //serialize
        builder.write(&mut result, &payload).unwrap();

        let new_ip = PacketHeaders::from_ip_slice(&result).unwrap();
        if let Some(TransportHeader::Icmpv4(hdr)) = new_ip.transport {
            if let Icmpv4Type::EchoRequest(echo) = hdr.icmp_type {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 2);
            } else {
                panic!("Not an EchoRequest!?");
            }
        } else {
            panic!("No transport header found!?")
        }
    }
    const ICMP4_ECHO_REQUEST_BYTES: [u8; 98] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x54, 0x13, 0x6f, 0x40, 0x00, 0x40, 0x01, 0x29, 0x38, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc9, 0x99, 0x00, 0x03, 0x00, 0x01, 0x79, 0xc5, 0xd9,
        0x61, 0x00, 0x00, 0x00, 0x00, 0x18, 0x68, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    const ICMP4_ECHO_REPLY_BYTES: [u8; 98] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x54, 0x13, 0x70, 0x00, 0x00, 0x40, 0x01, 0x69, 0x37, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0xd1, 0x99, 0x00, 0x03, 0x00, 0x01, 0x79, 0xc5, 0xd9,
        0x61, 0x00, 0x00, 0x00, 0x00, 0x18, 0x68, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    // real echo request/reply captured from tcpdump
    // ping 127.0.0.1 to 127.0.0.1
    #[test]
    fn pcap_echo_session() {
        let request = PacketHeaders::from_ethernet_slice(&ICMP4_ECHO_REQUEST_BYTES).unwrap();
        let request_icmp4 = request.transport.unwrap().icmpv4().unwrap();
        match request_icmp4.icmp_type {
            Icmpv4Type::EchoRequest(echo) => {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 3); // arbitrarily assigned by OS
            }
            _ => panic!(r#"Request didn't parse as ICMP4!?"#),
        }

        let reply = PacketHeaders::from_ethernet_slice(&ICMP4_ECHO_REPLY_BYTES).unwrap();
        let reply_icmp4 = reply.transport.unwrap().icmpv4().unwrap();
        match reply_icmp4.icmp_type {
            Icmpv4Type::EchoReply(echo) => {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 3); // arbitrarily assigned by OS
            }
            _ => panic!(r#"Request didn't parse as ICMP4!?"#),
        }
        let request_iph = request.ip.unwrap();
        let reply_iph = reply.ip.unwrap();
        if let IpHeader::Version4(request_ip, _) = request_iph {
            if let IpHeader::Version4(reply_ip, _) = reply_iph {
                assert_eq!(reply_ip.source, request_ip.destination);
                assert_eq!(reply_ip.destination, request_ip.source);
            } else {
                panic!("reply ip not v4!?");
            }
        } else {
            panic!("request ip not v4!?");
        }
    }

    #[test]
    fn echo_request_slice() {
        let echo = SlicedPacket::from_ethernet(&ICMP4_ECHO_REQUEST_BYTES).unwrap();
        use TransportSlice::*;
        let icmp4 = match echo.transport.unwrap() {
            Icmpv4(icmp4) => icmp4,
            Icmpv6(_) | Udp(_) | Tcp(_) | Unknown(_) => panic!("Misparsed header!"),
        };
        assert!(matches!(icmp4.icmp_type(), Icmpv4Type::EchoRequest(_)));
    }

    #[test]
    fn verify_icmp4_checksum() {
        for (pkt, checksum) in [
            (ICMP4_ECHO_REQUEST_BYTES, 0xc999),
            (ICMP4_ECHO_REPLY_BYTES, 0xd199),
        ] {
            // make sure we can unmarshall the correct checksum
            let request = PacketHeaders::from_ethernet_slice(&pkt).unwrap();
            let mut icmp4 = request.transport.unwrap().icmpv4().unwrap();
            let valid_checksum = icmp4.checksum;
            assert_ne!(valid_checksum, 0);
            assert_eq!(valid_checksum, checksum);
            // reset it and recalculate
            icmp4.checksum = 0;
            assert_eq!(icmp4.icmp_type.calc_checksum(request.payload), valid_checksum);
        }
    }

    // TTL unreachable from 'traceroute google.com'
    const ICMP4_TTL_EXCEEDED_BYTES: [u8; 94] = [
        0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x60, 0xa4, 0xb7, 0x25, 0x4b, 0x84, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x5c, 0x87, 0xd4, 0x9c, 0xc9, 0x72,
        0xc0, 0xa8, 0x01, 0x6e, 0x0b, 0x00, 0x24, 0x29, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00,
        0x3c, 0xe3, 0xaf, 0x00, 0x00, 0x01, 0x11, 0x14, 0x84, 0xc0, 0xa8, 0x01, 0x6e, 0xd8, 0xef,
        0x26, 0x78, 0xc2, 0x8e, 0x82, 0x9f, 0x00, 0x28, 0x03, 0xed, 0x40, 0x41, 0x42, 0x43, 0x44,
        0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57,
    ];
    #[test]
    fn parse_icmp4_ttl_exceeded() {
        let ttl_exceeded = PacketHeaders::from_ethernet_slice(&ICMP4_TTL_EXCEEDED_BYTES).unwrap();
        let ip_header = match ttl_exceeded.ip.unwrap() {
            IpHeader::Version4(ip4, _) => ip4,
            _ => panic!("Didn't parse inner v4 IP header!?"),
        };
        assert_eq!(
            Ipv4Addr::from(ip_header.source),
            "212.156.201.114".parse::<Ipv4Addr>().unwrap()
        );
        let icmp4 = ttl_exceeded.transport.unwrap().icmpv4().unwrap();
        let icmp_bytes = icmp4.to_bytes();
        assert_eq!(8, icmp_bytes.len());
        assert_eq!(icmp_bytes[0], icmpv4::TYPE_TIME_EXCEEDED);
        assert_eq!(icmp_bytes[1], 0); // code
        assert_eq!(&icmp_bytes[4..], &[0; 4]); // TTL exceeded doesn't use this field
                                               // now unpack the bounced packet in the payload
        let embedded_pkt = PacketHeaders::from_ip_slice(ttl_exceeded.payload).unwrap();
        let ip_header = match embedded_pkt.ip.unwrap() {
            IpHeader::Version4(ip4, _) => ip4,
            _ => panic!("Didn't parse inner v4 IP header!?"),
        };
        use std::net::Ipv4Addr;
        assert_eq!(
            Ipv4Addr::from(ip_header.source),
            "192.168.1.110".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            Ipv4Addr::from(ip_header.destination),
            "216.239.38.120".parse::<Ipv4Addr>().unwrap()
        );
        let udp_header = embedded_pkt.transport.unwrap().udp().unwrap();
        assert_eq!(udp_header.source_port, 49806); // numbers read from wireshark
        assert_eq!(udp_header.destination_port, 33439);
    }

    const ICMP4_PORT_UNREACHABLE_BYTES: [u8; 70] = [
        0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x60, 0xa4, 0xb7, 0x25, 0x4b, 0x84, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x39, 0x01, 0xc0, 0x47, 0xd8, 0xef, 0x26, 0x78,
        0xc0, 0xa8, 0x01, 0x6e, 0x03, 0x03, 0xb3, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x45, 0x80, 0x00,
        0x3c, 0xe3, 0xd2, 0x00, 0x00, 0x01, 0x11, 0x13, 0xe1, 0xc0, 0xa8, 0x01, 0x6e, 0xd8, 0xef,
        0x26, 0x78, 0xb3, 0x4e, 0x82, 0xb2, 0x00, 0x28, 0x13, 0x1a,
    ];
    #[test]
    fn icmp4_dst_unreachable() {
        let offset = 14 + 20 + 1; // ethernet + iphdr + icmp_type
                                  // test all of the unreachable codes to make sure the maps are right
        for code_u8 in 0..icmpv4::CODE_DST_UNREACH_PRECEDENCE_CUTOFF {
            let mut pkt = ICMP4_PORT_UNREACHABLE_BYTES.clone();
            pkt[offset] = code_u8; // over write the code
            let parsed = PacketHeaders::from_ethernet_slice(&pkt).unwrap();
            let icmp4 = parsed.transport.unwrap().icmpv4().unwrap();
            if let Icmpv4Type::DestinationUnreachable(icmp_code) = icmp4.icmp_type {
                assert_eq!(code_u8, icmp_code.code_u8());
            } else {
                panic!("Not destination unreachable!?");
            }
        }
    }
}
