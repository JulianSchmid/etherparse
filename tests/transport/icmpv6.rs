use super::super::*;
use proptest::prelude::*;

#[test]
fn constants() {
    use etherparse::icmpv6::*;
    // type values according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-16
    assert_eq!(1, TYPE_DST_UNREACH);
    assert_eq!(2, TYPE_PACKET_TOO_BIG);
    assert_eq!(3, TYPE_TIME_EXCEEDED);
    assert_eq!(4, TYPE_PARAM_PROB);
    assert_eq!(128, TYPE_ECHO_REQUEST);
    assert_eq!(129, TYPE_ECHO_REPLY);
    assert_eq!(130, TYPE_MULTICAST_LISTENER_QUERY);
    assert_eq!(131, TYPE_MULTICAST_LISTENER_REPORT);
    assert_eq!(132, TYPE_MULTICAST_LISTENER_REDUCTION);
    assert_eq!(133, TYPE_ROUTER_SOLICITATION);
    assert_eq!(134, TYPE_ROUTER_ADVERTISEMENT);
    assert_eq!(135, TYPE_NEIGHBOR_SOLICITATION);
    assert_eq!(136, TYPE_NEIGHBOR_ADVERTISEMENT);
    assert_eq!(137, TYPE_REDIRECT_MESSAGE);
    assert_eq!(138, TYPE_ROUTER_RENUMBERING);
    assert_eq!(141, TYPE_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION);
    assert_eq!(142, TYPE_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT);
    assert_eq!(160, TYPE_EXT_ECHO_REQUEST);
    assert_eq!(161, TYPE_EXT_ECHO_REPLY);

    // destination unreachable code values according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-2
    assert_eq!(0, CODE_DST_UNREACH_NO_ROUTE);
    assert_eq!(1, CODE_DST_UNREACH_PROHIBITED);
    assert_eq!(2, CODE_DST_UNREACH_BEYOND_SCOPE);
    assert_eq!(3, CODE_DST_UNREACH_ADDR);
    assert_eq!(4, CODE_DST_UNREACH_PORT);
    assert_eq!(5, CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY);
    assert_eq!(6, CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST);

    // time exceeded code values according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-4
    assert_eq!(0, CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED);
    assert_eq!(1, CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED);

    // parameter problem codes according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-5
    assert_eq!(0, CODE_PARAM_PROBLEM_ERR_HEADER_FIELD);
    assert_eq!(1, CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER);
    assert_eq!(2, CODE_PARAM_PROBLEM_UNRECOG_IPV6_OPTION);
    assert_eq!(3, CODE_PARAM_PROBLEM_IPV6_FIRST_FRAG_INCOMP_HEADER_CHAIN);
    assert_eq!(4, CODE_PARAM_PROBLEM_SR_UPPER_LAYER_HEADER_ERROR);
    assert_eq!(
        5,
        CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE
    );
    assert_eq!(6, CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG);
    assert_eq!(7, CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG);
    assert_eq!(8, CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS);
    assert_eq!(9, CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER);
    assert_eq!(10, CODE_PARAM_PROBLEM_OPTION_TOO_BIG);
}

mod icmp6_dest_unreachable {
    use etherparse::icmpv6::DestUnreachableCode;
    use etherparse::icmpv6::DestUnreachableCode::*;
    use etherparse::icmpv6::*;

    #[test]
    fn from_u8() {
        for code_u8 in 7u8..=0xff {
            assert!(DestUnreachableCode::from_u8(code_u8).is_none());
        }
        assert_eq!(
            NoRoute,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_NO_ROUTE).unwrap()
        );
        assert_eq!(
            Prohibited,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_PROHIBITED,).unwrap()
        );
        assert_eq!(
            BeyondScope,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_BEYOND_SCOPE,).unwrap()
        );
        assert_eq!(
            Address,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_ADDR,).unwrap()
        );
        assert_eq!(
            Port,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_PORT,).unwrap()
        );
        assert_eq!(
            SourceAddressFailedPolicy,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY,).unwrap()
        );
        assert_eq!(
            RejectRoute,
            DestUnreachableCode::from_u8(CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST,).unwrap()
        );
    }

    #[test]
    fn code_u8() {
        assert_eq!(NoRoute.code_u8(), CODE_DST_UNREACH_NO_ROUTE);
        assert_eq!(Prohibited.code_u8(), CODE_DST_UNREACH_PROHIBITED);
        assert_eq!(BeyondScope.code_u8(), CODE_DST_UNREACH_BEYOND_SCOPE);
        assert_eq!(Address.code_u8(), CODE_DST_UNREACH_ADDR);
        assert_eq!(Port.code_u8(), CODE_DST_UNREACH_PORT);
        assert_eq!(
            SourceAddressFailedPolicy.code_u8(),
            CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY
        );
        assert_eq!(RejectRoute.code_u8(), CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST);
    }

    #[test]
    fn clone_eq() {
        let values = [
            NoRoute,
            Prohibited,
            BeyondScope,
            Address,
            Port,
            SourceAddressFailedPolicy,
            RejectRoute,
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            (NoRoute, "NoRoute"),
            (Prohibited, "Prohibited"),
            (BeyondScope, "BeyondScope"),
            (Address, "Address"),
            (Port, "Port"),
            (SourceAddressFailedPolicy, "SourceAddressFailedPolicy"),
            (RejectRoute, "RejectRoute"),
        ];
        for test in tests {
            assert_eq!(format!("{:?}", test.0), test.1);
        }
    }
}

mod time_exceeded_code {
    use etherparse::icmpv6::TimeExceededCode::*;
    use etherparse::icmpv6::*;

    #[test]
    fn from_u8() {
        assert_eq!(
            Some(HopLimitExceeded),
            TimeExceededCode::from_u8(CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED)
        );
        assert_eq!(
            Some(FragmentReassemblyTimeExceeded),
            TimeExceededCode::from_u8(CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED)
        );
        for code_u8 in 2..=u8::MAX {
            assert_eq!(None, TimeExceededCode::from_u8(code_u8));
        }
    }

    #[test]
    fn from_enum() {
        assert_eq!(
            CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED,
            HopLimitExceeded.code_u8()
        );
        assert_eq!(
            CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
            FragmentReassemblyTimeExceeded.code_u8()
        );
    }

    #[test]
    fn clone_eq() {
        let values = [
            HopLimitExceeded,
            FragmentReassemblyTimeExceeded,
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            (HopLimitExceeded, "HopLimitExceeded"),
            (
                FragmentReassemblyTimeExceeded,
                "FragmentReassemblyTimeExceeded",
            ),
        ];
        for test in tests {
            assert_eq!(format!("{:?}", test.0), test.1);
        }
    }
}

mod parameter_problem_code {
    use etherparse::icmpv6::ParameterProblemCode::*;
    use etherparse::icmpv6::*;

    #[test]
    fn from_u8() {
        assert_eq!(
            ErroneousHeaderField,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_ERR_HEADER_FIELD)
        );
        assert_eq!(
            UnrecognizedNextHeader,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER)
        );
        assert_eq!(
            UnrecognizedIpv6Option,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_UNRECOG_IPV6_OPTION)
        );
        assert_eq!(
            Ipv6FirstFragmentIncompleteHeaderChain,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_IPV6_FIRST_FRAG_INCOMP_HEADER_CHAIN)
        );
        assert_eq!(
            SrUpperLayerHeaderError,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_SR_UPPER_LAYER_HEADER_ERROR)
        );
        assert_eq!(
            UnrecognizedNextHeaderByIntermediateNode,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE)
        );
        assert_eq!(
            ExtensionHeaderTooBig,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG)
        );
        assert_eq!(
            ExtensionHeaderChainTooLong,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG)
        );
        assert_eq!(
            TooManyExtensionHeaders,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS)
        );
        assert_eq!(
            TooManyOptionsInExtensionHeader,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER)
        );
        assert_eq!(
            OptionTooBig,
            ParameterProblemCode::from(CODE_PARAM_PROBLEM_OPTION_TOO_BIG)
        );
        for code_u8 in 11..=u8::MAX {
            assert_eq!(Raw { code_u8 }, ParameterProblemCode::from(code_u8));
        }
    }

    #[test]
    fn from_enum() {
        assert_eq!(
            CODE_PARAM_PROBLEM_ERR_HEADER_FIELD,
            u8::from(ErroneousHeaderField)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER,
            u8::from(UnrecognizedNextHeader)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_UNRECOG_IPV6_OPTION,
            u8::from(UnrecognizedIpv6Option)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_IPV6_FIRST_FRAG_INCOMP_HEADER_CHAIN,
            u8::from(Ipv6FirstFragmentIncompleteHeaderChain)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_SR_UPPER_LAYER_HEADER_ERROR,
            u8::from(SrUpperLayerHeaderError)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE,
            u8::from(UnrecognizedNextHeaderByIntermediateNode)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG,
            u8::from(ExtensionHeaderTooBig)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG,
            u8::from(ExtensionHeaderChainTooLong)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS,
            u8::from(TooManyExtensionHeaders)
        );
        assert_eq!(
            CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER,
            u8::from(TooManyOptionsInExtensionHeader)
        );
        assert_eq!(CODE_PARAM_PROBLEM_OPTION_TOO_BIG, u8::from(OptionTooBig));
        for code_u8 in 0..=u8::MAX {
            assert_eq!(code_u8, u8::from(Raw { code_u8 }));
        }
    }
    #[test]
    fn clone_eq() {
        let values = [
            Raw { code_u8: 8 },
            ErroneousHeaderField,
            UnrecognizedNextHeader,
            UnrecognizedIpv6Option,
            UnrecognizedNextHeader,
            UnrecognizedIpv6Option,
            Ipv6FirstFragmentIncompleteHeaderChain,
            SrUpperLayerHeaderError,
            UnrecognizedNextHeaderByIntermediateNode,
            ExtensionHeaderTooBig,
            ExtensionHeaderChainTooLong,
            TooManyExtensionHeaders,
            TooManyOptionsInExtensionHeader,
            OptionTooBig,
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            (Raw { code_u8: 8 }, "Raw { code_u8: 8 }"),
            (ErroneousHeaderField, "ErroneousHeaderField"),
            (UnrecognizedNextHeader, "UnrecognizedNextHeader"),
            (UnrecognizedIpv6Option, "UnrecognizedIpv6Option"),
            (UnrecognizedNextHeader, "UnrecognizedNextHeader"),
            (UnrecognizedIpv6Option, "UnrecognizedIpv6Option"),
            (
                Ipv6FirstFragmentIncompleteHeaderChain,
                "Ipv6FirstFragmentIncompleteHeaderChain",
            ),
            (SrUpperLayerHeaderError, "SrUpperLayerHeaderError"),
            (
                UnrecognizedNextHeaderByIntermediateNode,
                "UnrecognizedNextHeaderByIntermediateNode",
            ),
            (ExtensionHeaderTooBig, "ExtensionHeaderTooBig"),
            (ExtensionHeaderChainTooLong, "ExtensionHeaderChainTooLong"),
            (TooManyExtensionHeaders, "TooManyExtensionHeaders"),
            (
                TooManyOptionsInExtensionHeader,
                "TooManyOptionsInExtensionHeader",
            ),
            (OptionTooBig, "OptionTooBig"),
        ];
        for test in tests {
            assert_eq!(format!("{:?}", test.0), test.1);
        }
    }
}

mod icmpv6_type {
    use super::*;

    proptest! {
        #[test]
        fn from_bytes(
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, Icmpv6Type, icmpv6::*};

            // destination unreachable
            {
                use DestUnreachableCode::*;
                
                // known codes
                {
                    let tests = [
                        (NoRoute, CODE_DST_UNREACH_NO_ROUTE),
                        (Prohibited, CODE_DST_UNREACH_PROHIBITED),
                        (BeyondScope, CODE_DST_UNREACH_BEYOND_SCOPE),
                        (Address, CODE_DST_UNREACH_ADDR),
                        (Port, CODE_DST_UNREACH_PORT),
                        (SourceAddressFailedPolicy, CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY),
                        (RejectRoute, CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST),
                    ];
                    for t in tests {
                        assert_eq!(
                            Icmpv6Type::from_bytes(TYPE_DST_UNREACH, t.1, bytes5to8),
                            DestinationUnreachable(t.0)
                        );
                    }
                }

                // unknown codes
                for code_u8 in 7..=u8::MAX {
                    assert_eq!(
                        Icmpv6Type::from_bytes(TYPE_DST_UNREACH, code_u8, bytes5to8),
                        Unknown{
                            type_u8: TYPE_DST_UNREACH,
                            code_u8,
                            bytes5to8,
                        }
                    );
                }
            }

            // packet too big
            {
                // known code
                assert_eq!(
                    Icmpv6Type::from_bytes(TYPE_PACKET_TOO_BIG, 0, bytes5to8),
                    PacketTooBig{
                        mtu: u32::from_be_bytes(bytes5to8),
                    }
                );
                // unknown code
                for code_u8 in 1..=u8::MAX {
                    assert_eq!(
                        Icmpv6Type::from_bytes(TYPE_PACKET_TOO_BIG, code_u8, bytes5to8),
                        Unknown{
                            type_u8: TYPE_PACKET_TOO_BIG,
                            code_u8,
                            bytes5to8,
                        }
                    );
                }
            }
            
            // time exceeded
            {
                // known codes
                {
                    use TimeExceededCode::*;
                    let tests = [
                        (HopLimitExceeded, CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED),
                        (FragmentReassemblyTimeExceeded, CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED),
                    ];
                
                    for t in tests {
                        assert_eq!(
                            Icmpv6Type::from_bytes(TYPE_TIME_EXCEEDED, t.1, bytes5to8),
                            TimeExceeded(t.0)
                        );
                    }
                }

                // unknown codes
                for code_u8 in 2..=u8::MAX {
                    assert_eq!(
                        Icmpv6Type::from_bytes(TYPE_TIME_EXCEEDED, code_u8, bytes5to8),
                        Unknown{
                            type_u8: TYPE_TIME_EXCEEDED,
                            code_u8,
                            bytes5to8,
                        }
                    );
                }
            }
            assert_eq!(
                Icmpv6Type::from_bytes(TYPE_PARAM_PROB, code_u8, bytes5to8),
                ParameterProblem{
                    code: code_u8.into(),
                    pointer: u32::from_be_bytes(bytes5to8),
                }
            );
            assert_eq!(
                Icmpv6Type::from_bytes(TYPE_ECHO_REQUEST, 0, bytes5to8),
                EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8))
            );
            if 0 != code_u8 {
                assert_eq!(
                    Icmpv6Type::from_bytes(TYPE_ECHO_REQUEST, code_u8, bytes5to8),
                    Unknown{
                        type_u8: TYPE_ECHO_REQUEST,
                        code_u8,
                        bytes5to8,
                    }
                );
            }
            assert_eq!(
                Icmpv6Type::from_bytes(TYPE_ECHO_REPLY, 0, bytes5to8),
                EchoReply(IcmpEchoHeader::from_bytes(bytes5to8))
            );
            if 0 != code_u8 {
                assert_eq!(
                    Icmpv6Type::from_bytes(TYPE_ECHO_REPLY, code_u8, bytes5to8),
                    Unknown{
                        type_u8: TYPE_ECHO_REPLY,
                        code_u8,
                        bytes5to8,
                    }
                );
            }

            let known = [
                TYPE_DST_UNREACH,
                TYPE_PACKET_TOO_BIG,
                TYPE_TIME_EXCEEDED,
                TYPE_PARAM_PROB,
                TYPE_ECHO_REQUEST,
                TYPE_ECHO_REPLY
            ];
            for t in 0..=u8::MAX {
                if false == known.contains(&t) {
                    assert_eq!(
                        Icmpv6Type::from_bytes(t, code_u8, bytes5to8),
                        Unknown{
                            type_u8: t,
                            code_u8,
                            bytes5to8,
                        }
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn type_u8(
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, icmpv6::*};
            {
                let type_u8_type_pair = [
                    (TYPE_DST_UNREACH, DestinationUnreachable(DestUnreachableCode::SourceAddressFailedPolicy)),
                    (TYPE_PACKET_TOO_BIG, PacketTooBig{ mtu: u32::from_be_bytes(bytes5to8), }),
                    (TYPE_TIME_EXCEEDED, TimeExceeded(TimeExceededCode::HopLimitExceeded)),
                    (TYPE_PARAM_PROB, ParameterProblem{ code: code_u8.into(), pointer: u32::from_be_bytes(bytes5to8)}),
                    (TYPE_ECHO_REQUEST, EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8))),
                    (TYPE_ECHO_REPLY, EchoReply(IcmpEchoHeader::from_bytes(bytes5to8))),
                ];
                for test in type_u8_type_pair {
                    assert_eq!(test.0, test.1.type_u8());
                }
            }

            for t in 0..=u8::MAX {
                assert_eq!(
                    t,
                    Unknown{
                        type_u8: t,
                        code_u8,
                        bytes5to8,
                    }.type_u8()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn code_u8(
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, icmpv6::*};

            // types with 0 as code
            {
                let code_type_pair = [
                    (0, PacketTooBig{ mtu: u32::from_be_bytes(bytes5to8), }),
                    (code_u8, ParameterProblem{ code: code_u8.into(), pointer: u32::from_be_bytes(bytes5to8)}),
                    (0, EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8))),
                    (0, EchoReply(IcmpEchoHeader::from_bytes(bytes5to8))),
                ];
                for test in code_type_pair {
                    assert_eq!(test.0, test.1.code_u8());
                }
            }

            // destination unreachable
            {
                use DestUnreachableCode::*;
                let tests = [
                    (NoRoute, CODE_DST_UNREACH_NO_ROUTE),
                    (Prohibited, CODE_DST_UNREACH_PROHIBITED),
                    (BeyondScope, CODE_DST_UNREACH_BEYOND_SCOPE),
                    (Address, CODE_DST_UNREACH_ADDR),
                    (Port, CODE_DST_UNREACH_PORT),
                    (SourceAddressFailedPolicy, CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY),
                    (RejectRoute, CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST),
                ];
                for t in tests {
                    assert_eq!(t.1, DestinationUnreachable(t.0).code_u8());
                }
            }

            // time exceeded
            {
                use TimeExceededCode::*;
                let tests = [
                    (HopLimitExceeded, CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED),
                    (FragmentReassemblyTimeExceeded, CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED),
                ];
                for t in tests {
                    assert_eq!(t.1, TimeExceeded(t.0).code_u8());
                }
            }

            // unknown
            for t in 0..=u8::MAX {
                assert_eq!(
                    code_u8,
                    Unknown{
                        type_u8: t,
                        code_u8,
                        bytes5to8,
                    }.code_u8()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn calc_checksum(
            ip_header in ipv6_any(),
            icmpv6_type in icmpv6_type_any(),
            // max length is u32::MAX - header_len (7)
            bad_len in (std::u32::MAX - 7) as usize..=std::usize::MAX,
            payload in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            // size error case
            {
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_matches!(
                    icmpv6_type.calc_checksum(ip_header.source, ip_header.destination, too_big_slice),
                    Err(ValueError::Ipv6PayloadLengthTooLarge(_))
                );
            }

            // normal case
            {
                assert_eq!(
                    icmpv6_type.calc_checksum(ip_header.source, ip_header.destination, &payload).unwrap(),
                    {
                        let (type_u8, code_u8 , bytes5to8) = icmpv6_type.to_bytes();
                        etherparse::checksum::Sum16BitWords::new()
                        .add_16bytes(ip_header.source)
                        .add_16bytes(ip_header.destination)
                        .add_4bytes((
                            payload.len() as u32 + 8
                        ).to_be_bytes())
                        .add_2bytes([0, ip_number::IPV6_ICMP])
                        .add_2bytes([type_u8, code_u8])
                        .add_4bytes(bytes5to8)
                        .add_slice(&payload)
                        .ones_complement()
                        .to_be()
                    }
                );
            }

        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            type_u8 in any::<u8>(),
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
            mtu in any::<u32>(),
        ) {
            use Icmpv6Type::*;
            use icmpv6::*;
            assert_eq!(
                Unknown{type_u8, code_u8, bytes5to8}.to_bytes(),
                (type_u8, code_u8, bytes5to8)
            );
            if let Some(code) = DestUnreachableCode::from_u8(code_u8) {
                assert_eq!(
                    DestinationUnreachable(code).to_bytes(),
                    (TYPE_DST_UNREACH, code_u8, [0;4])
                );
            } else {
                assert_eq!(
                    DestinationUnreachable(DestUnreachableCode::NoRoute).to_bytes(),
                    (TYPE_DST_UNREACH, CODE_DST_UNREACH_NO_ROUTE, [0;4])
                );
            }
            assert_eq!(
                PacketTooBig{ mtu }.to_bytes(),
                (TYPE_PACKET_TOO_BIG, 0, mtu.to_be_bytes())
            );
            assert_eq!(
                TimeExceeded(TimeExceededCode::HopLimitExceeded).to_bytes(),
                (TYPE_TIME_EXCEEDED, CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED, [0u8;4])
            );
            assert_eq!(
                ParameterProblem{ code: ParameterProblemCode::Raw{ code_u8 }, pointer: mtu}.to_bytes(),
                (TYPE_PARAM_PROB, code_u8, mtu.to_be_bytes())
            );
            assert_eq!(
                EchoRequest(IcmpEchoHeader{
                    id: u16::from_be_bytes([bytes5to8[0], bytes5to8[1]]),
                    seq: u16::from_be_bytes([bytes5to8[2], bytes5to8[3]])
                }).to_bytes(),
                (TYPE_ECHO_REQUEST, 0, bytes5to8)
            );
            assert_eq!(
                EchoReply(IcmpEchoHeader{
                    id: u16::from_be_bytes([bytes5to8[0], bytes5to8[1]]),
                    seq: u16::from_be_bytes([bytes5to8[2], bytes5to8[3]])
                }).to_bytes(),
                (TYPE_ECHO_REPLY, 0, bytes5to8)
            );
        }
    }

    proptest! {
        #[test]
        fn to_header(
            ip_header in ipv6_any(),
            icmpv6_type in icmpv6_type_any(),
            // max length is u32::MAX - header_len (7)
            bad_len in (std::u32::MAX - 7) as usize..=std::usize::MAX,
            payload in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            // size error case
            {
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_matches!(
                    icmpv6_type.to_header(ip_header.source, ip_header.destination, too_big_slice),
                    Err(ValueError::Ipv6PayloadLengthTooLarge(_))
                );
            }
            // normal case
            assert_eq!(
                icmpv6_type.to_header(ip_header.source, ip_header.destination, &payload).unwrap(),
                Icmpv6Header {
                    checksum: icmpv6_type.calc_checksum(ip_header.source, ip_header.destination, &payload).unwrap(),
                    icmp_type: icmpv6_type,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn header_len(
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, icmpv6::*};

            let len_8_hdrs = [
                DestinationUnreachable(DestUnreachableCode::Prohibited),
                PacketTooBig{ mtu: u32::from_be_bytes(bytes5to8), },
                TimeExceeded(TimeExceededCode::FragmentReassemblyTimeExceeded),
                ParameterProblem{
                    code: code_u8.into(),
                    pointer: u32::from_be_bytes(bytes5to8),
                },
                EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8)),
                EchoReply(IcmpEchoHeader::from_bytes(bytes5to8)),
            ];

            for hdr in len_8_hdrs {
                assert_eq!(8, hdr.header_len());
            }

            for t in 0..=u8::MAX {
                assert_eq!(
                    8,
                    Unknown{
                        type_u8: t,
                        code_u8,
                        bytes5to8,
                    }.header_len()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn fixed_payload_size(
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, icmpv6::*};

            let variable_payload_headers = [
                DestinationUnreachable(DestUnreachableCode::Prohibited),
                PacketTooBig{ mtu: u32::from_be_bytes(bytes5to8), },
                TimeExceeded(TimeExceededCode::HopLimitExceeded),
                ParameterProblem{
                    code: code_u8.into(),
                    pointer: u32::from_be_bytes(bytes5to8),
                },
                EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8)),
                EchoReply(IcmpEchoHeader::from_bytes(bytes5to8)),
            ];

            for hdr in variable_payload_headers {
                assert_eq!(None, hdr.fixed_payload_size());
            }

            for t in 0..=u8::MAX {
                assert_eq!(
                    None,
                    Unknown{
                        type_u8: t,
                        code_u8,
                        bytes5to8,
                    }.fixed_payload_size()
                );
            }
        }
    }

    #[test]
    fn debug() {
        assert_eq!(
            format!(
                "{:?}",
                Icmpv6Type::Unknown {
                    type_u8: 0,
                    code_u8: 1,
                    bytes5to8: [2, 3, 4, 5]
                }
            ),
            "Unknown { type_u8: 0, code_u8: 1, bytes5to8: [2, 3, 4, 5] }"
        )
    }

    proptest! {
        #[test]
        fn clone_eq(t in icmpv6_type_any()) {
            assert_eq!(t, t.clone());
        }
    }
}

mod icmpv6_header {
    use super::*;

    proptest! {
        #[test]
        fn header_len(icmp_type in icmpv6_type_any(), checksum in any::<u16>()) {
            assert_eq!(
                icmp_type.header_len(),
                Icmpv6Header{
                    icmp_type,
                    checksum
                }.header_len()
            );
        }
    }

    proptest! {
        #[test]
        fn fixed_payload_size(icmp_type in icmpv6_type_any(), checksum in any::<u16>()) {
            assert_eq!(
                icmp_type.fixed_payload_size(),
                Icmpv6Header{
                    icmp_type,
                    checksum
                }.fixed_payload_size()
            );
        }
    }

    proptest! {
        #[test]
        fn new(icmp_type in icmpv6_type_any()) {
            assert_eq!(
                Icmpv6Header::new(icmp_type.clone()),
                Icmpv6Header {
                    icmp_type,
                    checksum: 0,
                }
            );
        }
    }

    proptest! {
        #[test]
        fn with_checksum(
            ip_header in ipv6_any(),
            icmp_type in icmpv6_type_any(),
            // max length is u32::MAX - header_len (7)
            bad_len in (std::u32::MAX - 7) as usize..=std::usize::MAX,
            payload in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {

            // error case
            {
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_matches!(
                    Icmpv6Header::with_checksum(icmp_type.clone(), ip_header.source, ip_header.destination, too_big_slice),
                    Err(ValueError::Ipv6PayloadLengthTooLarge(_))
                );
            }

            // non error case
            assert_eq!(
                Icmpv6Header::with_checksum(icmp_type.clone(), ip_header.source, ip_header.destination, &payload).unwrap(),
                Icmpv6Header {
                    icmp_type,
                    checksum: icmp_type.calc_checksum(ip_header.source, ip_header.destination, &payload).unwrap(),
                }
            );
        }
    }

    proptest! {
        #[test]
        fn write(
            icmp_type in icmpv6_type_any(),
            checksum in any::<u16>(),
            bad_len in 0..8usize
        ) {
            // normal case
            {
                let mut buffer = Vec::with_capacity(icmp_type.header_len());
                Icmpv6Header {
                    icmp_type,
                    checksum,
                }.write(&mut buffer).unwrap();
                let (b0, b1, bytes5to8) = icmp_type.to_bytes();
                let checksum_b = checksum.to_be_bytes();
                assert_eq!(
                    &[
                        b0, b1, checksum_b[0], checksum_b[1],
                        bytes5to8[0], bytes5to8[1], bytes5to8[2], bytes5to8[3],
                    ],
                    &buffer[..]
                );
            }

            // error case
            {
                let mut writer = TestWriter::with_max_size(bad_len);
                Icmpv6Header {
                    icmp_type,
                    checksum,
                }.write(&mut writer).unwrap_err();
            }
        }
    }

    proptest! {
        #[test]
        fn update_checksum(
            ip_header in ipv6_any(),
            icmp_type in icmpv6_type_any(),
            start_checksum in any::<u16>(),
            // max length is u32::MAX - header_len (7)
            bad_len in (std::u32::MAX - 7) as usize..=std::usize::MAX,
            payload in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {

            // error case
            {
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_matches!(
                    Icmpv6Header{
                        icmp_type,
                        checksum: 0
                    }.update_checksum(ip_header.source, ip_header.destination, too_big_slice),
                    Err(ValueError::Ipv6PayloadLengthTooLarge(_))
                );
            }

            // normal case
            assert_eq!(
                {
                    let mut header = Icmpv6Header{
                        icmp_type,
                        checksum: start_checksum,
                    };
                    header.update_checksum(ip_header.source, ip_header.destination, &payload).unwrap();
                    header
                },
                Icmpv6Header{
                    icmp_type,
                    checksum: icmp_type.calc_checksum(ip_header.source, ip_header.destination, &payload).unwrap(),
                }
            );
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            icmp_type in icmpv6_type_any(),
            checksum in any::<u16>(),
        ) {
            let bytes = {
                let (b0, b1, b5to8) = icmp_type.to_bytes();
                let checksum_be = checksum.to_be_bytes();
                [
                    b0, b1, checksum_be[0], checksum_be[1],
                    b5to8[0], b5to8[1], b5to8[2], b5to8[3],
                    0, 0,
                ]
            };

            // ok case
            {
                let result = Icmpv6Header::from_slice(&bytes).unwrap();
                assert_eq!(
                    Icmpv6Header{
                        icmp_type,
                        checksum,
                    },
                    result.0,
                );
                assert_eq!(&bytes[8..], result.1);
            }


            // size error case
            for length in 0..8 {
                assert_matches!(
                    Icmpv6Header::from_slice(&bytes[..length]),
                    Err(ReadError::UnexpectedEndOfSlice(_))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn to_bytes(
            icmp_type in icmpv6_type_any(),
            checksum in any::<u16>(),
        ) {
            let bytes = {
                let (b0, b1, b5to8) = icmp_type.to_bytes();
                let checksum_be = checksum.to_be_bytes();
                [
                    b0, b1, checksum_be[0], checksum_be[1],
                    b5to8[0], b5to8[1], b5to8[2], b5to8[3],
                ]
            };

            assert_eq!(
                Icmpv6Header{
                    icmp_type,
                    checksum,
                }.to_bytes(),
                bytes,
            );
        }
    }

    #[test]
    fn debug() {
        let t = Icmpv6Type::Unknown {
            type_u8: 0,
            code_u8: 1,
            bytes5to8: [2, 3, 4, 5],
        };
        assert_eq!(
            format!(
                "{:?}",
                Icmpv6Header {
                    icmp_type: t.clone(),
                    checksum: 7
                }
            ),
            format!("Icmpv6Header {{ icmp_type: {:?}, checksum: {:?} }}", t, 7)
        );
    }

    proptest! {
        #[test]
        fn clone_eq(icmp_type in icmpv6_type_any(), checksum in any::<u16>()) {
            let header = Icmpv6Header{ icmp_type, checksum };
            assert_eq!(header, header.clone());
        }
    }

    #[test]
    fn icmp6_echo_marshall_unmarshall() {
        let icmp6 = Icmpv6Header {
            icmp_type: Icmpv6Type::EchoRequest(IcmpEchoHeader { seq: 1, id: 2 }),
            checksum: 0,
        };
        // serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        icmp6.write(&mut buffer).unwrap();
        let (new_icmp6, rest) = Icmpv6Header::from_slice(&buffer).unwrap();
        assert_eq!(icmp6, new_icmp6);
        assert_eq!(rest.len(), 0);
    }

    #[test]
    fn ip6_echo_marshall_unmarshall() {
        let builder = PacketBuilder::ipv6(
            [0xfe, 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], //source ip
            [0xfe, 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 114], //dst ip
            20,
        ) //time to life
        .icmp6_echo_request(1, 2);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

        //serialize
        builder.write(&mut result, &payload).unwrap();

        let new_ip = PacketHeaders::from_ip_slice(&result).unwrap();
        if let Some(TransportHeader::Icmpv6(hdr)) = new_ip.transport {
            if let Icmpv6Type::EchoRequest(echo) = hdr.icmp_type {
                assert_eq!(echo.seq, 1);
                assert_eq!(echo.id, 2);
            } else {
                panic!("Not an EchoRequest!?");
            }
        } else {
            panic!("No transport header found!?")
        }
    }
    const ICMP6_ECHO_REQUEST_BYTES: [u8; 118] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60,
        0x00, 0xf3, 0xc2, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0xd5, 0x2f, 0x00, 0x05,
        0x00, 0x01, 0xe3, 0x58, 0xdb, 0x61, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xc0, 0x0d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
        0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    const ICMP6_ECHO_REPLY_BYTES: [u8; 118] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60,
        0x00, 0xa3, 0xde, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0xd4, 0x2f, 0x00, 0x05,
        0x00, 0x01, 0xe3, 0x58, 0xdb, 0x61, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xc0, 0x0d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
        0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    #[test]
    fn verify_icmp6_checksum() {
        for (pkt, checksum) in [
            (ICMP6_ECHO_REQUEST_BYTES, 0xd52f),
            (ICMP6_ECHO_REPLY_BYTES, 0xd42f),
        ] {
            // make sure we can unmarshall the correct checksum
            let request = PacketHeaders::from_ethernet_slice(&pkt).unwrap();
            let mut icmp6 = request.transport.unwrap().icmpv6().unwrap();
            let valid_checksum = icmp6.checksum;
            assert_ne!(valid_checksum, 0);
            assert_eq!(valid_checksum, checksum);
            // reset it and recalculate
            icmp6.checksum = 0;
            let iph = match request.ip {
                Some(IpHeader::Version6(ipv6, _)) => ipv6,
                _ => panic!("Failed to parse ipv6 part of packet?!"),
            };
            assert_eq!(
                icmp6
                    .icmp_type
                    .calc_checksum(iph.source, iph.destination, request.payload),
                Ok(valid_checksum)
            );
        }
    }

    #[test]
    fn echo_request_slice() {
        let echo = SlicedPacket::from_ethernet(&ICMP6_ECHO_REQUEST_BYTES).unwrap();
        use TransportSlice::*;
        let icmp6 = match echo.transport.unwrap() {
            Icmpv6(icmp6) => icmp6,
            Icmpv4(_) | Udp(_) | Tcp(_) | Unknown(_) => panic!("Misparsed header!"),
        };
        assert!(matches!(
            icmp6.header().icmp_type,
            Icmpv6Type::EchoRequest(_)
        ));
    }
}

mod icmpv6_slice {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(slice in proptest::collection::vec(any::<u8>(), 8..1024)) {
            // ok case
            assert_eq!(Icmpv6Slice::from_slice(&slice[..]).unwrap().slice(), &slice[..]);

            // too small size error case
            for len in 0..8 {
                assert_matches!(
                    Icmpv6Slice::from_slice(&slice[..len]),
                    Err(ReadError::UnexpectedEndOfSlice(Icmpv6Header::MIN_SERIALIZED_SIZE))
                );
            }
        }
    }

    proptest! {
        /// This error can only occur on systems with a pointer size
        /// bigger then 64 bits.
        #[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
        #[test]
        fn from_slice_too_big_error(
            bad_len in ((std::u32::MAX as usize) + 1)..=std::usize::MAX,
        ) {
            // too large packet error case
            {
                // SAFETY: In case the error is not triggered
                //         a segmentation fault will be triggered.
                let too_big_slice = unsafe {
                    //NOTE: The pointer must be initialized with a non null value
                    //      otherwise a key constraint of slices is not fullfilled
                    //      which can lead to crashes in release mode.
                    use std::ptr::NonNull;
                    std::slice::from_raw_parts(
                        NonNull::<u8>::dangling().as_ptr(),
                        bad_len
                    )
                };
                assert_matches!(
                    Icmpv6Slice::from_slice(too_big_slice),
                    Err(ReadError::Icmpv6PacketTooBig(_))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn header(
            icmp_type in icmpv6_type_any(),
            checksum in any::<u16>()
        ) {
            let expected = Icmpv6Header {
                icmp_type,
                checksum
            };
            assert_eq!(
                Icmpv6Slice::from_slice(&expected.to_bytes()).unwrap().header(),
                expected
            );
        }
    }

    proptest! {
        #[test]
        fn header_len(
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, icmpv6::*};

            let len_8_types = [
                DestinationUnreachable(DestUnreachableCode::Prohibited),
                PacketTooBig{ mtu: u32::from_be_bytes(bytes5to8), },
                TimeExceeded(TimeExceededCode::HopLimitExceeded),
                ParameterProblem{
                    code: code_u8.into(),
                    pointer: u32::from_be_bytes(bytes5to8),
                },
                EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8)),
                EchoReply(IcmpEchoHeader::from_bytes(bytes5to8)),
            ];

            for t in len_8_types {
                assert_eq!(
                    t.header_len(),
                    Icmpv6Slice::from_slice(
                        &Icmpv6Header::new(t).to_bytes()
                    ).unwrap().header_len()
                );
            }

            for t in 0..=u8::MAX {
                let header = Icmpv6Header::new(
                    Unknown{
                        type_u8: t,
                        code_u8,
                        bytes5to8,
                    }
                );
                assert_eq!(
                    8,
                    Icmpv6Slice::from_slice(
                        &header.to_bytes()
                    ).unwrap().header_len()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn type_u8(slice in proptest::collection::vec(any::<u8>(), 8..16)) {
            assert_eq!(
                Icmpv6Slice::from_slice(&slice[..]).unwrap().type_u8(),
                slice[0]
            );
        }
    }

    proptest! {
        #[test]
        fn code_u8(slice in proptest::collection::vec(any::<u8>(), 8..16)) {
            assert_eq!(
                Icmpv6Slice::from_slice(&slice[..]).unwrap().code_u8(),
                slice[1]
            );
        }
    }

    proptest! {
        #[test]
        fn checksum(slice in proptest::collection::vec(any::<u8>(), 8..16)) {
            assert_eq!(
                Icmpv6Slice::from_slice(&slice[..]).unwrap().checksum(),
                u16::from_be_bytes([slice[2], slice[3]])
            );
        }
    }

    proptest! {
        #[test]
        fn is_checksum_valid(
            ip_header in ipv6_any(),
            icmp_type in icmpv6_type_any(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
            flip_byte in 0usize..1032,
        ) {
            // generate slice with a correct checksum
            let header = Icmpv6Header::with_checksum(icmp_type, ip_header.source, ip_header.destination, &payload).unwrap();
            let bytes = {
                let mut bytes = Vec::with_capacity(header.header_len() + payload.len());
                header.write(&mut bytes).unwrap();
                bytes.extend_from_slice(&payload);
                bytes
            };

            // check that the checksum gets reported as ok
            assert!(
                Icmpv6Slice::from_slice(&bytes).unwrap().is_checksum_valid(ip_header.source, ip_header.destination)
            );

            // corrupt icmp packet
            {
                let mut corrupted_bytes = bytes.clone();
                let i = flip_byte % corrupted_bytes.len();
                corrupted_bytes[i] = !corrupted_bytes[i];

                assert_eq!(
                    false,
                    Icmpv6Slice::from_slice(&corrupted_bytes).unwrap().is_checksum_valid(ip_header.source, ip_header.destination)
                );
            }

            // corrupt ip source
            {
                let mut corrupted_source = ip_header.source;
                let i = flip_byte % corrupted_source.len();
                corrupted_source[i] = !corrupted_source[i];

                assert_eq!(
                    false,
                    Icmpv6Slice::from_slice(&bytes).unwrap().is_checksum_valid(corrupted_source, ip_header.destination)
                );
            }

            // corrupt ip destination
            {
                let mut corrupted_dest = ip_header.destination;
                let i = flip_byte % corrupted_dest.len();
                corrupted_dest[i] = !corrupted_dest[i];

                assert_eq!(
                    false,
                    Icmpv6Slice::from_slice(&bytes).unwrap().is_checksum_valid(ip_header.source, corrupted_dest)
                );
            }

            // corrupt length
            {
                let mut larger_bytes = bytes.clone();
                larger_bytes.push(0);
                larger_bytes.push(0);

                assert_eq!(
                    false,
                    Icmpv6Slice::from_slice(&larger_bytes).unwrap().is_checksum_valid(ip_header.source, ip_header.destination)
                );
            }
        }
    }

    proptest! {
        #[test]
        fn bytes5to8(slice in proptest::collection::vec(any::<u8>(), 8..16)) {
            assert_eq!(
                Icmpv6Slice::from_slice(&slice[..]).unwrap().bytes5to8(),
                [slice[4], slice[5], slice[6], slice[7]]
            );
        }
    }

    proptest! {
        #[test]
        fn slice(slice in proptest::collection::vec(any::<u8>(), 8..16)) {
            assert_eq!(
                Icmpv6Slice::from_slice(&slice[..]).unwrap().slice(),
                &slice[..]
            );
        }
    }

    proptest! {
        #[test]
        fn payload(
            type_u8 in any::<u8>(),
            code_u8 in any::<u8>(),
            bytes5to8 in any::<[u8;4]>(),
            payload in proptest::collection::vec(any::<u8>(), 8..16)
        ) {
            use etherparse::Icmpv6Type::*;
            use etherparse::{IcmpEchoHeader, icmpv6::*};

            let len_8_types = [
                Unknown{
                    type_u8,
                    code_u8,
                    bytes5to8,
                },
                DestinationUnreachable(DestUnreachableCode::Prohibited),
                PacketTooBig{ mtu: u32::from_be_bytes(bytes5to8), },
                TimeExceeded(TimeExceededCode::HopLimitExceeded),
                ParameterProblem{
                    code: code_u8.into(),
                    pointer: u32::from_be_bytes(bytes5to8),
                },
                EchoRequest(IcmpEchoHeader::from_bytes(bytes5to8)),
                EchoReply(IcmpEchoHeader::from_bytes(bytes5to8)),
            ];

            for t in len_8_types {
                let mut bytes = Vec::with_capacity(t.header_len() + payload.len());
                Icmpv6Header::new(t.clone()).write(&mut bytes).unwrap();
                bytes.extend_from_slice(&payload);

                assert_eq!(
                    Icmpv6Slice::from_slice(&bytes[..]).unwrap().payload(),
                    &payload[..]
                );
            }
        }
    }

    #[test]
    fn debug() {
        let data = [0u8; 8];
        assert_eq!(
            format!("{:?}", Icmpv6Slice::from_slice(&data).unwrap()),
            format!("Icmpv6Slice {{ slice: {:?} }}", &data)
        );
    }

    proptest! {
        #[test]
        fn clone_eq(slice in proptest::collection::vec(any::<u8>(), 8..16)) {
            assert_eq!(
                Icmpv6Slice::from_slice(&slice).unwrap().clone(),
                Icmpv6Slice::from_slice(&slice).unwrap()
            );
        }
    }
}
