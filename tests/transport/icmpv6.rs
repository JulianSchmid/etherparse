
#[test]
fn constants() {
    use etherparse::icmpv6::*;
    // type values according to
    // https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-16
    assert_eq!(  1, TYPE_DST_UNREACH);
    assert_eq!(  2, TYPE_PACKET_TOO_BIG);
    assert_eq!(  3, TYPE_TIME_EXCEEDED);
    assert_eq!(  4, TYPE_PARAM_PROB);
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
    assert_eq!(0, CODE_DST_UNREACH_NOROUTE);
    assert_eq!(1, CODE_DST_UNREACH_PROHIBITED);
    assert_eq!(2, CODE_DST_UNREACH_BEYONDSCOPE);
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
    assert_eq!(5, CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE);
    assert_eq!(6, CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG);
    assert_eq!(7, CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG);
    assert_eq!(8, CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS);
    assert_eq!(9, CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER);
    assert_eq!(10, CODE_PARAM_PROBLEM_OPTION_TOO_BIG);
}

mod icmp6_dest_unreachable {
    use etherparse::icmpv6::DestUnreachableHeader;
    use etherparse::icmpv6::DestUnreachableHeader::*;
    use etherparse::icmpv6::*;

    #[test]
    fn from_bytes() {
        for code in 7u8..=0xff {
            assert_eq!(
                Raw{
                    code,
                    bytes5to8: [1,2,3,4],
                },
                DestUnreachableHeader::from_bytes(
                    code,
                    [1,2,3,4]
                )
            );
        }
        assert_eq!(
            NoRoute,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_NOROUTE,
                [0;4]
            )
        );
        assert_eq!(
            Prohibited,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_PROHIBITED,
                [0;4]
            )
        );
        assert_eq!(
            BeyondScope,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_BEYONDSCOPE,
                [0;4]
            )
        );
        assert_eq!(
            Address,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_ADDR,
                [0;4]
            )
        );
        assert_eq!(
            Port,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_PORT,
                [0;4]
            )
        );
        assert_eq!(
            SourceAddressFailedPolicy,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY,
                [0;4]
            )
        );
        assert_eq!(
            RejectRoute,
            DestUnreachableHeader::from_bytes(
                CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST,
                [0;4]
            )
        );
    }

    #[test]
    fn code() {
        for code in 0u8..=0xff {
            assert_eq!(
                code,
                Raw{
                    code,
                    bytes5to8: [1,2,3,4],
                }.code(),
            );
        }
        assert_eq!(NoRoute.code(), CODE_DST_UNREACH_NOROUTE);
        assert_eq!(Prohibited.code(), CODE_DST_UNREACH_PROHIBITED);
        assert_eq!(BeyondScope.code(), CODE_DST_UNREACH_BEYONDSCOPE);
        assert_eq!(Address.code(), CODE_DST_UNREACH_ADDR);
        assert_eq!(Port.code(), CODE_DST_UNREACH_PORT);
        assert_eq!(SourceAddressFailedPolicy.code(), CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY);
        assert_eq!(RejectRoute.code(), CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST);
    }

    #[test]
    fn to_bytes() {
        for code in 0u8..=0xff {
            assert_eq!(
                (code, [1,2,3,4]),
                Raw{
                    code,
                    bytes5to8: [1,2,3,4],
                }.to_bytes(),
            );
        }
        assert_eq!(NoRoute.to_bytes(), (CODE_DST_UNREACH_NOROUTE, [0;4]));
        assert_eq!(Prohibited.to_bytes(), (CODE_DST_UNREACH_PROHIBITED, [0;4]));
        assert_eq!(BeyondScope.to_bytes(), (CODE_DST_UNREACH_BEYONDSCOPE, [0;4]));
        assert_eq!(Address.to_bytes(), (CODE_DST_UNREACH_ADDR, [0;4]));
        assert_eq!(Port.to_bytes(), (CODE_DST_UNREACH_PORT, [0;4]));
        assert_eq!(SourceAddressFailedPolicy.to_bytes(), (CODE_DST_UNREACH_SOURCE_ADDRESS_FAILED_POLICY, [0;4]));
        assert_eq!(RejectRoute.to_bytes(), (CODE_DST_UNREACH_REJECT_ROUTE_TO_DEST, [0;4]));
    }

    #[test]
    fn clone_eq() {
        let values = [
            Raw{ code: 8, bytes5to8: [1,2,3,4] },
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
            (Raw{ code: 8, bytes5to8: [1,2,3,4] }, "Raw { code: 8, bytes5to8: [1, 2, 3, 4] }"),
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
        assert_eq!(HopLimitExceeded, TimeExceededCode::from(CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED));
        assert_eq!(FragmentReassemblyTimeExceeded, TimeExceededCode::from(CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED));
        for code in 2..=u8::MAX {
            assert_eq!(Raw{ code }, TimeExceededCode::from(code));
        }
    }

    #[test]
    fn from_enum() {
        assert_eq!(CODE_TIME_EXCEEDED_HOP_LIMIT_EXCEEDED, u8::from(HopLimitExceeded));
        assert_eq!(CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY_TIME_EXCEEDED, u8::from(FragmentReassemblyTimeExceeded));
        for code in 0..=u8::MAX {
            assert_eq!(code, u8::from(Raw{ code }));
        }
    }

    #[test]
    fn clone_eq() {
        let values = [
            Raw{ code: 8},
            HopLimitExceeded,
            FragmentReassemblyTimeExceeded
        ];
        for value in values {
            assert_eq!(value.clone(), value);
        }
    }

    #[test]
    fn debug() {
        let tests = [
            (Raw{ code: 8}, "Raw { code: 8 }"),
            (HopLimitExceeded, "HopLimitExceeded"),
            (FragmentReassemblyTimeExceeded, "FragmentReassemblyTimeExceeded"),
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
        assert_eq!(ErroneousHeaderField, ParameterProblemCode::from(CODE_PARAM_PROBLEM_ERR_HEADER_FIELD));
        assert_eq!(UnrecognizedNextHeader, ParameterProblemCode::from(CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER));
        assert_eq!(UnrecognizedIpv6Option, ParameterProblemCode::from(CODE_PARAM_PROBLEM_UNRECOG_IPV6_OPTION));
        assert_eq!(Ipv6FirstFragmentIncompleteHeaderChain, ParameterProblemCode::from(CODE_PARAM_PROBLEM_IPV6_FIRST_FRAG_INCOMP_HEADER_CHAIN));
        assert_eq!(SrUpperLayerHeaderError, ParameterProblemCode::from(CODE_PARAM_PROBLEM_SR_UPPER_LAYER_HEADER_ERROR));
        assert_eq!(UnrecognizedNextHeaderByIntermediateNode, ParameterProblemCode::from(CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE));
        assert_eq!(ExtensionHeaderTooBig, ParameterProblemCode::from(CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG));
        assert_eq!(ExtensionHeaderChainTooLong, ParameterProblemCode::from(CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG));
        assert_eq!(TooManyExtensionHeaders, ParameterProblemCode::from(CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS));
        assert_eq!(TooManyOptionsInExtensionHeader, ParameterProblemCode::from(CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER));
        assert_eq!(OptionTooBig, ParameterProblemCode::from(CODE_PARAM_PROBLEM_OPTION_TOO_BIG));
        for code in 11..=u8::MAX {
            assert_eq!(Raw{ code }, ParameterProblemCode::from(code));
        }
    }

    #[test]
    fn from_enum() {
        assert_eq!(CODE_PARAM_PROBLEM_ERR_HEADER_FIELD, u8::from(ErroneousHeaderField));
        assert_eq!(CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER, u8::from(UnrecognizedNextHeader));
        assert_eq!(CODE_PARAM_PROBLEM_UNRECOG_IPV6_OPTION, u8::from(UnrecognizedIpv6Option));
        assert_eq!(CODE_PARAM_PROBLEM_IPV6_FIRST_FRAG_INCOMP_HEADER_CHAIN, u8::from(Ipv6FirstFragmentIncompleteHeaderChain));
        assert_eq!(CODE_PARAM_PROBLEM_SR_UPPER_LAYER_HEADER_ERROR, u8::from(SrUpperLayerHeaderError));
        assert_eq!(CODE_PARAM_PROBLEM_UNRECOG_NEXT_HEADER_BY_INTERMEDIATE_NODE, u8::from(UnrecognizedNextHeaderByIntermediateNode));
        assert_eq!(CODE_PARAM_PROBLEM_EXT_HEADER_TOO_BIG, u8::from(ExtensionHeaderTooBig));
        assert_eq!(CODE_PARAM_PROBLEM_EXT_HEADER_CHAIN_TOO_LONG, u8::from(ExtensionHeaderChainTooLong));
        assert_eq!(CODE_PARAM_PROBLEM_TOO_MANY_EXT_HEADERS, u8::from(TooManyExtensionHeaders));
        assert_eq!(CODE_PARAM_PROBLEM_TOO_MANY_OPTIONS_EXT_HEADER, u8::from(TooManyOptionsInExtensionHeader));
        assert_eq!(CODE_PARAM_PROBLEM_OPTION_TOO_BIG, u8::from(OptionTooBig));
        for code in 0..=u8::MAX {
            assert_eq!(code, u8::from(Raw{ code }));
        }
    }
    #[test]
    fn clone_eq() {
        let values = [
            Raw{ code: 8},
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
            (Raw{ code: 8}, "Raw { code: 8 }"),
            (ErroneousHeaderField, "ErroneousHeaderField"),
            (UnrecognizedNextHeader, "UnrecognizedNextHeader"),
            (UnrecognizedIpv6Option, "UnrecognizedIpv6Option"),
            (UnrecognizedNextHeader, "UnrecognizedNextHeader"),
            (UnrecognizedIpv6Option, "UnrecognizedIpv6Option"),
            (Ipv6FirstFragmentIncompleteHeaderChain, "Ipv6FirstFragmentIncompleteHeaderChain"),
            (SrUpperLayerHeaderError, "SrUpperLayerHeaderError"),
            (UnrecognizedNextHeaderByIntermediateNode, "UnrecognizedNextHeaderByIntermediateNode"),
            (ExtensionHeaderTooBig, "ExtensionHeaderTooBig"),
            (ExtensionHeaderChainTooLong, "ExtensionHeaderChainTooLong"),
            (TooManyExtensionHeaders, "TooManyExtensionHeaders"),
            (TooManyOptionsInExtensionHeader, "TooManyOptionsInExtensionHeader"),
            (OptionTooBig, "OptionTooBig"),
        ];
        for test in tests {
            assert_eq!(format!("{:?}", test.0), test.1);
        }
    }
}

mod icmp6_hdr {
    use etherparse::*;

    #[test]
    fn icmp6_echo_marshall_unmarshall() {
        let icmp6 = Icmpv6Header {
            icmp_type: Icmp6Type::EchoRequest(IcmpEchoHeader{
                seq: 1,
                id: 2,
            }),
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
        let builder = PacketBuilder::
            ipv6(   
                [0xfe,0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],  //source ip
                [0xfe,0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 114],  //dst ip
                20)            //time to life
            .icmp6_echo_request(1,2);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        //get some memory to store the result
        let mut result = Vec::<u8>::with_capacity(
                            builder.size(payload.len()));
            
        //serialize
        builder.write(&mut result, &payload).unwrap();

        let new_ip = PacketHeaders::from_ip_slice(&result).unwrap();
        if let Some(TransportHeader::Icmp6(hdr)) = new_ip.transport {
            if let Icmp6Type::EchoRequest(echo) = hdr.icmp_type {
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
        0xf3, 0xc2, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0xd5, 0x2f, 0x00, 0x05, 0x00, 0x01, 0xe3, 0x58,
        0xdb, 0x61, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xc0, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];
    const ICMP6_ECHO_REPLY_BYTES: [u8; 118] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
        0xa3, 0xde, 0x00, 0x40, 0x3a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0xd4, 0x2f, 0x00, 0x05, 0x00, 0x01, 0xe3, 0x58,
        0xdb, 0x61, 0x00, 0x00, 0x00, 0x00, 0x1f, 0xc0, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    #[test]
    fn verify_icmp6_checksum() {
        for (pkt, checksum) in [
                    (ICMP6_ECHO_REQUEST_BYTES, 0xd52f), 
                    (ICMP6_ECHO_REPLY_BYTES, 0xd42f)
                ] {
            // make sure we can unmarshall the correct checksum
            let request = PacketHeaders::from_ethernet_slice(&pkt).unwrap();
            let mut icmp6 = request.transport.unwrap().icmp6().unwrap();
            let valid_checksum =  icmp6.checksum;
            assert_ne!(valid_checksum, 0);  
            assert_eq!(valid_checksum, checksum);
            // reset it and recalculate
            icmp6.checksum = 0;
            let iph = match request.ip {
                Some(IpHeader::Version6(ipv6, _)) => ipv6,
                _ => panic!("Failed to parse ipv6 part of packet?!"),
            };
            assert_eq!(icmp6.icmp_type.calc_checksum(&iph, request.payload),
                Ok(valid_checksum));
        }
    }

    #[test]
    fn echo_request_slice() {
        let echo = SlicedPacket::from_ethernet(&ICMP6_ECHO_REQUEST_BYTES).unwrap();
        use TransportSlice::*;
        let icmp6 = match echo.transport.unwrap() {
            Icmp6(icmp6) => icmp6,
            Icmp4(_) | Udp(_) | Tcp(_) | Unknown(_) => panic!("Misparsed header!"),
        };
        assert!(matches!(icmp6.to_header().icmp_type, Icmp6Type::EchoRequest(_)));

    }


}