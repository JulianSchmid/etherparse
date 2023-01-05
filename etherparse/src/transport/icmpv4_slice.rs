use crate::{*, icmpv4::*};

/// A slice containing an ICMPv4 network package.
///
/// Struct allows the selective read of fields in the ICMPv4
/// packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icmpv4Slice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> Icmpv4Slice<'a> {
    /// Creates a slice containing an ICMPv4 packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` `ReadError::UnexpectedEndOfSlice`
    /// if the given slice is too small.
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Icmpv4Slice<'a>, ReadError> {
        // check length
        use ReadError::*;
        if slice.len() < Icmpv4Header::MIN_SERIALIZED_SIZE {
            return Err(SliceLen(err::SliceLenError {
                expected_min_len: Icmpv4Header::MIN_SERIALIZED_SIZE,
                actual_len: slice.len(),
                layer: err::Layer::Icmpv4,
            }));
        }

        // SAFETY:
        // Safe as it is previously checked that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        let icmp_type: u8 = unsafe { *slice.get_unchecked(0) };
        let icmp_code: u8 = unsafe { *slice.get_unchecked(1) };

        // check type specific length
        match icmp_type {
            TYPE_TIMESTAMP_REPLY | TYPE_TIMESTAMP => {
                if 0 == icmp_code && TimestampMessage::LEN != slice.len() {
                    return Err(UnexpectedLenOfSlice {
                        expected: TimestampMessage::LEN,
                        actual: slice.len(),
                    });
                }
            }
            _ => {}
        }

        //done
        Ok(Icmpv4Slice { slice })
    }

    /// Decode the header values into an [`Icmpv4Header`] struct.
    #[inline]
    pub fn header(&self) -> Icmpv4Header {
        let icmp_type = self.icmp_type();
        Icmpv4Header {
            icmp_type,
            checksum: self.checksum(),
        }
    }

    /// Number of bytes/octets that will be converted into a
    /// [`Icmpv4Header`] when [`Icmpv4Slice::header`] gets called.
    #[inline]
    pub fn header_len(&self) -> usize {
        match self.type_u8() {
            TYPE_TIMESTAMP | TYPE_TIMESTAMP_REPLY => {
                if 0 == self.code_u8() {
                    TimestampMessage::LEN
                } else {
                    8
                }
            }
            _ => 8,
        }
    }

    /// Decode the header values (excluding the checksum) into an [`Icmpv4Type`] enum.
    pub fn icmp_type(&self) -> Icmpv4Type {
        use Icmpv4Type::*;

        unsafe fn timestamp_message(ptr: *const u8) -> TimestampMessage {
            TimestampMessage {
                id: get_unchecked_be_u16(ptr.add(4)),
                seq: get_unchecked_be_u16(ptr.add(6)),
                originate_timestamp: get_unchecked_be_u32(ptr.add(8)),
                receive_timestamp: get_unchecked_be_u32(ptr.add(12)),
                transmit_timestamp: get_unchecked_be_u32(ptr.add(16)),
            }
        }

        match self.type_u8() {
            TYPE_ECHO_REPLY => {
                if 0 == self.code_u8() {
                    return EchoReply(IcmpEchoHeader::from_bytes(self.bytes5to8()));
                }
            }
            TYPE_DEST_UNREACH => {
                use DestUnreachableHeader::*;
                match self.code_u8() {
                    CODE_DST_UNREACH_NET => return DestinationUnreachable(Network),
                    CODE_DST_UNREACH_HOST => return DestinationUnreachable(Host),
                    CODE_DST_UNREACH_PROTOCOL => return DestinationUnreachable(Protocol),
                    CODE_DST_UNREACH_PORT => return DestinationUnreachable(Port),
                    CODE_DST_UNREACH_NEED_FRAG => {
                        return DestinationUnreachable(FragmentationNeeded {
                            // SAFETY:
                            // Safe as the contructor checks that the slice has
                            // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
                            next_hop_mtu: unsafe {
                                get_unchecked_be_u16(self.slice.as_ptr().add(6))
                            },
                        });
                    }
                    CODE_DST_UNREACH_SOURCE_ROUTE_FAILED => {
                        return DestinationUnreachable(SourceRouteFailed)
                    }
                    CODE_DST_UNREACH_NET_UNKNOWN => return DestinationUnreachable(NetworkUnknown),
                    CODE_DST_UNREACH_HOST_UNKNOWN => return DestinationUnreachable(HostUnknown),
                    CODE_DST_UNREACH_ISOLATED => return DestinationUnreachable(Isolated),
                    CODE_DST_UNREACH_NET_PROHIB => {
                        return DestinationUnreachable(NetworkProhibited)
                    }
                    CODE_DST_UNREACH_HOST_PROHIB => return DestinationUnreachable(HostProhibited),
                    CODE_DST_UNREACH_TOS_NET => return DestinationUnreachable(TosNetwork),
                    CODE_DST_UNREACH_TOS_HOST => return DestinationUnreachable(TosHost),
                    CODE_DST_UNREACH_FILTER_PROHIB => {
                        return DestinationUnreachable(FilterProhibited)
                    }
                    CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION => {
                        return DestinationUnreachable(HostPrecedenceViolation)
                    }
                    CODE_DST_UNREACH_PRECEDENCE_CUTOFF => {
                        return DestinationUnreachable(PrecedenceCutoff)
                    }
                    _ => {}
                }
            }
            TYPE_REDIRECT => {
                use RedirectCode::*;
                let code = match self.code_u8() {
                    CODE_REDIRECT_FOR_NETWORK => Some(RedirectForNetwork),
                    CODE_REDIRECT_FOR_HOST => Some(RedirectForHost),
                    CODE_REDIRECT_TYPE_OF_SERVICE_AND_NETWORK => {
                        Some(RedirectForTypeOfServiceAndNetwork)
                    }
                    CODE_REDIRECT_TYPE_OF_SERVICE_AND_HOST => Some(RedirectForTypeOfServiceAndHost),
                    _ => None,
                };
                if let Some(code) = code {
                    return Redirect(RedirectHeader {
                        code,
                        gateway_internet_address: self.bytes5to8(),
                    });
                }
            }
            TYPE_ECHO_REQUEST => {
                if 0 == self.code_u8() {
                    return EchoRequest(IcmpEchoHeader::from_bytes(self.bytes5to8()));
                }
            }
            TYPE_TIME_EXCEEDED => {
                use TimeExceededCode::*;
                match self.code_u8() {
                    CODE_TIME_EXCEEDED_TTL_EXCEEDED_IN_TRANSIT => {
                        return TimeExceeded(TtlExceededInTransit);
                    }
                    CODE_TIME_EXCEEDED_FRAG_REASSEMBLY_TIME_EXCEEDED => {
                        return TimeExceeded(FragmentReassemblyTimeExceeded);
                    }
                    _ => {}
                }
            }
            TYPE_PARAMETER_PROBLEM => {
                use ParameterProblemHeader::*;
                match self.code_u8() {
                    CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR => {
                        return ParameterProblem(PointerIndicatesError(
                            // SAFETY:
                            // Safe as the contructor checks that the slice has
                            // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
                            unsafe { *self.slice.get_unchecked(4) },
                        ));
                    }
                    CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION => {
                        return ParameterProblem(MissingRequiredOption);
                    }
                    CODE_PARAMETER_PROBLEM_BAD_LENGTH => {
                        return ParameterProblem(BadLength);
                    }
                    _ => {}
                }
            }
            TYPE_TIMESTAMP => {
                if 0 == self.code_u8() {
                    // SAFETY:
                    // Safe as the contructor checks that the slice has
                    // the length of TimestampMessage::SERIALIZED_SIZE (20).
                    unsafe {
                        return TimestampRequest(timestamp_message(self.slice.as_ptr()));
                    }
                }
            }
            TYPE_TIMESTAMP_REPLY => {
                if 0 == self.code_u8() {
                    // SAFETY:
                    // Safe as the contructor checks that the slice has
                    // the length of TimestampMessage::SERIALIZED_SIZE (20).
                    unsafe {
                        return TimestampReply(timestamp_message(self.slice.as_ptr()));
                    }
                }
            }
            _ => {}
        }

        Unknown {
            type_u8: self.type_u8(),
            code_u8: self.code_u8(),
            bytes5to8: self.bytes5to8(),
        }
    }

    /// Returns "type" value in the ICMPv4 header.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns "code" value in the ICMPv4 header.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns "checksum" value in the ICMPv4 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the bytes from position 4 till and including the 8th position
    /// in the ICMPv4 header.
    ///
    /// These bytes located at th 5th, 6th, 7th and 8th position of the ICMP
    /// packet can depending on the ICMPv4 type and code contain additional data.
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv4Header::MIN_SERIALIZED_SIZE (8).
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns a slice to the bytes not covered by `.header()`.
    ///
    /// The contents of the slice returned by `payload()` depends on the type
    /// and code of the ICMP packet:
    ///
    /// | `.header().icmp_type` or `.icmp_type()`                                                                                                    | Payload Content                                                              |
    /// |--------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
    /// | [`Icmpv4Type::EchoReply`]<br>[`Icmpv4Type::EchoRequest`]<br>                                                                               | Data part of the echo message                                                |
    /// | [`Icmpv4Type::DestinationUnreachable`]<br>[`Icmpv4Type::Redirect`]<br>[`Icmpv4Type::TimeExceeded`]<br>[`Icmpv4Type::ParameterProblem`]<br> | Internet Header + 64 bits of Original Data Datagram causing the ICMP message |
    /// | [`Icmpv4Type::TimestampRequest`]<br>[`Icmpv4Type::TimestampReply`]<br>                                                                     | Nothing                                                                      |
    /// | [`Icmpv4Type::Unknown`]                                                                                                                    | Everything after the 8th byte/octet of the ICMP packet.                      |
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // explicitly inlined the code to determine the
        // length of the payload to make the cecking of the
        // usafe code easier.
        let header_len = match self.type_u8() {
            // SAFETY:
            // Lenght safe as the contructor checks that the slice has
            // the length of TimestampMessage::SERIALIZED_SIZE (20)
            // for the messages types TYPE_TIMESTAMP and TYPE_TIMESTAMP_REPLY.
            TYPE_TIMESTAMP | TYPE_TIMESTAMP_REPLY => {
                if 0 == self.code_u8() {
                    TimestampMessage::LEN
                } else {
                    8
                }
            }
            // SAFETY:
            // Lneght safe as the contructor checks that the slice has
            // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE(8) for
            // all message types.
            _ => 8,
        };
        // SAFETY:
        // Lenghts have been depending on type in the constructor of the
        // ICMPv4Slice.
        unsafe {
            core::slice::from_raw_parts(
                self.slice.as_ptr().add(header_len),
                self.slice.len() - header_len,
            )
        }
    }

    /// Returns the slice containing the ICMPv4 packet.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}
