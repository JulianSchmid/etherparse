use crate::*;

/// Starting contents of an ICMPv4 packet without the checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icmpv4Type {
    /// In case of an unknown ICMP type and code combination is received the
    /// header elements are stored raw in this enum value. The `Unknown` value can
    /// also be passed to the `Icmpv4Header::write` function to write arbitrary ICMP
    /// packets.
    ///
    /// # What is part of the header for `Icmpv4Type::Unknown`?
    ///
    /// For unknown ICMP type & code combination the first 8 bytes are stored
    /// in the [`Icmpv4Header`] and the rest is stored in the payload
    /// ([`Icmpv4Slice::payload`] or [`PacketHeaders::payload`]).
    ///
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |     type_u8   |    code_u8    |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |                          bytes5to8                            |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ...                           ...                             ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    /// ```
    Unknown {
        /// ICMP type (present in the first byte of the ICMP packet).
        type_u8: u8,
        /// ICMP code (present in the 2nd byte of the ICMP packet).
        code_u8: u8,
        /// Bytes located at th 5th, 6th, 7th and 8th position of the ICMP packet.
        bytes5to8: [u8; 4],
    },

    /// Response to an `EchoRequest` message (defined in RFC792).
    ///
    /// # What is part of the header for `Icmpv4Type::EchoReply`?
    ///
    /// For the [`Icmpv4Type::EchoReply`] type the first 8 bytes/octets of the
    /// ICMP packet are part of the header. This includes the `id` and `seq`
    /// fields. The data part of the ICMP Echo Reply packet is part of the
    /// payload ([`Icmpv4Slice::payload`] or [`PacketHeaders::payload`])
    /// and not part of the [`Icmpv4Header`].
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |       0       |       0       |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |          [value].id           |         [value].seq           |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ...                          <data>                           ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    /// ```
    EchoReply(IcmpEchoHeader),

    /// Message sent to inform the client that the destination is unreachable for
    /// some reason (defined in RFC792).
    ///
    /// # What is part of the header for `Icmpv4Type::DestinationUnreachable`?
    ///
    /// For the [`Icmpv4Type::DestinationUnreachable`] type the first 8 bytes/octets
    /// of the ICMP packet are part of the header. This includes the `next_hop_mtu`
    /// field. The `unused` part is not stored and droped. The offending packet
    /// is stored in the payload part of the packet ([`Icmpv4Slice::payload`] or
    /// [`PacketHeaders::payload`]) and is not part of the [`Icmpv4Header`].
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |       3       |       0       |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |[v].next_hop...|                    <unused>                   |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ...    Internet Header + 64 bits of Original Data Datagram    ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    /// ```
    DestinationUnreachable(icmpv4::DestUnreachableHeader),

    /// Requests data packets be sent on an alternative route (defined in RFC792).
    ///
    /// # What is part of the header for `Icmpv4Type::Redirect`?
    ///
    /// For the [`Icmpv4Type::Redirect`] type the first 8 bytes/octets of the ICMP
    /// packet are part of the header. This includes the `gateway_internet_address`
    /// field. The offending packet is stored in the payload part of the packet
    /// ([`Icmpv4Slice::payload`] or [`PacketHeaders::payload`]) and is not part of
    /// the [`Icmpv4Header`].
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |       5       | [value].code  |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |                [value].gateway_internet_address               |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ..     Internet Header + 64 bits of Original Data Datagram    ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    Redirect(icmpv4::RedirectHeader),

    /// Requesting an `EchoReply` from the receiver (defined in RFC792)
    ///
    /// # What is part of the header for `Icmpv4Type::EchoRequest`?
    ///
    /// For the [`Icmpv4Type::EchoRequest`] type the first 8 bytes/octets of the
    /// ICMP packet are part of the header. This includes the `id` and `seq`
    /// fields. The data part of the ICMP echo request packet is part of the payload
    /// ([`Icmpv4Slice::payload`] & [`PacketHeaders::payload`]) and not part of the
    /// [`Icmpv4Header`].
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |       8       |       0       |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |          [value].id           |         [value].seq           |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ...                          <data>                           ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    /// ```
    EchoRequest(IcmpEchoHeader),

    /// Generated when a datagram had to be discarded due to the time to live field
    /// reaching zero (defined in RFC792).
    ///
    /// # What is part of the header for `Icmpv4Type::TimeExceeded`?
    ///
    /// For the `Icmpv4Type::TimeExceeded` type the first 8 bytes/octets of the ICMP
    /// packet are part of the header. The `unused` part is not stored and droped.
    /// The offending packet is stored in the payload part of the packet
    /// ([`Icmpv4Slice::payload`] & [`PacketHeaders::payload`]) and is not part of
    /// the [`Icmpv4Header`].
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |       11      | [value as u8] |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |                           <unused>                            |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ...    Internet Header + 64 bits of Original Data Datagram    ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    TimeExceeded(icmpv4::TimeExceededCode),

    /// Sent if there is a problem with a parameter in a received packet.
    ///
    /// # What is part of the header for `Icmpv4Type::ParameterProblem`?
    ///
    /// For the `Icmpv4Type::ParameterProblem` type the first 8 bytes/octets of the ICMP
    /// packet are part of the header. The `unused` part is not stored and droped.
    /// The offending packet is stored in the payload part of the packet
    /// ([`Icmpv4Slice::payload`] & [`PacketHeaders::payload`]) and is not part of
    /// the [`Icmpv4Header`].
    ///
    /// ```text
    /// 0               1               2               3               4
    /// +---------------------------------------------------------------+  -
    /// |       12      | [v].code_u8() |  checksum (in Icmpv4Header)   |  |
    /// +---------------------------------------------------------------+  | part of header & type
    /// |[value].pointer|                   <unused>                    |  ↓
    /// +---------------------------------------------------------------+  -
    /// |                                                               |  |
    /// ...    Internet Header + 64 bits of Original Data Datagram    ...  | part of payload
    /// |                                                               |  ↓
    /// +---------------------------------------------------------------+  -
    ParameterProblem(icmpv4::ParameterProblemHeader),

    /// Timestamp is used for time synchronization.
    ///
    /// # What is part of the header for `Icmpv4Type::TimestampRequest`?
    ///
    /// For the `Icmpv4Type::TimestampRequest` type the entire ICMP packet is
    /// contained within the header. The payload data is empty.
    TimestampRequest(icmpv4::TimestampMessage),

    /// Anwser to a `TimestampRequest` message.
    ///
    /// # What is part of the header for `Icmpv4Type::TimestampReply`?
    ///
    /// For the `Icmpv4Type::TimestampReply` type the entire ICMP packet is
    /// contained within the header. The payload data is empty.
    TimestampReply(icmpv4::TimestampMessage),
}

impl Icmpv4Type {
    /// Returns the length in bytes/octets of the header of
    /// this ICMPv4 message type.
    #[inline]
    pub fn header_len(&self) -> usize {
        use Icmpv4Type::*;
        match self {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            }
            | EchoReply(_)
            | DestinationUnreachable(_)
            | Redirect(_)
            | EchoRequest(_)
            | TimeExceeded(_)
            | ParameterProblem(_) => 8,
            TimestampRequest(_) | TimestampReply(_) => icmpv4::TimestampMessage::LEN,
        }
    }

    /// If the ICMP type has a fixed size returns the number of
    /// bytes that should be present after the header of this type.
    #[inline]
    pub fn fixed_payload_size(&self) -> Option<usize> {
        use Icmpv4Type::*;
        match self {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            }
            | EchoReply(_)
            | DestinationUnreachable(_)
            | Redirect(_)
            | EchoRequest(_)
            | TimeExceeded(_)
            | ParameterProblem(_) => None,
            TimestampRequest(_) | TimestampReply(_) => Some(0),
        }
    }

    /// Calculate the ICMP checksum value.
    pub fn calc_checksum(&self, payload: &[u8]) -> u16 {
        use crate::{Icmpv4Type::*, icmpv4::*};
        match self {
            Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => checksum::Sum16BitWords::new()
                .add_2bytes([*type_u8, *code_u8])
                .add_4bytes(*bytes5to8),
            EchoReply(header) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_ECHO_REPLY, 0])
                .add_2bytes(header.id.to_be_bytes())
                .add_2bytes(header.seq.to_be_bytes()),
            DestinationUnreachable(ref header) => {
                use DestUnreachableHeader::*;
                match header {
                    Network => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET]),
                    Host => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST]),
                    Protocol => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_PROTOCOL]),
                    Port => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_PORT]),
                    FragmentationNeeded { next_hop_mtu } => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NEED_FRAG])
                        .add_2bytes(next_hop_mtu.to_be_bytes()),
                    SourceRouteFailed => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_SOURCE_ROUTE_FAILED]),
                    NetworkUnknown => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_UNKNOWN]),
                    HostUnknown => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_UNKNOWN]),
                    Isolated => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_ISOLATED]),
                    NetworkProhibited => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_PROHIB]),
                    HostProhibited => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_PROHIB]),
                    TosNetwork => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_NET]),
                    TosHost => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_HOST]),
                    FilterProhibited => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_FILTER_PROHIB]),
                    HostPrecedenceViolation => checksum::Sum16BitWords::new().add_2bytes([
                        TYPE_DEST_UNREACH,
                        CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION,
                    ]),
                    PrecedenceCutoff => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_DEST_UNREACH, CODE_DST_UNREACH_PRECEDENCE_CUTOFF]),
                }
            }
            Redirect(header) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_REDIRECT, header.code as u8])
                .add_4bytes(header.gateway_internet_address),
            EchoRequest(header) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_ECHO_REQUEST, 0])
                .add_2bytes(header.id.to_be_bytes())
                .add_2bytes(header.seq.to_be_bytes()),
            TimeExceeded(code) => {
                checksum::Sum16BitWords::new().add_2bytes([TYPE_TIME_EXCEEDED, *code as u8])
            }
            ParameterProblem(header) => {
                use ParameterProblemHeader::*;
                match header {
                    PointerIndicatesError(pointer) => checksum::Sum16BitWords::new()
                        .add_2bytes([
                            TYPE_PARAMETER_PROBLEM,
                            CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR,
                        ])
                        .add_2bytes([*pointer, 0]),
                    MissingRequiredOption => checksum::Sum16BitWords::new().add_2bytes([
                        TYPE_PARAMETER_PROBLEM,
                        CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION,
                    ]),
                    BadLength => checksum::Sum16BitWords::new()
                        .add_2bytes([TYPE_PARAMETER_PROBLEM, CODE_PARAMETER_PROBLEM_BAD_LENGTH]),
                }
            }
            TimestampRequest(msg) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_TIMESTAMP, 0])
                .add_2bytes(msg.id.to_be_bytes())
                .add_2bytes(msg.seq.to_be_bytes())
                .add_4bytes(msg.originate_timestamp.to_be_bytes())
                .add_4bytes(msg.receive_timestamp.to_be_bytes())
                .add_4bytes(msg.transmit_timestamp.to_be_bytes()),
            TimestampReply(msg) => checksum::Sum16BitWords::new()
                .add_2bytes([TYPE_TIMESTAMP_REPLY, 0])
                .add_2bytes(msg.id.to_be_bytes())
                .add_2bytes(msg.seq.to_be_bytes())
                .add_4bytes(msg.originate_timestamp.to_be_bytes())
                .add_4bytes(msg.receive_timestamp.to_be_bytes())
                .add_4bytes(msg.transmit_timestamp.to_be_bytes()),
        }
        .add_slice(payload)
        .ones_complement()
        .to_be()
    }
}
