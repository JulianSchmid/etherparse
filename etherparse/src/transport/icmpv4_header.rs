use crate::*;
use arrayvec::ArrayVec;

/// A header of an ICMPv4 packet.
///
/// What is part of the header depends on the ICMPv4 type
/// and code. But usually the static sized elements are part
/// of the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv4Header {
    /// Type & type specific values & code.
    pub icmp_type: Icmpv4Type,
    /// Checksum in the ICMP header.
    pub checksum: u16,
}

impl Icmpv4Header {
    /// Minimum number of bytes/octets an Icmpv4Header takes up
    /// in serialized form.
    pub const MIN_SERIALIZED_SIZE: usize = 8;

    /// Maximum number of bytes/octets an Icmpv4Header takes up
    /// in serialized form.
    ///
    /// Currently this number is determined by the biggest
    /// supported ICMPv4 header type, which is currently the
    /// "Timestamp" and "Timestamp Reply Message".
    pub const MAX_SERIALIZED_SIZE: usize = 20;

    /// Constructs an [`Icmpv4Header`] using the given type
    /// and the checksum set to 0.
    pub fn new(icmp_type: Icmpv4Type) -> Icmpv4Header {
        // Note: will calculate checksum on send
        Icmpv4Header {
            icmp_type,
            checksum: 0,
        }
    }

    /// Creates a [`Icmpv4Header`] with a checksum calculated based on the given payload.
    pub fn with_checksum(icmp_type: Icmpv4Type, payload: &[u8]) -> Icmpv4Header {
        let checksum = icmp_type.calc_checksum(payload);
        Icmpv4Header {
            icmp_type,
            checksum,
        }
    }

    /// Reads an icmp4 header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Icmpv4Header, &[u8]), ReadError> {
        let header = Icmpv4Slice::from_slice(slice)?.header();
        let rest = &slice[header.header_len()..];
        Ok((header, rest))
    }

    /// Reads an ICMPv4 header from the given reader.
    pub fn read<T: io::Read + Sized>(reader: &mut T) -> Result<Icmpv4Header, ReadError> {
        let mut bytes = [0u8; Icmpv4Header::MAX_SERIALIZED_SIZE];

        // try reading the initial 8 bytes
        reader.read_exact(&mut bytes[..8])?;

        match bytes[0] {
            icmpv4::TYPE_TIMESTAMP_REPLY | icmpv4::TYPE_TIMESTAMP => {
                if 0 == bytes[1] {
                    // Timetamp messages need additional data read & it and
                    // then set the slice correspondently
                    reader.read_exact(&mut bytes[8..icmpv4::TimestampMessage::LEN])?;
                    Ok(Icmpv4Slice {
                        slice: &bytes[..icmpv4::TimestampMessage::LEN],
                    }
                    .header())
                } else {
                    // fallback to unknown
                    Ok(Icmpv4Slice { slice: &bytes[..8] }.header())
                }
            }
            _ => Ok(Icmpv4Slice { slice: &bytes[..8] }.header()),
        }
    }

    /// Write the ICMPv4 header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()).map_err(WriteError::from)
    }

    /// Length in bytes/octets of this header type.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.icmp_type.header_len()
    }

    /// If the ICMP type has a fixed size returns the number of
    /// bytes that should be present after the header of this type.
    #[inline]
    pub fn fixed_payload_size(&self) -> Option<usize> {
        self.icmp_type.fixed_payload_size()
    }

    /// Calculates & updates the checksum in the header.
    ///
    /// Note this method assumes that all unused bytes/octets
    /// are filled with zeroes.
    pub fn update_checksum(&mut self, payload: &[u8]) {
        self.checksum = self.icmp_type.calc_checksum(payload);
    }

    /// Converts the header to the on the wire bytes.
    #[rustfmt::skip]
    pub fn to_bytes(&self) -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {
        let checksum_be = self.checksum.to_be_bytes();
        let re_zero =
            |type_u8: u8, code_u8: u8| -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {

                #[rustfmt::skip]
                let mut re = ArrayVec::from([
                    type_u8, code_u8, checksum_be[0], checksum_be[1],
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                ]);
                // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 20.
                unsafe {
                    re.set_len(8);
                }
                re
            };

        let re_2u16 = |type_u8: u8,
                       code_u8: u8,
                       a_u16: u16,
                       b_u16: u16|
         -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {
            let a = a_u16.to_be_bytes();
            let b = b_u16.to_be_bytes();

            #[rustfmt::skip]
            let mut re = ArrayVec::from([
                type_u8, code_u8, checksum_be[0], checksum_be[1],
                a[0], a[1], b[0], b[1],
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]);
            // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 20.
            unsafe {
                re.set_len(8);
            }
            re
        };

        let re_4u8 = |type_u8: u8,
                      code_u8: u8,
                      bytes5to8: [u8; 4]|
         -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {

            #[rustfmt::skip]
            let mut re = ArrayVec::from([
                type_u8, code_u8, checksum_be[0], checksum_be[1],
                bytes5to8[0], bytes5to8[1], bytes5to8[2], bytes5to8[3],
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]);
            // SAFETY: Safe as u8 has no destruction behavior and as 8 is smaller then 20.
            unsafe {
                re.set_len(8);
            }
            re
        };

        let re_timestamp_msg = |type_u8: u8,
                                msg: &icmpv4::TimestampMessage|
         -> ArrayVec<u8, { Icmpv4Header::MAX_SERIALIZED_SIZE }> {
            let id = msg.id.to_be_bytes();
            let seq = msg.seq.to_be_bytes();
            let o = msg.originate_timestamp.to_be_bytes();
            let r = msg.receive_timestamp.to_be_bytes();
            let t = msg.transmit_timestamp.to_be_bytes();

            ArrayVec::from([
                type_u8, 0, checksum_be[0], checksum_be[1],
                id[0], id[1], seq[0], seq[1],
                o[0], o[1], o[2], o[3],
                r[0], r[1], r[2], r[3],
                t[0], t[1], t[2], t[3],
            ])
        };

        use Icmpv4Type::*;
        use icmpv4::*;
        match self.icmp_type {
            Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => re_4u8(type_u8, code_u8, bytes5to8),
            EchoReply(echo) => re_2u16(TYPE_ECHO_REPLY, 0, echo.id, echo.seq),
            DestinationUnreachable(ref dest) => {
                use DestUnreachableHeader::*;
                match dest {
                    Network => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET),
                    Host => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST),
                    Protocol => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_PROTOCOL),
                    Port => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_PORT),
                    FragmentationNeeded { next_hop_mtu } => {
                        let m_be = next_hop_mtu.to_be_bytes();
                        re_4u8(
                            TYPE_DEST_UNREACH,
                            CODE_DST_UNREACH_NEED_FRAG,
                            [0, 0, m_be[0], m_be[1]],
                        )
                    }
                    SourceRouteFailed => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_SOURCE_ROUTE_FAILED),
                    NetworkUnknown => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_UNKNOWN),
                    HostUnknown => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_UNKNOWN),
                    Isolated => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_ISOLATED),
                    NetworkProhibited => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_NET_PROHIB),
                    HostProhibited => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_HOST_PROHIB),
                    TosNetwork => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_NET),
                    TosHost => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_TOS_HOST),
                    FilterProhibited => re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_FILTER_PROHIB),
                    HostPrecedenceViolation => re_zero(
                        TYPE_DEST_UNREACH,
                        CODE_DST_UNREACH_HOST_PRECEDENCE_VIOLATION,
                    ),
                    PrecedenceCutoff => {
                        re_zero(TYPE_DEST_UNREACH, CODE_DST_UNREACH_PRECEDENCE_CUTOFF)
                    }
                }
            }
            Redirect(ref msg) => {
                re_4u8(TYPE_REDIRECT, msg.code as u8, msg.gateway_internet_address)
            }
            EchoRequest(echo) => re_2u16(TYPE_ECHO_REQUEST, 0, echo.id, echo.seq),
            TimeExceeded(code) => re_zero(TYPE_TIME_EXCEEDED, code as u8),
            ParameterProblem(ref header) => {
                use ParameterProblemHeader::*;
                match header {
                    PointerIndicatesError(pointer) => re_4u8(
                        TYPE_PARAMETER_PROBLEM,
                        CODE_PARAMETER_PROBLEM_POINTER_INDICATES_ERROR,
                        [*pointer, 0, 0, 0],
                    ),
                    MissingRequiredOption => re_zero(
                        TYPE_PARAMETER_PROBLEM,
                        CODE_PARAMETER_PROBLEM_MISSING_REQUIRED_OPTION,
                    ),
                    BadLength => re_zero(TYPE_PARAMETER_PROBLEM, CODE_PARAMETER_PROBLEM_BAD_LENGTH),
                }
            }
            TimestampRequest(ref msg) => re_timestamp_msg(TYPE_TIMESTAMP, msg),
            TimestampReply(ref msg) => re_timestamp_msg(TYPE_TIMESTAMP_REPLY, msg),
        }
    }
}
