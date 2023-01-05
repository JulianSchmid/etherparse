use crate::*;

/// A slice containing an ICMPv6 network package.
///
/// Struct allows the selective read of fields in the ICMPv6
/// packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icmpv6Slice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> Icmpv6Slice<'a> {
    /// Creates a slice containing an ICMPv6 packet.
    ///
    /// # Errors
    ///
    /// The function will return an `Err` `ReadError::UnexpectedEndOfSlice`
    /// if the given slice is too small (smaller then `Icmpv6Header::MIN_SERIALIZED_SIZE`) or
    /// too large (bigger then `icmpv6::MAX_ICMPV6_BYTE_LEN`).
    #[inline]
    pub fn from_slice(slice: &'a [u8]) -> Result<Icmpv6Slice<'a>, ReadError> {
        //check length
        use crate::ReadError::*;
        if slice.len() < Icmpv6Header::MIN_SERIALIZED_SIZE {
            return Err(SliceLen(err::SliceLenError {
                expected_min_len: Icmpv6Header::MIN_SERIALIZED_SIZE,
                actual_len: slice.len(),
                layer: err::Layer::Icmpv6,
            }));
        }
        if slice.len() > icmpv6::MAX_ICMPV6_BYTE_LEN {
            return Err(Icmpv6PacketTooBig(slice.len()));
        }

        //done
        Ok(Icmpv6Slice { slice })
    }

    /// Decode the header fields and copy the results to a [`Icmpv6Header`] struct.
    #[inline]
    pub fn header(&self) -> Icmpv6Header {
        Icmpv6Header {
            icmp_type: self.icmp_type(),
            checksum: self.checksum(),
        }
    }

    /// Number of bytes/octets that will be converted into a
    /// [`Icmpv6Header`] when [`Icmpv6Slice::header`] gets called.
    #[inline]
    pub fn header_len(&self) -> usize {
        8
    }

    /// Decode the header values (excluding the checksum) into an [`Icmpv6Type`] enum.
    pub fn icmp_type(&self) -> Icmpv6Type {
        use crate::{icmpv6::*, Icmpv6Type::*};

        match self.type_u8() {
            TYPE_DST_UNREACH => {
                if let Some(code) = DestUnreachableCode::from_u8(self.code_u8()) {
                    return DestinationUnreachable(code);
                }
            }
            TYPE_PACKET_TOO_BIG => {
                if 0 == self.code_u8() {
                    return PacketTooBig {
                        mtu: u32::from_be_bytes(self.bytes5to8()),
                    };
                }
            }
            TYPE_TIME_EXCEEDED => {
                if let Some(code) = TimeExceededCode::from_u8(self.code_u8()) {
                    return TimeExceeded(code);
                }
            }
            TYPE_PARAMETER_PROBLEM => {
                if let Some(code) = ParameterProblemCode::from_u8(self.code_u8()) {
                    return ParameterProblem(ParameterProblemHeader {
                        code,
                        pointer: u32::from_be_bytes(self.bytes5to8()),
                    });
                }
            }
            TYPE_ECHO_REQUEST => {
                if 0 == self.code_u8() {
                    return EchoRequest(IcmpEchoHeader::from_bytes(self.bytes5to8()));
                }
            }
            TYPE_ECHO_REPLY => {
                if 0 == self.code_u8() {
                    return EchoReply(IcmpEchoHeader::from_bytes(self.bytes5to8()));
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

    /// Returns "type" value in the ICMPv6 header.
    #[inline]
    pub fn type_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE (8).
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns "code" value in the ICMPv6 header.
    #[inline]
    pub fn code_u8(&self) -> u8 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE (8).
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Returns "checksum" value in the ICMPv6 header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE  (8).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns if the checksum in the slice is correct.
    pub fn is_checksum_valid(&self, source_ip: [u8; 16], destination_ip: [u8; 16]) -> bool {
        // NOTE: rfc4443 section 2.3 - Icmp6 *does* use a pseudoheader,
        // unlike Icmp4
        checksum::Sum16BitWords::new()
            .add_16bytes(source_ip)
            .add_16bytes(destination_ip)
            .add_4bytes((self.slice().len() as u32).to_be_bytes())
            .add_2bytes([0, ip_number::IPV6_ICMP])
            // NOTE: From RFC 1071
            // To check a checksum, the 1's complement sum is computed over the
            // same set of octets, including the checksum field.  If the result
            // is all 1 bits (-0 in 1's complement arithmetic), the check
            // succeeds.
            .add_slice(self.slice)
            .ones_complement()
            == 0
    }

    /// Returns the bytes from position 4 till and including the 8th position
    /// in the ICMPv6 header.
    ///
    /// These bytes located at th 5th, 6th, 7th and 8th position of the ICMP
    /// packet can depending on the ICMPv6 type and code contain additional data.
    #[inline]
    pub fn bytes5to8(&self) -> [u8; 4] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE  (8).
        unsafe {
            [
                *self.slice.get_unchecked(4),
                *self.slice.get_unchecked(5),
                *self.slice.get_unchecked(6),
                *self.slice.get_unchecked(7),
            ]
        }
    }

    /// Returns the slice containing the ICMPv6 packet.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns a slice to the bytes not covered by `.header()`.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of Icmpv6Header::MIN_SERIALIZED_SIZE(8).
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(8), self.slice.len() - 8) }
    }
}
