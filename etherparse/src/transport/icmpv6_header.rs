use crate::*;
use arrayvec::ArrayVec;

/// The statically sized data at the start of an ICMPv6 packet (at least the first 8 bytes of an ICMPv6 packet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv6Header {
    /// Type & type specific values & code.
    pub icmp_type: Icmpv6Type,
    /// Checksum in the ICMPv6 header.
    pub checksum: u16,
}

impl Icmpv6Header {

    /// Minimum number of bytes an ICMP header needs to have.
    ///
    /// Note that minimum size can be larger depending on
    /// the type and code.
    pub const MIN_LEN: usize = 8;

    /// Deprecated, use [`Icmpv6Header::MIN_LEN`] instead.
    #[deprecated(
        since = "0.14.0",
        note = "Please use Icmpv6Header::MIN_LEN instead"
    )]
    pub const MIN_SERIALIZED_SIZE: usize = 8;

    /// Maximum number of bytes/octets an Icmpv6Header takes up
    /// in serialized form.
    ///
    /// Currently this number is determined by the biggest
    /// planned ICMPv6 header type, which is currently the
    /// "Neighbor Discovery Protocol" "Redirect" message.
    pub const MAX_LEN: usize = 8 + 16 + 16;

    /// Deprecated, use [`Icmpv6Header::MAX_LEN`] instead.
    #[deprecated(
        since = "0.14.0",
        note = "Please use Icmpv6Header::MAX_LEN instead"
    )]
    pub const MAX_SERIALIZED_SIZE: usize = 8 + 16 + 16;

    /// Setups a new header with the checksum beeing set to 0.
    #[inline]
    pub fn new(icmp_type: Icmpv6Type) -> Icmpv6Header {
        Icmpv6Header {
            icmp_type,
            checksum: 0, // will be filled in later
        }
    }

    /// Creates a [`Icmpv6Header`] with a checksum calculated based
    /// on the given payload & ip addresses from the IPv6 header.
    pub fn with_checksum(
        icmp_type: Icmpv6Type,
        source_ip: [u8; 16],
        destination_ip: [u8; 16],
        payload: &[u8],
    ) -> Result<Icmpv6Header, ValueError> {
        let checksum = icmp_type.calc_checksum(source_ip, destination_ip, payload)?;
        Ok(Icmpv6Header {
            icmp_type,
            checksum,
        })
    }

    /// Reads an icmp6 header from a slice directly and returns a tuple
    /// containing the resulting header & unused part of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Icmpv6Header, &[u8]), ReadError> {
        let header = Icmpv6Slice::from_slice(slice)?.header();
        let len = header.header_len();
        Ok((header, &slice[len..]))
    }

    /// Read a ICMPv6 header from the given reader
    pub fn read<T: io::Read + Sized>(reader: &mut T) -> Result<Icmpv6Header, ReadError> {
        // read the initial 8 bytes
        let mut start = [0u8; 8];
        reader.read_exact(&mut start)?;
        Ok(Icmpv6Slice { slice: &start }.header())
    }

    /// Write the ICMPv6 header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()).map_err(WriteError::from)
    }

    /// Serialized length of the header in bytes/octets.
    ///
    /// Note that this size is not the size of the entire
    /// ICMPv6 packet but only the header.
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

    /// Updates the checksum of the header.
    pub fn update_checksum(
        &mut self,
        source_ip: [u8; 16],
        destination_ip: [u8; 16],
        payload: &[u8],
    ) -> Result<(), ValueError> {
        self.checksum = self
            .icmp_type
            .calc_checksum(source_ip, destination_ip, payload)?;
        Ok(())
    }

    /// Returns the header on the wire bytes.
    #[inline]
    pub fn to_bytes(&self) -> ArrayVec<u8, { Icmpv6Header::MAX_LEN }> {
        let checksum_be = self.checksum.to_be_bytes();

        let return_trivial =
            |type_u8: u8, code_u8: u8| -> ArrayVec<u8, { Icmpv6Header::MAX_LEN }> {
                #[rustfmt::skip]
            let mut re = ArrayVec::from([
                type_u8, code_u8, checksum_be[0], checksum_be[1],
                0, 0, 0, 0,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,

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

        let return_4u8 = |type_u8: u8,
                          code_u8: u8,
                          bytes5to8: [u8; 4]|
         -> ArrayVec<u8, { Icmpv6Header::MAX_LEN }> {
            #[rustfmt::skip]
            let mut re = ArrayVec::from([
                type_u8, code_u8, checksum_be[0], checksum_be[1],
                bytes5to8[0], bytes5to8[1], bytes5to8[2], bytes5to8[3],

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,

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

        use crate::{Icmpv6Type::*, icmpv6::*};
        match self.icmp_type {
            Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => return_4u8(type_u8, code_u8, bytes5to8),
            DestinationUnreachable(header) => return_trivial(TYPE_DST_UNREACH, header.code_u8()),
            PacketTooBig { mtu } => return_4u8(TYPE_PACKET_TOO_BIG, 0, mtu.to_be_bytes()),
            TimeExceeded(code) => return_trivial(TYPE_TIME_EXCEEDED, code.code_u8()),
            ParameterProblem(header) => return_4u8(
                TYPE_PARAMETER_PROBLEM,
                header.code.code_u8(),
                header.pointer.to_be_bytes(),
            ),
            EchoRequest(echo) => return_4u8(TYPE_ECHO_REQUEST, 0, echo.to_bytes()),
            EchoReply(echo) => return_4u8(TYPE_ECHO_REPLY, 0, echo.to_bytes()),
        }
    }
}
