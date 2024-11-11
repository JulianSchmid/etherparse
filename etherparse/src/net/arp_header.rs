use crate::*;

use crate::{err, ArpHardwareId, EtherType, LenSource};

/// Static sized part of an ARP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpHeader {
    /// This field specifies the network link protocol type (e.g. `ArpHardwareId::ETHERNET`).
    pub hw_addr_type: ArpHardwareId,

    /// This field specifies the  protocol for which the ARP request is intended (e.g. `EtherType::IPV4`).
    pub proto_addr_type: EtherType,

    /// Length (in octets) of a hardware address (e.g. 6 for Ethernet).
    pub hw_addr_size: u8,

    /// Length (in octets) of internetwork addresses (e.g. 4 for IPv4 or 16 for IPv6).
    pub proto_addr_size: u8,

    /// Specifies the operation that the sender is performing
    pub operation: ArpOperation,
}

impl ArpHeader {
    /// Serialized size of an ADP header in bytes/octets.
    pub const LEN: usize = 8;

    /// Reads a ARP header from a slice directly and returns a tuple containing the resulting header & unused part of the slice.
    pub fn from_slice(input: &[u8]) -> Result<(ArpHeader, &[u8]), err::LenError> {
        if input.len() < Self::LEN {
            return Err(err::LenError {
                required_len: 8,
                len_source: LenSource::Slice,
                len: input.len(),
                layer: err::Layer::EtherPayload,
                layer_start_offset: 0,
            });
        }
        let hw_addr_type: ArpHardwareId =
            u16::from_be_bytes(input[0..2].try_into().unwrap()).into();
        let proto_addr_type: EtherType = u16::from_be_bytes(input[2..4].try_into().unwrap()).into();
        let hw_addr_size = input[4];
        let proto_addr_size = input[5];
        let operation: ArpOperation = u16::from_be_bytes(input[6..8].try_into().unwrap()).into();

        let required = (8 + (hw_addr_size + proto_addr_size) * 2) as usize;

        if input.len() != required {
            return Err(err::LenError {
                required_len: required,
                len_source: LenSource::Slice,
                len: input.len(),
                layer: err::Layer::EtherPayload,
                layer_start_offset: 8,
            });
        }

        Ok((
            ArpHeader {
                hw_addr_type,
                proto_addr_type,
                hw_addr_size,
                proto_addr_size,
                operation,
            },
            &input[8..],
        ))
    }

    /// Expected payload length based on the hardware address size & protocol address size.
    #[inline]
    pub fn expected_payload_len(&self) -> usize {
        (self.hw_addr_size + self.proto_addr_size) as usize * 2
    }

    /// Returns the serialized header.
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let hw_addr_type = self.hw_addr_type.0.to_be_bytes();
        let proto_addr_type = self.proto_addr_type.0.to_be_bytes();
        let operation = self.operation.0.to_be_bytes();
        [
            hw_addr_type[0],
            hw_addr_type[1],
            proto_addr_type[0],
            proto_addr_type[1],
            self.hw_addr_size,
            self.proto_addr_size,
            operation[0],
            operation[1],
        ]
    }

    /// Writes the header to the given writer.
    #[cfg(feature = "std")]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write(&self.to_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use core::net::Ipv4Addr;

    #[test]
    fn arp_packet_works() {
        let bytes = [
            0, 1, // hardware type
            8, 0, // proto type
            6, 4, // sizes
            0, 1, // arp operation
            0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, // src mac
            10, 10, 1, 135, // src ip
            0xde, 0xad, 0xc0, 0x00, 0xff, 0xee, // dest mac
            192, 168, 1, 253, // dest ip
        ];

        let expected_header = ArpHeader {
            hw_addr_type: ArpHardwareId::ETHERNET,
            proto_addr_type: EtherType::IPV4,
            hw_addr_size: 6,
            proto_addr_size: 4,
            operation: ArpOperation::REQUEST,
        };

        let expected_payload = ArpPayload {
            src_hard_addr: HardwareAddr::Mac([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            src_addr: ProtocolAddr::Ipv4(Ipv4Addr::new(10, 10, 1, 135)),

            des_hard_addr: HardwareAddr::Mac([0xde, 0xad, 0xc0, 0x00, 0xff, 0xee]),
            des_addr: ProtocolAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 253)),
        };

        let (header, payload) = ArpHeader::from_slice(&bytes).unwrap();

        let payload = ArpPayload::from_pkg(header, payload).unwrap();

        assert_eq!(header, expected_header);
        assert_eq!(payload, expected_payload);
    }
}
