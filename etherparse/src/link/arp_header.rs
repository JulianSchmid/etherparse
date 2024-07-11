/// Address Resolution Protocol
///
use crate::*;

use crate::{err, ArpHardwareId, EtherType, LenSource};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Request,
    Reply,
    Other(u16),
}

impl Operation {
    fn value(&self) -> u16 {
        match self {
            Operation::Request => 1,
            Operation::Reply => 2,
            Operation::Other(o) => *o,
        }
    }
}

impl From<u16> for Operation {
    fn from(raw: u16) -> Self {
        match raw {
            1 => Self::Request,
            2 => Self::Reply,
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpHeader {
    pub hw_addr_type: ArpHardwareId,
    pub proto_addr_type: EtherType,

    pub hw_addr_size: u8,
    pub proto_addr_size: u8,

    pub operation: Operation,
}

impl ArpHeader {
    pub const LEN: usize = 8;

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
        let operation: Operation = u16::from_be_bytes(input[6..8].try_into().unwrap()).into();

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

    pub fn payload_len(&self) -> usize {
        (self.hw_addr_size + self.proto_addr_size) as usize * 2
    }

    pub fn header_len(&self) -> usize {
        8 + self.payload_len()
    }

    #[cfg(feature = "std")]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write(&self.hw_addr_type.0.to_be_bytes())?;
        writer.write(&self.proto_addr_type.0.to_be_bytes())?;
        writer.write(&self.hw_addr_size.to_be_bytes())?;
        writer.write(&self.proto_addr_size.to_be_bytes())?;
        writer.write(&self.operation.value().to_be_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use crate::{
        link::{
            arp_header::{ArpHeader, Operation},
            arp_payload::{ArpPayload, HardwareAddr, ProtocolAddr},
        },
        ArpHardwareId, EtherType,
    };

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
            hw_addr_type: ArpHardwareId::ETHER,
            proto_addr_type: EtherType::IPV4,

            hw_addr_size: 6,
            proto_addr_size: 4,

            operation: Operation::Request,
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
