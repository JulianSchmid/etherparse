use crate::{err, ArpHardwareId, LinuxSll2HeaderSlice, LinuxSllPacketType, LinuxSllProtocolType};

/// Linux Cooked Capture v2 (SLL2) Header
///
/// Layout (all multi byte values are big endian):
///
/// ```text
/// +---------------------------+
/// |       Protocol type       |  2 Octets
/// +---------------------------+
/// |      Reserved (MBZ)       |  2 Octets
/// +---------------------------+
/// |      Interface index      |  4 Octets
/// +---------------------------+
/// |        ARPHRD_ type       |  2 Octets
/// +---------------------------+
/// |        Packet type        |  1 Octet
/// +---------------------------+
/// | Link-layer address length |  1 Octet
/// +---------------------------+
/// |    Link-layer address     |  8 Octets
/// +---------------------------+
/// ```
///
/// See <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html>.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSll2Header {
    /// The protocol type of the encapsulated packet
    pub protocol_type: LinuxSllProtocolType,
    /// Interface index (as returned by `if_nametoindex(3)`) of the interface
    /// on which the packet was captured / sent.
    pub interface_index: u32,
    /// ARPHRD_ value for the link-layer device type
    pub arp_hrd_type: ArpHardwareId,
    /// Type of the captured packet
    pub packet_type: LinuxSllPacketType,
    /// The size of the address that is valid
    pub sender_address_valid_length: u8,
    /// The link-layer address of the sender of the packet. Only the first
    /// `sender_address_valid_length` bytes are meaningful. Capture producers
    /// truncate longer addresses to 8 bytes and zero-pad shorter ones, but
    /// this struct serializes the array as-is and does not enforce padding.
    pub sender_address: [u8; 8],
}

impl LinuxSll2Header {
    /// Serialized size of an SLL2 header in bytes/octets.
    pub const LEN: usize = 20;

    /// Read an SLL2 header from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(
        slice: &[u8],
    ) -> Result<(LinuxSll2Header, &[u8]), err::linux_sll::HeaderSliceError> {
        Ok((
            LinuxSll2HeaderSlice::from_slice(slice)?.to_header(),
            &slice[LinuxSll2Header::LEN..],
        ))
    }

    /// Read an SLL2 header from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 20]) -> Result<LinuxSll2Header, err::linux_sll::HeaderError> {
        let packet_type = LinuxSllPacketType::try_from(u16::from(bytes[10]))?;
        let arp_hrd_type = ArpHardwareId::from(u16::from_be_bytes([bytes[8], bytes[9]]));
        let protocol_type = LinuxSllProtocolType::try_from((
            arp_hrd_type,
            u16::from_be_bytes([bytes[0], bytes[1]]),
        ))?;
        let interface_index = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let sender_address_valid_length = bytes[11];
        let sender_address = [
            bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
        ];

        Ok(LinuxSll2Header {
            protocol_type,
            interface_index,
            arp_hrd_type,
            packet_type,
            sender_address_valid_length,
            sender_address,
        })
    }

    /// Reads an SLL2 header from the current position of the read argument.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read<T: std::io::Read + std::io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<LinuxSll2Header, err::ReadError> {
        let buffer = {
            let mut buffer = [0; LinuxSll2Header::LEN];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(LinuxSll2HeaderSlice::from_slice(&buffer)?.to_header())
    }

    /// Serialize the header to a given slice. Returns the unused part of the slice.
    pub fn write_to_slice<'a>(
        &self,
        slice: &'a mut [u8],
    ) -> Result<&'a mut [u8], err::SliceWriteSpaceError> {
        // length check
        if slice.len() < LinuxSll2Header::LEN {
            Err(err::SliceWriteSpaceError {
                required_len: LinuxSll2Header::LEN,
                len: slice.len(),
                layer: err::Layer::LinuxSll2Header,
                layer_start_offset: 0,
            })
        } else {
            slice[..LinuxSll2Header::LEN].copy_from_slice(&self.to_bytes());
            Ok(&mut slice[LinuxSll2Header::LEN..])
        }
    }

    /// Writes a given SLL2 header to the current position of the write argument.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[inline]
    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        Self::LEN
    }

    /// Returns the serialized form of the header as a statically
    /// sized byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let protocol_type_be = u16::from(self.protocol_type).to_be_bytes();
        let interface_index_be = self.interface_index.to_be_bytes();
        let arp_hrd_type_be = u16::from(self.arp_hrd_type).to_be_bytes();
        // packet type values are at most `LinuxSllPacketType::MAX_VAL` (7),
        // so the value always fits into the lower byte.
        let packet_type_be = u16::from(self.packet_type).to_be_bytes();
        let sender_address_be = self.sender_address;

        [
            protocol_type_be[0],
            protocol_type_be[1],
            // reserved (must be zero)
            0,
            0,
            interface_index_be[0],
            interface_index_be[1],
            interface_index_be[2],
            interface_index_be[3],
            arp_hrd_type_be[0],
            arp_hrd_type_be[1],
            packet_type_be[1],
            self.sender_address_valid_length,
            sender_address_be[0],
            sender_address_be[1],
            sender_address_be[2],
            sender_address_be[3],
            sender_address_be[4],
            sender_address_be[5],
            sender_address_be[6],
            sender_address_be[7],
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test_gens::*, LenSource};
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;
    use std::io::{Cursor, ErrorKind};

    proptest! {
        #[test]
        fn from_slice(
            input in linux_sll2_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(LinuxSll2Header::LEN + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let (result, rest) = LinuxSll2Header::from_slice(&buffer[..]).unwrap();
                assert_eq!(input, result);
                assert_eq!(&buffer[LinuxSll2Header::LEN..], rest);
            }

            // call with not enough data in the slice
            for len in 0..LinuxSll2Header::LEN {
                assert_eq!(
                    LinuxSll2Header::from_slice(&buffer[..len]).unwrap_err(),
                    err::linux_sll::HeaderSliceError::Len(err::LenError{
                        required_len: LinuxSll2Header::LEN,
                        len,
                        len_source: LenSource::Slice,
                        layer: err::Layer::LinuxSll2Header,
                        layer_start_offset: 0,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn from_bytes(
            input in linux_sll2_any(),
            bad_packet_type in (LinuxSllPacketType::MAX_VAL + 1)..=u16::from(u8::MAX),
            bad_hw_type in any::<u16>().prop_filter(
                "hw id must be unknown",
                |v| !LinuxSllProtocolType::SUPPORTED_ARPHWD.iter().any(|&x| *v == x.0)
            )
        ) {
            assert_eq!(
                input,
                LinuxSll2Header::from_bytes(input.to_bytes()).unwrap()
            );

            // reserved bytes are ignored
            {
                let mut bytes = input.to_bytes();
                bytes[2] = 0xff;
                bytes[3] = 0xff;
                assert_eq!(
                    input,
                    LinuxSll2Header::from_bytes(bytes).unwrap()
                );
            }

            // packet type error
            {
                let mut bytes = input.to_bytes();
                bytes[10] = bad_packet_type as u8;
                assert_eq!(
                    LinuxSll2Header::from_bytes(bytes).unwrap_err(),
                    err::linux_sll::HeaderError::UnsupportedPacketTypeField { packet_type: bad_packet_type }
                );
            }

            // arp hardware id error
            {
                let mut bytes = input.to_bytes();
                let hw_be = bad_hw_type.to_be_bytes();
                bytes[8] = hw_be[0];
                bytes[9] = hw_be[1];
                assert_eq!(
                    LinuxSll2Header::from_bytes(bytes).unwrap_err(),
                    err::linux_sll::HeaderError::UnsupportedArpHardwareId { arp_hardware_type: ArpHardwareId(bad_hw_type) }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn read(
            input in linux_sll2_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20),
            bad_packet_type in (LinuxSllPacketType::MAX_VAL + 1)..=u16::from(u8::MAX),
        ) {
            // normal read
            let mut buffer = Vec::with_capacity(LinuxSll2Header::LEN + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let mut cursor = Cursor::new(&buffer);
                let result = LinuxSll2Header::read(&mut cursor).unwrap();
                assert_eq!(input, result);
                assert_eq!(cursor.position(), u64::try_from(LinuxSll2Header::LEN).unwrap());
            }

            // unexpected eof
            for len in 0..LinuxSll2Header::LEN {
                let mut cursor = Cursor::new(&buffer[0..len]);
                assert_eq!(
                    LinuxSll2Header::read(&mut cursor)
                    .unwrap_err()
                    .io().unwrap()
                    .kind(),
                    ErrorKind::UnexpectedEof
                );
            }

            // content error
            {
                let mut bad = buffer.clone();
                bad[10] = bad_packet_type as u8;
                let mut cursor = Cursor::new(&bad);
                assert_eq!(
                    LinuxSll2Header::read(&mut cursor)
                    .unwrap_err()
                    .linux_sll().unwrap(),
                    &err::linux_sll::HeaderError::UnsupportedPacketTypeField { packet_type: bad_packet_type }
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write_to_slice(input in linux_sll2_any()) {
            // normal write
            {
                let mut buffer: [u8;LinuxSll2Header::LEN] = [0;LinuxSll2Header::LEN];
                input.write_to_slice(&mut buffer).unwrap();
                assert_eq!(buffer, input.to_bytes());
            }
            // len to small
            for len in 0..LinuxSll2Header::LEN {
                let mut buffer: [u8;LinuxSll2Header::LEN] = [0;LinuxSll2Header::LEN];
                assert_eq!(
                    err::SliceWriteSpaceError {
                        required_len: LinuxSll2Header::LEN,
                        len,
                        layer: err::Layer::LinuxSll2Header,
                        layer_start_offset: 0,
                    },
                    input.write_to_slice(&mut buffer[..len]).unwrap_err()
                );
            }
        }
    }

    proptest! {
        #[test]
        fn write(input in linux_sll2_any()) {
            // successful write
            {
                let mut buffer: Vec<u8> = Vec::with_capacity(LinuxSll2Header::LEN);
                input.write(&mut buffer).unwrap();
                assert_eq!(&buffer[..], &input.to_bytes());
            }

            // not enough memory for write (unexpected eof)
            for len in 0..8 {
                let mut buffer = [0u8;8];
                let mut writer = Cursor::new(&mut buffer[..len]);
                assert!(input.write(&mut writer).is_err());
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(input in linux_sll2_any()) {
            assert_eq!(input.header_len(), LinuxSll2Header::LEN);
        }
    }

    proptest! {
        #[test]
        fn to_bytes(input in linux_sll2_any()) {
            let protocol_type_be = u16::from(input.protocol_type).to_be_bytes();
            let interface_index_be = input.interface_index.to_be_bytes();
            let arp_hrd_type_be = u16::from(input.arp_hrd_type).to_be_bytes();
            let packet_type = u16::from(input.packet_type) as u8;
            let sender_address_be = input.sender_address;

            assert_eq!(
                input.to_bytes(),
                [
                    protocol_type_be[0],
                    protocol_type_be[1],
                    0,
                    0,
                    interface_index_be[0],
                    interface_index_be[1],
                    interface_index_be[2],
                    interface_index_be[3],
                    arp_hrd_type_be[0],
                    arp_hrd_type_be[1],
                    packet_type,
                    input.sender_address_valid_length,
                    sender_address_be[0],
                    sender_address_be[1],
                    sender_address_be[2],
                    sender_address_be[3],
                    sender_address_be[4],
                    sender_address_be[5],
                    sender_address_be[6],
                    sender_address_be[7],
                ]
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in linux_sll2_any()) {
            assert_eq!(input, input.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in linux_sll2_any()) {
            assert_eq!(
                &format!(
                    "LinuxSll2Header {{ protocol_type: {:?}, interface_index: {:?}, arp_hrd_type: {:?}, packet_type: {:?}, sender_address_valid_length: {:?}, sender_address: {:?} }}",
                    input.protocol_type,
                    input.interface_index,
                    input.arp_hrd_type,
                    input.packet_type,
                    input.sender_address_valid_length,
                    input.sender_address,
                ),
                &format!("{:?}", input)
            );
        }
    }
}
