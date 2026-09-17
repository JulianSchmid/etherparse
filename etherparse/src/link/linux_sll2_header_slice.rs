use crate::*;
use core::{cmp::min, slice::from_raw_parts};

/// A slice containing a Linux Cooked Capture v2 (SLL2) header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSll2HeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> LinuxSll2HeaderSlice<'a> {
    /// Creates a SLL2 header slice from an other slice.
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<LinuxSll2HeaderSlice<'a>, err::linux_sll::HeaderSliceError> {
        //check length
        if slice.len() < LinuxSll2Header::LEN {
            return Err(err::linux_sll::HeaderSliceError::Len(err::LenError {
                required_len: LinuxSll2Header::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::LinuxSll2Header,
                layer_start_offset: 0,
            }));
        }

        // check valid packet type

        // SAFETY:
        // Safe as it is checked at the start of the function that the
        // length of the slice is at least LinuxSll2Header::LEN (20).
        let packet_type_val = unsafe { *slice.get_unchecked(10) };
        if let Err(err) = LinuxSllPacketType::try_from(u16::from(packet_type_val)) {
            return Err(err::linux_sll::HeaderSliceError::Content(err));
        }

        // check supported ArpHardwareId

        // SAFETY:
        // Safe as it is checked at the start of the function that the
        // length of the slice is at least LinuxSll2Header::LEN (20).
        let arp_hardware_id = unsafe { get_unchecked_be_u16(slice.as_ptr().add(8)) };
        let arp_hardware_id = ArpHardwareId::from(arp_hardware_id);

        // SAFETY:
        // Safe as it is checked at the start of the function that the
        // length of the slice is at least LinuxSll2Header::LEN (20).
        let protocol_type = unsafe { get_unchecked_be_u16(slice.as_ptr()) };

        if let Err(err) = LinuxSllProtocolType::try_from((arp_hardware_id, protocol_type)) {
            return Err(err::linux_sll::HeaderSliceError::Content(err));
        }

        //all done
        Ok(LinuxSll2HeaderSlice {
            // SAFETY:
            // Safe as slice length is checked to be at least
            // LinuxSll2Header::LEN (20) before this.
            slice: unsafe { from_raw_parts(slice.as_ptr(), LinuxSll2Header::LEN) },
        })
    }

    /// Returns the slice containing the SLL2 header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the protocol type field
    #[inline]
    pub fn protocol_type(&self) -> LinuxSllProtocolType {
        let arp_hardware_type = self.arp_hardware_type();
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of LinuxSll2Header::LEN (20).
        let protocol_type_raw = unsafe { get_unchecked_be_u16(self.slice.as_ptr()) };

        // SAFETY:
        // Safe as the constructor checks that the arphw + protocol are supported
        unsafe {
            LinuxSllProtocolType::try_from((arp_hardware_type, protocol_type_raw))
                .unwrap_unchecked()
        }
    }

    /// Read the interface index field.
    #[inline]
    pub fn interface_index(&self) -> u32 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of LinuxSll2Header::LEN (20).
        unsafe { get_unchecked_be_u32(self.slice.as_ptr().add(4)) }
    }

    /// Read the arp hardware type field
    #[inline]
    pub fn arp_hardware_type(&self) -> ArpHardwareId {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of LinuxSll2Header::LEN (20).
        let arp_hardware_type_raw = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(8)) };

        ArpHardwareId::from(arp_hardware_type_raw)
    }

    /// Read the packet type field.
    #[inline]
    pub fn packet_type(&self) -> LinuxSllPacketType {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of LinuxSll2Header::LEN (20).
        let packet_type_raw = unsafe { *self.slice.get_unchecked(10) };

        // SAFETY:
        // Safe as the constructor checks that the packet type is valid
        unsafe { LinuxSllPacketType::try_from(u16::from(packet_type_raw)).unwrap_unchecked() }
    }

    /// Read the link layer address length field.
    #[inline]
    pub fn sender_address_valid_length(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of LinuxSll2Header::LEN (20).
        unsafe { *self.slice.get_unchecked(11) }
    }

    /// Read the link layer address field. Only the first
    /// `LinuxSll2HeaderSlice::sender_address_valid_length` bytes are meaningful
    #[inline]
    pub fn sender_address_full(&self) -> [u8; 8] {
        // SAFETY:
        // Safe as the constructor checks that the slice has
        // at least the length of LinuxSll2Header::LEN (20).
        unsafe { get_unchecked_8_byte_array(self.slice.as_ptr().add(12)) }
    }

    /// Get the meaningful bytes of the slice of the link layer address
    #[inline]
    pub fn sender_address(&self) -> &'a [u8] {
        let length = usize::from(self.sender_address_valid_length());
        &self.slice[12..min(12 + length, 12 + 8)]
    }

    /// Decode all the fields and copy the results to a [`LinuxSll2Header`] struct
    pub fn to_header(&self) -> LinuxSll2Header {
        LinuxSll2Header {
            protocol_type: self.protocol_type(),
            interface_index: self.interface_index(),
            arp_hrd_type: self.arp_hardware_type(),
            packet_type: self.packet_type(),
            sender_address_valid_length: self.sender_address_valid_length(),
            sender_address: self.sender_address_full(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use alloc::{format, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn from_slice(
            input in linux_sll2_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20),
            bad_packet_type in (LinuxSllPacketType::MAX_VAL + 1)..=u16::from(u8::MAX),
            bad_hw_type in any::<u16>().prop_filter(
                "hw id must be unknown",
                |v| !LinuxSllProtocolType::SUPPORTED_ARPHWD.iter().any(|&x| *v == x.0)
            )
        ) {
            // serialize
            let buffer = {
                let mut buffer: Vec<u8> = Vec::with_capacity(LinuxSll2Header::LEN + dummy_data.len());
                input.write(&mut buffer).unwrap();
                buffer.extend(&dummy_data[..]);
                buffer
            };

            // calls with a valid result
            {
                let result = LinuxSll2HeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(&buffer[..LinuxSll2Header::LEN], result.slice());
            }

            // call with not enough data in the slice
            for len in 0..LinuxSll2Header::LEN {
                assert_eq!(
                    LinuxSll2HeaderSlice::from_slice(&buffer[..len]),
                    Err(err::linux_sll::HeaderSliceError::Len(err::LenError{
                        required_len: LinuxSll2Header::LEN,
                        len,
                        len_source: LenSource::Slice,
                        layer: err::Layer::LinuxSll2Header,
                        layer_start_offset: 0,
                    }))
                );
            }

            // packet_type_val error
            {
                let mut modbuf = buffer.clone();
                modbuf[10] = bad_packet_type as u8;
                assert_eq!(
                    LinuxSll2HeaderSlice::from_slice(&modbuf),
                    Err(err::linux_sll::HeaderSliceError::Content(
                        err::linux_sll::HeaderError::UnsupportedPacketTypeField { packet_type: bad_packet_type }
                    ))
                );
            }

            // hardware_id error
            {
                let mut modbuf = buffer.clone();
                let p_be = bad_hw_type.to_be_bytes();
                modbuf[8] = p_be[0];
                modbuf[9] = p_be[1];
                assert_eq!(
                    LinuxSll2HeaderSlice::from_slice(&modbuf),
                    Err(err::linux_sll::HeaderSliceError::Content(
                        err::linux_sll::HeaderError::UnsupportedArpHardwareId { arp_hardware_type: ArpHardwareId(bad_hw_type) }
                    ))
                );
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in linux_sll2_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSll2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input.protocol_type, slice.protocol_type());
            assert_eq!(input.interface_index, slice.interface_index());
            assert_eq!(input.arp_hrd_type, slice.arp_hardware_type());
            assert_eq!(input.packet_type, slice.packet_type());
            assert_eq!(input.sender_address_valid_length, slice.sender_address_valid_length());
            assert_eq!(input.sender_address, slice.sender_address_full());
            assert_eq!(&input.sender_address[..usize::from(input.sender_address_valid_length)], slice.sender_address());
        }
    }

    #[test]
    fn sender_address_len_clamped() {
        // an address length larger then 8 must be clamped to the 8 available bytes
        let header = LinuxSll2Header {
            protocol_type: LinuxSllProtocolType::EtherType(EtherType::IPV4),
            interface_index: 1,
            arp_hrd_type: ArpHardwareId::ETHERNET,
            packet_type: LinuxSllPacketType::HOST,
            sender_address_valid_length: 20,
            sender_address: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let buffer = header.to_bytes();
        let slice = LinuxSll2HeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(&[1, 2, 3, 4, 5, 6, 7, 8], slice.sender_address());
    }

    proptest! {
        #[test]
        fn to_header(input in linux_sll2_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSll2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input, slice.to_header());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in linux_sll2_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSll2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in linux_sll2_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSll2HeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                &format!(
                    "LinuxSll2HeaderSlice {{ slice: {:?} }}",
                    slice.slice()
                ),
                &format!("{:?}", slice)
            );
        }
    }
}
