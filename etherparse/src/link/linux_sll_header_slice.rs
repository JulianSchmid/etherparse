use crate::*;
use core::{cmp::min, slice::from_raw_parts};

///A slice containing an Linux Cooked Capture (SLL) header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSllHeaderSlice<'a> {
    pub(crate) slice: &'a [u8],
}

impl<'a> LinuxSllHeaderSlice<'a> {
    /// Creates a SLL header slice from an other slice.
    pub fn from_slice(slice: &'a [u8]) -> Result<LinuxSllHeaderSlice<'a>, err::LenError> {
        //check length
        if slice.len() < LinuxSllHeader::LEN {
            return Err(err::LenError {
                required_len: LinuxSllHeader::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: err::Layer::LinuxSllHeader,
                layer_start_offset: 0,
            });
        }

        //all done
        Ok(LinuxSllHeaderSlice {
            // SAFETY:
            // Safe as slice length is checked to be at least
            // LinuxSllHeader::LEN (16) before this.
            slice: unsafe { from_raw_parts(slice.as_ptr(), LinuxSllHeader::LEN) },
        })
    }

    /// Converts the given slice into a SLL header slice WITHOUT any checks to 
    /// ensure that the data present is an sll header or that the slice length 
    /// is matching the header length.
    ///
    /// If you are not sure what this means, use [`LinuxSllHeaderSlice::from_slice`]
    /// instead.
    ///
    /// # Safety
    ///
    /// The caller must ensured that the given slice has the length of
    /// [`LinuxSllHeader::LEN`]
    #[inline]
    #[cfg(feature = "std")]
    pub(crate) unsafe fn from_slice_unchecked(slice: &[u8]) -> LinuxSllHeaderSlice {
        debug_assert!(slice.len() == LinuxSllHeader::LEN);
        LinuxSllHeaderSlice { slice }
    }

    /// Returns the slice containing the SLL header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Try read the packet type field.
    #[inline]
    pub fn packet_type(&self) -> Result<LinuxSllPacketType, err::linux_sll::HeaderError> {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of LinuxSllHeader::LEN (16).
        let packet_type_raw = unsafe { get_unchecked_be_u16(self.slice.as_ptr()) };

        LinuxSllPacketType::try_from(packet_type_raw)
    }

    /// Try read the arp hardware type field
    #[inline]
    pub fn arp_hardware_type(&self) -> ArpHardwareId {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of LinuxSllHeader::LEN (16).
        let arp_hardware_type_raw = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) };

        ArpHardwareId::from(arp_hardware_type_raw)
    }

    /// Read the link layer address length field.
    #[inline]
    pub fn sender_address_valid_length(&self) -> u16 {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of LinuxSllHeader::LEN (16).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(4)) }
    }

    /// Read the link layer address field. Only the first 
    /// `LinuxSllHeaderSlice::link_layer_address_length` bytes are meaningful
    #[inline]
    pub fn sender_address_full(&self) -> [u8; 8] {
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of LinuxSllHeader::LEN (16).
        unsafe { get_unchecked_8_byte_array(self.slice.as_ptr().add(6)) }
    }

    /// Get the meaningful bytes of the slice of the link layer address 
    #[inline]
    pub fn sender_address(&self) -> &'a [u8] {
        let length = self.sender_address_valid_length() as usize;
        &self.slice[6..min(length, 8)]
    }

    /// Try read the protocol type field
    #[inline]
    pub fn protocol_type(&self) -> Result<LinuxSllProtocolType, err::linux_sll::HeaderError> {
        let arp_harware_type = self.arp_hardware_type();
        // SAFETY:
        // Safe as the contructor checks that the slice has
        // at least the length of LinuxSllHeader::LEN (16).
        let protocol_type_raw = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(14)) };

        LinuxSllProtocolType::try_from((arp_harware_type, protocol_type_raw))
    }

    /// Try decode all the fields and copy the results to a [`LinuxSllHeader`] struct
    pub fn to_header(&self) -> Result<LinuxSllHeader, err::linux_sll::HeaderError> {
        Ok(LinuxSllHeader {
            packet_type: self.packet_type()?,
            arp_hrd_type: self.arp_hardware_type(),
            sender_address_valid_length: self.sender_address_valid_length(),
            sender_address: self.sender_address_full(),
            protocol_type: self.protocol_type()?
        })
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
            input in linux_sll_any(),
            dummy_data in proptest::collection::vec(any::<u8>(), 0..20)
        ) {
            // serialize
            let mut buffer: Vec<u8> = Vec::with_capacity(LinuxSllHeader::LEN + dummy_data.len());
            input.write(&mut buffer).unwrap();
            buffer.extend(&dummy_data[..]);

            // calls with a valid result
            {
                let result = LinuxSllHeaderSlice::from_slice(&buffer[..]).unwrap();
                assert_eq!(&buffer[..LinuxSllHeader::LEN], result.slice());
            }

            // call with not enough data in the slice
            for len in 0..=13 {
                assert_eq!(
                    LinuxSllHeaderSlice::from_slice(&buffer[..len]),
                    Err(err::LenError{
                        required_len: LinuxSllHeader::LEN,
                        len: len,
                        len_source: LenSource::Slice,
                        layer: err::Layer::LinuxSllHeader,
                        layer_start_offset: 0,
                    })
                );
            }
        }
    }

    proptest! {
        #[test]
        fn getters(input in linux_sll_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSllHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input.packet_type, slice.packet_type().unwrap());
            assert_eq!(input.arp_hrd_type, slice.arp_hardware_type());
            assert_eq!(input.sender_address_valid_length, slice.sender_address_valid_length());
            assert_eq!(input.sender_address, slice.sender_address_full());
            assert_eq!(input.protocol_type, slice.protocol_type().unwrap());
        }
    }

    proptest! {
        #[test]
        fn to_header(input in linux_sll_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSllHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(input, slice.to_header().unwrap());
        }
    }

    proptest! {
        #[test]
        fn clone_eq(input in linux_sll_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSllHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(slice, slice.clone());
        }
    }

    proptest! {
        #[test]
        fn dbg(input in linux_sll_any()) {
            let buffer = input.to_bytes();
            let slice = LinuxSllHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                &format!(
                    "LinuxSllHeaderSlice {{ slice: {:?} }}",
                    slice.slice()
                ),
                &format!("{:?}", slice)
            );
        }
    }
}
