use crate::{
    err::{self, Layer},
    ArpHardwareId, LenSource, LinuxSll2Header, LinuxSll2HeaderSlice, LinuxSllPacketType,
    LinuxSllPayloadSlice, LinuxSllProtocolType,
};

/// Slice containing a Linux Cooked Capture v2 (SLL2) header & payload.
#[derive(Clone, Eq, PartialEq)]
pub struct LinuxSll2Slice<'a> {
    header_slice: LinuxSll2HeaderSlice<'a>,
    header_and_payload_slice: &'a [u8],
}

impl<'a> LinuxSll2Slice<'a> {
    /// Try creating a [`LinuxSll2Slice`] from a slice containing the
    /// header & payload
    pub fn from_slice(
        slice: &'a [u8],
    ) -> Result<LinuxSll2Slice<'a>, err::linux_sll::HeaderSliceError> {
        // check length
        if slice.len() < LinuxSll2Header::LEN {
            return Err(err::linux_sll::HeaderSliceError::Len(err::LenError {
                required_len: LinuxSll2Header::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::LinuxSll2Header,
                layer_start_offset: 0,
            }));
        }

        // extract header
        match LinuxSll2HeaderSlice::from_slice(&slice[0..LinuxSll2Header::LEN]) {
            Err(err) => Err(err),
            Ok(header_slice) => Ok(LinuxSll2Slice {
                header_slice,
                header_and_payload_slice: slice,
            }),
        }
    }

    /// Returns the slice containing the Linux Cooked Capture v2 (SLL2) header &
    /// payload.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.header_and_payload_slice
    }

    /// Read the protocol type field from the header
    #[inline]
    pub fn protocol_type(&self) -> LinuxSllProtocolType {
        self.header_slice.protocol_type()
    }

    /// Read the interface index field from the header
    #[inline]
    pub fn interface_index(&self) -> u32 {
        self.header_slice.interface_index()
    }

    /// Read the arp hardware type field from the header
    #[inline]
    pub fn arp_hardware_type(&self) -> ArpHardwareId {
        self.header_slice.arp_hardware_type()
    }

    /// Read the packet type field from the header
    #[inline]
    pub fn packet_type(&self) -> LinuxSllPacketType {
        self.header_slice.packet_type()
    }

    /// Read the link layer address length field from the header
    #[inline]
    pub fn sender_address_valid_length(&self) -> u8 {
        self.header_slice.sender_address_valid_length()
    }

    /// Read the link layer address field from the header. Only the first
    /// `LinuxSll2Slice::sender_address_valid_length` bytes are meaningful
    #[inline]
    pub fn sender_address_full(&self) -> [u8; 8] {
        self.header_slice.sender_address_full()
    }

    /// Get the meaningful bytes of the slice of the link layer address from
    /// the header
    #[inline]
    pub fn sender_address(&self) -> &'a [u8] {
        self.header_slice.sender_address()
    }

    /// Decode all the header fields and copy the results to a
    /// [`LinuxSll2Header`] struct
    pub fn to_header(&self) -> LinuxSll2Header {
        self.header_slice.to_header()
    }

    /// Slice only containing the header
    pub fn header_slice(&self) -> &[u8] {
        self.header_slice.slice()
    }

    /// Returns the slice containing the SLL2 payload & the protocol type
    /// identifying it's content type.
    #[inline]
    pub fn payload(&self) -> LinuxSllPayloadSlice<'a> {
        LinuxSllPayloadSlice {
            protocol_type: self.protocol_type(),
            payload: self.payload_slice(),
        }
    }

    /// Slice only containing the payload
    #[inline]
    pub fn payload_slice(&self) -> &'a [u8] {
        // SAFETY: Safe as the slice length was verified to be at least
        // LinuxSll2Header::LEN by "from_slice".
        unsafe {
            core::slice::from_raw_parts(
                self.header_and_payload_slice
                    .as_ptr()
                    .add(LinuxSll2Header::LEN),
                self.header_and_payload_slice.len() - LinuxSll2Header::LEN,
            )
        }
    }

    /// Length of the header in bytes (equal to [`crate::LinuxSll2Header::LEN`])
    #[inline]
    pub const fn header_len(&self) -> usize {
        LinuxSll2Header::LEN
    }
}

impl core::fmt::Debug for LinuxSll2Slice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinuxSll2Slice")
            .field("header", &self.to_header())
            .field("payload", &self.payload())
            .finish()
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
        fn debug_clone_eq(
            linux_sll2 in linux_sll2_any()
        ) {
            let payload: [u8;8] = [1,2,3,4,5,6,7,8];
            let mut data = Vec::with_capacity(
                linux_sll2.header_len() +
                payload.len()
            );
            data.extend_from_slice(&linux_sll2.to_bytes());
            data.extend_from_slice(&payload);

            // decode packet
            let slice = LinuxSll2Slice::from_slice(&data).unwrap();

            // check debug output
            prop_assert_eq!(
                format!("{:?}", slice),
                format!(
                    "LinuxSll2Slice {{ header: {:?}, payload: {:?} }}",
                    slice.to_header(),
                    slice.payload(),
                )
            );
            prop_assert_eq!(slice.clone(), slice);
        }
    }

    proptest! {
        #[test]
        fn getters(linux_sll2 in linux_sll2_any()) {
            let payload: [u8;8] = [1,2,3,4,5,6,7,8];
            let mut data = Vec::with_capacity(
                linux_sll2.header_len() +
                payload.len()
            );
            data.extend_from_slice(&linux_sll2.to_bytes());
            data.extend_from_slice(&payload);

            let slice = LinuxSll2Slice::from_slice(&data).unwrap();
            assert_eq!(linux_sll2.protocol_type, slice.protocol_type());
            assert_eq!(linux_sll2.interface_index, slice.interface_index());
            assert_eq!(linux_sll2.arp_hrd_type, slice.arp_hardware_type());
            assert_eq!(linux_sll2.packet_type, slice.packet_type());
            assert_eq!(linux_sll2.sender_address_valid_length, slice.sender_address_valid_length());
            assert_eq!(linux_sll2.sender_address, slice.sender_address_full());
            assert_eq!(&linux_sll2.sender_address[..usize::from(linux_sll2.sender_address_valid_length)], slice.sender_address());
            assert_eq!(&payload, slice.payload_slice());
            assert_eq!(
                LinuxSllPayloadSlice{
                    payload: &payload,
                    protocol_type: linux_sll2.protocol_type,
                },
                slice.payload()
            );
            assert_eq!(linux_sll2, slice.to_header());
            assert_eq!(&data, slice.slice());
            assert_eq!(&data[..LinuxSll2Header::LEN], slice.header_slice());
            assert_eq!(LinuxSll2Header::LEN, slice.header_len());
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            linux_sll2 in linux_sll2_any(),
            bad_packet_type in (LinuxSllPacketType::MAX_VAL + 1)..=u16::from(u8::MAX),
        ) {

            let payload: [u8;10] = [1,2,3,4,5,6,7,8,9,10];
            let data = {
                let mut data = Vec::with_capacity(
                    linux_sll2.header_len() +
                    payload.len()
                );
                data.extend_from_slice(&linux_sll2.to_bytes());
                data.extend_from_slice(&payload);
                data
            };

            // normal decode
            {
                let slice = LinuxSll2Slice::from_slice(&data).unwrap();
                assert_eq!(slice.to_header(), linux_sll2);
                assert_eq!(slice.payload_slice(), &payload);
            }

            // decode without payload
            {
                let slice = LinuxSll2Slice::from_slice(&data[..LinuxSll2Header::LEN]).unwrap();
                assert_eq!(slice.to_header(), linux_sll2);
                assert_eq!(slice.payload_slice(), &[]);
            }

            // length error
            for len in 0..LinuxSll2Header::LEN {
                assert_eq!(
                    LinuxSll2Slice::from_slice(&data[..len]).unwrap_err(),
                    err::linux_sll::HeaderSliceError::Len(err::LenError{
                        required_len: LinuxSll2Header::LEN,
                        len,
                        len_source: LenSource::Slice,
                        layer: Layer::LinuxSll2Header,
                        layer_start_offset: 0
                    })
                );
            }

            // content error
            {
                let mut bad = data.clone();
                bad[10] = bad_packet_type as u8;
                assert_eq!(
                    LinuxSll2Slice::from_slice(&bad).unwrap_err(),
                    err::linux_sll::HeaderSliceError::Content(
                        err::linux_sll::HeaderError::UnsupportedPacketTypeField { packet_type: bad_packet_type }
                    )
                );
            }
        }
    }
}
