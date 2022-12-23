use crate::*;

/// IEEE 802.1Q VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SingleVlanHeader {
    /// A 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub priority_code_point: u8,
    /// Indicate that the frame may be dropped under the presence of congestion.
    pub drop_eligible_indicator: bool,
    /// 12 bits vland identifier.
    pub vlan_identifier: u16,
    /// "Tag protocol identifier": Type id of content after this header. Refer to the "EtherType" for a list of possible supported values.
    pub ether_type: u16,
}

impl SerializedSize for SingleVlanHeader {
    /// Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 4;
}

impl SingleVlanHeader {
    /// Read an SingleVlanHeader from a slice and return the header & unused parts of the slice.
    #[deprecated(since = "0.10.1", note = "Use SingleVlanHeader::from_slice instead.")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(SingleVlanHeader, &[u8]), err::UnexpectedEndOfSliceError> {
        SingleVlanHeader::from_slice(slice)
    }

    /// Read an SingleVlanHeader from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(SingleVlanHeader, &[u8]), err::UnexpectedEndOfSliceError> {
        Ok((
            SingleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[SingleVlanHeader::SERIALIZED_SIZE..],
        ))
    }

    /// Read an SingleVlanHeader from a static sized byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 4]) -> SingleVlanHeader {
        SingleVlanHeader {
            priority_code_point: (bytes[0] >> 5) & 0b0000_0111u8,
            drop_eligible_indicator: 0 != (bytes[0] & 0b0001_0000u8),
            vlan_identifier: u16::from_be_bytes([bytes[0] & 0b0000_1111u8, bytes[1]]),
            ether_type: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }

    /// Read a IEEE 802.1Q VLAN tagging header
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<SingleVlanHeader, io::Error> {
        let buffer = {
            let mut buffer: [u8; SingleVlanHeader::SERIALIZED_SIZE] =
                [0; SingleVlanHeader::SERIALIZED_SIZE];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(
            // SAFETY: Safe as the buffer has the exact size of an vlan header.
            unsafe {
                SingleVlanHeaderSlice::from_slice_unchecked(&buffer)
            }.to_header()
        )
    }

    /// Write the IEEE 802.1Q VLAN tagging header
    #[inline]
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()?)?;
        Ok(())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        4
    }

    /// Returns the serialized form of the header or an value error in case
    /// the header values are outside of range.
    #[inline]
    pub fn to_bytes(&self) -> Result<[u8; 4], ValueError> {
        use crate::ErrorField::*;
        // check value ranges
        max_check_u8(self.priority_code_point, 0x7, VlanTagPriorityCodePoint)?;
        max_check_u16(self.vlan_identifier, 0xfff, VlanTagVlanId)?;

        // serialize
        let id_be = self.vlan_identifier.to_be_bytes();
        let eth_type_be = self.ether_type.to_be_bytes();
        Ok([
            (if self.drop_eligible_indicator {
                id_be[0] | 0x10
            } else {
                id_be[0]
            } | (self.priority_code_point << 5)),
            id_be[1],
            eth_type_be[0],
            eth_type_be[1],
        ])
    }
}
