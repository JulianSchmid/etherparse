use crate::*;

/// IEEE 802.1Q double VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeader {
    /// The outer vlan tagging header
    pub outer: SingleVlanHeader,
    /// The inner vlan tagging header
    pub inner: SingleVlanHeader,
}

impl SerializedSize for DoubleVlanHeader {
    /// Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 8;
}

impl DoubleVlanHeader {
    /// Read an DoubleVlanHeader from a slice and return the header & unused parts of the slice.
    #[deprecated(since = "0.10.1", note = "Use SingleVlanHeader::from_slice instead.")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(DoubleVlanHeader, &[u8]), ReadError> {
        DoubleVlanHeader::from_slice(slice)
    }

    /// Read an DoubleVlanHeader from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(DoubleVlanHeader, &[u8]), ReadError> {
        Ok((
            DoubleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[DoubleVlanHeader::SERIALIZED_SIZE..],
        ))
    }

    /// Read a double tagging header from the given source
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<DoubleVlanHeader, ReadError> {
        let outer = SingleVlanHeader::read(reader)?;

        use crate::ether_type::{PROVIDER_BRIDGING, VLAN_DOUBLE_TAGGED_FRAME, VLAN_TAGGED_FRAME};
        //check that outer ethertype is matching
        match outer.ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                Ok(DoubleVlanHeader {
                    outer,
                    inner: SingleVlanHeader::read(reader)?,
                })
            }
            value => {
                use crate::ReadError::*;
                Err(DoubleVlanOuterNonVlanEtherType(value))
            }
        }
    }

    /// Write the double IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        self.outer.write(writer)?;
        self.inner.write(writer)
    }

    /// Length of the serialized headers in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        8
    }

    /// Returns the serialized form of the headers or an value error in case
    /// the headers contain values that are outside of range.
    #[inline]
    pub fn to_bytes(&self) -> Result<[u8; 8], ValueError> {
        let outer = self.outer.to_bytes()?;
        let inner = self.inner.to_bytes()?;
        Ok([
            outer[0], outer[1], outer[2], outer[3], inner[0], inner[1], inner[2], inner[3],
        ])
    }
}

impl Default for DoubleVlanHeader {
    fn default() -> Self {
        DoubleVlanHeader {
            outer: SingleVlanHeader {
                priority_code_point: 0,
                drop_eligible_indicator: false,
                vlan_identifier: 0,
                ether_type: ether_type::VLAN_TAGGED_FRAME,
            },
            inner: Default::default(),
        }
    }
}
