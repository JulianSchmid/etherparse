use super::super::*;

use std::io;
use std::slice::from_raw_parts;

///IEEE 802.1Q VLAN Tagging Header (can be single or double tagged).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanHeader {
    ///IEEE 802.1Q VLAN Tagging Header
    Single(SingleVlanHeader),
    ///IEEE 802.1Q double VLAN Tagging Header
    Double(DoubleVlanHeader)
}

impl VlanHeader {
    ///All ether types that identify a vlan header.
    pub const VLAN_ETHER_TYPES: [u16;3] = [
        ether_type::VLAN_TAGGED_FRAME,
        ether_type::PROVIDER_BRIDGING,
        ether_type::VLAN_DOUBLE_TAGGED_FRAME,
    ];
}

///IEEE 802.1Q VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SingleVlanHeader {
    ///A 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub priority_code_point: u8,
    ///Indicate that the frame may be dropped under the presence of congestion.
    pub drop_eligible_indicator: bool,
    ///12 bits vland identifier.
    pub vlan_identifier: u16,
    ///"Tag protocol identifier": Type id of content after this header. Refer to the "EtherType" for a list of possible supported values.
    pub ether_type: u16,
}

impl SerializedSize for SingleVlanHeader {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 4;
}

impl SingleVlanHeader {

    ///Read an SingleVlanHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(SingleVlanHeader, &[u8]), ReadError> {
        Ok((
            SingleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[SingleVlanHeader::SERIALIZED_SIZE .. ]
        ))
    }

    ///Read a IEEE 802.1Q VLAN tagging header
    pub fn read<T: io::Read + io::Seek + Sized >(reader: &mut T) -> Result<SingleVlanHeader, io::Error> {
        let buffer = {
            let mut buffer : [u8; SingleVlanHeader::SERIALIZED_SIZE] = [0;SingleVlanHeader::SERIALIZED_SIZE];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(SingleVlanHeaderSlice{
            slice: &buffer
        }.to_header())
    }

    ///Write the IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::ErrorField::*;
        //check value ranges
        max_check_u8(self.priority_code_point, 0x7, VlanTagPriorityCodePoint)?;
        max_check_u16(self.vlan_identifier, 0xfff, VlanTagVlanId)?;
        {
            let mut buffer: [u8;2] = self.vlan_identifier.to_be_bytes();
            if self.drop_eligible_indicator {
                buffer[0] |= 0x10;
            }
            buffer[0] |= self.priority_code_point << 5;
            writer.write_all(&buffer)?;
        }
        writer.write_all(&self.ether_type.to_be_bytes())?;
        Ok(())
    }
}

///IEEE 802.1Q double VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeader {
    ///The outer vlan tagging header
    pub outer: SingleVlanHeader,
    ///The inner vlan tagging header
    pub inner: SingleVlanHeader
}

impl SerializedSize for DoubleVlanHeader {
    ///Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 8;
}

impl DoubleVlanHeader {

    ///Read an DoubleVlanHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(slice: &[u8]) -> Result<(DoubleVlanHeader, &[u8]), ReadError> {
        Ok((
            DoubleVlanHeaderSlice::from_slice(slice)?.to_header(),
            &slice[DoubleVlanHeader::SERIALIZED_SIZE .. ]
        ))
    }

    ///Read a double tagging header from the given source
    pub fn read<T: io::Read + io::Seek + Sized >(reader: &mut T) -> Result<DoubleVlanHeader, ReadError> {
        let outer = SingleVlanHeader::read(reader)?;

        use crate::ether_type::{ VLAN_TAGGED_FRAME, PROVIDER_BRIDGING, VLAN_DOUBLE_TAGGED_FRAME };
        //check that outer ethertype is matching
        match outer.ether_type {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                Ok(DoubleVlanHeader{
                    outer,
                    inner: SingleVlanHeader::read(reader)?
                })
            },
            value => {
                use crate::ReadError::*;
                Err(DoubleVlanOuterNonVlanEtherType(value))
            }
        }
    }

    ///Write the double IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        self.outer.write(writer)?;
        self.inner.write(writer)
    }
}

impl Default for DoubleVlanHeader {
    fn default() -> Self {
        DoubleVlanHeader {
            outer: {
                let mut outer: SingleVlanHeader = Default::default();
                outer.ether_type = ether_type::VLAN_TAGGED_FRAME;
                outer
            },
            inner: Default::default()
        }
    }
}

///A slice containing a single vlan header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleVlanHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> SingleVlanHeaderSlice<'a> {
    ///Creates a vlan header slice from a slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<SingleVlanHeaderSlice<'a>, ReadError>{
        //check length
        use crate::ReadError::*;
        if slice.len() < SingleVlanHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(SingleVlanHeader::SERIALIZED_SIZE));
        }

        //all done
        Ok(SingleVlanHeaderSlice::<'a> {
            // SAFETY:
            // Safe as the slice length is checked beforehand to have
            // at least the length of SingleVlanHeader::SERIALIZED_SIZE (4)
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    SingleVlanHeader::SERIALIZED_SIZE
                )
            }
        })
    }

    ///Returns the slice containing the single vlan header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the "priority_code_point" field from the slice. This is a 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    #[inline]
    pub fn priority_code_point(&self) -> u8 {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe {
            *self.slice.get_unchecked(0) >> 5
        }
    }

    ///Read the "drop_eligible_indicator" flag from the slice. Indicates that the frame may be dropped under the presence of congestion.
    #[inline]
    pub fn drop_eligible_indicator(&self) -> bool {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe {
            0 != (*self.slice.get_unchecked(0) & 0x10)
        }
    }

    ///Reads the 12 bits "vland identifier" field from the slice.
    #[inline]
    pub fn vlan_identifier(&self) -> u16 {
        u16::from_be_bytes(
            // SAFETY:
            // Slice len checked in constructor to be at least 4.
            unsafe {
                [
                    *self.slice.get_unchecked(0) & 0xf,
                    *self.slice.get_unchecked(1)
                ]
            }
        )
    }

    ///Read the "Tag protocol identifier" field from the slice. Refer to the "EtherType" for a list of possible supported values.
    #[inline]
    pub fn ether_type(&self) -> u16 {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe {
            get_unchecked_be_u16(self.slice.as_ptr().add(2))
        }
    }

    ///Decode all the fields and copy the results to a SingleVlanHeader struct
    pub fn to_header(&self) -> SingleVlanHeader {
        SingleVlanHeader {
            priority_code_point: self.priority_code_point(),
            drop_eligible_indicator: self.drop_eligible_indicator(),
            vlan_identifier: self.vlan_identifier(),
            ether_type: self.ether_type(),
        }
    }
}

///A slice containing an double vlan header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoubleVlanHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> DoubleVlanHeaderSlice<'a> {
    ///Creates a double header slice from a slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<DoubleVlanHeaderSlice<'a>, ReadError>{
        //check length
        use crate::ReadError::*;
        if slice.len() < DoubleVlanHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(DoubleVlanHeader::SERIALIZED_SIZE));
        }

        //create slice
        let result = DoubleVlanHeaderSlice {
            // SAFETY:
            // Safe as the slice length is checked is before to have
            // at least the length of DoubleVlanHeader::SERIALIZED_SIZE (8)
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    DoubleVlanHeader::SERIALIZED_SIZE,
                )
            }
        };

        use crate::EtherType::*;
        const VLAN_TAGGED_FRAME: u16 = VlanTaggedFrame as u16;
        const PROVIDER_BRIDGING: u16 = ProviderBridging as u16;
        const VLAN_DOUBLE_TAGGED_FRAME: u16 = VlanDoubleTaggedFrame as u16;

        //check that outer ethertype is matching
        match result.outer().ether_type() {
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                //all done
                Ok(result)
            },
            value => {
                Err(DoubleVlanOuterNonVlanEtherType(value))
            }
        }
    }

    ///Returns the slice containing the double vlan header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Returns a slice with the outer vlan header
    #[inline]
    pub fn outer(&self) -> SingleVlanHeaderSlice<'a> {
        SingleVlanHeaderSlice::<'a> {
            // SAFETY:
            // Safe as the constructor checks that the slice has the length
            // of DoubleVlanHeader::SERIALIZED_SIZE (8) and the
            // SingleVlanHeader::SERIALIZED_SIZE has a size of 4.
            slice: unsafe {
                from_raw_parts(
                    self.slice.as_ptr(),
                    SingleVlanHeader::SERIALIZED_SIZE
                )
            }
        }
    }

    ///Returns a slice with the inner vlan header.
    #[inline]
    pub fn inner(&self) -> SingleVlanHeaderSlice<'a> {
        SingleVlanHeaderSlice::<'a> {
            // SAFETY:
            // Safe as the constructor checks that the slice has the length
            // of DoubleVlanHeader::SERIALIZED_SIZE (8) and the
            // SingleVlanHeader::SERIALIZED_SIZE has a size of 4.
            slice: unsafe {
                from_raw_parts(
                    self.slice.as_ptr().add(SingleVlanHeader::SERIALIZED_SIZE),
                    SingleVlanHeader::SERIALIZED_SIZE
                )
            }
        }
    }

    ///Decode all the fields and copy the results to a DoubleVlanHeader struct
    pub fn to_header(&self) -> DoubleVlanHeader {
        DoubleVlanHeader {
            outer: self.outer().to_header(),
            inner: self.inner().to_header()
        }
    }
}