use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

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
        let (priority_code_point, drop_eligible_indicator, vlan_identifier) = {
            let mut buffer: [u8;2] = [0;2];
            reader.read_exact(&mut buffer)?;
            let drop_eligible_indicator = 0 != (buffer[0] & 0x10);
            let priority_code_point = buffer[0] >> 5;
            //mask and read the vlan id
            buffer[0] &= 0xf;
            (priority_code_point, drop_eligible_indicator, BigEndian::read_u16(&buffer))
        };

        Ok(SingleVlanHeader{
            priority_code_point,
            drop_eligible_indicator,
            vlan_identifier,
            ether_type: reader.read_u16::<BigEndian>()?
        })
    }

    ///Write the IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::ErrorField::*;
        //check value ranges
        max_check_u8(self.priority_code_point, 0x7, VlanTagPriorityCodePoint)?;
        max_check_u16(self.vlan_identifier, 0xfff, VlanTagVlanId)?;
        {
            let mut buffer: [u8;2] = [0;2];
            BigEndian::write_u16(&mut buffer, self.vlan_identifier);
            if self.drop_eligible_indicator {
                buffer[0] |= 0x10;
            }
            buffer[0] |= self.priority_code_point << 5;
            writer.write_all(&buffer)?;
        }
        writer.write_u16::<BigEndian>(self.ether_type)?;
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
            slice: &slice[..SingleVlanHeader::SERIALIZED_SIZE]
        })
    }

    ///Returns the slice containing the single vlan header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    ///Read the "priority_code_point" field from the slice. This is a 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub fn priority_code_point(&self) -> u8 {
        self.slice[0] >> 5
    }

    ///Read the "drop_eligible_indicator" flag from the slice. Indicates that the frame may be dropped under the presence of congestion.
    pub fn drop_eligible_indicator(&self) -> bool {
        0 != (self.slice[0] & 0x10)
    }

    ///Reads the 12 bits "vland identifier" field from the slice.
    pub fn vlan_identifier(&self) -> u16 {
        let buffer = [self.slice[0] & 0xf, self.slice[1]];
        BigEndian::read_u16(&buffer)
    }

    ///Read the "Tag protocol identifier" field from the slice. Refer to the "EtherType" for a list of possible supported values.
    pub fn ether_type(&self) -> u16 {
        BigEndian::read_u16(&self.slice[2..4])
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
            slice: &slice[..DoubleVlanHeader::SERIALIZED_SIZE]
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
    pub fn outer(&self) -> SingleVlanHeaderSlice<'a> {
        SingleVlanHeaderSlice::<'a> {
            slice: &self.slice[..SingleVlanHeader::SERIALIZED_SIZE]
        }
    }

    ///Returns a slice with the inner vlan header.
    pub fn inner(&self) -> SingleVlanHeaderSlice<'a> {
        SingleVlanHeaderSlice::<'a> {
            slice: &self.slice[SingleVlanHeader::SERIALIZED_SIZE..SingleVlanHeader::SERIALIZED_SIZE*2]
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