use super::super::*;

extern crate byteorder;
use self::byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;

///IEEE 802.1Q VLAN Tagging Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlanTaggingHeader {
    ///A 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    pub priority_code_point: u8,
    ///Indicate that the frame may be dropped under the presence of congestion.
    pub drop_eligible_indicator: bool,
    ///12 bits vland identifier.
    pub vlan_identifier: u16,
    ///"Tag protocol identifier": Type id of content after this header. Refer to the "EtherType" for a list of possible supported values.
    pub ether_type: u16,
}

impl VlanTaggingHeader {
    ///Read a IEEE 802.1Q VLAN tagging header
    pub fn read<T: io::Read + io::Seek + Sized >(reader: &mut T) -> Result<VlanTaggingHeader, io::Error> {
        let (priority_code_point, drop_eligible_indicator, vlan_identifier) = {
            let mut buffer: [u8;2] = [0;2];
            reader.read_exact(&mut buffer)?;
            let drop_eligible_indicator = 0 != (buffer[0] & 0x10);
            let priority_code_point = buffer[0] >> 5;
            //mask and read the vlan id
            buffer[0] = buffer[0] & 0xf;
            (priority_code_point, drop_eligible_indicator, BigEndian::read_u16(&buffer))
        };

        Ok(VlanTaggingHeader{
            priority_code_point: priority_code_point,
            drop_eligible_indicator: drop_eligible_indicator,
            vlan_identifier: vlan_identifier,
            ether_type: reader.read_u16::<BigEndian>()?
        })
    }

    ///Write a IEEE 802.1Q VLAN tagging header
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use ErrorField::*;
        //check value ranges
        max_check_u8(self.priority_code_point, 0x3, VlanTagPriorityCodePoint)?;
        max_check_u16(self.vlan_identifier, 0xfff, VlanTagVlanId)?;
        {
            let mut buffer: [u8;2] = [0;2];
            BigEndian::write_u16(&mut buffer, self.vlan_identifier);
            if self.drop_eligible_indicator {
                buffer[0] = buffer[0] | 0x10;
            }
            buffer[0] = buffer[0] | (self.priority_code_point << 5);
            writer.write_all(&buffer)?;
        }
        writer.write_u16::<BigEndian>(self.ether_type)?;
        Ok(())
    }
}