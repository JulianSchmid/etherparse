use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{err, ArpHardwareId, EtherType, LenSource};

use super::arp_header::ArpHeader;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HardwareAddr<'a> {
    Mac([u8; 6]),
    Other(&'a [u8]),
}

impl<'a> HardwareAddr<'a> {
    fn new(typ: ArpHardwareId, data: &[u8]) -> Result<HardwareAddr, err::LenError> {
        match typ {
            ArpHardwareId::ETHER => match data.try_into() {
                Ok(addr) => Ok(HardwareAddr::Mac(addr)),
                Err(_) => Err(err::LenError {
                    required_len: 6,
                    len_source: LenSource::Slice,
                    len: data.len(),
                    layer: err::Layer::EtherPayload,
                    layer_start_offset: 8,
                }),
            },
            _ => Ok(HardwareAddr::Other(data)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolAddr<'a> {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Other(&'a [u8]),
}

impl<'a> ProtocolAddr<'a> {
    fn new(typ: EtherType, data: &[u8], start: usize) -> Result<ProtocolAddr, err::LenError> {
        match typ {
            EtherType::IPV4 => {
                if data.len() != 4 {
                    return Err(err::LenError {
                        required_len: 4,
                        len_source: LenSource::Slice,
                        len: data.len(),
                        layer: err::Layer::EtherPayload,
                        layer_start_offset: start,
                    });
                }
                Ok(ProtocolAddr::Ipv4(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            EtherType::IPV6 => {
                if data.len() != 16 {
                    return Err(err::LenError {
                        required_len: 16,
                        len_source: LenSource::Slice,
                        len: data.len(),
                        layer: err::Layer::EtherPayload,
                        layer_start_offset: start,
                    });
                }
                let data: [u8; 16] = data.try_into().unwrap();
                Ok(ProtocolAddr::Ipv6(Ipv6Addr::from(data)))
            }
            _ => Ok(ProtocolAddr::Other(data)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct ArpPayload<'a> {
    pub buffer: &'a [u8],

    pub src_hard_addr: HardwareAddr<'a>,
    pub src_addr: ProtocolAddr<'a>,

    pub des_hard_addr: HardwareAddr<'a>,
    pub des_addr: ProtocolAddr<'a>,
}

impl<'a> ArpPayload<'a> {
    pub fn from_pkg(header: ArpHeader, input: &[u8]) -> Result<ArpPayload, err::LenError> {
        let mut offset = 0;

        let src_hard_addr = HardwareAddr::new(
            header.hw_addr_type,
            &input[offset..(offset + header.hw_addr_size as usize)],
        )?;
        offset += header.hw_addr_size as usize;

        let src_addr = ProtocolAddr::new(
            header.proto_addr_type,
            &input[offset..(offset + header.proto_addr_size as usize)],
            offset,
        )?;
        offset += header.proto_addr_size as usize;

        let des_hard_addr = HardwareAddr::new(
            header.hw_addr_type,
            &input[offset..(offset + header.hw_addr_size as usize)],
        )?;

        offset += header.hw_addr_size as usize;

        let des_proto: &[u8] = &input[offset..(offset + header.proto_addr_size as usize)];
        let des_addr = ProtocolAddr::new(header.proto_addr_type, des_proto, offset)?;

        Ok(ArpPayload {
            buffer: input,
            src_hard_addr,
            src_addr,
            des_hard_addr,
            des_addr,
        })
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn write<T: std::io::Write + Sized>(&self, writer: &mut T) -> Result<(), std::io::Error> {
        match self.src_hard_addr {
            HardwareAddr::Mac(addr) => writer.write_all(&addr)?,
            HardwareAddr::Other(addr) => writer.write_all(addr)?,
        }
        match self.src_addr {
            ProtocolAddr::Ipv4(addr) => writer.write_all(&addr.octets())?,
            ProtocolAddr::Ipv6(addr) => writer.write_all(&addr.octets())?,
            ProtocolAddr::Other(addr) => writer.write_all(addr)?,
        }
        match self.des_hard_addr {
            HardwareAddr::Mac(addr) => writer.write_all(&addr)?,
            HardwareAddr::Other(addr) => writer.write_all(addr)?,
        }
        match self.des_addr {
            ProtocolAddr::Ipv4(addr) => writer.write_all(&addr.octets())?,
            ProtocolAddr::Ipv6(addr) => writer.write_all(&addr.octets())?,
            ProtocolAddr::Other(addr) => writer.write_all(addr)?,
        }
        Ok(())
    }
}
