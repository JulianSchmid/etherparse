use crate::{Ethernet2Header, VlanHeader, IpHeader, TransportHeader};

#[derive(Clone, Debug)]
pub(crate) struct TestPacket {
    pub link: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
}

impl TestPacket {

    pub fn len(&self, payload: &[u8]) -> usize {
        self.link.as_ref().map_or(0, |x| x.header_len()) +
        self.vlan.as_ref().map_or(0, |x| x.header_len()) +
        self.ip.as_ref().map_or(0, |x| x.header_len()) +
        self.transport.as_ref().map_or(0, |x| x.header_len()) +
        payload.len()
    }

    pub fn to_vec(&self, payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.len(payload));
        if let Some(link) = &self.link {
            link.write(&mut result).unwrap();
        }
        if let Some(vlan) = &self.vlan {
            vlan.write(&mut result).unwrap();
        }
        if let Some(ip) = &self.ip {
            match ip {
                IpHeader::Version4(ipv4, exts) => {
                    ipv4.write_raw(&mut result).unwrap();
                    exts.write(&mut result, ipv4.protocol).unwrap();
                },
                IpHeader::Version6(ipv6, exts) => {
                    ipv6.write(&mut result).unwrap();
                    exts.write(&mut result, ipv6.next_header).unwrap();
                },
            }
        }
        if let Some(transport) = &self.transport {
            transport.write(&mut result).unwrap();
        }
        result.extend_from_slice(payload);
        result
    }

    pub fn set_ether_type(&mut self, ether_type: u16) {
        if let Some(vlan) = &mut self.vlan {
            use VlanHeader::*;
            match vlan {
                Single(single) => {
                    single.ether_type = ether_type;
                },
                Double(double) => {
                    double.inner.ether_type = ether_type;
                },
            }
        } else if let Some(link) = &mut self.link {
            link.ether_type = ether_type;
        }
    }

    pub fn is_ip_payload_fragmented(&self) -> bool {
        self.ip.as_ref().map_or(false, |ip| ip.is_fragmenting_payload())
    }
}