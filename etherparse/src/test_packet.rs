use crate::*;
use alloc::vec::Vec;

#[derive(Clone)]
pub(crate) struct TestPacket {
    pub link: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub net: Option<NetHeaders>,
    pub transport: Option<TransportHeader>,
}

impl TestPacket {
    pub fn len(&self, payload: &[u8]) -> usize {
        self.link.as_ref().map_or(0, |x| x.header_len())
            + self.vlan.as_ref().map_or(0, |x| x.header_len())
            + self.net.as_ref().map_or(0, |x| x.header_len())
            + self.transport.as_ref().map_or(0, |x| x.header_len())
            + payload.len()
    }

    pub fn to_vec(&self, payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.len(payload));
        if let Some(link) = &self.link {
            link.write(&mut result).unwrap();
        }
        if let Some(vlan) = &self.vlan {
            vlan.write(&mut result).unwrap();
        }
        if let Some(ip) = &self.net {
            match ip {
                NetHeaders::Ipv4(ipv4, exts) => {
                    ipv4.write_raw(&mut result).unwrap();
                    exts.write(&mut result, ipv4.protocol).unwrap();
                }
                NetHeaders::Ipv6(ipv6, exts) => {
                    ipv6.write(&mut result).unwrap();
                    exts.write(&mut result, ipv6.next_header).unwrap();
                }
            }
        }
        if let Some(transport) = &self.transport {
            transport.write(&mut result).unwrap();
        }
        result.extend_from_slice(payload);
        result
    }

    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        if let Some(vlan) = &mut self.vlan {
            use VlanHeader::*;
            match vlan {
                Single(single) => {
                    single.ether_type = ether_type;
                }
                Double(double) => {
                    double.inner.ether_type = ether_type;
                }
            }
        } else if let Some(link) = &mut self.link {
            link.ether_type = ether_type;
        }
    }

    pub fn set_payload_len(&mut self, payload_len: usize) {
        use NetHeaders::*;
        match &mut self.net {
            None => {}
            Some(Ipv4(ref mut header, ref mut exts)) => {
                header
                    .set_payload_len(
                        exts.header_len()
                            + self.transport.as_ref().map_or(0, |t| t.header_len())
                            + payload_len,
                    )
                    .unwrap();
            }
            Some(Ipv6(ref mut header, ref mut exts)) => {
                header
                    .set_payload_length(
                        exts.header_len()
                            + self.transport.as_ref().map_or(0, |t| t.header_len())
                            + payload_len,
                    )
                    .unwrap();
            }
        }

        use TransportHeader::*;
        match &mut self.transport {
            None => {}
            Some(Udp(ref mut udp)) => {
                udp.length = udp.header_len_u16() + payload_len as u16;
            }
            Some(Tcp(_)) => {}
            Some(Icmpv4(_)) => {}
            Some(Icmpv6(_)) => {}
        }
    }

    /// Set the length relative to the end of the ip headers.
    pub fn set_payload_le_from_ip_on(&mut self, payload_len_from_ip_on: isize) {
        use NetHeaders::*;
        match self.net.as_mut().unwrap() {
            Ipv4(ref mut header, ref mut exts) => {
                header
                    .set_payload_len((exts.header_len() as isize + payload_len_from_ip_on) as usize)
                    .unwrap();
            }
            Ipv6(ref mut header, ref mut exts) => {
                header
                    .set_payload_length(
                        (exts.header_len() as isize + payload_len_from_ip_on) as usize,
                    )
                    .unwrap();
            }
        }
    }

    pub fn is_ip_payload_fragmented(&self) -> bool {
        self.net.as_ref().map_or(false, |net| match net {
            NetHeaders::Ipv4(h, _) => h.is_fragmenting_payload(),
            NetHeaders::Ipv6(_, e) => e.is_fragmenting_payload(),
        })
    }
}
