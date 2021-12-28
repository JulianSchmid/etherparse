pub mod icmp4;
pub mod icmp6;
pub mod udp;
pub mod tcp;

use super::*;

use std::io;

///The possible headers on the transport layer
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportHeader {
    Icmp4(icmp4::IcmpV4Header),
    Icmp6(icmp6::IcmpV6Header),
    Udp(udp::UdpHeader),
    Tcp(tcp::TcpHeader)

}

impl TransportHeader {

    pub fn icmp4(self) -> Option<icmp4::IcmpV4Header> {
        use crate::TransportHeader::*;
        if let Icmp4(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn icmp6(self) -> Option<icmp6::IcmpV6Header> {
        use crate::TransportHeader::*;
        if let Icmp6(value) = self {
            Some(value)
        } else {
            None
        }
    }

    ///Returns Result::Some containing the udp header if self has the value Udp. 
    ///Otherwise None is returned.
    pub fn udp(self) -> Option<udp::UdpHeader> {
        use crate::TransportHeader::*;
        if let Udp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    ///Returns Result::Some containing the udp header if self has the value Udp. 
    ///Otherwise None is returned.
    pub fn mut_udp(&mut self) -> Option<&mut udp::UdpHeader> {
        use crate::TransportHeader::*;
        if let Udp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    ///Returns Result::Some containing the tcp header if self has the value Tcp. 
    ///Otherwise None is returned.
    pub fn tcp(self) -> Option<tcp::TcpHeader> {
        use crate::TransportHeader::*;
        if let Tcp(value)  = self {
            Some(value)
        } else {
            None
        }
    }

    ///Returns Result::Some containing a mutable refernce to the tcp header if self has the value Tcp. 
    ///Otherwise None is returned.
    pub fn mut_tcp(&mut self) -> Option<&mut tcp::TcpHeader> {
        use crate::TransportHeader::*;
        if let Tcp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    ///Returns the size of the transport header (in case of UDP fixed, 
    ///in case of TCP cotanining the options).dd
    pub fn header_len(&self) -> usize {
        use crate::TransportHeader::*;
        match self {
            Icmp4(value) => value.header_len(),
            Icmp6(value) => value.header_len(),
            Udp(_) => udp::UdpHeader::SERIALIZED_SIZE,
            Tcp(value) => usize::from(value.header_len())
        }
    }

    ///Calculates the checksum for the transport header & sets it in the header for
    ///an ipv4 header.
    pub fn update_checksum_ipv4(&mut self, ip_header: &Ipv4Header, payload: &[u8]) -> Result<(), ValueError> {
        use crate::TransportHeader::*;
        match self {
            Icmp4(header) => {
                header.icmp_chksum = header.calc_checksum_ipv4(ip_header, payload)?;
            },
            Icmp6(_) => Err(ValueError::Icmp6InIpv4)?,
            Udp(header) => {
                header.checksum = header.calc_checksum_ipv4(ip_header, payload)?;
            },
            Tcp(header) => {
                header.checksum = header.calc_checksum_ipv4(ip_header, payload)?;
            }
        }
        Ok(())
    }

    ///Calculates the checksum for the transport header & sets it in the header for
    ///an ipv6 header.
    pub fn update_checksum_ipv6(&mut self, ip_header: &Ipv6Header, payload: &[u8]) -> Result<(), ValueError> {
        use crate::TransportHeader::*;
        match self {
            Icmp4(_) => Err(ValueError::Icmp4InIpv6)?,
            Icmp6(header) => {
                header.icmp_chksum = header.calc_checksum_ipv6(ip_header, payload)?;
            },
            Udp(header) => {
                header.checksum = header.calc_checksum_ipv6(ip_header, payload)?;
            },
            Tcp(header) => {
                header.checksum = header.calc_checksum_ipv6(ip_header, payload)?;
            }
        }
        Ok(())
    }

    ///Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::TransportHeader::*;
        match self {
            Icmp4(value) => value.write(writer),
            Icmp6(value) => value.write(writer),
            Udp(value) => value.write(writer),
            Tcp(value) => value.write(writer).map_err(WriteError::from)
        }
    }
}
