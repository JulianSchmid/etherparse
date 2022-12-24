pub mod icmp;
pub mod icmpv4_impl;
pub mod icmpv6_impl;
pub mod tcp;
pub mod udp_header;
pub mod udp_header_slice;

use super::*;

use std::io;

///The possible headers on the transport layer
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportHeader {
    Udp(udp_header::UdpHeader),
    Tcp(tcp::TcpHeader),
    Icmpv4(Icmpv4Header),
    Icmpv6(Icmpv6Header),
}

impl TransportHeader {
    /// Returns Result::Some containing the udp header if self has the value Udp.
    /// Otherwise None is returned.
    pub fn udp(self) -> Option<udp_header::UdpHeader> {
        use crate::TransportHeader::*;
        if let Udp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing the udp header if self has the value Udp.
    /// Otherwise None is returned.
    pub fn mut_udp(&mut self) -> Option<&mut udp_header::UdpHeader> {
        use crate::TransportHeader::*;
        if let Udp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing the tcp header if self has the value Tcp.
    /// Otherwise None is returned.
    pub fn tcp(self) -> Option<tcp::TcpHeader> {
        use crate::TransportHeader::*;
        if let Tcp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing a mutable refernce to the tcp header if self has the value Tcp.
    /// Otherwise None is returned.
    pub fn mut_tcp(&mut self) -> Option<&mut tcp::TcpHeader> {
        use crate::TransportHeader::*;
        if let Tcp(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing the ICMPv4 header if self has the value Icmpv4.
    /// Otherwise None is returned.
    pub fn icmpv4(self) -> Option<Icmpv4Header> {
        use crate::TransportHeader::*;
        if let Icmpv4(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing the ICMPv4 header if self has the value Icmpv4.
    /// Otherwise None is returned.
    pub fn mut_icmpv4(&mut self) -> Option<&mut Icmpv4Header> {
        use crate::TransportHeader::*;
        if let Icmpv4(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing the ICMPv6 header if self has the value Icmpv6.
    /// Otherwise None is returned.
    pub fn icmpv6(self) -> Option<Icmpv6Header> {
        use crate::TransportHeader::*;
        if let Icmpv6(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns Result::Some containing the ICMPv6 header if self has the value Icmpv6.
    /// Otherwise None is returned.
    pub fn mut_icmpv6(&mut self) -> Option<&mut Icmpv6Header> {
        use crate::TransportHeader::*;
        if let Icmpv6(value) = self {
            Some(value)
        } else {
            None
        }
    }

    /// Returns the size of the transport header (in case of UDP fixed,
    /// in case of TCP cotanining the options).
    pub fn header_len(&self) -> usize {
        use crate::TransportHeader::*;
        match self {
            Udp(_) => udp_header::UdpHeader::SERIALIZED_SIZE,
            Tcp(value) => usize::from(value.header_len()),
            Icmpv4(value) => value.header_len(),
            Icmpv6(value) => value.header_len(),
        }
    }

    /// Calculates the checksum for the transport header & sets it in the header for
    /// an ipv4 header.
    pub fn update_checksum_ipv4(
        &mut self,
        ip_header: &Ipv4Header,
        payload: &[u8],
    ) -> Result<(), ValueError> {
        use crate::TransportHeader::*;
        match self {
            Udp(header) => {
                header.checksum = header.calc_checksum_ipv4(ip_header, payload)?;
            }
            Tcp(header) => {
                header.checksum = header.calc_checksum_ipv4(ip_header, payload)?;
            }
            Icmpv4(header) => {
                header.update_checksum(payload);
            }
            Icmpv6(_) => return Err(ValueError::Icmpv6InIpv4),
        }
        Ok(())
    }

    /// Calculates the checksum for the transport header & sets it in the header for
    /// an ipv6 header.
    pub fn update_checksum_ipv6(
        &mut self,
        ip_header: &Ipv6Header,
        payload: &[u8],
    ) -> Result<(), ValueError> {
        use crate::TransportHeader::*;
        match self {
            Icmpv4(header) => header.update_checksum(payload),
            Icmpv6(header) => {
                header.update_checksum(ip_header.source, ip_header.destination, payload)?
            }
            Udp(header) => {
                header.checksum = header.calc_checksum_ipv6(ip_header, payload)?;
            }
            Tcp(header) => {
                header.checksum = header.calc_checksum_ipv6(ip_header, payload)?;
            }
        }
        Ok(())
    }

    /// Write the transport header to the given writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::TransportHeader::*;
        match self {
            Icmpv4(value) => value.write(writer),
            Icmpv6(value) => value.write(writer),
            Udp(value) => value.write(writer).map_err(WriteError::IoError),
            Tcp(value) => value.write(writer).map_err(WriteError::IoError),
        }
    }
}
