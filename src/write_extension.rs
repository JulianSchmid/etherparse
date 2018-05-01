use super::*;
use std::io;

///Helper for writing headers.
///Import this for adding write functions to every struct that implements the trait Read.
pub trait WriteEtherExt: io::Write + Sized {
    ///Writes a given Ethernet-II header to the current position.
    fn write_ethernet2_header(&mut self, value: &Ethernet2Header) -> Result<(), io::Error> {
        value.write(self)
    }

    ///Write a IEEE 802.1Q VLAN tagging header
    fn write_vlan_tagging_header(&mut self, value: &SingleVlanHeader) -> Result<(), WriteError> {
        value.write(self)
    }

    ///Writes a given IPv4 header to the current position (this method automatically calculates the header length and checksum).
    fn write_ipv4_header(&mut self, value: &Ipv4Header, options: &[u8]) -> Result<(), WriteError> {
        value.write(self, options)
    }

    ///Writes a given IPv4 header to the current position (this method just writes the specified checksum and header_length and does note compute it).
    fn write_ipv4_header_raw(&mut self, value: &Ipv4Header, options: &[u8]) -> Result<(), WriteError> {
        value.write_raw(self, options)
    }

    ///Writes a given IPv6 header to the current position.
    fn write_ipv6_header(&mut self, value: &Ipv6Header) -> Result<(), WriteError> {
        value.write(self)
    }

    ///Write the udp header without recalculating the checksum or length.
    fn write_udp_header_raw(&mut self, value: &UdpHeader) -> Result<(), WriteError> {
        value.write(self)
    }

    ///Write an udp header (includes the calculation of checksum).
    fn write_udp_header_ipv4_with_checksum(&mut self, source_port: u16, destination_port: u16, ip_header: &Ipv4Header, payload: &[u8]) -> Result<(), WriteError> {
        UdpHeader::with_ipv4_checksum(source_port, destination_port, ip_header, payload)?.write(self)
    }

    ///Write an udp header with checksum 0 (= checksum disabled).
    fn write_udp_header(&mut self, source_port: u16, destination_port: u16, payload_length: usize) -> Result<(), WriteError> {
        UdpHeader::without_ipv4_checksum(source_port, destination_port, payload_length)?.write(self)
    }
}

impl<W: io::Write + Sized> WriteEtherExt for W {}