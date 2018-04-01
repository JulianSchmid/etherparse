use super::*;
use std::io;

///Helper for reading headers.
///Import this for adding read functions to every struct that implements the trait Read.
pub trait ReadEtherExt: io::Read + io::Seek + Sized {
    ///Reads an Ethernet-II header from the current position of the read argument.
    fn read_ethernet2_header(&mut self) -> Result<Ethernet2Header, io::Error> {
        Ethernet2Header::read(self)
    }

    ///Read a IEEE 802.1Q VLAN tagging header
    fn read_vlan_tagging_header(&mut self) -> Result<VlanTaggingHeader, io::Error> {
        VlanTaggingHeader::read(self)
    }

    ///Reads an IP (v4 or v6) header from the current position.
    fn read_ip_header(&mut self) -> Result<IpHeader, ReadError> {
        IpHeader::read(self)
    }

    ///Reads an IPv4 header from the current position.
    fn read_ipv4_header(&mut self) -> Result<Ipv4Header, ReadError> {
        Ipv4Header::read(self)
    }

    ///Reads an IPv4 header assuming the version & ihl field have already been read.
    fn read_ipv4_header_without_version(&mut self, version_rest: u8) -> Result<Ipv4Header, io::Error> {
        Ipv4Header::read_without_version(self, version_rest)
    }

    ///Reads an IPv6 header from the current position.
    fn read_ipv6_header(&mut self) -> Result<Ipv6Header, ReadError> {
        Ipv6Header::read(self)
    }

    ///Reads an IPv6 header assuming the version & flow_label field have already been read.
    fn read_ipv6_header_without_version(&mut self, version_rest: u8) -> Result<Ipv6Header, io::Error> {
        Ipv6Header::read_without_version(self, version_rest)
    }

    ///Skips the ipv6 header extension and returns the traffic_class
    fn skip_ipv6_header_extension(&mut self) -> Result<u8, io::Error> {
        Ipv6Header::skip_header_extension(self)
    }

    ///Skips all ipv6 header extensions and returns the last traffic_class
    fn skip_all_ipv6_header_extensions(&mut self, traffic_class: u8) -> Result<u8, ReadError> {
        Ipv6Header::skip_all_header_extensions(self, traffic_class)
    }

    ///Tries to read an udp header from the current position.
    fn read_udp_header(&mut self) -> Result<UdpHeader, io::Error> {
        UdpHeader::read(self)
    }
}

impl<W: io::Read + io::Seek + Sized> ReadEtherExt for W {}