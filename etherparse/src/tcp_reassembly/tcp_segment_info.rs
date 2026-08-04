use crate::{tcp_reassembly::*, *};
use arrayvec::ArrayVec;

/// The values of a received TCP segment that are relevant for the reassembly.
///
/// [`TcpSegmentInfo::from_sliced_packet`] extracts them from a parsed packet.
/// Modifying the result before passing it to
/// [`TcpStreamReassemblyPool::process_tcp`] allows customizing what
/// differentiates connections (e.g. clearing [`TcpSegmentInfo::vlan_ids`] and
/// moving them into [`TcpSegmentInfo::channel_id`], see
/// [`TcpConnectionId`]).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TcpSegmentInfo<'a, CustomChannelId = ()> {
    /// Source of the segment (IP address & TCP port).
    pub source: TcpEndpoint,

    /// Destination of the segment (IP address & TCP port).
    pub destination: TcpEndpoint,

    /// VLAN ids of the packet (part of the connection identity, clear to
    /// ignore them).
    pub vlan_ids: ArrayVec<VlanId, 3>,

    /// Custom user defined channel identifier (part of the connection
    /// identity).
    pub channel_id: CustomChannelId,

    /// Sequence number of the segment.
    pub sequence_number: u32,

    /// Acknowledgment number of the segment or `None` if the `ACK` flag was
    /// not set.
    ///
    /// Note that this acknowledges data of the **reverse** direction.
    pub acknowledgment_number: Option<u32>,

    /// Payload of the segment.
    pub payload: &'a [u8],

    /// `SYN` flag of the segment.
    pub syn: bool,

    /// `FIN` flag of the segment.
    pub fin: bool,

    /// `RST` flag of the segment.
    pub rst: bool,
}

impl<'a, CustomChannelId> TcpSegmentInfo<'a, CustomChannelId> {
    /// Extracts the values relevant for the reassembly from a sliced packet.
    ///
    /// Returns `None` if the packet does not contain a TCP segment with an IP
    /// header (e.g. a non TCP packet or an IP fragment, as the TCP layer of a
    /// fragmented packet is not decoded).
    pub fn from_sliced_packet(
        slice: &'a SlicedPacket,
        channel_id: CustomChannelId,
    ) -> Option<TcpSegmentInfo<'a, CustomChannelId>> {
        use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let Some(TransportSlice::Tcp(tcp)) = &slice.transport else {
            return None;
        };

        let (source_ip, destination_ip) = match &slice.net {
            Some(NetSlice::Ipv4(v4)) => (
                IpAddr::V4(Ipv4Addr::from(v4.header().source())),
                IpAddr::V4(Ipv4Addr::from(v4.header().destination())),
            ),
            Some(NetSlice::Ipv6(v6)) => (
                IpAddr::V6(Ipv6Addr::from(v6.header().source())),
                IpAddr::V6(Ipv6Addr::from(v6.header().destination())),
            ),
            Some(NetSlice::Arp(_)) | None => return None,
        };

        Some(TcpSegmentInfo {
            source: TcpEndpoint::new(source_ip, tcp.source_port()),
            destination: TcpEndpoint::new(destination_ip, tcp.destination_port()),
            vlan_ids: slice.vlan_ids(),
            channel_id,
            sequence_number: tcp.sequence_number(),
            acknowledgment_number: if tcp.ack() {
                Some(tcp.acknowledgment_number())
            } else {
                None
            },
            payload: tcp.payload(),
            syn: tcp.syn(),
            fin: tcp.fin(),
            rst: tcp.rst(),
        })
    }

    /// Extracts the values relevant for the reassembly from a laxly sliced
    /// packet.
    ///
    /// Returns `None` if the packet does not contain a TCP segment with an IP
    /// header.
    ///
    /// Note that a [`LaxSlicedPacket`] may have stopped parsing because of an
    /// error (see [`LaxSlicedPacket::stop_err`]) and that its lengths are not
    /// validated, so the payload of a truncated packet is shorter than the
    /// sender intended. Feeding such a segment inserts the truncated data at
    /// its sequence number, which leaves a gap that is only filled if the
    /// data arrives again.
    pub fn from_lax_sliced_packet(
        slice: &'a LaxSlicedPacket,
        channel_id: CustomChannelId,
    ) -> Option<TcpSegmentInfo<'a, CustomChannelId>> {
        use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let Some(TransportSlice::Tcp(tcp)) = &slice.transport else {
            return None;
        };

        let (source_ip, destination_ip) = match &slice.net {
            Some(LaxNetSlice::Ipv4(v4)) => (
                IpAddr::V4(Ipv4Addr::from(v4.header().source())),
                IpAddr::V4(Ipv4Addr::from(v4.header().destination())),
            ),
            Some(LaxNetSlice::Ipv6(v6)) => (
                IpAddr::V6(Ipv6Addr::from(v6.header().source())),
                IpAddr::V6(Ipv6Addr::from(v6.header().destination())),
            ),
            Some(LaxNetSlice::Arp(_)) | None => return None,
        };

        Some(TcpSegmentInfo {
            source: TcpEndpoint::new(source_ip, tcp.source_port()),
            destination: TcpEndpoint::new(destination_ip, tcp.destination_port()),
            vlan_ids: slice.vlan_ids(),
            channel_id,
            sequence_number: tcp.sequence_number(),
            acknowledgment_number: if tcp.ack() {
                Some(tcp.acknowledgment_number())
            } else {
                None
            },
            payload: tcp.payload(),
            syn: tcp.syn(),
            fin: tcp.fin(),
            rst: tcp.rst(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec::Vec};

    fn build_packet(ack: Option<u32>, payload: &[u8]) -> Vec<u8> {
        let mut tcp = TcpHeader::new(1234, 80, 1000, 4096);
        tcp.syn = true;
        tcp.fin = true;
        tcp.rst = true;
        if let Some(ack) = ack {
            tcp.ack = true;
            tcp.acknowledgment_number = ack;
        }
        let tcp_bytes = tcp.to_bytes();

        let mut ipv4 = Ipv4Header {
            protocol: IpNumber::TCP,
            source: [1, 2, 3, 4],
            destination: [5, 6, 7, 8],
            total_len: (Ipv4Header::MIN_LEN + tcp_bytes.len() + payload.len()) as u16,
            time_to_live: 2,
            ..Default::default()
        };
        ipv4.header_checksum = ipv4.calc_header_checksum();

        let mut buf = Vec::new();
        buf.extend_from_slice(
            &Ethernet2Header {
                source: [0; 6],
                destination: [0; 6],
                ether_type: EtherType::IPV4,
            }
            .to_bytes(),
        );
        buf.extend_from_slice(&ipv4.to_bytes());
        buf.extend_from_slice(&tcp_bytes);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn from_sliced_packet_ipv4() {
        let data = build_packet(Some(555), &[1, 2, 3]);
        let slice = SlicedPacket::from_ethernet(&data).unwrap();
        let info = TcpSegmentInfo::from_sliced_packet(&slice, 7u16).unwrap();

        let _ = format!("{:?}", info);
        assert_eq!(info.source, TcpEndpoint::from_ipv4([1, 2, 3, 4], 1234));
        assert_eq!(info.destination, TcpEndpoint::from_ipv4([5, 6, 7, 8], 80));
        assert!(info.vlan_ids.is_empty());
        assert_eq!(info.channel_id, 7);
        assert_eq!(info.sequence_number, 1000);
        assert_eq!(info.acknowledgment_number, Some(555));
        assert_eq!(info.payload, &[1, 2, 3]);
        assert!(info.syn);
        assert!(info.fin);
        assert!(info.rst);
        assert_eq!(info, info.clone());
    }

    #[test]
    fn from_sliced_packet_without_ack_flag() {
        let data = build_packet(None, &[]);
        let slice = SlicedPacket::from_ethernet(&data).unwrap();
        let info = TcpSegmentInfo::from_sliced_packet(&slice, ()).unwrap();
        assert_eq!(info.acknowledgment_number, None);
    }

    #[test]
    fn from_sliced_packet_non_tcp() {
        // packet without any content
        let empty = SlicedPacket {
            link: None,
            link_exts: Default::default(),
            net: None,
            transport: None,
        };
        assert!(TcpSegmentInfo::from_sliced_packet(&empty, ()).is_none());
    }
}
