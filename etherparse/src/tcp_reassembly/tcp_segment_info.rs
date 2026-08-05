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
    /// Assembles the info from an already parsed TCP segment and the
    /// addressing information of the packet that carried it.
    ///
    /// The ports, sequence & acknowledgment numbers, flags and the payload
    /// are taken from `tcp`, so only the IP addresses (and optionally the
    /// VLAN ids & channel id, see [`TcpConnectionId`]) have to be supplied.
    ///
    /// Useful whenever the TCP segment does not arrive as one parsable packet
    /// that [`TcpSegmentInfo::from_sliced_packet`] could be used on, e.g.
    /// after re-assembling a fragmented IP packet (see
    /// [`TcpSegmentInfo::from_defragmented_payload`] for a shortcut of that
    /// case) or when the packet was parsed by something else than a
    /// [`SlicedPacket`].
    ///
    /// ```
    /// # use etherparse::{tcp_reassembly::*, *};
    /// # use core::net::IpAddr;
    /// # let tcp_bytes = TcpHeader::new(1234, 80, 1000, 4096).to_bytes();
    /// # let source_ip: IpAddr = "1.2.3.4".parse().unwrap();
    /// # let destination_ip: IpAddr = "5.6.7.8".parse().unwrap();
    /// let tcp = TcpSlice::from_slice(&tcp_bytes).unwrap();
    /// let info = TcpSegmentInfo::from_tcp_slice(
    ///     &tcp,
    ///     source_ip,
    ///     destination_ip,
    ///     Default::default(), // vlan ids
    ///     (),                 // channel id
    /// );
    /// assert_eq!(info.source, TcpEndpoint::new(source_ip, 1234));
    /// assert_eq!(info.sequence_number, 1000);
    /// ```
    pub fn from_tcp_slice(
        tcp: &TcpSlice<'a>,
        source_ip: core::net::IpAddr,
        destination_ip: core::net::IpAddr,
        vlan_ids: ArrayVec<VlanId, 3>,
        channel_id: CustomChannelId,
    ) -> TcpSegmentInfo<'a, CustomChannelId> {
        TcpSegmentInfo {
            source: TcpEndpoint::new(source_ip, tcp.source_port()),
            destination: TcpEndpoint::new(destination_ip, tcp.destination_port()),
            vlan_ids,
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
        }
    }

    /// Extracts the values relevant for the reassembly from a sliced packet.
    ///
    /// Returns `None` if the packet does not contain a TCP segment with an IP
    /// header (e.g. a non TCP packet or an IP fragment, as the TCP layer of a
    /// fragmented packet is not decoded, see
    /// [`TcpSegmentInfo::from_defragmented_payload`] for that case).
    pub fn from_sliced_packet(
        slice: &'a SlicedPacket,
        channel_id: CustomChannelId,
    ) -> Option<TcpSegmentInfo<'a, CustomChannelId>> {
        let Some(TransportSlice::Tcp(tcp)) = &slice.transport else {
            return None;
        };
        let (source_ip, destination_ip) = net_slice_ip_addrs(&slice.net)?;
        Some(Self::from_tcp_slice(
            tcp,
            source_ip,
            destination_ip,
            slice.vlan_ids(),
            channel_id,
        ))
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
        let Some(TransportSlice::Tcp(tcp)) = &slice.transport else {
            return None;
        };
        let (source_ip, destination_ip) = lax_net_slice_ip_addrs(&slice.net)?;
        Some(Self::from_tcp_slice(
            tcp,
            source_ip,
            destination_ip,
            slice.vlan_ids(),
            channel_id,
        ))
    }

    /// Assembles the info of a TCP segment that had to be re-assembled from
    /// IP fragments (e.g. via [`crate::defrag::IpDefragPool`]).
    ///
    /// `tcp_segment` is the re-assembled IP payload (the TCP header followed
    /// by its payload), while the IP addresses & VLAN ids are taken from
    /// `packet`. Any of the fragments can be passed as `packet` as they all
    /// carry the same addresses (its transport layer is not used, as the TCP
    /// layer of a fragmented packet is not decoded).
    ///
    /// Returns:
    /// * `Ok(Some(..))` with the assembled info.
    /// * `Ok(None)` if `packet` does not contain an IP header.
    /// * `Err` if `tcp_segment` could not be parsed as a TCP header.
    ///
    /// Note that it is up to the caller to check that the re-assembled
    /// payload actually is a TCP segment (compare
    /// [`crate::defrag::IpDefragPayloadVec::ip_number`] against
    /// [`IpNumber::TCP`]).
    ///
    /// ```no_run
    /// # use etherparse::{defrag::*, tcp_reassembly::*, *};
    /// # let mut defrag_pool = IpDefragPool::<(), ()>::new();
    /// # let mut tcp_pool = TcpStreamReassemblyPool::<(), ()>::new();
    /// # let slice: SlicedPacket = unimplemented!();
    /// if let Ok(Some(finished)) = defrag_pool.process_sliced_packet(&slice, (), ()) {
    ///     if finished.ip_number == IpNumber::TCP {
    ///         if let Ok(Some(info)) =
    ///             TcpSegmentInfo::from_defragmented_payload(&slice, &finished.payload, ())
    ///         {
    ///             tcp_pool.process_tcp(info, ()).unwrap();
    ///         }
    ///     }
    ///     defrag_pool.return_buf(finished);
    /// }
    /// ```
    pub fn from_defragmented_payload(
        packet: &SlicedPacket,
        tcp_segment: &'a [u8],
        channel_id: CustomChannelId,
    ) -> Result<Option<TcpSegmentInfo<'a, CustomChannelId>>, err::tcp::HeaderSliceError> {
        let Some((source_ip, destination_ip)) = net_slice_ip_addrs(&packet.net) else {
            return Ok(None);
        };
        let tcp = TcpSlice::from_slice(tcp_segment)?;
        Ok(Some(Self::from_tcp_slice(
            &tcp,
            source_ip,
            destination_ip,
            packet.vlan_ids(),
            channel_id,
        )))
    }
}

/// Source & destination IP addresses of a sliced packet (`None` if it does
/// not contain an IP header).
fn net_slice_ip_addrs(net: &Option<NetSlice>) -> Option<(core::net::IpAddr, core::net::IpAddr)> {
    match net {
        Some(NetSlice::Ipv4(v4)) => Some((
            v4.header().source_addr().into(),
            v4.header().destination_addr().into(),
        )),
        Some(NetSlice::Ipv6(v6)) => Some((
            v6.header().source_addr().into(),
            v6.header().destination_addr().into(),
        )),
        Some(NetSlice::Arp(_)) | None => None,
    }
}

/// Source & destination IP addresses of a laxly sliced packet (`None` if it
/// does not contain an IP header).
fn lax_net_slice_ip_addrs(
    net: &Option<LaxNetSlice>,
) -> Option<(core::net::IpAddr, core::net::IpAddr)> {
    match net {
        Some(LaxNetSlice::Ipv4(v4)) => Some((
            v4.header().source_addr().into(),
            v4.header().destination_addr().into(),
        )),
        Some(LaxNetSlice::Ipv6(v6)) => Some((
            v6.header().source_addr().into(),
            v6.header().destination_addr().into(),
        )),
        Some(LaxNetSlice::Arp(_)) | None => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec::Vec};
    use core::net::{IpAddr, Ipv4Addr};

    /// TCP segment bytes (header + payload) as they appear in an IP payload.
    fn build_tcp_segment(ack: Option<u32>, payload: &[u8]) -> Vec<u8> {
        let mut tcp = TcpHeader::new(1234, 80, 1000, 4096);
        tcp.syn = true;
        tcp.fin = true;
        tcp.rst = true;
        if let Some(ack) = ack {
            tcp.ack = true;
            tcp.acknowledgment_number = ack;
        }
        let mut result = tcp.to_bytes().to_vec();
        result.extend_from_slice(payload);
        result
    }

    /// Ethernet + IPv6 + TCP packet.
    fn build_ipv6_packet(payload: &[u8]) -> Vec<u8> {
        let tcp_bytes = build_tcp_segment(Some(555), payload);
        let ipv6 = Ipv6Header {
            payload_length: tcp_bytes.len() as u16,
            next_header: IpNumber::TCP,
            hop_limit: 4,
            source: [1; 16],
            destination: [2; 16],
            ..Default::default()
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(
            &Ethernet2Header {
                source: [0; 6],
                destination: [0; 6],
                ether_type: EtherType::IPV6,
            }
            .to_bytes(),
        );
        buf.extend_from_slice(&ipv6.to_bytes());
        buf.extend_from_slice(&tcp_bytes);
        buf
    }

    /// Ethernet + IPv4 packet that is a fragment (so the TCP layer is not
    /// decoded), as it is fed to a `defrag::IpDefragPool`.
    fn build_ipv4_fragment(fragment_payload: &[u8]) -> Vec<u8> {
        let mut ipv4 = Ipv4Header {
            protocol: IpNumber::TCP,
            source: [1, 2, 3, 4],
            destination: [5, 6, 7, 8],
            identification: 4711,
            more_fragments: true,
            total_len: (Ipv4Header::MIN_LEN + fragment_payload.len()) as u16,
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
        buf.extend_from_slice(fragment_payload);
        buf
    }

    #[test]
    fn from_tcp_slice_assembles_the_parts() {
        let segment = build_tcp_segment(Some(555), &[1, 2, 3]);
        let tcp = TcpSlice::from_slice(&segment).unwrap();

        let source_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let destination_ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let mut vlan_ids = ArrayVec::<VlanId, 3>::new_const();
        vlan_ids.push(VlanId::try_new(12).unwrap());

        let info =
            TcpSegmentInfo::from_tcp_slice(&tcp, source_ip, destination_ip, vlan_ids.clone(), 7u16);

        // the ports are taken from the tcp slice & combined with the ips
        assert_eq!(info.source, TcpEndpoint::new(source_ip, 1234));
        assert_eq!(info.destination, TcpEndpoint::new(destination_ip, 80));
        assert_eq!(info.vlan_ids, vlan_ids);
        assert_eq!(info.channel_id, 7);
        assert_eq!(info.sequence_number, 1000);
        assert_eq!(info.acknowledgment_number, Some(555));
        assert_eq!(info.payload, &[1, 2, 3]);
        assert!(info.syn);
        assert!(info.fin);
        assert!(info.rst);

        // without the ACK flag no acknowledgment number is reported
        let segment = build_tcp_segment(None, &[]);
        let tcp = TcpSlice::from_slice(&segment).unwrap();
        let info =
            TcpSegmentInfo::from_tcp_slice(&tcp, source_ip, destination_ip, Default::default(), ());
        assert_eq!(info.acknowledgment_number, None);
        assert!(info.payload.is_empty());
    }

    #[test]
    fn from_defragmented_payload_ok() {
        // the re-assembled TCP segment & any fragment of the packet
        let segment = build_tcp_segment(Some(555), &[1, 2, 3]);
        let fragment = build_ipv4_fragment(&segment[..8]);
        let slice = SlicedPacket::from_ethernet(&fragment).unwrap();
        // the fragment itself carries no decoded transport layer
        assert!(slice.transport.is_none());

        let info = TcpSegmentInfo::from_defragmented_payload(&slice, &segment, 7u16)
            .unwrap()
            .unwrap();

        // addresses from the fragment, everything else from the segment
        assert_eq!(info.source, TcpEndpoint::from_ipv4([1, 2, 3, 4], 1234));
        assert_eq!(info.destination, TcpEndpoint::from_ipv4([5, 6, 7, 8], 80));
        assert_eq!(info.channel_id, 7);
        assert_eq!(info.sequence_number, 1000);
        assert_eq!(info.acknowledgment_number, Some(555));
        assert_eq!(info.payload, &[1, 2, 3]);
        assert!(info.syn);
        assert!(info.fin);
        assert!(info.rst);
    }

    #[test]
    fn from_defragmented_payload_without_ip_header() {
        let segment = build_tcp_segment(None, &[]);
        let empty = SlicedPacket {
            link: None,
            link_exts: Default::default(),
            net: None,
            transport: None,
        };
        assert_eq!(
            TcpSegmentInfo::from_defragmented_payload(&empty, &segment, ()),
            Ok(None)
        );
    }

    #[test]
    fn from_defragmented_payload_malformed_segment() {
        let fragment = build_ipv4_fragment(&[1, 2, 3, 4]);
        let slice = SlicedPacket::from_ethernet(&fragment).unwrap();

        // too short to contain a TCP header
        let err = TcpSegmentInfo::from_defragmented_payload(&slice, &[1, 2, 3], ()).unwrap_err();
        assert!(matches!(err, err::tcp::HeaderSliceError::Len(_)));
    }

    #[test]
    fn from_sliced_packet_ipv6() {
        let data = build_ipv6_packet(&[1, 2, 3]);
        let slice = SlicedPacket::from_ethernet(&data).unwrap();
        let info = TcpSegmentInfo::from_sliced_packet(&slice, ()).unwrap();
        assert_eq!(info.source, TcpEndpoint::from_ipv6([1; 16], 1234));
        assert_eq!(info.destination, TcpEndpoint::from_ipv6([2; 16], 80));
        assert_eq!(info.payload, &[1, 2, 3]);
    }

    #[test]
    fn from_lax_sliced_packet_ipv4_and_ipv6() {
        // ipv4
        let data = build_packet(Some(555), &[1, 2, 3]);
        let slice = LaxSlicedPacket::from_ethernet(&data).unwrap();
        let info = TcpSegmentInfo::from_lax_sliced_packet(&slice, 7u16).unwrap();
        assert_eq!(info.source, TcpEndpoint::from_ipv4([1, 2, 3, 4], 1234));
        assert_eq!(info.destination, TcpEndpoint::from_ipv4([5, 6, 7, 8], 80));
        assert_eq!(info.channel_id, 7);
        assert_eq!(info.acknowledgment_number, Some(555));
        assert_eq!(info.payload, &[1, 2, 3]);

        // ipv6
        let data = build_ipv6_packet(&[4, 5]);
        let slice = LaxSlicedPacket::from_ethernet(&data).unwrap();
        let info = TcpSegmentInfo::from_lax_sliced_packet(&slice, ()).unwrap();
        assert_eq!(info.source, TcpEndpoint::from_ipv6([1; 16], 1234));
        assert_eq!(info.destination, TcpEndpoint::from_ipv6([2; 16], 80));
        assert_eq!(info.payload, &[4, 5]);

        // packet without any content
        let empty = LaxSlicedPacket {
            link: None,
            link_exts: Default::default(),
            net: None,
            transport: None,
            stop_err: None,
        };
        assert!(TcpSegmentInfo::from_lax_sliced_packet(&empty, ()).is_none());
    }

    #[test]
    fn from_sliced_packet_without_ip_header() {
        // a packet with a TCP layer but no IP header (e.g. only partially
        // parsed) has no addresses to identify the connection with
        let data = build_packet(Some(555), &[]);
        let mut slice = SlicedPacket::from_ethernet(&data).unwrap();
        slice.net = None;
        assert!(TcpSegmentInfo::from_sliced_packet(&slice, ()).is_none());
    }

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
