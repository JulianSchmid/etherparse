use crate::*;
use arrayvec::ArrayVec;
use core::net::IpAddr;

/// TCP segment together with the values that identify its connection.
///
/// Use it to pass a segment to
/// [`crate::tcp_reassembly::TcpReassemblyPool::process_segment`], e.g. after
/// [`crate::defrag::IpDefragPool`] put an IP-fragmented segment back
/// together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a, CustomChannelId = ()> {
    /// VLAN IDs of the packet.
    pub vlan_ids: ArrayVec<VlanId, 3>,

    /// Source IP address.
    pub source: IpAddr,

    /// Destination IP address.
    pub destination: IpAddr,

    /// User-defined channel id (e.g. the capture interface or a tunnel),
    /// part of the connection key.
    pub channel_id: CustomChannelId,

    /// TCP header and payload.
    pub tcp: TcpSlice<'a>,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::format;

    #[test]
    fn derived_traits() {
        let bytes = TcpHeader::new(1, 2, 3, 4).to_bytes();
        let segment = TcpSegment {
            vlan_ids: ArrayVec::new(),
            source: IpAddr::from([1, 2, 3, 4]),
            destination: IpAddr::from([5, 6, 7, 8]),
            channel_id: 9u8,
            tcp: TcpSlice::from_slice(&bytes).unwrap(),
        };

        // clone & eq
        assert_eq!(segment.clone(), segment);

        // debug
        assert_eq!(
            format!(
                "TcpSegment {{ vlan_ids: [], source: 1.2.3.4, destination: 5.6.7.8, channel_id: 9, tcp: {:?} }}",
                segment.tcp
            ),
            format!("{:?}", segment)
        );
    }
}
