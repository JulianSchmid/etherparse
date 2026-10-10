use crate::{tcp_reassembly::*, *};
use arrayvec::ArrayVec;
use core::net::SocketAddr;
use std::vec::Vec;

/// Segment written by a [`ConnectionScript`].
#[derive(Clone, Debug)]
pub(crate) struct TestSegment<CustomChannelId = ()> {
    /// Role of the endpoint sending the segment.
    pub sender: TcpRole,
    /// Stream offset of the first payload byte.
    pub offset: u64,
    pub vlan_ids: ArrayVec<VlanId, 3>,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub channel_id: CustomChannelId,
    pub header: TcpHeader,
    pub payload: Vec<u8>,
}

impl<CustomChannelId> TestSegment<CustomChannelId>
where
    CustomChannelId: core::hash::Hash + Eq + Clone,
{
    /// Serializes the segment and passes it to the pool.
    pub fn feed<'p, Timestamp: Clone>(
        &self,
        pool: &'p mut TcpReassemblyPool<Timestamp, CustomChannelId>,
        timestamp: Timestamp,
    ) -> TcpProcessed<'p, Timestamp, CustomChannelId> {
        let mut bytes = Vec::with_capacity(self.header.header_len() + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        pool.process_segment(
            TcpSegment {
                vlan_ids: self.vlan_ids.clone(),
                source: self.source.ip(),
                destination: self.destination.ip(),
                channel_id: self.channel_id.clone(),
                tcp: TcpSlice::from_slice(&bytes).unwrap(),
            },
            timestamp,
        )
    }
}

impl<CustomChannelId> ConnectionScript<CustomChannelId>
where
    CustomChannelId: core::hash::Hash + Eq + Clone,
{
    /// Feeds the segments in `range` to the pool with the default timestamp
    /// and returns the result of the last one.
    pub fn feed<'p, Timestamp: Clone + Default>(
        &self,
        pool: &'p mut TcpReassemblyPool<Timestamp, CustomChannelId>,
        range: impl core::slice::SliceIndex<
            [TestSegment<CustomChannelId>],
            Output = [TestSegment<CustomChannelId>],
        >,
    ) -> TcpProcessed<'p, Timestamp, CustomChannelId> {
        let (last, rest) = self.segments[range].split_last().unwrap();
        for segment in rest {
            segment.feed(pool, Timestamp::default());
        }
        last.feed(pool, Timestamp::default())
    }

    /// Feeds all segments to the pool with the default timestamp and returns
    /// the result of the last one.
    pub fn feed_all<'p, Timestamp: Clone + Default>(
        &self,
        pool: &'p mut TcpReassemblyPool<Timestamp, CustomChannelId>,
    ) -> TcpProcessed<'p, Timestamp, CustomChannelId> {
        self.feed(pool, ..)
    }
}

/// Writes a TCP connection as a script of segments for both directions.
///
/// Every method appends segments to `segments`, sending the next bytes of
/// a stream and ACKing everything the other side sent so far.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionScript<CustomChannelId = ()> {
    pub vlan_ids: ArrayVec<VlanId, 3>,
    pub channel_id: CustomChannelId,
    /// Endpoints indexed by role.
    endpoints: [SocketAddr; 2],
    /// Initial sequence numbers indexed by role.
    isns: [u32; 2],
    /// Stream offset of the next byte to send, indexed by role.
    next_offsets: [u64; 2],
    /// Whether each role sent its SYN.
    syns_sent: [bool; 2],
    /// Window scale option put into the SYN of each role.
    pub window_scales: [Option<u8>; 2],
    pub segments: Vec<TestSegment<CustomChannelId>>,
}

/// Index of a role in arrays indexed by role.
pub(crate) fn role_index(role: TcpRole) -> usize {
    match role {
        TcpRole::Initiator => 0,
        TcpRole::Responder => 1,
    }
}

/// Parses a socket address for tests.
pub(crate) fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

impl ConnectionScript<()> {
    /// Connection from 10.0.0.1:50000 to 10.0.0.2:80 with the given ISNs.
    pub fn with_isns(initiator_isn: u32, responder_isn: u32) -> ConnectionScript<()> {
        ConnectionScript::new(
            addr("10.0.0.1:50000"),
            addr("10.0.0.2:80"),
            initiator_isn,
            responder_isn,
        )
    }

    pub fn new(
        initiator: SocketAddr,
        responder: SocketAddr,
        initiator_isn: u32,
        responder_isn: u32,
    ) -> ConnectionScript<()> {
        ConnectionScript {
            vlan_ids: ArrayVec::new(),
            channel_id: (),
            endpoints: [initiator, responder],
            isns: [initiator_isn, responder_isn],
            next_offsets: [0, 0],
            syns_sent: [false, false],
            window_scales: [None, None],
            segments: Vec::new(),
        }
    }
}

impl<CustomChannelId: Clone> ConnectionScript<CustomChannelId> {
    /// Replaces the channel id (call it before adding segments).
    pub fn with_channel_id<C>(self, channel_id: C) -> ConnectionScript<C> {
        assert!(self.segments.is_empty());
        ConnectionScript {
            vlan_ids: self.vlan_ids,
            channel_id,
            endpoints: self.endpoints,
            isns: self.isns,
            next_offsets: self.next_offsets,
            syns_sent: self.syns_sent,
            window_scales: self.window_scales,
            segments: Vec::new(),
        }
    }

    /// Endpoint of a role.
    pub fn endpoint(&self, role: TcpRole) -> SocketAddr {
        self.endpoints[role_index(role)]
    }

    /// Sequence number of the byte at `offset` in the stream of `role`.
    pub fn seq(&self, role: TcpRole, offset: u64) -> u32 {
        self.isns[role_index(role)]
            .wrapping_add(1)
            .wrapping_add(offset as u32)
    }

    /// Header of a segment sent by `sender` starting at `offset`, ACKing
    /// everything the other side sent so far (once its SYN was sent).
    fn header(&self, sender: TcpRole, offset: u64) -> TcpHeader {
        let mut header = TcpHeader::new(
            self.endpoint(sender).port(),
            self.endpoint(sender.other()).port(),
            self.seq(sender, offset),
            0xffff,
        );
        if self.syns_sent[role_index(sender.other())] {
            header.ack = true;
            header.acknowledgment_number = self.seq(
                sender.other(),
                self.next_offsets[role_index(sender.other())],
            );
        }
        header
    }

    fn push(
        &mut self,
        sender: TcpRole,
        offset: u64,
        header: TcpHeader,
        payload: &[u8],
    ) -> &mut Self {
        let next_offset = &mut self.next_offsets[role_index(sender)];
        *next_offset = (*next_offset).max(offset + payload.len() as u64);
        self.segments.push(TestSegment {
            sender,
            offset,
            vlan_ids: self.vlan_ids.clone(),
            source: self.endpoint(sender),
            destination: self.endpoint(sender.other()),
            channel_id: self.channel_id.clone(),
            header,
            payload: payload.to_vec(),
        });
        self
    }

    /// SYN of `sender` carrying `data` (TCP Fast Open if not empty).
    fn syn_of(&mut self, sender: TcpRole, data: &[u8]) -> &mut Self {
        let mut header = self.header(sender, 0);
        header.syn = true;
        header.sequence_number = self.isns[role_index(sender)];
        self.syns_sent[role_index(sender)] = true;
        if let Some(scale) = self.window_scales[role_index(sender)] {
            header
                .set_options(&[TcpOptionElement::WindowScale(scale), TcpOptionElement::Noop])
                .unwrap();
        }
        self.push(sender, 0, header, data)
    }

    /// SYN of the initiator.
    pub fn syn(&mut self) -> &mut Self {
        self.syn_with_data(&[])
    }

    /// SYN of the initiator carrying data (TCP Fast Open).
    pub fn syn_with_data(&mut self, data: &[u8]) -> &mut Self {
        self.syn_of(TcpRole::Initiator, data)
    }

    /// SYN-ACK of the responder.
    pub fn syn_ack(&mut self) -> &mut Self {
        self.syn_of(TcpRole::Responder, &[])
    }

    /// ACK of `sender` without data.
    pub fn ack(&mut self, sender: TcpRole) -> &mut Self {
        self.send(sender, &[])
    }

    /// SYN, SYN-ACK and the initiator's ACK.
    pub fn handshake(&mut self) -> &mut Self {
        self.syn().syn_ack().ack(TcpRole::Initiator)
    }

    /// Next bytes of the stream of `sender`.
    pub fn send(&mut self, sender: TcpRole, data: &[u8]) -> &mut Self {
        self.send_at(sender, self.next_offsets[role_index(sender)], data)
    }

    /// Bytes of the stream of `sender` starting at `offset`, e.g. to
    /// retransmit bytes.
    pub fn send_at(&mut self, sender: TcpRole, offset: u64, data: &[u8]) -> &mut Self {
        let header = self.header(sender, offset);
        self.push(sender, offset, header, data)
    }
}
