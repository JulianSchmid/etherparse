use crate::{tcp_reassembly::*, *};
use core::net::SocketAddr;

/// Both streams of a TCP connection, as reassembled by a
/// [`TcpReassemblyPool`].
#[derive(Clone, Debug)]
pub struct TcpConnection<Timestamp = (), CustomChannelId = ()> {
    id: TcpConnectionId,
    key: TcpConnectionKey<CustomChannelId>,
    initiator: SocketAddr,
    initiator_stream: TcpStream,
    responder_stream: TcpStream,
    first_seen: Timestamp,
    last_seen: Timestamp,
}

impl<Timestamp, CustomChannelId> TcpConnection<Timestamp, CustomChannelId> {
    /// Creates a connection whose first packet, sent by `initiator`, was
    /// seen at `timestamp`.
    pub(crate) fn new(
        id: TcpConnectionId,
        key: TcpConnectionKey<CustomChannelId>,
        initiator: SocketAddr,
        timestamp: Timestamp,
    ) -> TcpConnection<Timestamp, CustomChannelId>
    where
        Timestamp: Clone,
    {
        TcpConnection {
            id,
            key,
            initiator,
            initiator_stream: TcpStream::new(),
            responder_stream: TcpStream::new(),
            first_seen: timestamp.clone(),
            last_seen: timestamp,
        }
    }

    /// Id the pool assigned to the connection.
    pub fn id(&self) -> TcpConnectionId {
        self.id
    }

    /// Key identifying the connection.
    pub fn key(&self) -> &TcpConnectionKey<CustomChannelId> {
        &self.key
    }

    /// Address and port of the endpoint with the given role.
    pub fn endpoint(&self, role: TcpRole) -> SocketAddr {
        match role {
            TcpRole::Initiator => self.initiator,
            TcpRole::Responder => {
                let [a, b] = self.key.endpoints();
                if a == self.initiator {
                    b
                } else {
                    a
                }
            }
        }
    }

    /// Stream sent by the endpoint with the given role.
    pub fn stream(&self, role: TcpRole) -> &TcpStream {
        match role {
            TcpRole::Initiator => &self.initiator_stream,
            TcpRole::Responder => &self.responder_stream,
        }
    }

    /// Stream sent by the endpoint with the given role, for reading.
    pub fn stream_mut(&mut self, role: TcpRole) -> &mut TcpStream {
        match role {
            TcpRole::Initiator => &mut self.initiator_stream,
            TcpRole::Responder => &mut self.responder_stream,
        }
    }

    /// Timestamp of the connection's first packet.
    pub fn first_seen(&self) -> &Timestamp {
        &self.first_seen
    }

    /// Timestamp of the connection's last packet.
    pub fn last_seen(&self) -> &Timestamp {
        &self.last_seen
    }

    /// Applies a segment sent by `source` and returns the role of the sender.
    pub(crate) fn add_segment(
        &mut self,
        source: SocketAddr,
        tcp: &TcpSlice<'_>,
        timestamp: Timestamp,
    ) -> TcpRole {
        self.last_seen = timestamp;
        let sender = if source == self.initiator {
            TcpRole::Initiator
        } else {
            TcpRole::Responder
        };
        self.stream_mut(sender).add_segment(tcp);
        sender
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tcp_reassembly::TcpRole::*;
    use std::format;

    #[test]
    fn derived_traits() {
        let mut pool = TcpReassemblyPool::<u32, ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();

        // clone
        {
            let mut clone = connection.clone();
            assert_eq!(connection.id(), clone.id());
            assert_eq!(connection.key(), clone.key());
            assert_eq!(connection.endpoint(Initiator), clone.endpoint(Initiator));
            assert_eq!(connection.first_seen(), clone.first_seen());
            assert_eq!(connection.last_seen(), clone.last_seen());
            assert_eq!(
                TcpRead::Data(b"abc"),
                clone.stream_mut(Initiator).read_received()
            );
        }

        // debug
        assert!(format!("{:?}", connection).starts_with(&format!(
            "TcpConnection {{ id: TcpConnectionId(0), key: {:?}, ",
            connection.key()
        )));
    }

    #[test]
    fn id() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        for (i, port) in [50000, 50001, 50002].into_iter().enumerate() {
            let mut script = ConnectionScript::new(
                addr(&format!("10.0.0.1:{}", port)),
                addr("10.0.0.2:80"),
                1000,
                2000,
            );
            script.handshake();
            for segment in &script.segments {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(TcpConnectionId(i as u64), connection.id());
            }
        }
    }

    #[test]
    fn key() {
        let mut pool = TcpReassemblyPool::<(), u8>::default();
        let mut script = ConnectionScript::new(addr("[::2]:443"), addr("[::1]:50000"), 1000, 2000)
            .with_channel_id(7u8);
        script.vlan_ids.push(VlanId::try_new(3).unwrap());
        script.handshake();
        let expected = TcpConnectionKey::new(
            script.vlan_ids.clone(),
            addr("[::1]:50000"),
            addr("[::2]:443"),
            7u8,
        );
        for segment in &script.segments {
            let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
            assert_eq!(&expected, connection.key());
        }
    }

    #[test]
    fn endpoint() {
        let cases = [
            // initiator is the lower endpoint
            (addr("10.0.0.1:50000"), addr("10.0.0.2:80")),
            // initiator is the higher endpoint
            (addr("10.0.0.3:50000"), addr("10.0.0.2:80")),
            // connection to itself
            (addr("10.0.0.1:50000"), addr("10.0.0.1:50000")),
        ];
        for (initiator, responder) in cases {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::new(initiator, responder, 1000, 2000);
            script.handshake();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(initiator, connection.endpoint(Initiator));
            assert_eq!(responder, connection.endpoint(Responder));
        }
    }

    #[test]
    fn stream() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script
            .handshake()
            .send(Initiator, b"abc")
            .send(Responder, b"defgh");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        connection.stream_mut(Initiator).read_received();
        connection.stream_mut(Initiator).consume(3);
        connection.stream_mut(Responder).read_received();
        connection.stream_mut(Responder).consume(5);
        assert_eq!(3, connection.stream(Initiator).read_offset());
        assert_eq!(5, connection.stream(Responder).read_offset());
    }

    #[test]
    fn stream_mut() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script
            .handshake()
            .send(Initiator, b"abc")
            .send(Responder, b"def");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        assert_eq!(
            TcpRead::Data(b"abc"),
            connection.stream_mut(Initiator).read_received()
        );
        assert_eq!(
            TcpRead::Data(b"def"),
            connection.stream_mut(Responder).read_received()
        );
    }

    #[test]
    fn first_seen() {
        let mut pool = TcpReassemblyPool::<u32, ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        for (i, segment) in script.segments.iter().enumerate() {
            let (connection, _) = segment.feed(&mut pool, 10 + i as u32).active.unwrap();
            assert_eq!(&10, connection.first_seen());
        }
    }

    #[test]
    fn last_seen() {
        let mut pool = TcpReassemblyPool::<u32, ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        // a retransmission updates it too
        let retransmission = script.segments[3].clone();
        script.segments.push(retransmission);
        for (i, segment) in script.segments.iter().enumerate() {
            let (connection, _) = segment.feed(&mut pool, 10 + i as u32).active.unwrap();
            assert_eq!(&(10 + i as u32), connection.last_seen());
        }
    }
}
