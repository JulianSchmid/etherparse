use crate::tcp_reassembly::*;

/// The reconstructed payload byte streams of both directions of a TCP
/// connection.
///
/// The direction of a stream is relative to the endpoint order of the
/// [`TcpConnectionId`] it is stored under (see [`TcpDirection`]).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TcpConnection {
    /// Stream carrying the data from [`TcpConnectionId::first`] to
    /// [`TcpConnectionId::second`].
    first_to_second: TcpStreamReassemblyBuf,

    /// Stream carrying the data from [`TcpConnectionId::second`] to
    /// [`TcpConnectionId::first`].
    second_to_first: TcpStreamReassemblyBuf,
}

impl TcpConnection {
    /// Creates a connection from the two (already configured) direction
    /// buffers.
    #[inline]
    pub fn new(
        first_to_second: TcpStreamReassemblyBuf,
        second_to_first: TcpStreamReassemblyBuf,
    ) -> TcpConnection {
        TcpConnection {
            first_to_second,
            second_to_first,
        }
    }

    /// Stream of the given direction.
    #[inline]
    pub fn stream(&self, direction: TcpDirection) -> &TcpStreamReassemblyBuf {
        match direction {
            TcpDirection::FirstToSecond => &self.first_to_second,
            TcpDirection::SecondToFirst => &self.second_to_first,
        }
    }

    /// Mutable access to the stream of the given direction.
    #[inline]
    pub fn stream_mut(&mut self, direction: TcpDirection) -> &mut TcpStreamReassemblyBuf {
        match direction {
            TcpDirection::FirstToSecond => &mut self.first_to_second,
            TcpDirection::SecondToFirst => &mut self.second_to_first,
        }
    }

    /// Mutable access to both streams at once as
    /// `(direction, direction.reverse())`.
    ///
    /// Useful as a segment adds its payload to one direction while its
    /// acknowledgment number releases data of the other one.
    #[inline]
    pub fn streams_mut(
        &mut self,
        direction: TcpDirection,
    ) -> (&mut TcpStreamReassemblyBuf, &mut TcpStreamReassemblyBuf) {
        match direction {
            TcpDirection::FirstToSecond => (&mut self.first_to_second, &mut self.second_to_first),
            TcpDirection::SecondToFirst => (&mut self.second_to_first, &mut self.first_to_second),
        }
    }

    /// True if at least one segment was observed in the given direction.
    #[inline]
    pub fn is_direction_observed(&self, direction: TcpDirection) -> bool {
        self.stream(direction).base_sequence_number().is_some()
    }

    /// True if segments were observed in **both** directions of the
    /// connection.
    ///
    /// Under [`TcpAckPolicy::Required`] no data is handed out for a
    /// connection that only ever sees one direction (there are no
    /// acknowledgments). This differentiates a genuinely one-way capture from
    /// the case where the two directions were not matched up, e.g. because
    /// they carry different VLAN ids (see [`TcpConnectionId`]).
    #[inline]
    pub fn is_bidirectional(&self) -> bool {
        self.is_direction_observed(TcpDirection::FirstToSecond)
            && self.is_direction_observed(TcpDirection::SecondToFirst)
    }

    /// True once **both** directions received all data up to their `FIN`,
    /// i.e. the connection was closed gracefully and nothing is missing.
    ///
    /// A connection is not removed from a
    /// [`TcpStreamReassemblyPool`] automatically when this becomes true (the
    /// data still has to be drained). Use it to decide when to call
    /// [`TcpStreamReassemblyPool::end_connection`] or as part of a
    /// [`TcpStreamReassemblyPool::retain`] predicate (connections that are
    /// simply inactive are better discarded via
    /// [`TcpStreamReassemblyPool::evict_older_than`]).
    ///
    /// Note that this is about *reception* and ignores the
    /// [`TcpAckPolicy`], see
    /// [`TcpStreamReassemblyBuf::is_fin_reached`].
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.first_to_second.is_fin_reached() && self.second_to_first.is_fin_reached()
    }

    /// True if either direction still holds in-order data that was not
    /// consumed yet (ignoring the [`TcpAckPolicy`]).
    #[inline]
    pub fn has_leftover_data(&self) -> bool {
        false == self.first_to_second.contiguous_unacked().is_empty()
            || false == self.second_to_first.contiguous_unacked().is_empty()
    }

    /// Consume the connection and return the two direction buffers for
    /// re-use.
    #[inline]
    pub fn take_bufs(self) -> (TcpStreamReassemblyBuf, TcpStreamReassemblyBuf) {
        (self.first_to_second, self.second_to_first)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, vec::Vec};

    fn new_conn() -> TcpConnection {
        TcpConnection::new(
            TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 1 << 20),
            TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 1 << 20),
        )
    }

    #[test]
    fn debug_clone_eq_hash() {
        let value = new_conn();
        let _ = format!("{:?}", value);
        assert_eq!(value, value.clone());

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            value.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            value.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn stream_access_by_direction() {
        let mut conn = new_conn();
        conn.stream_mut(TcpDirection::FirstToSecond)
            .add(1000, &[1, 2, 3], false)
            .unwrap();

        assert_eq!(
            conn.stream(TcpDirection::FirstToSecond)
                .base_sequence_number(),
            Some(1000)
        );
        assert_eq!(
            conn.stream(TcpDirection::SecondToFirst)
                .base_sequence_number(),
            None
        );

        // streams_mut returns (sender, receiver) for the given direction
        let (sender, receiver) = conn.streams_mut(TcpDirection::SecondToFirst);
        assert_eq!(sender.base_sequence_number(), None);
        assert_eq!(receiver.base_sequence_number(), Some(1000));
    }

    #[test]
    fn direction_observation() {
        let mut conn = new_conn();
        assert_eq!(false, conn.is_bidirectional());
        assert_eq!(
            false,
            conn.is_direction_observed(TcpDirection::FirstToSecond)
        );

        conn.stream_mut(TcpDirection::FirstToSecond)
            .add(1000, &[1, 2, 3], false)
            .unwrap();
        assert!(conn.is_direction_observed(TcpDirection::FirstToSecond));
        assert_eq!(false, conn.is_bidirectional());

        // even an empty segment (e.g. a pure ACK) anchors the direction
        conn.stream_mut(TcpDirection::SecondToFirst)
            .add(500, &[], false)
            .unwrap();
        assert!(conn.is_bidirectional());
    }

    #[test]
    fn leftover_data_and_take_bufs() {
        let mut conn = new_conn();
        assert_eq!(false, conn.has_leftover_data());

        conn.stream_mut(TcpDirection::SecondToFirst)
            .add(1000, &[1, 2, 3], false)
            .unwrap();
        // not acknowledged, but still "leftover" (unacked data counts)
        assert!(conn.has_leftover_data());

        conn.stream_mut(TcpDirection::SecondToFirst)
            .consume_unacked(3);
        assert_eq!(false, conn.has_leftover_data());

        let (a, b) = conn.take_bufs();
        assert_eq!(a.base_sequence_number(), None);
        assert_eq!(b.base_sequence_number(), Some(1003));
    }
}
