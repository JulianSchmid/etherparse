use crate::{tcp_reassembly::*, *};
use std::collections::HashMap;
use std::vec::Vec;

/// Result of processing a packet with a [`TcpStreamReassemblyPool`].
#[derive(Debug)]
pub enum TcpReassemblyEvent<'a, CustomChannelId = ()> {
    /// The packet did not affect any connection (not a TCP segment, or a
    /// segment of an unknown connection that carries nothing to reconstruct,
    /// e.g. a pure ACK or an out of window RST).
    Ignored,

    /// The segment was added to this (potentially newly created) connection.
    Segment {
        /// Identifier the connection is tracked under (e.g. to key caller
        /// side state or to access the connection later via
        /// [`TcpStreamReassemblyPool::connection_mut`]).
        id: TcpConnectionId<CustomChannelId>,

        /// Direction the segment was travelling in.
        direction: TcpDirection,

        /// Stream the payload of the segment was added to.
        ///
        /// Read the available in-order data via
        /// [`TcpStreamReassemblyBuf::contiguous`] and free it via
        /// [`TcpStreamReassemblyBuf::consume`].
        sender: &'a mut TcpStreamReassemblyBuf,

        /// Stream of the opposite direction.
        ///
        /// If the segment carried an acknowledgment number the data available
        /// in this stream may have grown (see [`TcpAckPolicy::Required`]), so
        /// it is worth draining as well.
        receiver: &'a mut TcpStreamReassemblyBuf,
    },

    /// The connection was ended by a RST or replaced by a SYN with a new
    /// initial sequence number.
    Closed {
        /// Identifier the connection was tracked under.
        ///
        /// In the "replaced by a SYN" case the newly created connection is
        /// tracked under the same identifier and can be accessed via
        /// [`TcpStreamReassemblyPool::connection_mut`].
        id: TcpConnectionId<CustomChannelId>,

        /// The closed connection.
        ///
        /// In-order data that was never consumed can still be read from both
        /// directions (use [`TcpStreamReassemblyBuf::contiguous_unacked`], as
        /// the closing segment is usually not acknowledged anymore). The
        /// buffers are automatically recycled on the next `process_*` call.
        connection: &'a mut TcpConnection,
    },
}

/// Pool to reassemble the payload byte streams of multiple TCP connections in
/// parallel (re-uses buffers to minimize allocations).
///
/// Both directions of a connection are tracked together (see
/// [`TcpConnectionId`] & [`TcpConnection`]), which is what allows the
/// acknowledgment numbers of one direction to release the data of the other
/// one.
///
/// # Only acknowledged data is handed out
///
/// By default ([`TcpAckPolicy::Required`]) [`TcpStreamReassemblyBuf::contiguous`]
/// only returns data that the receiver acknowledged. As a capture usually ends
/// before the last data is acknowledged, drain the remaining bytes via
/// [`TcpStreamReassemblyBuf::contiguous_unacked`] &
/// [`TcpStreamReassemblyBuf::consume_unacked`] at the end of a capture.
///
/// This requires both directions of a connection to be present in the capture
/// and to be identified as the same connection. Use
/// [`TcpConnection::is_bidirectional`] to detect connections where that is not
/// the case, or set [`TcpAckPolicy::Ignore`] via
/// [`TcpStreamReassemblyPool::with_ack_policy`] for captures that only contain
/// one direction.
///
/// # Interpretation of the TCP flags
///
/// * `SYN` establishes the stream start. Duplicated/retransmitted SYNs and a
///   late SYN of an already tracked stream are recognized and do **not** drop
///   already buffered data. A SYN with a new initial sequence number replaces
///   the tracked connection (see [`TcpReassemblyEvent::Closed`]).
/// * `ACK` releases the data of the **reverse** direction.
/// * `FIN` marks the end of a stream (see
///   [`TcpStreamReassemblyBuf::is_fin_reached`]). Note that a connection is
///   *not* automatically removed from the pool when the FIN is reached (use
///   [`TcpStreamReassemblyPool::end_connection`] or
///   [`TcpStreamReassemblyPool::retain`]).
/// * `RST` ends the connection (both directions) & recycles its buffers (see
///   [`TcpReassemblyEvent::Closed`]). RSTs carrying a sequence number outside
///   of the tracked window are ignored so a blindly injected RST cannot tear
///   down a connection. Note that this check needs previously observed
///   segments of the direction the RST travels in to judge against: a RST
///   arriving in a direction that was never observed before is accepted with
///   any sequence number (rejecting it would also drop legitimate RSTs like
///   a "connection refused" answering the initial SYN).
///
/// Streams for which no SYN was observed (e.g. when the capture starts in the
/// middle of a connection) are anchored on their first segment and
/// reconstructed from there on. They can be identified via
/// [`TcpStreamReassemblyBuf::syn_observed`].
///
/// # IP fragmentation
///
/// [`TcpStreamReassemblyPool::process_sliced_packet`] ignores IP fragments
/// (the TCP layer of a fragmented packet is not decoded). Re-assemble
/// fragmented packets first (e.g. via [`crate::defrag::IpDefragPool`]), turn
/// the result into a [`TcpSegmentInfo`] via
/// [`TcpSegmentInfo::from_defragmented_payload`] and feed that via
/// [`TcpStreamReassemblyPool::process_tcp`] (see the `pcap_tcp_reassembly`
/// example).
///
/// # TCP checksums are not verified
///
/// The reassembly does not validate the TCP checksum of the segments it is
/// fed, so corrupted segments end up in the reconstructed stream. Compare
/// [`crate::TcpSlice::checksum`] against
/// [`crate::TcpSlice::calc_checksum_ipv4`] /
/// [`crate::TcpSlice::calc_checksum_ipv6`] beforehand if that matters.
///
/// # Memory usage
///
/// Each individual stream is bounded by `max_capacity` (buffered bytes) &
/// `max_sections` (tracked ranges), and the buffers that are kept around for
/// re-use after a connection ended are bounded by
/// [`TcpStreamReassemblyPool::with_pool_limits`].
///
/// The number of parallel connections is **unlimited by default**, so in an
/// untrusted environment an attacker could cause an "out of memory error" by
/// opening up many parallel connections. Set
/// [`TcpStreamReassemblyPool::with_max_connections`] to bound it (new
/// connections are then rejected with
/// [`TcpReassembleError::TooManyConnections`]) and evict stale connections
/// via [`TcpStreamReassemblyPool::retain`].
#[derive(Debug, Clone)]
pub struct TcpStreamReassemblyPool<Timestamp = (), CustomChannelId = ()> {
    /// Currently reconstructing TCP connections.
    active: HashMap<TcpConnectionId<CustomChannelId>, (TcpConnection, Timestamp)>,

    /// Connection that was closed by the last `process_*` call (RST or
    /// replaced via a SYN), kept around so the caller can still drain the
    /// leftover data. Recycled at the start of the next `process_*` call.
    pending_closed: Option<TcpConnection>,

    /// Data buffers that can be re-used.
    finished_data_bufs: Vec<Vec<u8>>,

    /// Section buffers that can be re-used.
    finished_section_bufs: Vec<Vec<TcpStreamRange>>,

    /// Maximum number of bytes buffered ahead of the read cursor per stream.
    default_max_capacity: usize,

    /// Maximum number of separate (non-contiguous) data sections per stream.
    default_max_sections: usize,

    /// Policy deciding if data has to be acknowledged before it is handed out.
    default_ack_policy: TcpAckPolicy,

    /// Maximum number of buffers kept in the free lists for re-use.
    max_pooled_bufs: usize,

    /// Maximum capacity (in bytes) a data buffer may have to be pooled.
    max_pooled_buf_capacity: usize,

    /// Maximum number of connections tracked at the same time (`None` for
    /// unlimited).
    max_connections: Option<usize>,
}

/// Takes a buffer from the free lists (or allocates a new one).
fn pop_free_buf(
    free_data: &mut Vec<Vec<u8>>,
    free_sections: &mut Vec<Vec<TcpStreamRange>>,
    max_capacity: usize,
    max_sections: usize,
    ack_policy: TcpAckPolicy,
) -> TcpStreamReassemblyBuf {
    TcpStreamReassemblyBuf::new(
        free_data.pop().unwrap_or_default(),
        free_sections.pop().unwrap_or_default(),
        max_capacity,
    )
    .with_max_sections(max_sections)
    .with_ack_policy(ack_policy)
}

/// Returns the allocations of the given buffer to the free lists.
///
/// Buffers beyond `max_pooled_bufs` are dropped and buffers that grew beyond
/// `max_pooled_buf_capacity` are shrunk, so a burst of connections (or a
/// single big stream) does not make the pool hold on to the memory for the
/// rest of its lifetime.
fn recycle_buf(
    free_data: &mut Vec<Vec<u8>>,
    free_sections: &mut Vec<Vec<TcpStreamRange>>,
    max_pooled_bufs: usize,
    max_pooled_buf_capacity: usize,
    buf: TcpStreamReassemblyBuf,
) {
    let (mut data, mut sections) = buf.take_bufs();
    if free_data.len() < max_pooled_bufs {
        // clear first, as `shrink_to` never shrinks below the length
        data.clear();
        data.shrink_to(max_pooled_buf_capacity);
        free_data.push(data);
    }
    if free_sections.len() < max_pooled_bufs {
        // the number of sections is already bounded by `max_sections` per
        // stream, so only the count of pooled buffers has to be limited
        sections.clear();
        free_sections.push(sections);
    }
}

/// Takes the two buffers of a connection from the free lists.
fn pop_free_connection(
    free_data: &mut Vec<Vec<u8>>,
    free_sections: &mut Vec<Vec<TcpStreamRange>>,
    max_capacity: usize,
    max_sections: usize,
    ack_policy: TcpAckPolicy,
) -> TcpConnection {
    TcpConnection::new(
        pop_free_buf(
            free_data,
            free_sections,
            max_capacity,
            max_sections,
            ack_policy,
        ),
        pop_free_buf(
            free_data,
            free_sections,
            max_capacity,
            max_sections,
            ack_policy,
        ),
    )
}

/// Returns the allocations of both directions of a connection to the free
/// lists.
fn recycle_connection(
    free_data: &mut Vec<Vec<u8>>,
    free_sections: &mut Vec<Vec<TcpStreamRange>>,
    max_pooled_bufs: usize,
    max_pooled_buf_capacity: usize,
    connection: TcpConnection,
) {
    let (first_to_second, second_to_first) = connection.take_bufs();
    recycle_buf(
        free_data,
        free_sections,
        max_pooled_bufs,
        max_pooled_buf_capacity,
        first_to_second,
    );
    recycle_buf(
        free_data,
        free_sections,
        max_pooled_bufs,
        max_pooled_buf_capacity,
        second_to_first,
    );
}

impl<Timestamp, CustomChannelId> TcpStreamReassemblyPool<Timestamp, CustomChannelId>
where
    CustomChannelId: core::hash::Hash + Eq,
{
    /// Creates a new pool with the [`DEFAULT_MAX_TCP_STREAM_CAPACITY`] &
    /// [`DEFAULT_MAX_TCP_STREAM_SECTIONS`] per stream limits.
    pub fn new() -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        Self::with_max_capacity(DEFAULT_MAX_TCP_STREAM_CAPACITY)
    }

    /// Creates a new pool with a custom per stream buffer limit.
    ///
    /// `max_capacity` must be less than 2^31 (see
    /// [`TcpStreamReassemblyBuf::new`]).
    pub fn with_max_capacity(
        max_capacity: usize,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        Self::with_limits(max_capacity, DEFAULT_MAX_TCP_STREAM_SECTIONS)
    }

    /// Creates a new pool with custom per stream buffer & section limits.
    ///
    /// `max_capacity` must be less than 2^31 (see
    /// [`TcpStreamReassemblyBuf::new`]).
    pub fn with_limits(
        max_capacity: usize,
        max_sections: usize,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        TcpStreamReassemblyPool {
            active: HashMap::new(),
            pending_closed: None,
            finished_data_bufs: Vec::new(),
            finished_section_bufs: Vec::new(),
            default_max_capacity: max_capacity,
            default_max_sections: max_sections,
            default_ack_policy: TcpAckPolicy::default(),
            max_pooled_bufs: DEFAULT_MAX_TCP_POOLED_BUFS,
            max_pooled_buf_capacity: DEFAULT_MAX_TCP_POOLED_BUF_CAPACITY,
            max_connections: None,
        }
    }

    /// Sets if data has to be acknowledged by the receiver before it is
    /// handed out by [`TcpStreamReassemblyBuf::contiguous`] (defaults to
    /// [`TcpAckPolicy::Required`]).
    pub fn with_ack_policy(
        mut self,
        ack_policy: TcpAckPolicy,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        self.default_ack_policy = ack_policy;
        self
    }

    /// Sets how many buffers are kept around for re-use after the connections
    /// they belonged to ended and how big a single pooled buffer may be
    /// (defaults to [`DEFAULT_MAX_TCP_POOLED_BUFS`] &
    /// [`DEFAULT_MAX_TCP_POOLED_BUF_CAPACITY`]).
    pub fn with_pool_limits(
        mut self,
        max_pooled_bufs: usize,
        max_pooled_buf_capacity: usize,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        self.max_pooled_bufs = max_pooled_bufs;
        self.max_pooled_buf_capacity = max_pooled_buf_capacity;
        self
    }

    /// Limits the number of connections that are tracked at the same time
    /// (unlimited by default).
    ///
    /// Segments starting a new connection while the limit is reached are
    /// rejected with [`TcpReassembleError::TooManyConnections`]. Evict
    /// connections that are no longer of interest via
    /// [`TcpStreamReassemblyPool::retain`] or
    /// [`TcpStreamReassemblyPool::end_connection`] to make room.
    pub fn with_max_connections(
        mut self,
        max_connections: usize,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        self.max_connections = Some(max_connections);
        self
    }

    /// Maximum number of connections tracked at the same time (`None` if
    /// unlimited).
    #[inline]
    pub fn max_connections(&self) -> Option<usize> {
        self.max_connections
    }

    /// Process a TCP segment contained in a [`SlicedPacket`].
    ///
    /// The VLAN ids of the packet are part of the connection identity. Use
    /// [`TcpSegmentInfo::from_sliced_packet`] together with
    /// [`TcpStreamReassemblyPool::process_tcp`] to change that (see
    /// [`TcpConnectionId`]).
    ///
    /// Returns:
    /// * `Ok(TcpReassemblyEvent::Ignored)` if the packet did not affect any
    ///   connection (e.g. not a TCP segment).
    /// * `Ok(TcpReassemblyEvent::Segment{..})` giving access to both
    ///   directions of the affected connection.
    /// * `Ok(TcpReassemblyEvent::Closed{..})` if a connection was ended by a
    ///   RST or replaced by a new connection (leftover data can be drained).
    /// * `Err` if the segment could not be added (see [`TcpReassembleError`]).
    pub fn process_sliced_packet(
        &mut self,
        slice: &SlicedPacket,
        timestamp: Timestamp,
        channel_id: CustomChannelId,
    ) -> Result<TcpReassemblyEvent<'_, CustomChannelId>, TcpReassembleError>
    where
        CustomChannelId: Clone,
    {
        match TcpSegmentInfo::from_sliced_packet(slice, channel_id) {
            Some(segment) => self.process(segment, timestamp),
            None => {
                self.recycle_pending_closed();
                Ok(TcpReassemblyEvent::Ignored)
            }
        }
    }

    /// Process a TCP segment contained in a [`LaxSlicedPacket`].
    ///
    /// Behaves like [`TcpStreamReassemblyPool::process_sliced_packet`], but
    /// accepts packets that were parsed without the length & consistency
    /// checks. See [`TcpSegmentInfo::from_lax_sliced_packet`] for what that
    /// implies for the reconstructed stream.
    pub fn process_lax_sliced_packet(
        &mut self,
        slice: &LaxSlicedPacket,
        timestamp: Timestamp,
        channel_id: CustomChannelId,
    ) -> Result<TcpReassemblyEvent<'_, CustomChannelId>, TcpReassembleError>
    where
        CustomChannelId: Clone,
    {
        match TcpSegmentInfo::from_lax_sliced_packet(slice, channel_id) {
            Some(segment) => self.process(segment, timestamp),
            None => {
                self.recycle_pending_closed();
                Ok(TcpReassemblyEvent::Ignored)
            }
        }
    }

    /// Process an already parsed TCP segment (lower level entry point that
    /// does not require a [`SlicedPacket`] and allows customizing what
    /// differentiates connections).
    pub fn process_tcp(
        &mut self,
        segment: TcpSegmentInfo<'_, CustomChannelId>,
        timestamp: Timestamp,
    ) -> Result<TcpReassemblyEvent<'_, CustomChannelId>, TcpReassembleError>
    where
        CustomChannelId: Clone,
    {
        self.process(segment, timestamp)
    }

    /// Recycles the buffers of the connection closed by the previous
    /// `process_*` call (the caller had the chance to drain it until now).
    fn recycle_pending_closed(&mut self) {
        if let Some(closed) = self.pending_closed.take() {
            recycle_connection(
                &mut self.finished_data_bufs,
                &mut self.finished_section_bufs,
                self.max_pooled_bufs,
                self.max_pooled_buf_capacity,
                closed,
            );
        }
    }

    fn process(
        &mut self,
        segment: TcpSegmentInfo<'_, CustomChannelId>,
        timestamp: Timestamp,
    ) -> Result<TcpReassemblyEvent<'_, CustomChannelId>, TcpReassembleError>
    where
        CustomChannelId: Clone,
    {
        use std::collections::hash_map::Entry;
        use TcpReassemblyEvent::*;

        self.recycle_pending_closed();

        let TcpSegmentInfo {
            source,
            destination,
            vlan_ids,
            channel_id,
            sequence_number: seq,
            acknowledgment_number: ack,
            payload,
            syn,
            fin,
            rst,
        } = segment;

        let (id, direction) = TcpConnectionId::new(source, destination, vlan_ids, channel_id);

        // a RST tears down the whole connection (both directions)
        if rst {
            // Only accept a RST that is plausible for the stream it was sent
            // in, so a blindly injected out of window RST cannot end the
            // connection.
            let accepted = match self.active.get(&id) {
                Some((connection, _)) => connection.stream(direction).is_seq_in_window(seq),
                None => return Ok(Ignored),
            };
            if false == accepted {
                return Ok(Ignored);
            }
            return Ok(match self.active.remove(&id) {
                Some((connection, _)) => Closed {
                    id,
                    connection: self.pending_closed.insert(connection),
                },
                None => Ignored,
            });
        }

        // captured before the entry below borrows `self.active`
        let active_len = self.active.len();

        match self.active.entry(id) {
            Entry::Occupied(entry) => {
                // the id was moved into the entry lookup, so the copy for the
                // returned event has to be cloned back out of the key
                let id = entry.key().clone();
                let value = entry.into_mut();

                // note: the timestamp is only updated after the fallible
                // steps, so an error leaves the connection fully unchanged
                let outcome = value
                    .0
                    .stream_mut(direction)
                    .add_segment(seq, payload, syn, fin)?;

                match outcome {
                    TcpSegmentOutcome::Continued => {
                        if let Some(ack) = ack {
                            value.0.stream_mut(direction.reverse()).add_ack(ack);
                        }
                        value.1 = timestamp;
                        let (sender, receiver) = value.0.streams_mut(direction);
                        Ok(Segment {
                            id,
                            direction,
                            sender,
                            receiver,
                        })
                    }
                    TcpSegmentOutcome::NewConnection => {
                        // reconnect: replace both directions with fresh streams
                        let mut fresh = pop_free_connection(
                            &mut self.finished_data_bufs,
                            &mut self.finished_section_bufs,
                            self.default_max_capacity,
                            self.default_max_sections,
                            self.default_ack_policy,
                        );
                        // the fresh streams have no base yet, so this only
                        // fails if the SYN payload exceeds the limits. The
                        // replacement did not happen yet, so the previous
                        // connection stays untouched & accessible then.
                        if let Err(err) = fresh
                            .stream_mut(direction)
                            .add_segment(seq, payload, syn, fin)
                        {
                            recycle_connection(
                                &mut self.finished_data_bufs,
                                &mut self.finished_section_bufs,
                                self.max_pooled_bufs,
                                self.max_pooled_buf_capacity,
                                fresh,
                            );
                            return Err(err);
                        }
                        if let Some(ack) = ack {
                            fresh.stream_mut(direction.reverse()).add_ack(ack);
                        }

                        value.1 = timestamp;
                        let old = core::mem::replace(&mut value.0, fresh);
                        if old.has_leftover_data() {
                            // "value" can no longer be returned, but the
                            // leftover data of the replaced connection can
                            Ok(Closed {
                                id,
                                connection: self.pending_closed.insert(old),
                            })
                        } else {
                            recycle_connection(
                                &mut self.finished_data_bufs,
                                &mut self.finished_section_bufs,
                                self.max_pooled_bufs,
                                self.max_pooled_buf_capacity,
                                old,
                            );
                            let (sender, receiver) = value.0.streams_mut(direction);
                            Ok(Segment {
                                id,
                                direction,
                                sender,
                                receiver,
                            })
                        }
                    }
                }
            }
            Entry::Vacant(entry) => {
                // segments without payload, SYN & FIN carry no data for the
                // reassembly -> don't create a connection for them (e.g. pure
                // ACKs, port scans, keep alives of unknown connections)
                if payload.is_empty() && false == syn && false == fin {
                    return Ok(Ignored);
                }
                // keep the number of tracked connections bounded
                if let Some(max_connections) = self.max_connections {
                    if active_len >= max_connections {
                        return Err(TcpReassembleError::TooManyConnections { max_connections });
                    }
                }
                let mut connection = pop_free_connection(
                    &mut self.finished_data_bufs,
                    &mut self.finished_section_bufs,
                    self.default_max_capacity,
                    self.default_max_sections,
                    self.default_ack_policy,
                );
                if let Err(err) = connection
                    .stream_mut(direction)
                    .add_segment(seq, payload, syn, fin)
                {
                    recycle_connection(
                        &mut self.finished_data_bufs,
                        &mut self.finished_section_bufs,
                        self.max_pooled_bufs,
                        self.max_pooled_buf_capacity,
                        connection,
                    );
                    return Err(err);
                }
                if let Some(ack) = ack {
                    connection.stream_mut(direction.reverse()).add_ack(ack);
                }
                let id = entry.key().clone();
                let value = entry.insert((connection, timestamp));
                let (sender, receiver) = value.0.streams_mut(direction);
                Ok(Segment {
                    id,
                    direction,
                    sender,
                    receiver,
                })
            }
        }
    }

    /// Direct access to an active connection.
    pub fn connection(
        &self,
        id: &TcpConnectionId<CustomChannelId>,
    ) -> Option<&TcpConnection> {
        self.active.get(id).map(|(connection, _)| connection)
    }

    /// Direct mutable access to an active connection (e.g. to read & consume
    /// data outside of a `process_*` call).
    pub fn connection_mut(
        &mut self,
        id: &TcpConnectionId<CustomChannelId>,
    ) -> Option<&mut TcpConnection> {
        self.active.get_mut(id).map(|(connection, _)| connection)
    }

    /// Direct mutable access to a single direction of an active connection.
    pub fn stream_mut(
        &mut self,
        id: &TcpConnectionId<CustomChannelId>,
        direction: TcpDirection,
    ) -> Option<&mut TcpStreamReassemblyBuf> {
        self.active
            .get_mut(id)
            .map(|(connection, _)| connection.stream_mut(direction))
    }

    /// Explicitly end a connection and recycle its buffers.
    pub fn end_connection(&mut self, id: &TcpConnectionId<CustomChannelId>) {
        if let Some((connection, _)) = self.active.remove(id) {
            recycle_connection(
                &mut self.finished_data_bufs,
                &mut self.finished_section_bufs,
                self.max_pooled_bufs,
                self.max_pooled_buf_capacity,
                connection,
            );
        }
    }

    /// Number of currently active connections.
    #[inline]
    pub fn active_connections(&self) -> usize {
        self.active.len()
    }

    /// Iterates over all active connections (e.g. to drain the remaining data
    /// of all streams at the end of a capture).
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<
        Item = (
            &TcpConnectionId<CustomChannelId>,
            &mut TcpConnection,
            &Timestamp,
        ),
    > {
        self.active.iter_mut().map(|(id, v)| (id, &mut v.0, &v.1))
    }

    /// Retains only the connections specified by the predicate and recycles
    /// the buffers of the evicted ones (e.g. to remove connections that have
    /// not received data for a while based on the `Timestamp`).
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&TcpConnectionId<CustomChannelId>, &Timestamp) -> bool,
    {
        let finished_data_bufs = &mut self.finished_data_bufs;
        let finished_section_bufs = &mut self.finished_section_bufs;
        let max_pooled_bufs = self.max_pooled_bufs;
        let max_pooled_buf_capacity = self.max_pooled_buf_capacity;
        self.active.retain(|id, value| {
            if f(id, &value.1) {
                true
            } else {
                recycle_connection(
                    finished_data_bufs,
                    finished_section_bufs,
                    max_pooled_bufs,
                    max_pooled_buf_capacity,
                    core::mem::replace(
                        &mut value.0,
                        TcpConnection::new(
                            TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 0),
                            TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 0),
                        ),
                    ),
                );
                false
            }
        });
    }
}

impl<Timestamp, CustomChannelId> Default for TcpStreamReassemblyPool<Timestamp, CustomChannelId>
where
    CustomChannelId: core::hash::Hash + Eq,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use arrayvec::ArrayVec;
    use proptest::prelude::*;
    use std::format;
    use std::vec::Vec;

    fn endpoint_a() -> TcpEndpoint {
        TcpEndpoint::from_ipv4([1, 2, 3, 4], 1234)
    }

    fn endpoint_b() -> TcpEndpoint {
        TcpEndpoint::from_ipv4([5, 6, 7, 8], 80)
    }

    /// Direction of segments travelling from a to b (see `canonical_direction`).
    const A_TO_B: TcpDirection = TcpDirection::FirstToSecond;

    /// Segment travelling from a to b (`reverse == false`) or from b to a.
    fn segment(reverse: bool, seq: u32, payload: &[u8], channel_id: u16) -> TcpSegmentInfo<'_, u16> {
        let (source, destination) = if reverse {
            (endpoint_b(), endpoint_a())
        } else {
            (endpoint_a(), endpoint_b())
        };
        TcpSegmentInfo {
            source,
            destination,
            vlan_ids: Default::default(),
            channel_id,
            sequence_number: seq,
            acknowledgment_number: None,
            payload,
            syn: false,
            fin: false,
            rst: false,
        }
    }

    fn conn_id(channel_id: u16) -> TcpConnectionId<u16> {
        TcpConnectionId::new(endpoint_a(), endpoint_b(), Default::default(), channel_id).0
    }

    fn sequence(start: usize, len: usize) -> Vec<u8> {
        (start..start + len).map(|i| (i & 0xff) as u8).collect()
    }

    /// Pool that hands out data without requiring acknowledgments (for the
    /// tests targeting the flag handling & lifecycle).
    fn new_pool<Timestamp>() -> TcpStreamReassemblyPool<Timestamp, u16> {
        TcpStreamReassemblyPool::new().with_ack_policy(TcpAckPolicy::Ignore)
    }

    /// Unwraps the stream the payload was added to.
    fn sender<C: core::fmt::Debug>(ev: TcpReassemblyEvent<'_, C>) -> &mut TcpStreamReassemblyBuf {
        match ev {
            TcpReassemblyEvent::Segment { sender, .. } => sender,
            other => panic!("expected TcpReassemblyEvent::Segment, got {other:?}"),
        }
    }

    /// Unwraps the stream of the opposite direction.
    fn receiver<C: core::fmt::Debug>(
        ev: TcpReassemblyEvent<'_, C>,
    ) -> &mut TcpStreamReassemblyBuf {
        match ev {
            TcpReassemblyEvent::Segment { receiver, .. } => receiver,
            other => panic!("expected TcpReassemblyEvent::Segment, got {other:?}"),
        }
    }

    /// Unwraps a [`TcpReassemblyEvent::Closed`].
    fn closed<C: core::fmt::Debug>(ev: TcpReassemblyEvent<'_, C>) -> &mut TcpConnection {
        match ev {
            TcpReassemblyEvent::Closed { connection, .. } => connection,
            other => panic!("expected TcpReassemblyEvent::Closed, got {other:?}"),
        }
    }

    fn assert_ignored<C>(ev: TcpReassemblyEvent<'_, C>) {
        assert!(matches!(ev, TcpReassemblyEvent::Ignored));
    }

    #[test]
    fn new_default() {
        let pool = TcpStreamReassemblyPool::<(), ()>::new();
        assert_eq!(pool.active_connections(), 0);
        // acknowledgments are required by default
        assert_eq!(pool.default_ack_policy, TcpAckPolicy::Required);

        let pool: TcpStreamReassemblyPool<u32, u16> = Default::default();
        assert_eq!(pool.active_connections(), 0);

        let pool = TcpStreamReassemblyPool::<(), ()>::with_max_capacity(16);
        assert_eq!(pool.default_max_capacity, 16);
        assert_eq!(pool.default_max_sections, DEFAULT_MAX_TCP_STREAM_SECTIONS);

        let pool = TcpStreamReassemblyPool::<(), ()>::with_limits(16, 4)
            .with_ack_policy(TcpAckPolicy::Ignore);
        assert_eq!(pool.default_max_capacity, 16);
        assert_eq!(pool.default_max_sections, 4);
        assert_eq!(pool.default_ack_policy, TcpAckPolicy::Ignore);
    }

    #[test]
    fn debug_clone() {
        let pool = TcpStreamReassemblyPool::<(), ()>::new();
        let _ = std::format!("{:?}", pool.clone());
    }

    #[test]
    fn canonical_direction() {
        // both directions map to the same connection id
        let (id_ab, dir_ab) =
            TcpConnectionId::new(endpoint_a(), endpoint_b(), Default::default(), 0u16);
        let (id_ba, dir_ba) =
            TcpConnectionId::new(endpoint_b(), endpoint_a(), Default::default(), 0u16);
        assert_eq!(id_ab, id_ba);
        assert_eq!(dir_ab, A_TO_B);
        assert_eq!(dir_ba, A_TO_B.reverse());
    }

    #[test]
    fn ack_releases_peer_data() {
        // acknowledgments are required by default
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();

        // a sends data, nothing acknowledged yet
        let buf = sender(
            pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &[]);
        assert_eq!(buf.contiguous_unacked(), &sequence(0, 8)[..]);
        assert_eq!(false, buf.ack_observed());

        // b acknowledges the first 4 bytes with a pure ACK: the data of the
        // *opposite* direction becomes available
        let mut ack = segment(true, 5000, &[], 0);
        ack.acknowledgment_number = Some(1004);
        let buf = receiver(pool.process_tcp(ack, ()).unwrap());
        assert!(buf.ack_observed());
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        buf.consume(4);

        // acknowledging the rest releases it
        let mut ack = segment(true, 5000, &[], 0);
        ack.acknowledgment_number = Some(1008);
        let buf = receiver(pool.process_tcp(ack, ()).unwrap());
        assert_eq!(buf.contiguous(), &sequence(4, 4)[..]);
    }

    #[test]
    fn ack_carried_by_a_data_segment() {
        // a data segment acknowledges the reverse direction at the same time
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();

        let payload = sequence(100, 4);
        let mut seg = segment(true, 5000, &payload, 0);
        seg.acknowledgment_number = Some(1008);
        let ev = pool.process_tcp(seg, ()).unwrap();
        match ev {
            TcpReassemblyEvent::Segment {
                id,
                direction,
                sender,
                receiver,
            } => {
                assert_eq!(id, conn_id(0));
                assert_eq!(direction, A_TO_B.reverse());
                // the payload of this segment is not acknowledged yet
                assert_eq!(sender.contiguous(), &[]);
                assert_eq!(sender.contiguous_unacked(), &sequence(100, 4)[..]);
                // ... while it released the data of the other direction
                assert_eq!(receiver.contiguous(), &sequence(0, 8)[..]);
            }
            other => panic!("expected Segment, got {other:?}"),
        }
    }

    #[test]
    fn basic_syn_data_flow() {
        let mut pool = TcpStreamReassemblyPool::<u32, u16>::new();

        // SYN from a (isn 999, so data starts at 1000)
        let mut syn = segment(false, 999, &[], 0);
        syn.syn = true;
        let buf = sender(pool.process_tcp(syn, 1).unwrap());
        assert_eq!(buf.base_sequence_number(), Some(1000));
        assert!(buf.syn_observed());
        assert_eq!(pool.active_connections(), 1);

        // SYN-ACK from b
        let mut syn_ack = segment(true, 4999, &[], 0);
        syn_ack.syn = true;
        syn_ack.acknowledgment_number = Some(1000);
        let buf = sender(pool.process_tcp(syn_ack, 2).unwrap());
        assert_eq!(buf.base_sequence_number(), Some(5000));

        // data from a, acknowledged by b
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), 3)
            .unwrap();
        let mut ack = segment(true, 5000, &[], 0);
        ack.acknowledgment_number = Some(1008);
        let buf = receiver(pool.process_tcp(ack, 4).unwrap());
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
        buf.consume(8);

        // more data + FIN from a
        let payload = sequence(8, 4);
        let mut fin = segment(false, 1008, &payload, 0);
        fin.fin = true;
        let buf = sender(pool.process_tcp(fin, 5).unwrap());
        assert!(buf.is_fin_reached());
        // ... but it was not acknowledged, so only reachable unacked
        assert_eq!(buf.contiguous(), &[]);
        assert_eq!(buf.contiguous_unacked(), &sequence(8, 4)[..]);
    }

    #[test]
    fn events_carry_the_connection_id() {
        let mut pool = new_pool::<()>();

        // a new connection reports the id it is tracked under ...
        match pool
            .process_tcp(segment(false, 1000, &sequence(0, 4), 7), ())
            .unwrap()
        {
            TcpReassemblyEvent::Segment { id, direction, .. } => {
                assert_eq!(id, conn_id(7));
                assert_eq!(direction, A_TO_B);
            }
            other => panic!("expected Segment, got {other:?}"),
        }

        // ... as do segments of both directions of an existing connection
        match pool
            .process_tcp(segment(true, 5000, &sequence(4, 4), 7), ())
            .unwrap()
        {
            TcpReassemblyEvent::Segment { id, direction, .. } => {
                assert_eq!(id, conn_id(7));
                assert_eq!(direction, A_TO_B.reverse());
            }
            other => panic!("expected Segment, got {other:?}"),
        }

        // ... and the close event
        let mut rst = segment(false, 1004, &[], 7);
        rst.rst = true;
        match pool.process_tcp(rst, ()).unwrap() {
            TcpReassemblyEvent::Closed { id, .. } => assert_eq!(id, conn_id(7)),
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn lazy_init_without_syn() {
        let mut pool = new_pool::<()>();
        let buf = sender(
            pool.process_tcp(segment(false, 5000, &sequence(0, 4), 0), ())
                .unwrap(),
        );
        assert_eq!(buf.base_sequence_number(), Some(5000));
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert_eq!(false, buf.syn_observed());
    }

    #[test]
    fn pure_ack_of_unknown_connection_is_ignored() {
        let mut pool = new_pool::<()>();
        let mut ack = segment(false, 5000, &[], 0);
        ack.acknowledgment_number = Some(1);
        assert_ignored(pool.process_tcp(ack, ()).unwrap());
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn duplicated_syn_keeps_connection_state() {
        let mut pool = new_pool::<()>();

        let mut syn = segment(false, 999, &[], 0);
        syn.syn = true;
        pool.process_tcp(syn, ()).unwrap();
        let buf = sender(
            pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
                .unwrap(),
        );
        buf.consume(4);

        // a duplicate of the SYN arrives late -> state must be kept
        let mut syn = segment(false, 999, &[], 0);
        syn.syn = true;
        let buf = sender(pool.process_tcp(syn, ()).unwrap());
        assert_eq!(buf.base_offset(), 4);
        assert_eq!(buf.contiguous(), &sequence(4, 4)[..]);
    }

    #[test]
    fn late_syn_marks_stream_start_observed() {
        let mut pool = new_pool::<()>();

        // connection anchored mid-stream (data before the SYN was seen)
        let buf = sender(
            pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
                .unwrap(),
        );
        assert_eq!(false, buf.syn_observed());

        // the SYN arrives re-ordered (isn 999 -> data starts at 1000)
        let mut syn = segment(false, 999, &[], 0);
        syn.syn = true;
        let buf = sender(pool.process_tcp(syn, ()).unwrap());
        assert!(buf.syn_observed());
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
    }

    #[test]
    fn syn_with_fin_and_payload() {
        // TCP Fast Open SYN with payload & FIN in one segment
        let mut pool = new_pool::<()>();
        let payload = sequence(0, 4);
        let mut seg = segment(false, 999, &payload, 0);
        seg.syn = true;
        seg.fin = true;
        let buf = sender(pool.process_tcp(seg, ()).unwrap());
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert!(buf.is_fin_reached());

        // SYN+FIN without payload must record the FIN as well
        let mut seg = segment(false, 42, &[], 1);
        seg.syn = true;
        seg.fin = true;
        let buf = sender(pool.process_tcp(seg, ()).unwrap());
        assert_eq!(buf.fin_offset(), Some(0));
        assert!(buf.is_fin_reached());
    }

    #[test]
    fn rst_closes_both_directions_and_recycles_on_next_call() {
        let mut pool = new_pool::<()>();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();
        pool.process_tcp(segment(true, 5000, &sequence(8, 4), 0), ())
            .unwrap();
        assert_eq!(pool.active_connections(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 0);

        // the RST ends the whole connection, both directions stay drainable
        let mut rst = segment(false, 1008, &[], 0);
        rst.rst = true;
        let connection = closed(pool.process_tcp(rst, ()).unwrap());
        assert_eq!(
            connection.stream(A_TO_B).contiguous_unacked(),
            &sequence(0, 8)[..]
        );
        assert_eq!(
            connection.stream(A_TO_B.reverse()).contiguous_unacked(),
            &sequence(8, 4)[..]
        );
        assert_eq!(pool.active_connections(), 0);
        // not yet recycled (still drainable)
        assert_eq!(pool.finished_data_bufs.len(), 0);

        // a RST for an unknown connection is ignored & the closed connection
        // of the previous call is recycled (two buffers, one per direction)
        let mut rst = segment(false, 1, &[], 1);
        rst.rst = true;
        assert_ignored(pool.process_tcp(rst, ()).unwrap());
        assert_eq!(pool.finished_data_bufs.len(), 2);
        assert_eq!(pool.finished_section_bufs.len(), 2);
    }

    #[test]
    fn rst_outside_of_the_window_is_ignored() {
        let mut pool = new_pool::<()>();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();

        // blindly injected RST with a sequence number far outside the window
        let mut rst = segment(false, 0x4000_0000, &[], 0);
        rst.rst = true;
        assert_ignored(pool.process_tcp(rst, ()).unwrap());
        assert_eq!(pool.active_connections(), 1);

        // a stale RST (behind the read cursor) is ignored as well
        let mut rst = segment(false, 900, &[], 0);
        rst.rst = true;
        assert_ignored(pool.process_tcp(rst, ()).unwrap());
        assert_eq!(pool.active_connections(), 1);

        // ... while a plausible one ends the connection
        let mut rst = segment(false, 1008, &[], 0);
        rst.rst = true;
        let _ = closed(pool.process_tcp(rst, ()).unwrap());
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn reconnect_via_syn() {
        let mut pool = new_pool::<()>();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();

        // reconnect: a new SYN with a fresh ISN replaces the connection, the
        // old data stays drainable via the "Closed" event
        let mut syn = segment(false, 20000, &[], 0);
        syn.syn = true;
        let connection = closed(pool.process_tcp(syn, ()).unwrap());
        assert_eq!(
            connection.stream(A_TO_B).contiguous_unacked(),
            &sequence(0, 8)[..]
        );
        assert_eq!(pool.active_connections(), 1);

        // the new connection is registered & re-based
        let buf = pool.stream_mut(&conn_id(0), A_TO_B).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(20001));
        assert!(buf.contiguous().is_empty());

        let buf = sender(
            pool.process_tcp(segment(false, 20001, &sequence(100, 4), 0), ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(100, 4)[..]);
    }

    #[test]
    fn reconnect_with_lower_isn_is_detected() {
        // initial sequence numbers are random, so a reconnect is just as
        // likely to pick a *lower* isn as a higher one
        let mut pool = new_pool::<()>();

        let mut syn = segment(false, 999, &[], 0);
        syn.syn = true;
        pool.process_tcp(syn, ()).unwrap();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();

        let mut syn = segment(false, 499, &[], 0);
        syn.syn = true;
        let connection = closed(pool.process_tcp(syn, ()).unwrap());
        assert_eq!(
            connection.stream(A_TO_B).contiguous_unacked(),
            &sequence(0, 8)[..]
        );

        // the new connection carries none of the old data
        let buf = pool.stream_mut(&conn_id(0), A_TO_B).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(500));
        assert!(buf.contiguous().is_empty());

        let buf = sender(
            pool.process_tcp(segment(false, 500, &sequence(100, 4), 0), ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(100, 4)[..]);
        assert_eq!(buf.sections().len(), 1);
    }

    #[test]
    fn reconnect_via_syn_without_leftover() {
        let mut pool = new_pool::<()>();
        let buf = sender(
            pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
                .unwrap(),
        );
        buf.consume(8);

        // nothing left to drain -> the new connection is returned directly &
        // the old buffers are recycled
        let mut syn = segment(false, 20000, &[], 0);
        syn.syn = true;
        let buf = sender(pool.process_tcp(syn, ()).unwrap());
        assert_eq!(buf.base_sequence_number(), Some(20001));
        assert_eq!(pool.active_connections(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 2);
    }

    #[test]
    fn error_on_fresh_connection_recycles_bufs() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::with_max_capacity(8);
        let err = pool
            .process_tcp(segment(false, 0, &sequence(0, 16), 0), ())
            .unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 16,
                max_capacity: 8
            }
        );
        assert_eq!(pool.active_connections(), 0);
        // both direction buffers were returned
        assert_eq!(pool.finished_data_bufs.len(), 2);
        assert_eq!(pool.finished_section_bufs.len(), 2);
    }

    #[test]
    fn error_on_existing_connection_keeps_it() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::with_max_capacity(8)
            .with_ack_policy(TcpAckPolicy::Ignore);
        pool.process_tcp(segment(false, 0, &sequence(0, 4), 0), ())
            .unwrap();
        let err = pool
            .process_tcp(segment(false, 4, &sequence(4, 16), 0), ())
            .unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 20,
                max_capacity: 8
            }
        );
        // the connection is retained with its previously received data
        assert_eq!(pool.active_connections(), 1);
        let buf = pool.stream_mut(&conn_id(0), A_TO_B).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn connection_access_and_end_connection() {
        let mut pool = new_pool::<()>();
        assert!(pool.connection(&conn_id(0)).is_none());
        assert!(pool.connection_mut(&conn_id(0)).is_none());
        assert!(pool.stream_mut(&conn_id(0), A_TO_B).is_none());

        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();
        assert!(pool.connection(&conn_id(0)).is_some());
        assert!(pool.connection_mut(&conn_id(0)).is_some());
        assert_eq!(
            pool.stream_mut(&conn_id(0), A_TO_B).unwrap().contiguous(),
            &sequence(0, 8)[..]
        );

        pool.end_connection(&conn_id(0));
        assert_eq!(pool.active_connections(), 0);
        assert_eq!(pool.finished_data_bufs.len(), 2);
    }

    #[test]
    fn is_bidirectional_detects_unpaired_directions() {
        let mut pool = new_pool::<()>();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), ())
            .unwrap();
        assert_eq!(
            false,
            pool.connection(&conn_id(0)).unwrap().is_bidirectional()
        );

        // even a pure ACK of the reverse direction anchors it
        let mut ack = segment(true, 5000, &[], 0);
        ack.acknowledgment_number = Some(1008);
        pool.process_tcp(ack, ()).unwrap();
        assert!(pool.connection(&conn_id(0)).unwrap().is_bidirectional());
    }

    #[test]
    fn vlan_ids_are_part_of_the_identity() {
        let mut vlan_a = ArrayVec::<VlanId, 3>::new_const();
        vlan_a.push(VlanId::try_new(10).unwrap());
        let mut vlan_b = ArrayVec::<VlanId, 3>::new_const();
        vlan_b.push(VlanId::try_new(20).unwrap());

        let payload_a = sequence(0, 8);
        let payload_b = sequence(8, 4);

        // the two directions are tagged differently -> two separate
        // connections, each containing only one direction
        let mut pool = new_pool::<()>();
        let mut seg = segment(false, 1000, &payload_a, 0);
        seg.vlan_ids = vlan_a.clone();
        pool.process_tcp(seg, ()).unwrap();
        let mut seg = segment(true, 5000, &payload_b, 0);
        seg.vlan_ids = vlan_b.clone();
        pool.process_tcp(seg, ()).unwrap();

        assert_eq!(pool.active_connections(), 2);
        for (_id, connection, _) in pool.iter_mut() {
            assert_eq!(false, connection.is_bidirectional());
        }

        // clearing the vlan ids (e.g. after moving them into the channel id)
        // matches the two directions up again
        let mut pool = new_pool::<()>();
        let mut seg = segment(false, 1000, &payload_a, 0);
        seg.vlan_ids.clear();
        pool.process_tcp(seg, ()).unwrap();
        let mut seg = segment(true, 5000, &payload_b, 0);
        seg.vlan_ids.clear();
        pool.process_tcp(seg, ()).unwrap();

        assert_eq!(pool.active_connections(), 1);
        assert!(pool.connection(&conn_id(0)).unwrap().is_bidirectional());
    }

    #[test]
    fn iter_mut_drains_leftovers() {
        let mut pool = new_pool::<u32>();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), 1)
            .unwrap();
        pool.process_tcp(segment(false, 2000, &sequence(8, 4), 1), 2)
            .unwrap();

        // e.g. at the end of a capture: collect the data of all connections
        let mut collected = Vec::new();
        for (id, connection, timestamp) in pool.iter_mut() {
            let channel_id = *id.channel_id();
            let buf = connection.stream_mut(A_TO_B);
            let len = buf.contiguous_unacked().len();
            collected.push((channel_id, buf.contiguous_unacked().to_vec(), *timestamp));
            buf.consume_unacked(len);
        }
        collected.sort();
        assert_eq!(
            collected,
            std::vec![(0, sequence(0, 8), 1), (1, sequence(8, 4), 2)]
        );
    }

    #[test]
    fn retain_evicts_and_recycles() {
        let mut pool = new_pool::<u32>();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 0), 1)
            .unwrap();
        pool.process_tcp(segment(false, 1000, &sequence(0, 8), 1), 2)
            .unwrap();
        assert_eq!(pool.active_connections(), 2);

        // no-op retain
        pool.retain(|_, ts| *ts > 0);
        assert_eq!(pool.active_connections(), 2);

        // evict timestamp 1 (the connection id is passed to the predicate too)
        pool.retain(|id, ts| {
            assert_eq!(id.second().port, 80);
            *ts > 1
        });
        assert_eq!(pool.active_connections(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 2);
        assert_eq!(pool.finished_section_bufs.len(), 2);
        assert!(pool.connection(&conn_id(1)).is_some());
    }

    #[test]
    fn free_lists_are_bounded() {
        // evicting many connections must not make the pool hold on to the
        // buffers of every one of them forever
        let payload = sequence(0, 64);
        let mut pool = new_pool::<u32>();
        for channel_id in 0..200u16 {
            pool.process_tcp(segment(false, 1000, &payload, channel_id), 1)
                .unwrap();
        }
        assert_eq!(pool.active_connections(), 200);

        pool.retain(|_, _| false);
        assert_eq!(pool.active_connections(), 0);

        assert_eq!(pool.finished_data_bufs.len(), DEFAULT_MAX_TCP_POOLED_BUFS);
        assert_eq!(
            pool.finished_section_bufs.len(),
            DEFAULT_MAX_TCP_POOLED_BUFS
        );

        // the pooled buffers are still re-used
        pool.process_tcp(segment(false, 1000, &payload, 0), 1)
            .unwrap();
        assert_eq!(
            pool.finished_data_bufs.len(),
            DEFAULT_MAX_TCP_POOLED_BUFS - 2
        );
    }

    #[test]
    fn oversized_bufs_are_shrunk_before_pooling() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new()
            .with_ack_policy(TcpAckPolicy::Ignore)
            .with_pool_limits(8, 1024);

        // a stream that buffers far more than the pooled buffer limit
        let payload = sequence(0, 16 * 1024);
        pool.process_tcp(segment(false, 1000, &payload, 0), ())
            .unwrap();
        pool.end_connection(&conn_id(0));

        // the memory of the burst is released instead of being held forever
        assert_eq!(pool.finished_data_bufs.len(), 2);
        for buf in &pool.finished_data_bufs {
            assert!(
                buf.capacity() <= 1024,
                "oversized buffer kept: {}",
                buf.capacity()
            );
        }
    }

    #[test]
    fn max_connections_limit() {
        let payload = sequence(0, 4);
        let mut pool = new_pool::<()>().with_max_connections(2);
        assert_eq!(pool.max_connections(), Some(2));

        pool.process_tcp(segment(false, 1000, &payload, 0), ())
            .unwrap();
        pool.process_tcp(segment(false, 1000, &payload, 1), ())
            .unwrap();
        assert_eq!(pool.active_connections(), 2);

        // a third connection is rejected ...
        let err = pool
            .process_tcp(segment(false, 1000, &payload, 2), ())
            .unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::TooManyConnections { max_connections: 2 }
        );
        assert_eq!(pool.active_connections(), 2);

        // ... while the already tracked ones keep working
        let buf = sender(
            pool.process_tcp(segment(false, 1004, &sequence(4, 4), 0), ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);

        // evicting makes room again
        pool.retain(|id, _| *id.channel_id() != 0);
        assert_eq!(pool.active_connections(), 1);
        pool.process_tcp(segment(false, 1000, &payload, 2), ())
            .unwrap();
        assert_eq!(pool.active_connections(), 2);
    }

    #[test]
    fn unlimited_connections_by_default() {
        let pool = TcpStreamReassemblyPool::<(), ()>::new();
        assert_eq!(pool.max_connections(), None);
        assert_eq!(pool.max_pooled_bufs, DEFAULT_MAX_TCP_POOLED_BUFS);
        assert_eq!(
            pool.max_pooled_buf_capacity,
            DEFAULT_MAX_TCP_POOLED_BUF_CAPACITY
        );
    }

    #[test]
    fn is_closed_after_both_fins() {
        let mut pool = new_pool::<()>();

        let payload = sequence(0, 4);
        let mut fin = segment(false, 1000, &payload, 0);
        fin.fin = true;
        pool.process_tcp(fin, ()).unwrap();
        // only one direction is done so far
        assert_eq!(false, pool.connection(&conn_id(0)).unwrap().is_closed());

        let mut fin = segment(true, 5000, &payload, 0);
        fin.fin = true;
        pool.process_tcp(fin, ()).unwrap();
        assert!(pool.connection(&conn_id(0)).unwrap().is_closed());

        // the connection is not evicted automatically, the data is still there
        assert_eq!(pool.active_connections(), 1);
        pool.retain(|_, _| false);
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn process_lax_sliced_packet() {
        let mut pool = new_pool::<()>();

        // a laxly parsed packet is accepted as well
        let payload = sequence(0, 8);
        let pdata = build_ipv4_tcp_packet(1000, false, false, false, &payload);
        let slice = LaxSlicedPacket::from_ethernet(&pdata).unwrap();
        let buf = sender(pool.process_lax_sliced_packet(&slice, (), 0).unwrap());
        assert_eq!(buf.contiguous(), &payload[..]);
        assert_eq!(pool.active_connections(), 1);

        // a packet without a TCP layer is ignored
        let empty = LaxSlicedPacket {
            link: None,
            link_exts: Default::default(),
            net: None,
            transport: None,
            stop_err: None,
        };
        assert_ignored(pool.process_lax_sliced_packet(&empty, (), 0).unwrap());
    }

    #[test]
    fn non_tcp_and_process_sliced_packet() {
        let mut pool = TcpStreamReassemblyPool::<(), ()>::new().with_ack_policy(TcpAckPolicy::Ignore);

        // empty sliced packet -> Ignored
        let empty = SlicedPacket {
            link: None,
            link_exts: ArrayVec::new_const(),
            net: None,
            transport: None,
        };
        assert_ignored(pool.process_sliced_packet(&empty, (), ()).unwrap());

        // build a real ethernet/ipv4/tcp packet and feed it
        let payload = sequence(0, 8);
        let pdata = build_ipv4_tcp_packet(1000, false, false, false, &payload);
        let slice = SlicedPacket::from_ethernet(&pdata).unwrap();
        let buf = sender(pool.process_sliced_packet(&slice, (), ()).unwrap());
        assert_eq!(buf.contiguous(), &payload[..]);
        assert_eq!(pool.active_connections(), 1);

        // RST via a sliced packet closes the connection
        let pdata = build_ipv4_tcp_packet(1008, false, false, true, &[]);
        let slice = SlicedPacket::from_ethernet(&pdata).unwrap();
        let connection = closed(pool.process_sliced_packet(&slice, (), ()).unwrap());
        assert_eq!(
            connection.stream(A_TO_B).contiguous_unacked(),
            &payload[..]
        );
        assert_eq!(pool.active_connections(), 0);
    }

    proptest! {
        /// Drives a full bidirectional exchange through the pool: a handshake,
        /// the client data split into randomly re-ordered & duplicated
        /// segments, server acknowledgments releasing it and injected garbage
        /// (out of window RSTs & pure ACKs) that must not disturb anything.
        #[test]
        fn pool_reassemble_random(
            reference in proptest::collection::vec(any::<u8>(), 1..400usize),
            client_isn in any::<u32>(),
            server_isn in any::<u32>(),
            seed in any::<u64>(),
        ) {
            // simple deterministic xorshift RNG so no extra dependency is needed
            let mut state = seed | 1;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };

            // split the reference into contiguous segments, duplicate some of
            // them & shuffle the send order
            let mut segments: Vec<(usize, usize)> = Vec::new();
            let mut pos = 0usize;
            while pos < reference.len() {
                let remaining = reference.len() - pos;
                let len = 1 + (next() as usize % remaining.min(40));
                segments.push((pos, len));
                pos += len;
            }
            let mut to_send = segments.clone();
            for seg in &segments {
                if next() & 1 == 0 {
                    to_send.push(*seg);
                }
            }
            for i in (1..to_send.len()).rev() {
                let j = next() as usize % (i + 1);
                to_send.swap(i, j);
            }

            // the SYN consumes one sequence number
            let data_start = client_isn.wrapping_add(1);
            let id = conn_id(0);
            let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
            let mut collected: Vec<u8> = Vec::new();

            /// Feeds a segment & asserts the connection was not torn down.
            macro_rules! feed {
                ($seg:expr) => {
                    match pool.process_tcp($seg, ()) {
                        Ok(TcpReassemblyEvent::Closed { .. }) => {
                            return Err(TestCaseError::fail("unexpected connection close"))
                        }
                        Ok(_) => {}
                        Err(err) => {
                            return Err(TestCaseError::fail(std::format!("{err}")))
                        }
                    }
                };
            }

            // handshake
            let mut syn = segment(false, client_isn, &[], 0);
            syn.syn = true;
            feed!(syn);
            let mut syn_ack = segment(true, server_isn, &[], 0);
            syn_ack.syn = true;
            syn_ack.acknowledgment_number = Some(data_start);
            feed!(syn_ack);

            for (offset, len) in to_send {
                let is_last = offset + len == reference.len();
                let mut seg = segment(
                    false,
                    data_start.wrapping_add(offset as u32),
                    &reference[offset..offset + len],
                    0,
                );
                seg.fin = is_last;
                seg.acknowledgment_number = Some(server_isn.wrapping_add(1));
                feed!(seg);

                // an out of window RST must never end the connection: one far
                // in the future & one behind the read cursor
                if next() & 3 == 0 {
                    let bogus = if next() & 1 == 0 {
                        data_start.wrapping_add(5_000_000)
                    } else {
                        data_start.wrapping_sub(1_000)
                    };
                    let mut rst = segment(false, bogus, &[], 0);
                    rst.rst = true;
                    feed!(rst);
                }

                // the server acknowledges a random position of the stream
                if next() & 1 == 0 {
                    let acked = next() as usize % (reference.len() + 1);
                    let mut ack = segment(true, server_isn.wrapping_add(1), &[], 0);
                    ack.acknowledgment_number =
                        Some(data_start.wrapping_add(acked as u32));
                    feed!(ack);
                }

                // drain whatever became available
                if let Some(stream) = pool.stream_mut(&id, A_TO_B) {
                    stream.drain(|available| {
                        collected.extend_from_slice(available);
                        available.len()
                    });
                }
            }

            // the server acknowledges everything
            let mut ack = segment(true, server_isn.wrapping_add(1), &[], 0);
            ack.acknowledgment_number =
                Some(data_start.wrapping_add(reference.len() as u32));
            feed!(ack);

            let stream = pool.stream_mut(&id, A_TO_B).unwrap();
            stream.drain(|available| {
                collected.extend_from_slice(available);
                available.len()
            });

            prop_assert_eq!(&collected, &reference);
            prop_assert!(stream.syn_observed());
            prop_assert!(stream.is_fin_reached());
            prop_assert_eq!(pool.active_connections(), 1);
            prop_assert!(pool.connection(&id).unwrap().is_bidirectional());

            // an in window RST does end it
            let mut rst = segment(
                false,
                data_start.wrapping_add(reference.len() as u32),
                &[],
                0,
            );
            rst.rst = true;
            match pool.process_tcp(rst, ()) {
                Ok(TcpReassemblyEvent::Closed { .. }) => {}
                other => {
                    return Err(TestCaseError::fail(std::format!(
                        "expected the connection to be closed, got {other:?}"
                    )))
                }
            }
            prop_assert_eq!(pool.active_connections(), 0);
        }

        /// A SYN with a new initial sequence number replaces the connection
        /// without leaking any data of the previous one.
        #[test]
        fn pool_reconnect_random(
            first in proptest::collection::vec(any::<u8>(), 1..200usize),
            second in proptest::collection::vec(any::<u8>(), 1..200usize),
            first_isn in any::<u32>(),
            second_isn in any::<u32>(),
        ) {
            // the two connections have to be distinguishable
            prop_assume!(first_isn != second_isn);

            let id = conn_id(0);
            let mut pool = new_pool::<()>();

            // first connection
            let mut syn = segment(false, first_isn, &[], 0);
            syn.syn = true;
            pool.process_tcp(syn, ()).unwrap();
            pool.process_tcp(
                segment(false, first_isn.wrapping_add(1), &first, 0),
                (),
            )
            .unwrap();

            // reconnect with a fresh isn (which is just as likely to be lower
            // as it is to be higher than the previous one)
            let mut syn = segment(false, second_isn, &[], 0);
            syn.syn = true;
            match pool.process_tcp(syn, ()) {
                Ok(TcpReassemblyEvent::Closed { id: closed_id, connection }) => {
                    prop_assert_eq!(closed_id, id.clone());
                    prop_assert_eq!(
                        connection.stream(A_TO_B).contiguous_unacked(),
                        &first[..]
                    );
                }
                other => {
                    return Err(TestCaseError::fail(std::format!(
                        "expected the previous connection to be closed, got {other:?}"
                    )))
                }
            }

            // the replacement carries only the data of the new connection
            pool.process_tcp(
                segment(false, second_isn.wrapping_add(1), &second, 0),
                (),
            )
            .unwrap();
            let stream = pool.stream_mut(&id, A_TO_B).unwrap();
            prop_assert_eq!(
                stream.base_sequence_number(),
                Some(second_isn.wrapping_add(1))
            );
            prop_assert_eq!(stream.contiguous(), &second[..]);
            prop_assert_eq!(stream.sections().len(), 1);
        }
    }

    fn build_ipv4_tcp_packet(seq: u32, syn: bool, fin: bool, rst: bool, payload: &[u8]) -> Vec<u8> {
        let mut tcp = TcpHeader::new(1234, 80, seq, 4096);
        tcp.syn = syn;
        tcp.fin = fin;
        tcp.rst = rst;
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
}
