use crate::{tcp_reassembly::*, *};
use std::collections::HashMap;
use std::vec::Vec;

/// Result of processing a packet with a [`TcpStreamReassemblyPool`].
#[derive(Debug)]
pub enum TcpReassemblyEvent<'a> {
    /// The packet did not affect any stream (not a TCP segment, a RST for an
    /// unknown stream or an empty segment of an unknown stream, e.g. a pure
    /// ACK).
    Ignored,

    /// The segment belongs to this (potentially newly created) stream.
    ///
    /// Read the available in-order data via
    /// [`TcpStreamReassemblyBuf::contiguous`] and free it via
    /// [`TcpStreamReassemblyBuf::consume`].
    Stream(&'a mut TcpStreamReassemblyBuf),

    /// A stream was ended by a RST or replaced by a SYN with a new initial
    /// sequence number.
    ///
    /// In-order data that was never consumed can still be read from the
    /// returned buffer. The buffer is automatically recycled on the next
    /// `process_*` call.
    ///
    /// In the "replaced by a SYN" case the newly created stream can be
    /// accessed via [`TcpStreamReassemblyPool::stream_mut`].
    Closed(&'a mut TcpStreamReassemblyBuf),
}

/// Pool to reassemble the payload byte streams of multiple TCP connections in
/// parallel (re-uses buffers to minimize allocations).
///
/// Streams are differentiated by their VLAN ids, IP source & destination
/// address and TCP source & destination port. A custom "channel id" can be
/// added to further differentiate streams (e.g. when capturing from multiple
/// interfaces). Note that each *direction* of a connection is a separate stream
/// (the source & destination are swapped between the two directions).
///
/// # Interpretation of the TCP flags
///
/// * `SYN` establishes the stream start. Duplicated/retransmitted SYNs and a
///   late SYN of an already tracked stream are recognized and do **not** drop
///   already buffered data. A SYN with a new initial sequence number replaces
///   the tracked stream (see [`TcpReassemblyEvent::Closed`]).
/// * `FIN` marks the end of the stream (see
///   [`TcpStreamReassemblyBuf::is_fin_reached`]). Note that a stream is *not*
///   automatically removed from the pool when the FIN is reached (use
///   [`TcpStreamReassemblyPool::end_stream`] or
///   [`TcpStreamReassemblyPool::retain`]).
/// * `RST` ends the stream & recycles its buffers (see
///   [`TcpReassemblyEvent::Closed`]).
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
/// fragmented packets first (e.g. via [`crate::defrag::IpDefragPool`]) and
/// feed the result via [`TcpStreamReassemblyPool::process_tcp`].
///
/// # This implementation is NOT safe against "Out of Memory" attacks
///
/// While each individual stream is bounded (`max_capacity` bytes of buffered
/// data & `max_sections` tracked ranges), the number of parallel streams is
/// not. If you use the [`TcpStreamReassemblyPool`] in an untrusted environment
/// an attacker could cause an "out of memory error" by opening up many
/// parallel connections. Use [`TcpStreamReassemblyPool::retain`] (or a custom
/// `channel_id` limit) to evict stale streams.
#[derive(Debug, Clone)]
pub struct TcpStreamReassemblyPool<Timestamp = (), CustomChannelId = ()> {
    /// Currently reconstructing TCP streams.
    active: HashMap<TcpStreamId<CustomChannelId>, (TcpStreamReassemblyBuf, Timestamp)>,

    /// Stream that was closed by the last `process_*` call (RST or replaced
    /// via a SYN), kept around so the caller can still drain the leftover
    /// data. Recycled at the start of the next `process_*` call.
    pending_closed: Option<TcpStreamReassemblyBuf>,

    /// Data buffers that can be re-used.
    finished_data_bufs: Vec<Vec<u8>>,

    /// Section buffers that can be re-used.
    finished_section_bufs: Vec<Vec<TcpSegmentRange>>,

    /// Maximum number of bytes buffered ahead of the read cursor per stream.
    default_max_capacity: usize,

    /// Maximum number of separate (non-contiguous) data sections per stream.
    default_max_sections: usize,
}

/// Takes a buffer from the free lists (or allocates a new one).
fn pop_free_buf(
    free_data: &mut Vec<Vec<u8>>,
    free_sections: &mut Vec<Vec<TcpSegmentRange>>,
    max_capacity: usize,
    max_sections: usize,
) -> TcpStreamReassemblyBuf {
    TcpStreamReassemblyBuf::new(
        free_data.pop().unwrap_or_default(),
        free_sections.pop().unwrap_or_default(),
        max_capacity,
    )
    .with_max_sections(max_sections)
}

/// Returns the allocations of the given buffer to the free lists.
fn recycle_buf(
    free_data: &mut Vec<Vec<u8>>,
    free_sections: &mut Vec<Vec<TcpSegmentRange>>,
    buf: TcpStreamReassemblyBuf,
) {
    let (data, sections) = buf.take_bufs();
    free_data.push(data);
    free_sections.push(sections);
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
    pub fn with_max_capacity(
        max_capacity: usize,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        Self::with_limits(max_capacity, DEFAULT_MAX_TCP_STREAM_SECTIONS)
    }

    /// Creates a new pool with custom per stream buffer & section limits.
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
        }
    }

    /// Process a TCP segment contained in a [`SlicedPacket`].
    ///
    /// Returns:
    /// * `Ok(TcpReassemblyEvent::Ignored)` if the packet did not affect any
    ///   stream (e.g. not a TCP segment).
    /// * `Ok(TcpReassemblyEvent::Stream(..))` giving access to the affected
    ///   stream.
    /// * `Ok(TcpReassemblyEvent::Closed(..))` if a stream was ended by a RST
    ///   or replaced by a new connection (leftover data can be drained).
    /// * `Err` if the segment could not be added (see [`TcpReassembleError`]).
    pub fn process_sliced_packet(
        &mut self,
        slice: &SlicedPacket,
        timestamp: Timestamp,
        channel_id: CustomChannelId,
    ) -> Result<TcpReassemblyEvent<'_>, TcpReassembleError> {
        // only TCP segments are relevant
        let Some(TransportSlice::Tcp(tcp)) = &slice.transport else {
            return Ok(TcpReassemblyEvent::Ignored);
        };

        // extract the source & destination addresses
        let ip = match &slice.net {
            Some(NetSlice::Ipv4(v4)) => TcpStreamIpId::Ipv4 {
                source: v4.header().source(),
                destination: v4.header().destination(),
            },
            Some(NetSlice::Ipv6(v6)) => TcpStreamIpId::Ipv6 {
                source: v6.header().source(),
                destination: v6.header().destination(),
            },
            Some(NetSlice::Arp(_)) | None => {
                return Ok(TcpReassemblyEvent::Ignored);
            }
        };

        let id = TcpStreamId {
            vlan_ids: slice.vlan_ids(),
            ip,
            source_port: tcp.source_port(),
            destination_port: tcp.destination_port(),
            channel_id,
        };

        self.process(
            id,
            tcp.sequence_number(),
            tcp.payload(),
            tcp.syn(),
            tcp.fin(),
            tcp.rst(),
            timestamp,
        )
    }

    /// Process an already parsed TCP segment (lower level entry point that does
    /// not require a [`SlicedPacket`]).
    #[allow(clippy::too_many_arguments)]
    pub fn process_tcp(
        &mut self,
        id: TcpStreamId<CustomChannelId>,
        sequence_number: u32,
        payload: &[u8],
        syn: bool,
        fin: bool,
        rst: bool,
        timestamp: Timestamp,
    ) -> Result<TcpReassemblyEvent<'_>, TcpReassembleError> {
        self.process(id, sequence_number, payload, syn, fin, rst, timestamp)
    }

    #[allow(clippy::too_many_arguments)]
    fn process(
        &mut self,
        id: TcpStreamId<CustomChannelId>,
        seq: u32,
        payload: &[u8],
        syn: bool,
        fin: bool,
        rst: bool,
        timestamp: Timestamp,
    ) -> Result<TcpReassemblyEvent<'_>, TcpReassembleError> {
        use std::collections::hash_map::Entry;
        use TcpReassemblyEvent::*;

        // recycle the buffer of the stream that was closed by the previous
        // call (the caller had the chance to drain it until now)
        if let Some(closed) = self.pending_closed.take() {
            recycle_buf(
                &mut self.finished_data_bufs,
                &mut self.finished_section_bufs,
                closed,
            );
        }

        // a RST tears the stream down
        if rst {
            return Ok(match self.active.remove(&id) {
                Some((buf, _)) => Closed(self.pending_closed.insert(buf)),
                None => Ignored,
            });
        }

        match self.active.entry(id) {
            Entry::Occupied(entry) => {
                let value = entry.into_mut();

                // note: the timestamp is only updated after the fallible
                // steps, so an error leaves the stream fully unchanged
                match value.0.add_segment(seq, payload, syn, fin)? {
                    TcpSegmentOutcome::Continued => {
                        value.1 = timestamp;
                        Ok(Stream(&mut value.0))
                    }
                    TcpSegmentOutcome::NewConnection => {
                        // reconnect: replace the stream with a fresh one
                        let mut fresh = pop_free_buf(
                            &mut self.finished_data_bufs,
                            &mut self.finished_section_bufs,
                            self.default_max_capacity,
                            self.default_max_sections,
                        );
                        // the fresh buffer has no base yet, so this only
                        // fails if the SYN payload exceeds the limits. The
                        // replacement did not happen yet, so the previous
                        // stream stays untouched & accessible in that case.
                        if let Err(err) = fresh.add_segment(seq, payload, syn, fin) {
                            recycle_buf(
                                &mut self.finished_data_bufs,
                                &mut self.finished_section_bufs,
                                fresh,
                            );
                            return Err(err);
                        }

                        value.1 = timestamp;
                        let old = core::mem::replace(&mut value.0, fresh);
                        if old.contiguous().is_empty() {
                            recycle_buf(
                                &mut self.finished_data_bufs,
                                &mut self.finished_section_bufs,
                                old,
                            );
                            Ok(Stream(&mut value.0))
                        } else {
                            // "value" can no longer be returned, but the
                            // leftover data of the replaced stream can
                            Ok(Closed(self.pending_closed.insert(old)))
                        }
                    }
                }
            }
            Entry::Vacant(entry) => {
                // segments without payload, SYN & FIN carry no data for the
                // reassembly -> don't create a stream for them (e.g. pure
                // ACKs, port scans, keep alives of unknown streams)
                if payload.is_empty() && false == syn && false == fin {
                    return Ok(Ignored);
                }
                let mut buf = pop_free_buf(
                    &mut self.finished_data_bufs,
                    &mut self.finished_section_bufs,
                    self.default_max_capacity,
                    self.default_max_sections,
                );
                match buf.add_segment(seq, payload, syn, fin) {
                    Ok(_) => Ok(Stream(&mut entry.insert((buf, timestamp)).0)),
                    Err(err) => {
                        recycle_buf(
                            &mut self.finished_data_bufs,
                            &mut self.finished_section_bufs,
                            buf,
                        );
                        Err(err)
                    }
                }
            }
        }
    }

    /// Direct mutable access to an active stream (e.g. to read & consume data
    /// outside of a `process_*` call).
    pub fn stream_mut(
        &mut self,
        id: &TcpStreamId<CustomChannelId>,
    ) -> Option<&mut TcpStreamReassemblyBuf> {
        self.active.get_mut(id).map(|(buf, _)| buf)
    }

    /// Explicitly end a stream and recycle its buffers.
    pub fn end_stream(&mut self, id: &TcpStreamId<CustomChannelId>) {
        if let Some((buf, _)) = self.active.remove(id) {
            recycle_buf(
                &mut self.finished_data_bufs,
                &mut self.finished_section_bufs,
                buf,
            );
        }
    }

    /// Number of currently active streams.
    #[inline]
    pub fn active_streams(&self) -> usize {
        self.active.len()
    }

    /// Iterates over all active streams (e.g. to drain the remaining data of
    /// all streams at the end of a capture).
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<
        Item = (
            &TcpStreamId<CustomChannelId>,
            &mut TcpStreamReassemblyBuf,
            &Timestamp,
        ),
    > {
        self.active.iter_mut().map(|(id, v)| (id, &mut v.0, &v.1))
    }

    /// Retains only the streams specified by the predicate and recycles the
    /// buffers of the evicted ones (e.g. to remove streams that have not
    /// received data for a while based on the `Timestamp`).
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&TcpStreamId<CustomChannelId>, &Timestamp) -> bool,
    {
        let finished_data_bufs = &mut self.finished_data_bufs;
        let finished_section_bufs = &mut self.finished_section_bufs;
        self.active.retain(|id, value| {
            if f(id, &value.1) {
                true
            } else {
                recycle_buf(
                    finished_data_bufs,
                    finished_section_bufs,
                    core::mem::replace(
                        &mut value.0,
                        TcpStreamReassemblyBuf::new(Vec::new(), Vec::new(), 0),
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
    use std::vec::Vec;

    fn ipv4_id(channel_id: u16) -> TcpStreamId<u16> {
        TcpStreamId {
            vlan_ids: ArrayVec::new_const(),
            ip: TcpStreamIpId::Ipv4 {
                source: [1, 2, 3, 4],
                destination: [5, 6, 7, 8],
            },
            source_port: 1234,
            destination_port: 80,
            channel_id,
        }
    }

    fn sequence(start: usize, len: usize) -> Vec<u8> {
        (start..start + len).map(|i| (i & 0xff) as u8).collect()
    }

    /// Unwraps a [`TcpReassemblyEvent::Stream`].
    fn stream(ev: TcpReassemblyEvent<'_>) -> &mut TcpStreamReassemblyBuf {
        match ev {
            TcpReassemblyEvent::Stream(buf) => buf,
            other => panic!("expected TcpReassemblyEvent::Stream, got {other:?}"),
        }
    }

    /// Unwraps a [`TcpReassemblyEvent::Closed`].
    fn closed(ev: TcpReassemblyEvent<'_>) -> &mut TcpStreamReassemblyBuf {
        match ev {
            TcpReassemblyEvent::Closed(buf) => buf,
            other => panic!("expected TcpReassemblyEvent::Closed, got {other:?}"),
        }
    }

    fn assert_ignored(ev: TcpReassemblyEvent<'_>) {
        assert!(matches!(ev, TcpReassemblyEvent::Ignored));
    }

    #[test]
    fn new_default() {
        let pool = TcpStreamReassemblyPool::<(), ()>::new();
        assert_eq!(pool.active_streams(), 0);
        let pool: TcpStreamReassemblyPool<u32, u16> = Default::default();
        assert_eq!(pool.active_streams(), 0);
        let pool = TcpStreamReassemblyPool::<(), ()>::with_max_capacity(16);
        assert_eq!(pool.default_max_capacity, 16);
        assert_eq!(pool.default_max_sections, DEFAULT_MAX_TCP_STREAM_SECTIONS);
        let pool = TcpStreamReassemblyPool::<(), ()>::with_limits(16, 4);
        assert_eq!(pool.default_max_capacity, 16);
        assert_eq!(pool.default_max_sections, 4);
    }

    #[test]
    fn debug_clone() {
        let pool = TcpStreamReassemblyPool::<(), ()>::new();
        let _ = std::format!("{:?}", pool.clone());
    }

    #[test]
    fn basic_syn_data_flow() {
        let mut pool = TcpStreamReassemblyPool::<u32, u16>::new();
        let id = ipv4_id(0);

        // SYN (isn = 999, so data starts at 1000)
        let buf = stream(
            pool.process_tcp(id.clone(), 999, &[], true, false, false, 1)
                .unwrap(),
        );
        assert_eq!(buf.base_sequence_number(), Some(1000));
        assert!(buf.syn_observed());
        assert_eq!(pool.active_streams(), 1);

        // data
        let buf = stream(
            pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, 2)
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
        buf.consume(8);

        // more data + FIN
        let buf = stream(
            pool.process_tcp(id.clone(), 1008, &sequence(8, 4), false, true, false, 3)
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(8, 4)[..]);
        assert!(buf.is_fin_reached());
    }

    #[test]
    fn lazy_init_without_syn() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);
        // first ever segment is data (no SYN captured)
        let buf = stream(
            pool.process_tcp(id.clone(), 5000, &sequence(0, 4), false, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.base_sequence_number(), Some(5000));
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        // identifiable as "stream start not observed"
        assert_eq!(false, buf.syn_observed());
    }

    #[test]
    fn pure_ack_of_unknown_stream_is_ignored() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        // empty segment without SYN/FIN/RST of an unknown stream -> no stream
        assert_ignored(
            pool.process_tcp(ipv4_id(0), 5000, &[], false, false, false, ())
                .unwrap(),
        );
        assert_eq!(pool.active_streams(), 0);
    }

    #[test]
    fn duplicated_syn_keeps_stream_state() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);

        // SYN + data, partially consumed
        pool.process_tcp(id.clone(), 999, &[], true, false, false, ())
            .unwrap();
        let buf = stream(
            pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
                .unwrap(),
        );
        buf.consume(4);

        // a duplicate of the SYN arrives late -> state must be kept
        let buf = stream(
            pool.process_tcp(id.clone(), 999, &[], true, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.base_offset(), 4);
        assert_eq!(buf.contiguous(), &sequence(4, 4)[..]);

        // the stream continues seamlessly
        let buf = stream(
            pool.process_tcp(id.clone(), 1008, &sequence(8, 4), false, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(4, 8)[..]);
    }

    #[test]
    fn late_syn_marks_stream_start_observed() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);

        // stream anchored mid-stream (data before the SYN was seen)
        let buf = stream(
            pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
                .unwrap(),
        );
        assert_eq!(false, buf.syn_observed());

        // the SYN arrives re-ordered (isn = 999 -> data starts at 1000)
        let buf = stream(
            pool.process_tcp(id.clone(), 999, &[], true, false, false, ())
                .unwrap(),
        );
        assert!(buf.syn_observed());
        // buffered data was kept
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
    }

    #[test]
    fn syn_with_fin_and_payload() {
        // TCP Fast Open SYN with payload & FIN in one segment
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let buf = stream(
            pool.process_tcp(ipv4_id(0), 999, &sequence(0, 4), true, true, false, ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
        assert!(buf.is_fin_reached());

        // SYN+FIN without payload must record the FIN as well
        let buf = stream(
            pool.process_tcp(ipv4_id(1), 42, &[], true, true, false, ())
                .unwrap(),
        );
        assert_eq!(buf.fin_offset(), Some(0));
        assert!(buf.is_fin_reached());
    }

    #[test]
    fn rst_closes_stream_and_recycles_on_next_call() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);
        pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
            .unwrap();
        assert_eq!(pool.active_streams(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 0);

        // RST closes the stream, the not yet consumed data stays drainable
        let buf = closed(
            pool.process_tcp(id.clone(), 1008, &[], false, false, true, ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
        assert_eq!(pool.active_streams(), 0);
        // not yet recycled (still drainable)
        assert_eq!(pool.finished_data_bufs.len(), 0);

        // a RST for an unknown stream is ignored & the closed buffer of the
        // previous call is recycled
        assert_ignored(
            pool.process_tcp(ipv4_id(1), 1, &[], false, false, true, ())
                .unwrap(),
        );
        assert_eq!(pool.finished_data_bufs.len(), 1);
        assert_eq!(pool.finished_section_bufs.len(), 1);

        // buffers get re-used for the next stream
        pool.process_tcp(ipv4_id(1), 1, &sequence(0, 4), false, false, false, ())
            .unwrap();
        assert_eq!(pool.finished_data_bufs.len(), 0);
        assert_eq!(pool.finished_section_bufs.len(), 0);
    }

    #[test]
    fn reconnect_via_syn() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);
        pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
            .unwrap();

        // reconnect: new SYN with a fresh ISN replaces the stream; the old
        // stream data stays drainable via the "Closed" event
        let buf = closed(
            pool.process_tcp(id.clone(), 20000, &[], true, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
        assert_eq!(pool.active_streams(), 1);

        // the new stream is registered & re-based
        let buf = pool.stream_mut(&id).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(20001));
        assert!(buf.contiguous().is_empty());

        let buf = stream(
            pool.process_tcp(
                id.clone(),
                20001,
                &sequence(100, 4),
                false,
                false,
                false,
                (),
            )
            .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(100, 4)[..]);
    }

    #[test]
    fn reconnect_via_syn_without_leftover() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);

        // stream with fully consumed data
        let buf = stream(
            pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
                .unwrap(),
        );
        buf.consume(8);

        // reconnect with a new ISN -> nothing left to drain, so the new
        // stream is returned directly & the old buffer is recycled
        let buf = stream(
            pool.process_tcp(id.clone(), 20000, &[], true, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.base_sequence_number(), Some(20001));
        assert_eq!(pool.active_streams(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 1);
    }

    #[test]
    fn error_on_fresh_stream_recycles_buf() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::with_max_capacity(8);
        let id = ipv4_id(0);
        // first segment already exceeds the window -> error, no stream created,
        // buffers recycled
        let err = pool
            .process_tcp(id, 0, &sequence(0, 16), false, false, false, ())
            .unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 16,
                max_capacity: 8
            }
        );
        assert_eq!(pool.active_streams(), 0);
        assert_eq!(pool.finished_data_bufs.len(), 1);
        assert_eq!(pool.finished_section_bufs.len(), 1);
    }

    #[test]
    fn error_on_existing_stream_keeps_it() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::with_max_capacity(8);
        let id = ipv4_id(0);
        pool.process_tcp(id.clone(), 0, &sequence(0, 4), false, false, false, ())
            .unwrap();
        let err = pool
            .process_tcp(id.clone(), 4, &sequence(4, 16), false, false, false, ())
            .unwrap_err();
        assert_eq!(
            err,
            TcpReassembleError::SegmentBeyondMaxWindow {
                required_capacity: 20,
                max_capacity: 8
            }
        );
        // the stream is retained with its previously received data
        assert_eq!(pool.active_streams(), 1);
        let buf = pool.stream_mut(&id).unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn stream_mut_and_end_stream() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);
        assert!(pool.stream_mut(&id).is_none());
        pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
            .unwrap();
        assert!(pool.stream_mut(&id).is_some());
        pool.end_stream(&id);
        assert_eq!(pool.active_streams(), 0);
        assert_eq!(pool.finished_data_bufs.len(), 1);
    }

    #[test]
    fn iter_mut_drains_leftovers() {
        let mut pool = TcpStreamReassemblyPool::<u32, u16>::new();
        pool.process_tcp(ipv4_id(0), 1000, &sequence(0, 8), false, false, false, 1)
            .unwrap();
        pool.process_tcp(ipv4_id(1), 2000, &sequence(8, 4), false, false, false, 2)
            .unwrap();

        // e.g. at the end of a capture: collect the data of all streams
        let mut collected = Vec::new();
        for (id, buf, timestamp) in pool.iter_mut() {
            let len = buf.contiguous().len();
            collected.push((id.channel_id, buf.contiguous().to_vec(), *timestamp));
            buf.consume(len);
        }
        collected.sort();
        assert_eq!(
            collected,
            std::vec![(0, sequence(0, 8), 1), (1, sequence(8, 4), 2)]
        );
    }

    #[test]
    fn retain_evicts_and_recycles() {
        let mut pool = TcpStreamReassemblyPool::<u32, u16>::new();
        pool.process_tcp(ipv4_id(0), 1000, &sequence(0, 8), false, false, false, 1)
            .unwrap();
        pool.process_tcp(ipv4_id(1), 1000, &sequence(0, 8), false, false, false, 2)
            .unwrap();
        assert_eq!(pool.active_streams(), 2);

        // no-op retain
        pool.retain(|_, ts| *ts > 0);
        assert_eq!(pool.active_streams(), 2);

        // evict timestamp 1 (the stream id is passed to the predicate too)
        pool.retain(|id, ts| {
            assert_eq!(id.destination_port, 80);
            *ts > 1
        });
        assert_eq!(pool.active_streams(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 1);
        assert_eq!(pool.finished_section_bufs.len(), 1);
        assert!(pool.stream_mut(&ipv4_id(1)).is_some());
    }

    #[test]
    fn non_tcp_and_process_sliced_packet() {
        let mut pool = TcpStreamReassemblyPool::<(), ()>::new();

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
        let buf = stream(pool.process_sliced_packet(&slice, (), ()).unwrap());
        assert_eq!(buf.contiguous(), &payload[..]);
        assert_eq!(pool.active_streams(), 1);

        // RST via a sliced packet closes the stream
        let pdata = build_ipv4_tcp_packet(1008, false, false, true, &[]);
        let slice = SlicedPacket::from_ethernet(&pdata).unwrap();
        let buf = closed(pool.process_sliced_packet(&slice, (), ()).unwrap());
        assert_eq!(buf.contiguous(), &payload[..]);
        assert_eq!(pool.active_streams(), 0);
    }

    #[test]
    fn reconnect_with_lower_isn_is_detected() {
        // initial sequence numbers are random, so a reconnect is just as
        // likely to pick a *lower* isn as a higher one
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);

        pool.process_tcp(id.clone(), 999, &[], true, false, false, ())
            .unwrap();
        pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
            .unwrap();

        // reconnect: the old stream is closed & stays drainable
        let buf = closed(
            pool.process_tcp(id.clone(), 499, &[], true, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);

        // the new stream is re-based and carries none of the old data
        let buf = pool.stream_mut(&id).unwrap();
        assert_eq!(buf.base_sequence_number(), Some(500));
        assert!(buf.contiguous().is_empty());

        let buf = stream(
            pool.process_tcp(id.clone(), 500, &sequence(100, 4), false, false, false, ())
                .unwrap(),
        );
        assert_eq!(buf.contiguous(), &sequence(100, 4)[..]);
        assert_eq!(buf.sections().len(), 1);
    }

    #[test]
    fn free_lists_are_bounded() {
        // evicting many streams must not make the pool hold on to one buffer
        // per evicted stream forever
        let mut pool = TcpStreamReassemblyPool::<u32, u16>::new();
        for port in 0..200u16 {
            pool.process_tcp(ipv4_id(port), 1000, &sequence(0, 64), false, false, false, 1)
                .unwrap();
        }
        assert_eq!(pool.active_streams(), 200);

        pool.retain(|_, _| false);
        assert_eq!(pool.active_streams(), 0);

        // limit picked in phase 5 (max_pooled_bufs), 64 is an upper bound
        assert!(
            pool.finished_data_bufs.len() <= 64,
            "unbounded data buf free list: {}",
            pool.finished_data_bufs.len()
        );
        assert!(
            pool.finished_section_bufs.len() <= 64,
            "unbounded section buf free list: {}",
            pool.finished_section_bufs.len()
        );
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
