use crate::{tcp_reassembly::*, *};
use std::collections::HashMap;
use std::vec::Vec;

/// Pool to reassemble the payload byte streams of multiple TCP connections in
/// parallel (re-uses buffers to minimize allocations).
///
/// Streams are differentiated by their VLAN ids, IP source & destination
/// address and TCP source & destination port. A custom "channel id" can be
/// added to further differentiate streams (e.g. when capturing from multiple
/// interfaces). Note that each *direction* of a connection is a separate stream
/// (the source & destination are swapped between the two directions).
///
/// # This implementation is NOT safe against "Out of Memory" attacks
///
/// While each individual stream is bounded by `max_capacity`, the number of
/// parallel streams is not. If you use the [`TcpStreamReassemblyPool`] in an
/// untrusted environment an attacker could cause an "out of memory error" by
/// opening up many parallel connections. Use [`TcpStreamReassemblyPool::retain`]
/// (or a custom `channel_id` limit) to evict stale streams.
#[derive(Debug, Clone)]
pub struct TcpStreamReassemblyPool<Timestamp = (), CustomChannelId = ()>
where
    Timestamp: Sized + core::fmt::Debug + Clone,
    CustomChannelId: Sized + core::fmt::Debug + Clone + core::hash::Hash + Eq + PartialEq,
{
    /// Currently reconstructing TCP streams.
    active: HashMap<TcpStreamId<CustomChannelId>, (TcpStreamReassemblyBuf, Timestamp)>,

    /// Data buffers that can be re-used.
    finished_data_bufs: Vec<Vec<u8>>,

    /// Section buffers that can be re-used.
    finished_section_bufs: Vec<Vec<TcpSegmentRange>>,

    /// Maximum number of bytes buffered ahead of the read cursor per stream.
    default_max_capacity: usize,
}

impl<Timestamp, CustomChannelId> TcpStreamReassemblyPool<Timestamp, CustomChannelId>
where
    Timestamp: Sized + core::fmt::Debug + Clone,
    CustomChannelId: Sized + core::fmt::Debug + Clone + core::hash::Hash + Eq + PartialEq,
{
    /// Creates a new pool with the [`DEFAULT_MAX_TCP_STREAM_CAPACITY`] per
    /// stream limit.
    pub fn new() -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        Self::with_max_capacity(DEFAULT_MAX_TCP_STREAM_CAPACITY)
    }

    /// Creates a new pool with a custom per stream buffer limit.
    pub fn with_max_capacity(
        max_capacity: usize,
    ) -> TcpStreamReassemblyPool<Timestamp, CustomChannelId> {
        TcpStreamReassemblyPool {
            active: HashMap::new(),
            finished_data_bufs: Vec::new(),
            finished_section_bufs: Vec::new(),
            default_max_capacity: max_capacity,
        }
    }

    /// Process a TCP segment contained in a [`SlicedPacket`].
    ///
    /// Returns:
    /// * `Ok(None)` if the packet did not contain a TCP segment (or a RST reset
    ///   the stream).
    /// * `Ok(Some(&mut buf))` giving access to the affected stream. Read the
    ///   available in-order data via [`TcpStreamReassemblyBuf::contiguous`] and
    ///   free it via [`TcpStreamReassemblyBuf::consume`].
    /// * `Err` if the segment could not be added (see [`TcpReassembleError`]).
    pub fn process_sliced_packet(
        &mut self,
        slice: &SlicedPacket,
        timestamp: Timestamp,
        channel_id: CustomChannelId,
    ) -> Result<Option<&mut TcpStreamReassemblyBuf>, TcpReassembleError> {
        // only TCP segments are relevant
        let Some(TransportSlice::Tcp(tcp)) = &slice.transport else {
            return Ok(None);
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
                return Ok(None);
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
    ) -> Result<Option<&mut TcpStreamReassemblyBuf>, TcpReassembleError> {
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
    ) -> Result<Option<&mut TcpStreamReassemblyBuf>, TcpReassembleError> {
        use std::collections::hash_map::Entry;

        // a RST tears the stream down and recycles its buffers
        if rst {
            if let Some((buf, _)) = self.active.remove(&id) {
                let (data, sections) = buf.take_bufs();
                self.finished_data_bufs.push(data);
                self.finished_section_bufs.push(sections);
            }
            return Ok(None);
        }

        // a SYN (re)establishes the stream base (handles reconnects). The SYN
        // flag consumes one sequence number, so the payload starts at seq + 1.
        if syn {
            let base = seq.wrapping_add(1);
            match self.active.entry(id) {
                Entry::Occupied(mut entry) => {
                    let value = entry.get_mut();
                    value.0.reset(base);
                    value.1 = timestamp;
                    // TCP Fast Open: a SYN may already carry payload
                    if false == payload.is_empty() {
                        value.0.add(base, payload, fin)?;
                    }
                    Ok(Some(&mut entry.into_mut().0))
                }
                Entry::Vacant(entry) => {
                    let data_buf = if let Some(mut d) = self.finished_data_bufs.pop() {
                        d.clear();
                        d
                    } else {
                        Vec::new()
                    };
                    let sections = if let Some(mut s) = self.finished_section_bufs.pop() {
                        s.clear();
                        s
                    } else {
                        Vec::new()
                    };
                    let mut buf =
                        TcpStreamReassemblyBuf::new(data_buf, sections, self.default_max_capacity);
                    buf.reset(base);
                    if false == payload.is_empty() {
                        if let Err(err) = buf.add(base, payload, fin) {
                            let (data, sections) = buf.take_bufs();
                            self.finished_data_bufs.push(data);
                            self.finished_section_bufs.push(sections);
                            return Err(err);
                        }
                    }
                    Ok(Some(&mut entry.insert((buf, timestamp)).0))
                }
            }
        } else {
            // regular data / FIN / ACK segment
            match self.active.entry(id) {
                Entry::Occupied(mut entry) => {
                    let value = entry.get_mut();
                    value.1 = timestamp;
                    value.0.add(seq, payload, fin)?;
                    Ok(Some(&mut entry.into_mut().0))
                }
                Entry::Vacant(entry) => {
                    let data_buf = if let Some(mut d) = self.finished_data_bufs.pop() {
                        d.clear();
                        d
                    } else {
                        Vec::new()
                    };
                    let sections = if let Some(mut s) = self.finished_section_bufs.pop() {
                        s.clear();
                        s
                    } else {
                        Vec::new()
                    };
                    let mut buf =
                        TcpStreamReassemblyBuf::new(data_buf, sections, self.default_max_capacity);
                    match buf.add(seq, payload, fin) {
                        Ok(()) => Ok(Some(&mut entry.insert((buf, timestamp)).0)),
                        Err(err) => {
                            let (data, sections) = buf.take_bufs();
                            self.finished_data_bufs.push(data);
                            self.finished_section_bufs.push(sections);
                            Err(err)
                        }
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
            let (data, sections) = buf.take_bufs();
            self.finished_data_bufs.push(data);
            self.finished_section_bufs.push(sections);
        }
    }

    /// Number of currently active streams.
    #[inline]
    pub fn active_streams(&self) -> usize {
        self.active.len()
    }

    /// Retains only the streams specified by the predicate and recycles the
    /// buffers of the evicted ones (e.g. to remove streams that have not
    /// received data for a while based on the `Timestamp`).
    pub fn retain<F>(&mut self, f: F)
    where
        F: Fn(&Timestamp) -> bool,
    {
        if self.active.iter().any(|(_, (_, t))| false == f(t)) {
            self.active = self
                .active
                .drain()
                .filter_map(|(k, v)| {
                    if f(&v.1) {
                        Some((k, v))
                    } else {
                        let (data, sections) = v.0.take_bufs();
                        self.finished_data_bufs.push(data);
                        self.finished_section_bufs.push(sections);
                        None
                    }
                })
                .collect();
        }
    }
}

impl<Timestamp, CustomChannelId> Default for TcpStreamReassemblyPool<Timestamp, CustomChannelId>
where
    Timestamp: Sized + core::fmt::Debug + Clone,
    CustomChannelId: Sized + core::fmt::Debug + Clone + core::hash::Hash + Eq + PartialEq,
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

    #[test]
    fn new_default() {
        let pool = TcpStreamReassemblyPool::<(), ()>::new();
        assert_eq!(pool.active_streams(), 0);
        let pool: TcpStreamReassemblyPool<u32, u16> = Default::default();
        assert_eq!(pool.active_streams(), 0);
        let pool = TcpStreamReassemblyPool::<(), ()>::with_max_capacity(16);
        assert_eq!(pool.default_max_capacity, 16);
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
        let buf = pool
            .process_tcp(id.clone(), 999, &[], true, false, false, 1)
            .unwrap()
            .unwrap();
        assert_eq!(buf.base_sequence_number(), Some(1000));
        assert_eq!(pool.active_streams(), 1);

        // data
        let buf = pool
            .process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, 2)
            .unwrap()
            .unwrap();
        assert_eq!(buf.contiguous(), &sequence(0, 8)[..]);
        buf.consume(8);

        // more data + FIN
        let buf = pool
            .process_tcp(id.clone(), 1008, &sequence(8, 4), false, true, false, 3)
            .unwrap()
            .unwrap();
        assert_eq!(buf.contiguous(), &sequence(8, 4)[..]);
        assert!(buf.is_fin_reached());
    }

    #[test]
    fn lazy_init_without_syn() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);
        // first ever segment is data (no SYN captured)
        let buf = pool
            .process_tcp(id.clone(), 5000, &sequence(0, 4), false, false, false, ())
            .unwrap()
            .unwrap();
        assert_eq!(buf.base_sequence_number(), Some(5000));
        assert_eq!(buf.contiguous(), &sequence(0, 4)[..]);
    }

    #[test]
    fn rst_recycles_stream() {
        let mut pool = TcpStreamReassemblyPool::<(), u16>::new();
        let id = ipv4_id(0);
        pool.process_tcp(id.clone(), 1000, &sequence(0, 8), false, false, false, ())
            .unwrap();
        assert_eq!(pool.active_streams(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 0);

        // RST tears down the stream and recycles buffers
        let r = pool
            .process_tcp(id.clone(), 1008, &[], false, false, true, ())
            .unwrap();
        assert!(r.is_none());
        assert_eq!(pool.active_streams(), 0);
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

        // reconnect: new SYN with a fresh ISN re-bases the stream and drops the
        // old buffered data
        let buf = pool
            .process_tcp(id.clone(), 42, &[], true, false, false, ())
            .unwrap()
            .unwrap();
        assert_eq!(buf.base_sequence_number(), Some(43));
        assert!(buf.contiguous().is_empty());
        assert_eq!(pool.active_streams(), 1);

        let buf = pool
            .process_tcp(id.clone(), 43, &sequence(100, 4), false, false, false, ())
            .unwrap()
            .unwrap();
        assert_eq!(buf.contiguous(), &sequence(100, 4)[..]);
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
                end_offset: 16,
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
                end_offset: 20,
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
    fn retain_evicts_and_recycles() {
        let mut pool = TcpStreamReassemblyPool::<u32, u16>::new();
        pool.process_tcp(ipv4_id(0), 1000, &sequence(0, 8), false, false, false, 1)
            .unwrap();
        pool.process_tcp(ipv4_id(1), 1000, &sequence(0, 8), false, false, false, 2)
            .unwrap();
        assert_eq!(pool.active_streams(), 2);

        // no-op retain
        pool.retain(|ts| *ts > 0);
        assert_eq!(pool.active_streams(), 2);

        // evict timestamp 1
        pool.retain(|ts| *ts > 1);
        assert_eq!(pool.active_streams(), 1);
        assert_eq!(pool.finished_data_bufs.len(), 1);
        assert_eq!(pool.finished_section_bufs.len(), 1);
    }

    #[test]
    fn non_tcp_and_process_sliced_packet() {
        let mut pool = TcpStreamReassemblyPool::<(), ()>::new();

        // empty sliced packet -> None
        let empty = SlicedPacket {
            link: None,
            link_exts: ArrayVec::new_const(),
            net: None,
            transport: None,
        };
        assert!(pool
            .process_sliced_packet(&empty, (), ())
            .unwrap()
            .is_none());

        // build a real ethernet/ipv4/tcp packet and feed it
        let payload = sequence(0, 8);
        let pdata = build_ipv4_tcp_packet(1000, false, false, false, &payload);
        let slice = SlicedPacket::from_ethernet(&pdata).unwrap();
        let buf = pool.process_sliced_packet(&slice, (), ()).unwrap().unwrap();
        assert_eq!(buf.contiguous(), &payload[..]);
        assert_eq!(pool.active_streams(), 1);
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
