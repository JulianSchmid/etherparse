use crate::{tcp_reassembly::*, *};
use core::ops::Range;
use std::vec::Vec;

/// Bytes sent in one direction of a TCP connection.
///
/// Positions in a stream are 64-bit offsets counted from the stream's first
/// byte, so they never wrap around.
#[derive(Clone, Debug)]
pub struct TcpStream {
    /// Sequence number of the byte at offset 0 (`None` while the start of
    /// the stream is unknown).
    start_seq: Option<u32>,

    /// Window scale option in the sender's SYN.
    // Only stored so far, the receiver window is not tracked yet.
    #[allow(dead_code)]
    window_scale: Option<u8>,

    /// Offset of the byte at `buf[head]`.
    read_offset: u64,

    /// Offset after the furthest byte the sender is known to have sent.
    highest_offset: u64,

    /// Received bytes up to the furthest one, where `buf[head]` is the byte
    /// at `read_offset`. The bytes before `head` are already consumed, and
    /// the bytes in holes are placeholders.
    buf: Vec<u8>,

    /// Number of consumed bytes at the start of `buf`.
    head: usize,

    /// Missing bytes between `read_offset` and `highest_offset`, sorted and
    /// without overlaps. Missing bytes after the end of `buf` always lie in
    /// a hole.
    holes: Vec<Range<u64>>,

    /// Number of bytes the last read returned that are not consumed yet.
    last_read_len: usize,

    /// Offset of the FIN (`None` until the first FIN was seen).
    fin_offset: Option<u64>,

    /// Highest offset ACKed by the receiver, where an ACK of the FIN is
    /// `fin_offset + 1`.
    seen_ack: u64,

    status: TcpStreamStatus,
}

impl TcpStream {
    /// Creates a stream whose start is not known yet, storing its bytes in
    /// the empty buffer `buf`.
    pub(crate) fn new(buf: Vec<u8>) -> TcpStream {
        TcpStream {
            start_seq: None,
            window_scale: None,
            read_offset: 0,
            highest_offset: 0,
            buf,
            head: 0,
            holes: Vec::new(),
            last_read_len: 0,
            fin_offset: None,
            seen_ack: 0,
            status: TcpStreamStatus {
                conflicting_retransmissions: 0,
                out_of_window_segments: 0,
            },
        }
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte.
    ///
    /// Call [`TcpStream::consume`] with the number of bytes you used to move
    /// the read position forward. Without readable bytes, the result is
    /// [`TcpRead::Pending`] while more bytes can arrive (e.g. to fill a
    /// hole), and [`TcpRead::End`] once all bytes up to the FIN were read.
    ///
    /// Use [`TcpStream::read_acked`] to read only the bytes the receiver
    /// ACKed.
    pub fn read_received(&mut self) -> TcpRead<'_> {
        self.read_until(u64::MAX)
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte, but only the ones the receiver ACKed (see
    /// [`TcpStream::acked_offset`]).
    ///
    /// Otherwise it works like [`TcpStream::read_received`]. Bytes that were
    /// consumed after reading them with [`TcpStream::read_received`] are
    /// not returned again.
    pub fn read_acked(&mut self) -> TcpRead<'_> {
        self.read_until(self.acked_offset())
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte, but not after `limit`.
    fn read_until(&mut self, limit: u64) -> TcpRead<'_> {
        // all bytes before the first hole were received
        let end = self
            .holes
            .first()
            .map_or(self.highest_offset, |hole| hole.start)
            .min(limit)
            .max(self.read_offset);
        let data = &self.buf[self.head..self.index(end)];
        self.last_read_len = data.len();
        if false == data.is_empty() {
            TcpRead::Data(data)
        } else if Some(self.read_offset) == self.fin_offset {
            TcpRead::End(TcpStreamEnd::Fin)
        } else {
            TcpRead::Pending
        }
    }

    /// Consumes `len` bytes at the read position.
    ///
    /// At most the bytes returned by the last read are consumed, so bytes
    /// that arrived after the read stay unread.
    pub fn consume(&mut self, len: usize) {
        let len = len.min(self.last_read_len);
        self.head += len;
        self.read_offset += len as u64;
        self.last_read_len -= len;
    }

    /// Offset of the next byte to read.
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Offset up to which the receiver ACKed the stream's bytes.
    pub fn acked_offset(&self) -> u64 {
        // ACKs can lie after the highest offset (e.g. the ACK of the FIN)
        self.seen_ack.min(self.highest_offset)
    }

    /// Offset after the furthest byte the sender is known to have sent.
    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
    }

    /// Offset of the stream's FIN, which is the number of bytes in the
    /// stream, if a FIN was seen.
    pub fn fin_offset(&self) -> Option<u64> {
        self.fin_offset
    }

    /// Ranges of missing bytes between the read position and the highest
    /// offset, in order.
    ///
    /// Reading stops at the first hole until a retransmission fills it.
    pub fn holes(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.holes.iter().cloned()
    }

    /// Counters that describe the quality of the stream.
    pub fn status(&self) -> TcpStreamStatus {
        self.status
    }

    /// Returns true if the stream has no defects so far: no retransmission
    /// with differing bytes (see
    /// [`TcpStreamStatus::conflicting_retransmissions`]).
    ///
    /// Holes don't count, as retransmissions can still fill them.
    pub fn is_clean(&self) -> bool {
        0 == self.status.conflicting_retransmissions
    }

    /// Returns true if the stream's FIN was seen and no bytes before it are
    /// missing.
    pub fn is_finished(&self) -> bool {
        // the FIN moves the highest offset to it, so all holes lie before it
        self.fin_offset.is_some() && self.holes.is_empty()
    }

    /// Returns true if the stream is complete: it is clean (see
    /// [`TcpStream::is_clean`]), has an observed start and is finished (see
    /// [`TcpStream::is_finished`]).
    ///
    /// All bytes the sender sent are then delivered exactly once and
    /// unambiguously.
    pub fn is_complete(&self) -> bool {
        // every stream has an observed start so far
        self.is_clean() && self.is_finished()
    }

    /// Returns the stream's buffer, emptied for re-use.
    pub(crate) fn into_buffer(self) -> Vec<u8> {
        let mut buf = self.buf;
        buf.clear();
        buf
    }

    /// Returns true if the receiver ACKed the stream's FIN.
    pub(crate) fn is_fin_acked(&self) -> bool {
        self.fin_offset.is_some_and(|fin| fin < self.seen_ack)
    }

    /// Offset after the last byte in `buf`.
    fn buf_end(&self) -> u64 {
        self.read_offset + (self.buf.len() - self.head) as u64
    }

    /// Index in `buf` of the byte at `offset` (at or after `read_offset`).
    fn index(&self, offset: u64) -> usize {
        self.head + (offset - self.read_offset) as usize
    }

    /// Maps the sequence number `seq` to a stream offset, relative to the
    /// highest offset (RFC 1982 serial number arithmetic).
    ///
    /// Offsets before the stream's first byte are negative.
    fn offset(&self, start_seq: u32, seq: u32) -> i64 {
        let highest = self.highest_offset;
        let distance = seq.wrapping_sub(start_seq.wrapping_add(highest as u32)) as i32;
        highest as i64 + i64::from(distance)
    }

    /// Applies a segment sent by the stream's sender.
    pub(crate) fn add_segment(&mut self, tcp: &TcpSlice<'_>) {
        // the SYN occupies the sequence number before the first byte
        let seq = if tcp.syn() {
            tcp.sequence_number().wrapping_add(1)
        } else {
            tcp.sequence_number()
        };
        if tcp.syn() && self.start_seq.is_none() {
            self.start_seq = Some(seq);
            self.window_scale = window_scale(tcp);
        }
        let Some(start_seq) = self.start_seq else {
            return;
        };
        let start = self.offset(start_seq, seq);
        let data = tcp.payload();
        let end = start + data.len() as i64;

        // the first FIN wins, but it can't lie before received bytes (even
        // if bytes before it are missing)
        if tcp.fin() && self.fin_offset.is_none() && end >= self.highest_offset as i64 {
            self.fin_offset = Some(end as u64);
        }

        // bytes after the FIN are not part of the stream
        let data = match self.fin_offset {
            Some(fin) if false == data.is_empty() && end > fin as i64 => {
                self.status.out_of_window_segments += 1;
                let len = (fin as i64 - start).max(0) as usize;
                data.get(..len).unwrap_or_default()
            }
            _ => data,
        };
        self.add_data(start, data);

        // the sender sent all bytes before its FIN
        if let Some(fin) = self.fin_offset {
            self.extend_to(fin);
        }
    }

    /// Applies the ACK number of a segment sent by the stream's receiver.
    pub(crate) fn add_ack(&mut self, ack: u32) {
        if let Some(start_seq) = self.start_seq {
            let offset = self.offset(start_seq, ack);
            if offset > self.seen_ack as i64 {
                self.seen_ack = offset as u64;
            }
        }
    }

    /// Stores the bytes of `data` (starting at offset `start`) that were not
    /// received before.
    fn add_data(&mut self, start: i64, data: &[u8]) {
        // skip the bytes before the read position (consumed, or before the
        // stream's first byte)
        let skipped = (self.read_offset as i64).saturating_sub(start).max(0) as usize;
        let data = match data.get(skipped..) {
            Some(data) if false == data.is_empty() => data,
            _ => return,
        };
        let start = (start + skipped as i64) as u64;
        let end = start + data.len() as u64;

        // bytes received before keep their content
        if self.differs_from_received(start, data) {
            self.status.conflicting_retransmissions += 1;
        }

        // fill the holes in the buffer
        let buf_end = self.buf_end();
        for hole in &self.holes {
            let from = hole.start.max(start);
            let to = hole.end.min(end).min(buf_end);
            if from < to {
                let (buf_from, buf_to) = (self.index(from), self.index(to));
                self.buf[buf_from..buf_to]
                    .copy_from_slice(&data[(from - start) as usize..(to - start) as usize]);
            }
        }

        // append the bytes after the end of the buffer (all missing so far)
        if buf_end < end {
            // drop the consumed bytes once they make up half of the buffer
            if self.head >= self.buf.len() - self.head {
                self.buf.drain(..self.head);
                self.head = 0;
            }
            // placeholders for missing bytes before the segment
            let from = start.max(buf_end);
            self.buf.resize(self.index(from), 0);
            self.buf.extend_from_slice(&data[(from - start) as usize..]);
        }
        self.extend_to(end);
        self.remove_from_holes(start..end);
    }

    /// Returns true if bytes of `data` (starting at offset `start`, at or
    /// after the read position) differ from the bytes received for the same
    /// offsets.
    fn differs_from_received(&self, start: u64, data: &[u8]) -> bool {
        let end = start + data.len() as u64;
        // the received bytes lie before each hole and before the highest
        // offset (an empty hole at the end)
        let mut received_start = self.read_offset;
        let holes = self
            .holes
            .iter()
            .map(|hole| (hole.start, hole.end))
            .chain([(self.highest_offset, self.highest_offset)]);
        for (hole_start, hole_end) in holes {
            let from = received_start.max(start);
            let to = hole_start.min(end);
            if from < to
                && self.buf[self.index(from)..self.index(to)]
                    != data[(from - start) as usize..(to - start) as usize]
            {
                return true;
            }
            received_start = hole_end;
        }
        false
    }

    /// Moves the highest offset forward to `offset`, the bytes in between
    /// are missing.
    fn extend_to(&mut self, offset: u64) {
        if offset > self.highest_offset {
            self.holes.push(self.highest_offset..offset);
            self.highest_offset = offset;
        }
    }

    /// Removes the bytes in `range` from the holes.
    fn remove_from_holes(&mut self, range: Range<u64>) {
        // holes overlapping the range
        let first = self.holes.partition_point(|hole| hole.end <= range.start);
        let last = self.holes.partition_point(|hole| hole.start < range.end);
        if first >= last {
            return;
        }

        // the parts of these holes before and after the range stay missing
        let before = self.holes[first].start..range.start;
        let after = range.end..self.holes[last - 1].end;
        self.holes.drain(first..last);
        let mut index = first;
        for part in [before, after] {
            if false == part.is_empty() {
                self.holes.insert(index, part);
                index += 1;
            }
        }
    }
}

/// Returns the value of the window scale option (RFC 7323), if present.
fn window_scale(tcp: &TcpSlice<'_>) -> Option<u8> {
    tcp.options_iterator()
        .map_while(Result::ok)
        .find_map(|option| match option {
            TcpOptionElement::WindowScale(scale) => Some(scale),
            _ => None,
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tcp_reassembly::TcpRole::*;
    use std::format;

    #[test]
    fn derived_traits() {
        let mut pool = TcpReassemblyPool::<(), ()>::default();
        let mut script = ConnectionScript::with_isns(1000, 2000);
        script.handshake().send(Initiator, b"abc");
        let (connection, _) = script.feed_all(&mut pool).active.unwrap();
        let stream = connection.stream_mut(Initiator);

        // clone
        {
            let mut clone = stream.clone();
            assert_eq!(TcpRead::Data(b"abc"), clone.read_received());
            clone.consume(3);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // debug
        assert!(format!("{:?}", stream).starts_with("TcpStream { "));
    }

    #[test]
    fn read_received() {
        // nothing received yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Pending,
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Pending,
                connection.stream_mut(Responder).read_received()
            );
        }

        // in-order data of several segments is read as one slice
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"GET")
                .send(Responder, b"HTTP")
                .send(Initiator, b" /")
                .send(Responder, b"/1.1");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"GET /"),
                connection.stream_mut(Initiator).read_received()
            );
            assert_eq!(
                TcpRead::Data(b"HTTP/1.1"),
                connection.stream_mut(Responder).read_received()
            );
        }

        // data in the SYN (TCP Fast Open) starts at offset 0
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn_with_data(b"fast")
                .syn_ack()
                .ack(Initiator)
                .send(Initiator, b" open");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"fast open"), stream.read_received());
            assert_eq!(0, stream.read_offset());
        }

        // SYNs with options start the streams too
        for options in [
            // window scale
            &[TcpOptionElement::WindowScale(7), TcpOptionElement::Noop][..],
            // window scale after another option
            &[
                TcpOptionElement::MaximumSegmentSize(1460),
                TcpOptionElement::WindowScale(14),
                TcpOptionElement::Noop,
            ][..],
            // no window scale
            &[TcpOptionElement::MaximumSegmentSize(1460)][..],
        ] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            script.segments[0].header.set_options(options).unwrap();
            script.segments[1].header.set_options(options).unwrap();
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

        // SYNs with malformed options start the streams too
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.window_scales = [Some(7), Some(7)];
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Responder, b"def");
            // window scale option with a wrong length
            script.segments[0]
                .header
                .set_options_raw(&[3, 4, 7, 0])
                .unwrap();
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

        // retransmitted bytes are delivered once (also across a
        // wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                // the same segment again
                .send_at(Initiator, 3, b"def")
                // the same bytes cut differently, with new bytes at the end
                .send_at(Initiator, 1, b"bcdefgh")
                // only bytes received before
                .send_at(Initiator, 0, b"ab");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdefgh"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // reading stops at a hole and continues once it is filled
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"de")
                .send(Initiator, b"fg");
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
                assert_eq!(TcpRead::Pending, stream.read_received());
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"defg"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a hole at the start of the stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let missing = script.segments.remove(3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(
                    TcpRead::Pending,
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdef"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // data of a stream whose start was not seen is ignored
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Responder, b"abc");
            // remove the SYN-ACK
            script.segments.remove(1);
            let (connection, sender) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Responder, sender);
            assert_eq!(
                TcpRead::Pending,
                connection.stream_mut(Responder).read_received()
            );
        }

        // the end is reported once all bytes up to the FIN were read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .fin_with_data(Initiator, b"c")
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"c"), stream.read_received());
            stream.consume(1);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
            // without bytes
            assert_eq!(
                TcpRead::End(TcpStreamEnd::Fin),
                connection.stream_mut(Responder).read_received()
            );
        }

        // bytes after the FIN are never readable
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .send(Initiator, b"def")
                .send_at(Initiator, 1, b"bcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // no end while bytes before the FIN are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
            stream.consume(3);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // a retransmitted SYN changes nothing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .syn_with_data(b"abc")
                .syn_ack()
                .send(Initiator, b"def");
            let syn = script.segments[0].clone();
            script.segments.push(syn);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdef"),
                connection.stream_mut(Initiator).read_received()
            );
        }
    }

    #[test]
    fn read_acked() {
        // nothing ACKed yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Pending, stream.read_acked());
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // bytes up to the ACKed offset (also across a wrap-around of the
        // sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .ack_to(Responder, 4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abcd"), stream.read_acked());
                stream.consume(4);
                assert_eq!(TcpRead::Pending, stream.read_acked());
            }
            script.ack(Responder);
            let (connection, _) = script.feed(&mut pool, 6..).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"ef"),
                connection.stream_mut(Initiator).read_acked()
            );
        }

        // consuming is limited to the ACKed bytes that were read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"ab"), stream.read_acked());
            stream.consume(10);
            assert_eq!(2, stream.read_offset());
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
        }

        // reading stops at a hole, even if bytes after it are ACKed
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .send(Initiator, b"ghi")
                .ack(Responder);
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert_eq!(
                    TcpRead::Data(b"abc"),
                    connection.stream_mut(Initiator).read_acked()
                );
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdefghi"),
                connection.stream_mut(Initiator).read_acked()
            );
        }

        // the end is reported once all bytes up to the FIN were read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .ack(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_acked());
            stream.consume(3);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_acked());
        }

        // bytes consumed after reading them with read_received
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 2);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.consume(4);
            assert_eq!(TcpRead::Pending, stream.read_acked());
            assert_eq!(TcpRead::Data(b"ef"), stream.read_received());
        }
    }

    #[test]
    fn consume() {
        // partial consumes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"cdef"), stream.read_received());
            stream.consume(1);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"f"), stream.read_received());
            stream.consume(1);
            assert_eq!(TcpRead::Pending, stream.read_received());
        }

        // consuming is limited to the bytes the last read returned
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                assert_eq!(
                    TcpRead::Data(b"abc"),
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.consume(10);
            assert_eq!(TcpRead::Data(b"def"), stream.read_received());
        }

        // nothing is consumed without a read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // nothing is consumed after a pending read
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            {
                let (connection, _) = script.feed(&mut pool, ..3).active.unwrap();
                assert_eq!(
                    TcpRead::Pending,
                    connection.stream_mut(Initiator).read_received()
                );
            }
            let (connection, _) = script.feed(&mut pool, 3..).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.consume(2);
            assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
        }

        // bytes arriving after a consume follow the unconsumed bytes
        for consumed in 0..=6 {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .send(Initiator, b"gh");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
                stream.consume(consumed);
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            assert_eq!(
                TcpRead::Data(&b"abcdefgh"[consumed..]),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // a long stream with swapped segments, consumed in small steps that
        // fall behind the received bytes
        {
            let data: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            for chunk in data.chunks(1000) {
                script.send(Initiator, chunk);
            }
            for pair in script.segments[3..].chunks_mut(2) {
                pair.reverse();
            }
            let mut delivered = Vec::new();
            for (i, segment) in script.segments.iter().enumerate() {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                // at most 100 reads per segment, all bytes after the last one
                let last = i + 1 == script.segments.len();
                let mut reads = 0;
                while let TcpRead::Data(d) = stream.read_received() {
                    if 100 == reads && false == last {
                        break;
                    }
                    let len = d.len().min(7);
                    delivered.extend_from_slice(&d[..len]);
                    stream.consume(len);
                    reads += 1;
                }
            }
            assert_eq!(data, delivered);
        }

        // retransmissions of consumed bytes are not delivered again
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(TcpRead::Data(b"abc"), stream.read_received());
                stream.consume(3);
            }
            let (connection, _) = script.segments[3].feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(TcpRead::Pending, stream.read_received());
            assert_eq!(3, stream.read_offset());
        }
    }

    #[test]
    fn read_offset() {
        // starts at 0 and grows by the consumed bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abcdef");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(0, stream.read_offset());
            stream.read_received();
            stream.consume(4);
            assert_eq!(4, stream.read_offset());
            stream.consume(4);
            assert_eq!(6, stream.read_offset());
        }

        // keeps growing across several wrap-arounds of the sequence numbers
        {
            const SEGMENT_LEN: usize = 1 << 20;
            const SEGMENTS: u64 = (3 << 32) / (SEGMENT_LEN as u64) + 1;

            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(u32::MAX - 10, 2000);
            script.handshake().send(Initiator, &[0; SEGMENT_LEN]);
            script.feed(&mut pool, ..3);

            // re-use the bytes of the data segment and only change the
            // sequence number and the first payload bytes
            let data = &script.segments[3];
            let mut bytes = data.header.to_bytes().to_vec();
            let header_len = bytes.len();
            bytes.extend_from_slice(&data.payload);

            let mut offset = 0u64;
            for _ in 0..SEGMENTS {
                bytes[4..8].copy_from_slice(&script.seq(Initiator, offset).to_be_bytes());
                bytes[header_len..header_len + 8].copy_from_slice(&offset.to_be_bytes());
                let (connection, _) = pool
                    .process_segment(
                        TcpSegment {
                            vlan_ids: Default::default(),
                            source: data.source.ip(),
                            destination: data.destination.ip(),
                            channel_id: (),
                            tcp: TcpSlice::from_slice(&bytes).unwrap(),
                        },
                        (),
                    )
                    .active
                    .unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(offset, stream.read_offset());
                match stream.read_received() {
                    TcpRead::Data(d) => {
                        assert_eq!(SEGMENT_LEN, d.len());
                        assert_eq!(&offset.to_be_bytes(), &d[..8]);
                    }
                    other => panic!("unexpected read {:?}", other),
                }
                stream.consume(SEGMENT_LEN);
                offset += SEGMENT_LEN as u64;
            }
            assert!(offset > 3 << 32);
        }
    }

    #[test]
    fn acked_offset() {
        // nothing ACKed yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).acked_offset());
            assert_eq!(0, connection.stream(Responder).acked_offset());
        }

        // follows the highest ACK, older ACKs arriving later change nothing
        // (also across a wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                .ack_to(Responder, 2)
                .ack_to(Responder, 5)
                .ack_to(Responder, 3)
                .ack_to(Responder, 6);
            script.feed(&mut pool, ..4);
            for (segment, expected) in script.segments[4..].iter().zip([2, 5, 5, 6]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).acked_offset());
            }
        }

        // an ACK of the FIN ACKs all bytes, but nothing after them
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .ack_to(Responder, 4)
                .ack_to(Responder, 5);
            script.feed(&mut pool, ..4);
            for segment in &script.segments[4..] {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!(3, stream.acked_offset());
                assert_eq!(0, stream.holes().count());
            }
        }
    }

    #[test]
    fn highest_offset() {
        // nothing received yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).highest_offset());
            assert_eq!(0, connection.stream(Responder).highest_offset());
        }

        // follows the furthest received byte, also behind holes (and across
        // a wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 2] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"abc")
                // behind a hole
                .send_at(Initiator, 6, b"gh")
                // filling the hole
                .send_at(Initiator, 3, b"def")
                // retransmission
                .send_at(Initiator, 0, b"ab");
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([3, 8, 8, 8]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(expected, connection.stream(Initiator).highest_offset());
            }
        }

        // reading doesn't move it
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            stream.read_received();
            stream.consume(2);
            assert_eq!(3, stream.highest_offset());
        }

        // a FIN behind missing bytes moves it to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(6, connection.stream(Initiator).highest_offset());
        }
    }

    #[test]
    fn holes() {
        // no holes while the bytes arrive in order
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(0, connection.stream(Initiator).holes().count());
        }

        // segments create holes and fill them completely or in parts
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake();
            let steps: [(u64, &[u8], &[Range<u64>]); 10] = [
                // hole at the start of the stream
                (2, b"c", &[0..2]),
                // hole after received bytes
                (6, b"gh", &[0..2, 3..6]),
                (12, b"m", &[0..2, 3..6, 8..12]),
                // splits a hole
                (4, b"e", &[0..2, 3..4, 5..6, 8..12]),
                (9, b"j", &[0..2, 3..4, 5..6, 8..9, 10..12]),
                // fills the end of one hole and another one completely
                (1, b"bcde", &[0..1, 5..6, 8..9, 10..12]),
                // fills two holes completely
                (5, b"fghij", &[0..1, 10..12]),
                // fills the start of a hole
                (10, b"k", &[0..1, 11..12]),
                // fills a hole and overlaps received bytes
                (11, b"lm", &[0..1]),
                // fills the last hole
                (0, b"a", &[]),
            ];
            for (offset, data, _) in steps {
                script.send_at(Initiator, offset, data);
            }
            script.feed(&mut pool, ..3);
            for (segment, (_, _, expected)) in script.segments[3..].iter().zip(steps) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(expected, stream.holes().collect::<Vec<_>>());
                if expected.is_empty() {
                    assert_eq!(TcpRead::Data(b"abcdefghijklm"), stream.read_received());
                }
            }
        }

        // missing bytes before a FIN, with and without bytes in the FIN
        for fin_data in [&b""[..], b"gh"] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin_with_data(Initiator, fin_data);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                &[3..6][..],
                connection.stream(Initiator).holes().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn fin_offset() {
        // no FIN yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.stream(Initiator).fin_offset());
            assert_eq!(None, connection.stream(Responder).fin_offset());
        }

        // FIN after the bytes, with and without data (also across a
        // wrap-around of the sequence numbers)
        for isn in [1000, u32::MAX - 4] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(isn, isn);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .send(Responder, b"de")
                .fin_with_data(Responder, b"fgh");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(3), connection.stream(Initiator).fin_offset());
            assert_eq!(Some(5), connection.stream(Responder).fin_offset());
        }

        // FIN of a stream without bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin(Initiator);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(0), connection.stream(Initiator).fin_offset());
        }

        // FIN behind missing bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(6), connection.stream(Initiator).fin_offset());
        }

        // the first FIN wins, a retransmission of it (offset 2) and later
        // FINs at other offsets change nothing
        for later_offset in [2, 3, 4, 10] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"ab")
                .fin(Initiator)
                .fin_at(Initiator, later_offset, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(Some(2), connection.stream(Initiator).fin_offset());
        }

        // a FIN before already received bytes is ignored
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin_at(Initiator, 2, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.stream(Initiator).fin_offset());
        }

        // a FIN before already received bytes is ignored, even if bytes
        // before the FIN are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"defgh")
                .fin_at(Initiator, 6, &[]);
            let missing = script.segments.remove(3);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                let stream = connection.stream(Initiator);
                assert_eq!(None, stream.fin_offset());
                assert_eq!(8, stream.highest_offset());
            }
            // the bytes after it stay readable
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abcdefgh"),
                connection.stream_mut(Initiator).read_received()
            );
        }

        // FIN of a stream whose start was not seen
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().fin(Responder);
            // remove the SYN-ACK
            script.segments.remove(1);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(None, connection.stream(Responder).fin_offset());
        }
    }

    #[test]
    fn is_finished() {
        // no FIN yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_finished());
        }

        // FIN after all bytes (finished before they were read)
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(connection.stream(Initiator).is_finished());
            assert!(connection.stream(Responder).is_finished());
        }

        // FIN behind missing bytes finishes once they arrive, with and
        // without bytes in the FIN
        for fin_data in [&b""[..], b"gh"] {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin_with_data(Initiator, fin_data);
            let missing = script.segments.remove(4);
            {
                let (connection, _) = script.feed_all(&mut pool).active.unwrap();
                assert!(false == connection.stream(Initiator).is_finished());
            }
            let (connection, _) = missing.feed(&mut pool, ()).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert!(stream.is_finished());
            assert_eq!(
                TcpRead::Data(&[&b"abcdef"[..], fin_data].concat()[..]),
                stream.read_received()
            );
        }

        // FIN behind several holes finishes once the last one is filled
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 1, b"b")
                .fin_at(Initiator, 3, b"d")
                .send_at(Initiator, 0, b"a")
                .send_at(Initiator, 2, b"c");
            script.feed(&mut pool, ..3);
            for (segment, finished) in script.segments[3..].iter().zip([false, false, false, true])
            {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(finished, connection.stream(Initiator).is_finished());
            }
        }
    }

    #[test]
    fn status() {
        // new stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpStreamStatus {
                    conflicting_retransmissions: 0,
                    out_of_window_segments: 0,
                },
                connection.stream(Initiator).status()
            );
        }

        // every segment with bytes after the FIN counts as out-of-window
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                // bytes after the FIN
                .send(Initiator, b"x")
                // bytes starting at the FIN
                .send_at(Initiator, 3, b"y")
                // retransmitted bytes followed by bytes after the FIN
                .send_at(Initiator, 1, b"bcz");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(3, stream.status().out_of_window_segments);
            assert!(stream.is_finished());
        }

        // segments without bytes after the FIN don't count
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                // ACK after the FIN
                .ack(Initiator)
                // retransmission of the FIN
                .fin_at(Initiator, 0, b"abc")
                // a FIN without bytes at another offset
                .fin_at(Initiator, 7, &[]);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                0,
                connection.stream(Initiator).status().out_of_window_segments
            );
        }

        // bytes after the FIN count while bytes before it are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .send(Initiator, b"x");
            let missing = script.segments.remove(4);
            script.segments.push(missing);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(1, stream.status().out_of_window_segments);
            assert_eq!(TcpRead::Data(b"abcdef"), stream.read_received());
            stream.consume(6);
            assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        }

        // retransmissions with differing bytes count once per segment, the
        // bytes received first are kept
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abcdef")
                // same bytes
                .send_at(Initiator, 1, b"bcd")
                // one differing byte
                .send_at(Initiator, 0, b"aXc")
                // several differing bytes
                .send_at(Initiator, 2, b"XYZ")
                // differing bytes followed by new bytes
                .send_at(Initiator, 5, b"Xgh");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream_mut(Initiator);
            assert_eq!(3, stream.status().conflicting_retransmissions);
            assert_eq!(TcpRead::Data(b"abcdefgh"), stream.read_received());
        }

        // bytes in holes are not compared, the received bytes around them
        // are
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send_at(Initiator, 0, b"ab")
                .send_at(Initiator, 4, b"ef")
                .send_at(Initiator, 8, b"ij")
                // fills the holes
                .send_at(Initiator, 1, b"bcdefgh")
                // received bytes after a hole differ
                .send_at(Initiator, 5, b"Xghi");
            script.feed(&mut pool, ..3);
            let segments = &script.segments[3..];
            for (i, (segment, expected)) in segments.iter().zip([0, 0, 0, 0, 1]).enumerate() {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                assert_eq!(expected, stream.status().conflicting_retransmissions);
                if i + 1 == segments.len() {
                    assert_eq!(TcpRead::Data(b"abcdefghij"), stream.read_received());
                }
            }
        }

        // bytes that were already consumed are not compared
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 0, b"XYc");
            {
                let (connection, _) = script.feed(&mut pool, ..4).active.unwrap();
                let stream = connection.stream_mut(Initiator);
                stream.read_received();
                stream.consume(2);
            }
            let (connection, _) = script.feed(&mut pool, 4..).active.unwrap();
            assert_eq!(
                0,
                connection
                    .stream(Initiator)
                    .status()
                    .conflicting_retransmissions
            );
        }

        // differing bytes after the FIN only count as out-of-window, a
        // differing FIN retransmission counts
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .fin_with_data(Initiator, b"abc")
                .send_at(Initiator, 2, b"cX")
                .fin_at(Initiator, 1, b"Xc");
            script.feed(&mut pool, ..3);
            for (segment, expected) in script.segments[3..].iter().zip([0, 0, 1]) {
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                assert_eq!(
                    expected,
                    connection
                        .stream(Initiator)
                        .status()
                        .conflicting_retransmissions
                );
            }
        }
    }

    #[test]
    fn is_clean() {
        // new stream
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.syn();
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(connection.stream(Initiator).is_clean());
        }

        // holes, retransmissions with the same bytes and bytes after the FIN
        // keep it clean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator)
                .send_at(Initiator, 4, b"efX")
                .send_at(Initiator, 0, b"abc");
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert_eq!(1, stream.holes().count());
            assert!(stream.is_clean());
        }

        // a conflicting retransmission makes it unclean
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 0, b"X");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_clean());
        }
    }

    #[test]
    fn is_complete() {
        // no FIN yet
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script.handshake().send(Initiator, b"abc");
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_complete());
        }

        // bytes before the FIN are missing
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"def")
                .fin(Initiator);
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(false == connection.stream(Initiator).is_complete());
        }

        // all bytes from the SYN to the FIN
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .fin(Initiator)
                .fin(Responder);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert!(connection.stream(Initiator).is_complete());
            assert!(connection.stream(Responder).is_complete());
        }

        // finished, but a retransmission had differing bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send_at(Initiator, 0, b"X")
                .fin(Initiator);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            let stream = connection.stream(Initiator);
            assert!(stream.is_finished());
            assert!(false == stream.is_complete());
        }
    }
}
