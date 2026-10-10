use crate::{tcp_reassembly::*, *};
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

    /// Received bytes, the ones before `head` are already consumed.
    buf: Vec<u8>,

    /// Number of consumed bytes at the start of `buf`.
    head: usize,

    /// Number of bytes the last read returned that are not consumed yet.
    last_read_len: usize,
}

impl TcpStream {
    /// Creates a stream whose start is not known yet.
    pub(crate) fn new() -> TcpStream {
        TcpStream {
            start_seq: None,
            window_scale: None,
            read_offset: 0,
            buf: Vec::new(),
            head: 0,
            last_read_len: 0,
        }
    }

    /// Returns the received bytes from the read position up to the first
    /// missing byte, or [`TcpRead::Pending`] if there are none yet.
    ///
    /// Call [`TcpStream::consume`] with the number of bytes you used to move
    /// the read position forward.
    pub fn read_received(&mut self) -> TcpRead<'_> {
        let data = &self.buf[self.head..];
        self.last_read_len = data.len();
        if data.is_empty() {
            TcpRead::Pending
        } else {
            TcpRead::Data(data)
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

    /// Offset after the last received byte.
    fn received_end(&self) -> u64 {
        self.read_offset + (self.buf.len() - self.head) as u64
    }

    /// Maps the sequence number `seq` to a stream offset, relative to the
    /// end of the received bytes (RFC 1982 serial number arithmetic).
    ///
    /// Offsets before the stream's first byte are negative.
    fn offset(&self, start_seq: u32, seq: u32) -> i64 {
        let end = self.received_end();
        let distance = seq.wrapping_sub(start_seq.wrapping_add(end as u32)) as i32;
        end as i64 + i64::from(distance)
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
        self.add_data(start, tcp.payload());
    }

    /// Appends the bytes of `data` (starting at offset `start`) that follow
    /// the received bytes.
    fn add_data(&mut self, start: i64, data: &[u8]) {
        let end = self.received_end() as i64;
        if start > end {
            // bytes behind missing bytes are not stored
            return;
        }

        // skip the bytes that were already received
        let new_bytes = match data.get((end - start) as usize..) {
            Some(new_bytes) if false == new_bytes.is_empty() => new_bytes,
            _ => return,
        };

        // drop the consumed bytes once they make up half of the buffer
        if self.head >= self.buf.len() - self.head {
            self.buf.drain(..self.head);
            self.head = 0;
        }
        self.buf.extend_from_slice(new_bytes);
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

        // reading stops at missing bytes
        {
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut script = ConnectionScript::with_isns(1000, 2000);
            script
                .handshake()
                .send(Initiator, b"abc")
                .send(Initiator, b"de")
                .send(Initiator, b"fg");
            script.segments.remove(4);
            let (connection, _) = script.feed_all(&mut pool).active.unwrap();
            assert_eq!(
                TcpRead::Data(b"abc"),
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
}
