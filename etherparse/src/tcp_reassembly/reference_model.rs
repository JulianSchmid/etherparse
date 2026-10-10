use crate::tcp_reassembly::*;
use std::vec::Vec;

/// Simple model of the bytes a [`TcpReassemblyPool`] delivers.
///
/// It works on the true stream offsets that a [`ConnectionScript`] records
/// in its segments, so it is independent of the sequence number handling
/// it checks.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReferenceModel {
    /// Streams indexed by role.
    streams: [ModelStream; 2],
}

/// Model of one stream.
#[derive(Clone, Debug, Default)]
struct ModelStream {
    /// Received bytes by offset.
    bytes: Vec<Option<u8>>,
    /// Contiguous received bytes from offset 0 on.
    received: Vec<u8>,
    /// Offset of the FIN.
    fin_offset: Option<u64>,
    /// Number of segments with bytes after the FIN.
    out_of_window_segments: u64,
}

impl ModelStream {
    /// Applies a segment of the stream's sender:
    /// - bytes received for the first time are stored, bytes received before
    ///   keep their first content;
    /// - the first FIN that doesn't lie before received bytes ends the
    ///   stream, and bytes after it are counted and dropped.
    fn add_segment<CustomChannelId>(&mut self, segment: &TestSegment<CustomChannelId>) {
        let start = segment.offset;
        let end = start + segment.payload.len() as u64;
        if segment.header.fin && self.fin_offset.is_none() && end >= self.received.len() as u64 {
            self.fin_offset = Some(end);
        }
        let payload = match self.fin_offset {
            Some(fin) if end > fin && false == segment.payload.is_empty() => {
                self.out_of_window_segments += 1;
                &segment.payload[..fin.saturating_sub(start) as usize]
            }
            _ => &segment.payload[..],
        };

        let start = start as usize;
        let end = start + payload.len();
        if self.bytes.len() < end {
            self.bytes.resize(end, None);
        }
        for (slot, byte) in self.bytes[start..end].iter_mut().zip(payload) {
            if slot.is_none() {
                *slot = Some(*byte);
            }
        }
        let received_len = self.received.len();
        let next = self.bytes[received_len..].iter().map_while(|byte| *byte);
        self.received.extend(next);
    }

    /// Returns true if the FIN was seen and all bytes before it were
    /// received.
    fn is_finished(&self) -> bool {
        Some(self.received.len() as u64) == self.fin_offset
    }
}

impl ReferenceModel {
    /// Applies a segment to the stream of its sender.
    pub fn apply<CustomChannelId>(&mut self, segment: &TestSegment<CustomChannelId>) {
        self.streams[role_index(segment.sender)].add_segment(segment);
    }

    /// Contiguous received bytes of the stream of `role` from offset 0 on.
    pub fn received(&self, role: TcpRole) -> &[u8] {
        &self.streams[role_index(role)].received
    }

    /// FIN offset of the stream of `role`.
    pub fn fin_offset(&self, role: TcpRole) -> Option<u64> {
        self.streams[role_index(role)].fin_offset
    }

    /// Checks that `stream` matches the stream of `role`, then consumes
    /// `consume_len` bytes of it. `consumed` holds the number of bytes
    /// consumed before.
    pub fn check_and_consume(
        &self,
        role: TcpRole,
        stream: &mut TcpStream,
        consumed: &mut usize,
        consume_len: usize,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        use proptest::prelude::*;

        let expected = &self.streams[role_index(role)];
        prop_assert_eq!(*consumed as u64, stream.read_offset());
        prop_assert_eq!(expected.fin_offset, stream.fin_offset());
        prop_assert_eq!(expected.is_finished(), stream.is_finished());
        prop_assert_eq!(expected.is_finished(), stream.is_complete());
        prop_assert_eq!(
            TcpStreamStatus {
                out_of_window_segments: expected.out_of_window_segments,
            },
            stream.status()
        );
        if *consumed < expected.received.len() {
            prop_assert_eq!(
                TcpRead::Data(&expected.received[*consumed..]),
                stream.read_received()
            );
        } else if Some(*consumed as u64) == expected.fin_offset {
            prop_assert_eq!(TcpRead::End(TcpStreamEnd::Fin), stream.read_received());
        } else {
            prop_assert_eq!(TcpRead::Pending, stream.read_received());
        }
        stream.consume(consume_len);
        *consumed = (*consumed + consume_len).min(expected.received.len());
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{tcp_reassembly::TcpRole::*, test_gens::*};
    use proptest::{collection::vec, prelude::*};

    /// Order in which the endpoints send their FINs.
    #[derive(Copy, Clone, Debug)]
    enum FinOrder {
        InitiatorFirst,
        ResponderFirst,
    }

    proptest! {
        #[test]
        fn in_order_streams(
            initiator_isn in tcp_isn_any(),
            responder_isn in tcp_isn_any(),
            initiator_data in stream_data_any(16 * 1024),
            responder_data in stream_data_any(16 * 1024),
            segment_lens in vec(1usize..2000, 1..32),
            resent_lens in vec(0usize..1000, 1..32),
            directions in vec(any::<bool>(), 1..64),
            fin_data_lens in [proptest::option::of(0usize..64), proptest::option::of(0usize..64)],
            fin_order in prop_oneof![Just(FinOrder::InitiatorFirst), Just(FinOrder::ResponderFirst)],
            late_segments in vec(
                (tcp_role_any(), 0usize..8, vec(any::<u8>(), 0..8), any::<bool>()),
                0..8
            ),
            consume_lens in vec(0usize..3000, 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // some of them starting with bytes that were already sent
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data, &responder_data];
            // bytes sent before the FIN segment (which carries the rest)
            let data_lens = [0, 1].map(|i| {
                data[i].len() - fin_data_lens[i].unwrap_or(0).min(data[i].len())
            });
            let mut sent = [0usize, 0usize];
            let mut step = 0;
            while sent[0] < data_lens[0] || sent[1] < data_lens[1] {
                let initiator_done = sent[0] == data_lens[0];
                let responder_done = sent[1] == data_lens[1];
                let role = if responder_done
                    || (false == initiator_done && directions[step % directions.len()])
                {
                    Initiator
                } else {
                    Responder
                };
                let i = role_index(role);
                let start = sent[i] - resent_lens[step % resent_lens.len()].min(sent[i]);
                let len = segment_lens[step % segment_lens.len()].min(data_lens[i] - sent[i]);
                script.send_at(role, start as u64, &data[i][start..sent[i] + len]);
                sent[i] += len;
                step += 1;
            }

            // FINs carrying the rest of the bytes
            let roles = match fin_order {
                FinOrder::InitiatorFirst => [Initiator, Responder],
                FinOrder::ResponderFirst => [Responder, Initiator],
            };
            for role in roles {
                let i = role_index(role);
                if fin_data_lens[i].is_some() {
                    script.fin_with_data(role, &data[i][data_lens[i]..]);
                } else {
                    // without a FIN, the rest is sent as normal bytes
                    script.send(role, &data[i][data_lens[i]..]);
                }
            }

            // late segments ending before, at, or after the end of the
            // stream (possibly with another FIN)
            for (role, back, payload, fin) in &late_segments {
                let len = data[role_index(*role)].len();
                let start = (len - (*back).min(len)) as u64;
                if *fin {
                    script.fin_at(*role, start, payload);
                } else {
                    script.send_at(*role, start, payload);
                }
            }

            // feed the segments and read partially after each one
            let mut pool = TcpReassemblyPool::<(), ()>::default();
            let mut model = ReferenceModel::default();
            let mut consumed = [0usize, 0usize];
            for (step, segment) in script.segments.iter().enumerate() {
                model.apply(segment);
                let (connection, _) = segment.feed(&mut pool, ()).active.unwrap();
                for role in [Initiator, Responder] {
                    let i = role_index(role);
                    model.check_and_consume(
                        role,
                        connection.stream_mut(role),
                        &mut consumed[i],
                        consume_lens[(step + i) % consume_lens.len()],
                    )?;
                }
            }

            // the model received everything that was sent, and the FINs end
            // the streams
            for (i, role) in [Initiator, Responder].into_iter().enumerate() {
                prop_assert_eq!(&data[i][..], &model.received(role)[..data[i].len()]);
                if fin_data_lens[i].is_some() {
                    prop_assert_eq!(Some(data[i].len() as u64), model.fin_offset(role));
                }
            }
        }
    }
}
