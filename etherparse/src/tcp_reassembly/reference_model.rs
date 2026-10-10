use crate::tcp_reassembly::*;
use std::vec::Vec;

/// Simple model of the bytes a [`TcpReassemblyPool`] delivers.
///
/// It works on the true stream offsets that a [`ConnectionScript`] records
/// in its segments, so it is independent of the sequence number handling
/// it checks.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReferenceModel {
    /// Received bytes of each stream by offset, indexed by role.
    streams: [Vec<Option<u8>>; 2],
    /// Contiguous received bytes of each stream from offset 0 on, indexed
    /// by role.
    received: [Vec<u8>; 2],
}

impl ReferenceModel {
    /// Applies a segment: bytes received for the first time are stored,
    /// bytes received before keep their first content.
    pub fn apply<CustomChannelId>(&mut self, segment: &TestSegment<CustomChannelId>) {
        let i = role_index(segment.sender);
        let stream = &mut self.streams[i];
        let start = segment.offset as usize;
        let end = start + segment.payload.len();
        if stream.len() < end {
            stream.resize(end, None);
        }
        for (slot, byte) in stream[start..end].iter_mut().zip(&segment.payload) {
            if slot.is_none() {
                *slot = Some(*byte);
            }
        }
        let received = &mut self.received[i];
        let next = stream[received.len()..].iter().map_while(|byte| *byte);
        received.extend(next);
    }

    /// Contiguous received bytes of the stream of `role` from offset 0 on.
    pub fn received(&self, role: TcpRole) -> &[u8] {
        &self.received[role_index(role)]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{tcp_reassembly::TcpRole::*, test_gens::*};
    use proptest::{collection::vec, prelude::*};

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
            consume_lens in vec(0usize..3000, 1..32),
        ) {
            // write the connection with randomly cut and interleaved segments,
            // some of them starting with bytes that were already sent
            let mut script = ConnectionScript::with_isns(initiator_isn, responder_isn);
            script.handshake();
            let data = [&initiator_data, &responder_data];
            let mut sent = [0usize, 0usize];
            let mut step = 0;
            while sent[0] < data[0].len() || sent[1] < data[1].len() {
                let initiator_done = sent[0] == data[0].len();
                let responder_done = sent[1] == data[1].len();
                let role = if responder_done
                    || (false == initiator_done && directions[step % directions.len()])
                {
                    Initiator
                } else {
                    Responder
                };
                let i = role_index(role);
                let start = sent[i] - resent_lens[step % resent_lens.len()].min(sent[i]);
                let len = segment_lens[step % segment_lens.len()].min(data[i].len() - sent[i]);
                script.send_at(role, start as u64, &data[i][start..sent[i] + len]);
                sent[i] += len;
                step += 1;
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
                    let expected = model.received(role);
                    let stream = connection.stream_mut(role);
                    prop_assert_eq!(consumed[i] as u64, stream.read_offset());
                    if consumed[i] == expected.len() {
                        prop_assert_eq!(TcpRead::Pending, stream.read_received());
                    } else {
                        prop_assert_eq!(
                            TcpRead::Data(&expected[consumed[i]..]),
                            stream.read_received()
                        );
                    }
                    let len = consume_lens[(step + i) % consume_lens.len()];
                    stream.consume(len);
                    consumed[i] = (consumed[i] + len).min(expected.len());
                }
            }

            // the model received everything that was sent
            prop_assert_eq!(&initiator_data[..], model.received(Initiator));
            prop_assert_eq!(&responder_data[..], model.received(Responder));
        }
    }
}
