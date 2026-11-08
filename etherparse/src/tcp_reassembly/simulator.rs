//! Ground-truth simulator for reconnects and late segments (ticket 17).
//!
//! A [`World`] is the history of one four-tuple whose endpoints behave like
//! TCP stacks do: they open, transfer, close (or reset, or vanish), reuse
//! the four-tuple with the ISNs stacks pick, and emit the late segments
//! stacks emit (the ACK with which a server in TIME-WAIT or with a stale
//! established connection answers a new SYN, the client's RST to it, FIN
//! retransmissions in LAST-ACK, bytes still in flight when the peer
//! aborted). Every segment carries the real connection it belongs to (its
//! `incarnation`) and the true offsets of its bytes.
//!
//! [`Capture::apply`] turns the true sequence into what a capture shows:
//! loss, reordering with a bounded skew (merged taps), a start in the middle
//! of the history, one direction only, duplicates.
//!
//! [`Oracle::check`] feeds the capture to a [`TcpReassemblyPool`] and checks
//! the result against the truth, not against the rules of the reference
//! model: each visible real connection comes out as exactly one pool
//! connection with its captured bytes readable in order and nothing
//! swallowed, with the end the capture shows, without ghost connections and
//! without resyncs. The [`Trace`] of a failing case shows every segment
//! with the pool's decision and the state of the streams.

use crate::tcp_reassembly::*;
use std::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use TcpRole::{Initiator, Responder};

/// Sequence numbers per millisecond that Linux's ISN clock advances (RFC
/// 6528 with a 64 ns tick).
const ISN_CLOCK_PER_MS: u32 = 15_625;

/// How a connection chooses its ISNs relative to the connection before it
/// on the same four-tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reuse {
    /// Random ISNs far away from the old ones.
    Far,
    /// Linux TIME-WAIT reuse: the client picks the old client end plus
    /// 65537, which a server in TIME-WAIT accepts right away.
    TimeWait,
    /// The client's ISN lies this far below the old client end: a server
    /// that still holds the old connection answers the SYN with an ACK.
    NearBelow(u32),
    /// Both ISNs from a clock that ran this many milliseconds (at least
    /// one) since the old ISNs were picked: close to the old ones, maybe
    /// inside the old spans.
    ClockAhead(u32),
    /// Both ISNs lie inside the old streams' spans (a reuse after a reset,
    /// which has no TIME-WAIT to keep them apart).
    InsideSpans,
}

impl Reuse {
    /// Every kind, with a representative parameter.
    pub const ALL: [Reuse; 5] = [
        Reuse::Far,
        Reuse::TimeWait,
        Reuse::NearBelow(500),
        Reuse::ClockAhead(1),
        Reuse::InsideSpans,
    ];
}

/// How a connection ends in the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Close {
    /// The endpoints keep the connection open: the client vanished (a
    /// reboot), the server still holds it.
    None,
    /// `role` sends its FIN first, the other side answers with its FIN, and
    /// `role` ACKs it.
    By(TcpRole),
    /// Both FINs cross, each side ACKs the other's.
    Simultaneous,
    /// `role` resets the connection.
    Reset(TcpRole),
}

impl Close {
    /// Every kind.
    pub const ALL: [Close; 6] = [
        Close::None,
        Close::By(Initiator),
        Close::By(Responder),
        Close::Simultaneous,
        Close::Reset(Initiator),
        Close::Reset(Responder),
    ];

    /// Returns true if the server still holds state for the connection when
    /// the client's next SYN arrives: the connection is established (the
    /// client vanished), or the server closed first and sits in TIME-WAIT.
    fn server_holds_state(self) -> bool {
        matches!(
            self,
            Close::None | Close::By(Responder) | Close::Simultaneous
        )
    }
}

/// What a connection in the world looks like.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionPlan {
    /// How its ISNs relate to the connection before (ignored for the first).
    pub reuse: Reuse,
    /// Bytes each role sends.
    pub data: [Vec<u8>; 2],
    /// Lengths of the data segments, cycled.
    pub segment_lens: Vec<usize>,
    /// Which role sends next, cycled (`true` is the initiator).
    pub directions: Vec<bool>,
    /// How it ends.
    pub close: Close,
    /// Whether the last segment of an orderly close (the ACK of the second
    /// FIN) is lost on the wire, so that the passive closer retransmits its
    /// FIN later (in LAST-ACK).
    pub last_ack_lost_on_wire: bool,
    /// Number of 100-byte data segments of the other side still in flight
    /// when `role` reset the connection (they arrive after the RST).
    pub in_flight_after_reset: usize,
}

impl ConnectionPlan {
    /// A plan with a request and a response and the given reuse and close.
    pub fn simple(reuse: Reuse, close: Close) -> ConnectionPlan {
        ConnectionPlan {
            reuse,
            data: [
                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
            ],
            segment_lens: vec![10],
            directions: vec![true, false],
            close,
            last_ack_lost_on_wire: false,
            in_flight_after_reset: 0,
        }
    }
}

/// The history of a four-tuple: the real connections in order and the true
/// sequence of their segments.
#[derive(Clone, Debug)]
pub(crate) struct World {
    pub connections: Vec<ConnectionScript>,
    pub segments: Vec<TestSegment>,
}

impl World {
    /// Builds the world of `plans`, one connection each in order, with the
    /// first connection's ISNs `isns`. `late_positions` are cycled to place
    /// a connection's late segments among the next connection's first
    /// segments (0 is before its SYN).
    pub fn build(isns: [u32; 2], plans: &[ConnectionPlan], late_positions: &[usize]) -> World {
        let endpoints = [addr("10.0.0.1:50000"), addr("10.0.0.2:80")];
        let mut connections: Vec<ConnectionScript> = Vec::new();
        let mut segments: Vec<TestSegment> = Vec::new();
        // late segments of the connection before, with the position among
        // the next connection's segments they arrive at
        let mut late: Vec<(TestSegment, usize)> = Vec::new();
        let mut late_position = 0;
        let mut next_late_position = |late: &mut Vec<(TestSegment, usize)>, segment| {
            let at = late_positions[late_position % late_positions.len()];
            late_position += 1;
            late.push((segment, at));
        };
        for (index, plan) in plans.iter().enumerate() {
            let previous = connections.last().map(|old| (old, plans[index - 1].close));
            let isns = match previous {
                None => isns,
                Some((old, _)) => pick_isns(old, plan.reuse, index as u32),
            };
            let mut script = ConnectionScript::new(endpoints[0], endpoints[1], isns[0], isns[1]);
            script.incarnation = index as u32;
            script.syn();
            // segments of the connection before that this handshake triggers
            let mut triggered: Vec<(TestSegment, usize)> = Vec::new();
            // a server that still holds the old connection answers a SYN
            // that doesn't lie after the old client end with an ACK (in
            // TIME-WAIT: of the old FIN; established: a challenge ACK, RFC
            // 5961); the client in SYN-SENT answers an ACK that doesn't ACK
            // its SYN with <SEQ=SEG.ACK><CTL=RST> and drops one that does
            // (RFC 9293 3.10.7.3); the server drops the old connection, and
            // the client retransmits its SYN
            if let Some((old, close)) = previous {
                let old_client_end = old.seq(Initiator, old.next_offset(Initiator));
                let after_old_end = 0 < isns[0].wrapping_sub(old_client_end) as i32;
                if close.server_holds_state() && (Close::None == close || false == after_old_end) {
                    let mut old = old.clone();
                    old.ack(Responder);
                    triggered.push((old.segments.last().unwrap().clone(), 1));
                    if old_client_end != isns[0].wrapping_add(1) {
                        old.rst(Initiator);
                        let rst = old.segments.last_mut().unwrap();
                        rst.header.ack = false;
                        rst.ack = None;
                        triggered.push((rst.clone(), 1));
                    }
                    let retransmitted = script.segments[0].clone();
                    script.segments.push(retransmitted);
                }
            }
            script.syn_ack().ack(Initiator);
            send_interleaved(
                &mut script,
                &plan.data,
                &plan.segment_lens,
                &plan.directions,
            );
            let mut tail: Vec<TestSegment> = Vec::new();
            match plan.close {
                Close::None => {}
                Close::By(first) => {
                    script.fin(first).fin(first.other());
                    if plan.last_ack_lost_on_wire {
                        // the passive closer retransmits its FIN in LAST-ACK
                        tail.push(script.segments.last().unwrap().clone());
                    } else {
                        script.ack(first);
                    }
                }
                Close::Simultaneous => {
                    script.simultaneous_fins().ack(Initiator).ack(Responder);
                }
                Close::Reset(by) => {
                    // bytes of the other side still in flight arrive after
                    // the RST
                    let other = by.other();
                    for i in 0..plan.in_flight_after_reset {
                        let offset = script.next_offset(other) + 100 * i as u64;
                        let mut copy = script.clone();
                        copy.send_at(other, offset, &[b'f'; 100]);
                        tail.push(copy.segments.pop().unwrap());
                    }
                    script.rst(by);
                }
            }
            // the late segments of the connection before, and the ones this
            // handshake triggered, among this connection's first segments;
            // an endpoint's segments can't overtake its later segments on
            // one path, so a late segment of the connection before arrives
            // before the first segment its sender sends in this connection
            // (what merged taps do is the capture's skew)
            let mut inserts = core::mem::take(&mut late);
            for (segment, at) in &mut inserts {
                let first_own = script
                    .segments
                    .iter()
                    .position(|own| own.sender == segment.sender)
                    .unwrap_or(script.segments.len());
                *at = (*at).min(first_own);
            }
            inserts.extend(triggered);
            inserts.sort_by_key(|(_, at)| *at);
            let mut inserts = inserts.into_iter().peekable();
            for (at, segment) in script.segments.iter().enumerate() {
                while let Some((late_segment, _)) = inserts.next_if(|(_, late_at)| *late_at <= at) {
                    segments.push(late_segment);
                }
                segments.push(segment.clone());
            }
            segments.extend(inserts.map(|(segment, _)| segment));
            for segment in tail {
                next_late_position(&mut late, segment);
            }
            connections.push(script);
        }
        segments.extend(late.into_iter().map(|(segment, _)| segment));
        World {
            connections,
            segments,
        }
    }
}

/// ISNs of the connection with the number `index` after `old`, chosen by
/// `reuse`.
fn pick_isns(old: &ConnectionScript, reuse: Reuse, index: u32) -> [u32; 2] {
    let old_isns = [Initiator, Responder].map(|role| old.seq(role, 0).wrapping_sub(1));
    let old_ends = [Initiator, Responder].map(|role| old.seq(role, old.next_offset(role)));
    let far = old_isns.map(|isn| isn.wrapping_add((1 << 30) + 7919 * index));
    let mut isns = pick_isns_by(reuse, old, old_isns, old_ends, far);
    // a new connection with the very ISN of the old one is a retransmission
    // to any observer, so stacks' clocks never produce it
    for (isn, old_isn) in isns.iter_mut().zip(old_isns) {
        if *isn == old_isn {
            *isn = isn.wrapping_add(1);
        }
    }
    isns
}

/// See [`pick_isns`].
fn pick_isns_by(
    reuse: Reuse,
    old: &ConnectionScript,
    old_isns: [u32; 2],
    old_ends: [u32; 2],
    far: [u32; 2],
) -> [u32; 2] {
    match reuse {
        Reuse::Far => far,
        Reuse::TimeWait => [old_ends[0].wrapping_add(65537), far[1]],
        Reuse::NearBelow(distance) => [old_ends[0].wrapping_sub(distance.max(1)), far[1]],
        Reuse::ClockAhead(ms) => old_isns.map(|isn| isn.wrapping_add(ISN_CLOCK_PER_MS * ms.max(1))),
        Reuse::InsideSpans => [Initiator, Responder].map(|role| {
            // the middle of the span (right after the old ISN for a stream
            // that sent nothing: the same ISN would be a retransmission)
            let span = old.next_offset(role);
            old.seq(role, span / 2)
        }),
    }
}

/// Appends the data segments of both roles to `script`: `segment_lens`
/// bytes at a time, in the order of `directions` (both cycled).
fn send_interleaved(
    script: &mut ConnectionScript,
    data: &[Vec<u8>; 2],
    segment_lens: &[usize],
    directions: &[bool],
) {
    let mut sent = [0usize, 0usize];
    let mut step = 0;
    while sent[0] < data[0].len() || sent[1] < data[1].len() {
        let initiator_done = sent[0] == data[0].len();
        let responder_done = sent[1] == data[1].len();
        let role =
            if responder_done || (false == initiator_done && directions[step % directions.len()]) {
                Initiator
            } else {
                Responder
            };
        let i = role_index(role);
        let len = segment_lens[step % segment_lens.len()]
            .max(1)
            .min(data[i].len() - sent[i]);
        script.send(role, &data[i][sent[i]..sent[i] + len]);
        sent[i] += len;
        step += 1;
    }
}

/// What a capture does to the true sequence of segments.
#[derive(Clone, Debug, Default)]
pub(crate) struct Capture {
    /// Whether each segment is lost (indexed by position in the world,
    /// cycled); the SYN and the SYN-ACK of one connection are never both
    /// lost (a reconnect without any half of its handshake continues the
    /// old connection behind a resync, a known limit of C2 and R2).
    pub lost: Vec<bool>,
    /// How many positions each segment of the responder arrives later than
    /// in the world (cycled): a capture merged from two taps. The segments
    /// of one direction keep their order (one tap sees one path; reordering
    /// within a direction is the reference model's domain), and the SYN-ACK
    /// of a connection whose SYN is lost keeps its place: a tap's skew lies
    /// far below a round trip, and the client sends its first bytes a round
    /// trip after the SYN, so they can't arrive before the SYN-ACK (bytes
    /// on the tombstone of the connection before would be absorbed as its
    /// late segments, a known limit of C1).
    pub skew: Vec<usize>,
    /// Whether each segment is captured twice (cycled).
    pub duplicated: Vec<bool>,
    /// Only the segments of this role are captured.
    pub one_direction: Option<TcpRole>,
    /// Number of segments before the capture starts.
    pub start: usize,
}

impl Capture {
    /// The captured segments of `world`.
    pub fn apply(&self, world: &[TestSegment]) -> Vec<TestSegment> {
        let cycled = |values: &[bool], i: usize| values.get(i % values.len().max(1)).copied();
        // a segment the capture doesn't show: lost, or of the direction
        // the capture doesn't see
        let lost = |i: usize, segment: &TestSegment| {
            cycled(&self.lost, i).unwrap_or(false)
                || self
                    .one_direction
                    .is_some_and(|role| role != segment.sender)
        };
        let mut kept: Vec<(usize, TestSegment)> = Vec::new();
        // the position the last responder segment arrived at
        let mut last_responder_at = 0;
        for (i, segment) in world.iter().enumerate() {
            let other_half_lost = segment.header.syn
                && world.iter().enumerate().any(|(j, other)| {
                    j != i
                        && other.header.syn
                        && other.incarnation == segment.incarnation
                        && other.sender != segment.sender
                        && lost(j, other)
                });
            if lost(i, segment) && false == other_half_lost {
                continue;
            }
            let syn_lost = segment.header.syn
                && world.iter().enumerate().any(|(j, syn)| {
                    syn.header.syn
                        && false == syn.header.ack
                        && syn.incarnation == segment.incarnation
                        && lost(j, syn)
                });
            let skew = if Responder == segment.sender
                && false == self.skew.is_empty()
                && false == syn_lost
            {
                self.skew[i % self.skew.len()]
            } else {
                0
            };
            let mut at = i + skew;
            if Responder == segment.sender {
                at = at.max(last_responder_at);
                last_responder_at = at;
            }
            kept.push((at, segment.clone()));
            if cycled(&self.duplicated, i).unwrap_or(false) {
                kept.push((at, segment.clone()));
            }
        }
        kept.sort_by_key(|(at, _)| *at);
        kept.into_iter()
            .map(|(_, segment)| segment)
            .filter(|segment| self.one_direction.is_none_or(|role| role == segment.sender))
            .skip(self.start)
            .collect()
    }
}

/// What the pool did with one captured segment.
#[derive(Clone, Debug)]
struct Step {
    segment: TestSegment,
    active: Option<TcpConnectionId>,
    ended: Option<(TcpConnectionId, Option<TcpConnectionEnd>)>,
    ignored: Option<TcpIgnoreReason>,
    /// State of the active connection's streams after the segment.
    streams: Option<[StreamState; 2]>,
}

/// Snapshot of a stream for the trace.
#[derive(Clone, Debug)]
struct StreamState {
    start: TcpStreamStart,
    highest: u64,
    acked: u64,
    holes: usize,
    fin: Option<u64>,
    resyncs: u64,
    out_of_window: u64,
}

impl StreamState {
    fn of(stream: &TcpStream) -> StreamState {
        StreamState {
            start: stream.status().start,
            highest: stream.highest_offset(),
            acked: stream.acked_offset(),
            holes: stream.holes().count(),
            fin: stream.fin_offset(),
            resyncs: stream.status().resyncs,
            out_of_window: stream.status().out_of_window_segments,
        }
    }
}

/// The timeline of a run, rendered for a human when a check fails.
#[derive(Clone, Debug, Default)]
pub(crate) struct Trace {
    steps: Vec<Step>,
}

impl core::fmt::Display for Trace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "step  conn dir flags      offset       ack      len  -> pool decision | initiator stream | responder stream")?;
        for (i, step) in self.steps.iter().enumerate() {
            let s = &step.segment;
            let dir = match s.sender {
                Initiator => "c>s",
                Responder => "s>c",
            };
            let flags = format!(
                "{}{}{}{}",
                if s.header.syn { "S" } else { "." },
                if s.header.ack { "A" } else { "." },
                if s.header.fin { "F" } else { "." },
                if s.header.rst { "R" } else { "." },
            );
            let ack = s.ack.map_or("-".into(), |ack| ack.to_string());
            let decision = match (&step.active, &step.ended, &step.ignored) {
                (_, _, Some(reason)) => format!("ignored {reason:?}"),
                (Some(id), Some((ended, end)), _) => {
                    format!("{id:?}, ended {ended:?} as {end:?}")
                }
                (Some(id), None, _) => format!("{id:?}"),
                (None, Some((ended, end)), _) => format!("ended {ended:?} as {end:?}"),
                (None, None, None) => "nothing".into(),
            };
            let streams = match &step.streams {
                Some([initiator, responder]) => {
                    format!("{} | {}", describe(initiator), describe(responder))
                }
                None => String::new(),
            };
            writeln!(
                f,
                "{i:>4}  {:>4} {dir} {flags} {:>12} {ack:>9} {:>6}  -> {decision} | {streams}",
                s.incarnation,
                s.offset,
                s.payload.len(),
            )?;
        }
        Ok(())
    }
}

fn describe(state: &StreamState) -> String {
    let start = match state.start {
        TcpStreamStart::Observed => "syn",
        TcpStreamStart::MidStreamPickup => "pickup",
    };
    format!(
        "{start} high={} ack={} holes={} fin={:?} resyncs={} oow={}",
        state.highest, state.acked, state.holes, state.fin, state.resyncs, state.out_of_window
    )
}

/// Everything the pool produced for a capture.
pub(crate) struct Outcome {
    /// All connections, ended or evicted, by id.
    pub connections: Vec<TcpConnection<u32>>,
    /// The bytes read from each connection's streams (by id), as an eager
    /// reader reads them: after every segment, and to the end once the
    /// connection ended.
    pub delivered: Vec<[Vec<u8>; 2]>,
    pub trace: Trace,
}

/// Runs and checks captures against the truth.
pub(crate) struct Oracle;

impl Oracle {
    /// Feeds `capture` to a pool with `config` and evicts everything at the
    /// end.
    pub fn run(capture: &[TestSegment], config: TcpReassemblyConfig) -> Outcome {
        let mut pool = TcpReassemblyPool::<u32, ()>::new(config);
        let mut connections = Vec::new();
        let mut delivered: Vec<[Vec<u8>; 2]> = Vec::new();
        let mut trace = Trace::default();
        // an eager reader: reads after every segment
        let read = |connection: &mut TcpConnection<u32>, delivered: &mut Vec<[Vec<u8>; 2]>| {
            let id = connection.id().0 as usize;
            while delivered.len() <= id {
                delivered.push([Vec::new(), Vec::new()]);
            }
            for role in [Initiator, Responder] {
                let (bytes, _) = read_to_end(connection.stream_mut(role));
                delivered[id][role_index(role)].extend(bytes);
            }
        };
        for (i, segment) in capture.iter().enumerate() {
            let mut processed = segment.feed(&mut pool, i as u32);
            let streams = processed.active.as_ref().map(|(connection, _)| {
                [Initiator, Responder].map(|role| StreamState::of(connection.stream(role)))
            });
            trace.steps.push(Step {
                segment: segment.clone(),
                active: processed
                    .active
                    .as_ref()
                    .map(|(connection, _)| connection.id()),
                ended: processed
                    .ended
                    .as_ref()
                    .map(|connection| (connection.id(), connection.end())),
                ignored: processed.ignored,
                streams,
            });
            if let Some(ended) = processed.ended.as_mut() {
                read(ended, &mut delivered);
            }
            if let Some((active, _)) = processed.active.as_mut() {
                read(active, &mut delivered);
            }
            if let Some(ended) = processed.ended {
                connections.push(ended);
            }
        }
        pool.evict_all(|connection| {
            read(connection, &mut delivered);
            connections.push(connection.clone());
        });
        connections.sort_by_key(|connection| connection.id());
        Outcome {
            connections,
            delivered,
            trace,
        }
    }

    /// Checks `outcome` against the truth of `world` and `capture`. Returns
    /// a description of the first mismatch, with the trace.
    pub fn check(world: &World, capture: &[TestSegment], outcome: &Outcome) -> Result<(), String> {
        let expected = Expectations::derive(world, capture);
        let fail = |what: String| Err(format!("{what}\n\n{}", outcome.trace));
        if outcome.connections.len() != expected.connections.len() {
            return fail(format!(
                "{} pool connections, expected {} (real connections {:?})",
                outcome.connections.len(),
                expected.connections.len(),
                expected
                    .connections
                    .iter()
                    .map(|c| c.incarnation)
                    .collect::<Vec<_>>()
            ));
        }
        for (index, (connection, expected)) in outcome
            .connections
            .iter()
            .zip(&expected.connections)
            .enumerate()
        {
            let real = &world.connections[expected.incarnation as usize];
            let who = format!(
                "pool connection {index} (real connection {})",
                expected.incarnation
            );
            if connection.id() != TcpConnectionId(index as u64) {
                return fail(format!("{who} has id {:?}", connection.id()));
            }
            if connection.endpoint(Initiator) != real.endpoint(Initiator) {
                return fail(format!(
                    "{who} has initiator {}",
                    connection.endpoint(Initiator)
                ));
            }
            if false
                == connection
                    .end()
                    .is_some_and(|end| expected.ends.contains(&end))
            {
                return fail(format!(
                    "{who} ended as {:?}, expected one of {:?}",
                    connection.end(),
                    expected.ends
                ));
            }
            for role in [Initiator, Responder] {
                let stream = connection.stream(role);
                if 0 != stream.status().resyncs {
                    return fail(format!("{who}: the {role:?} stream resynced"));
                }
            }
        }
        // the bytes are read after the check of the ends, as reading needs
        // the connections mutably
        Ok(())
    }

    /// Checks the bytes an eager reader got from every stream of `outcome`
    /// against the truth: the captured bytes of the real connection, in
    /// order, nothing swallowed. Call after [`Oracle::check`].
    pub fn check_bytes(
        world: &World,
        capture: &[TestSegment],
        outcome: &Outcome,
    ) -> Result<(), String> {
        let expected = Expectations::derive(world, capture);
        for (index, expected) in expected.connections.iter().enumerate() {
            for role in [Initiator, Responder] {
                let delivered = outcome
                    .delivered
                    .get(index)
                    .map_or(&[][..], |streams| &streams[role_index(role)][..]);
                let wanted: Vec<&Vec<u8>> = expected
                    .bytes
                    .iter()
                    .map(|streams| &streams[role_index(role)])
                    .collect();
                if false == wanted.iter().any(|wanted| delivered == &wanted[..]) {
                    let shown = |bytes: &[u8]| {
                        let n = bytes.len().min(60);
                        format!(
                            "{} bytes, starting {:?}",
                            bytes.len(),
                            String::from_utf8_lossy(&bytes[..n])
                        )
                    };
                    let wanted: Vec<String> = wanted.iter().map(|w| shown(w)).collect();
                    return Err(format!(
                        "pool connection {index} (real connection {}), {role:?} stream delivered {}, expected one of {:?}\n\n{}",
                        expected.incarnation,
                        shown(delivered),
                        wanted,
                        outcome.trace
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Reads `stream` to its end, stepping over gaps. Returns the bytes and the
/// number of gaps.
fn read_to_end(stream: &mut TcpStream) -> (Vec<u8>, usize) {
    let mut bytes = Vec::new();
    let mut gaps = 0;
    for _ in 0..100_000 {
        match stream.read_received() {
            TcpRead::Data(data) => {
                let len = data.len();
                bytes.extend_from_slice(data);
                stream.consume(len);
            }
            TcpRead::Gap { .. } => {
                gaps += 1;
                stream.consume_gap();
            }
            TcpRead::Pending | TcpRead::End(_) => break,
        }
    }
    (bytes, gaps)
}

/// What the pool has to show for one visible real connection.
#[derive(Clone, Debug)]
struct ExpectedConnection {
    incarnation: u32,
    /// The ends the pool may report: the one the capture shows, and
    /// `Reconnect` as well if a later connection started before the close
    /// or the reset was captured completely.
    ends: Vec<TcpConnectionEnd>,
    /// The captured bytes of each stream the pool may deliver, in order:
    /// the ones that arrived before the connection's end and not before
    /// the stream's start (its SYN, or its first captured byte if the SYN
    /// came later or not at all: an eager reader read that byte already, so
    /// nothing can be put in front of it). If a later connection started
    /// before the close or the reset was captured completely, the pool may
    /// have replaced the connection there or let it finish, so the bytes up
    /// to the replacement are a second possibility.
    bytes: Vec<[Vec<u8>; 2]>,
}

/// What the truth and the capture say the pool has to produce.
#[derive(Clone, Debug)]
struct Expectations {
    connections: Vec<ExpectedConnection>,
}

/// State of a real connection while walking the capture.
#[derive(Clone, Debug)]
struct Walk {
    incarnation: u32,
    visible: bool,
    end: Option<TcpConnectionEnd>,
    /// Whether a later connection started while this one was open, and the
    /// captured bytes of each stream up to then.
    replaced: Option<[std::collections::BTreeMap<u64, u8>; 2]>,
    fins_seen: [bool; 2],
    fins_acked: [bool; 2],
    /// Offset each stream starts at: 0 if its SYN was captured before its
    /// bytes, else the offset of its first captured byte.
    first_offset: [Option<u64>; 2],
    /// Furthest offset of each stream the other side ACKed so far.
    acked: [u64; 2],
    /// Captured data by offset (later copies of a byte don't change it).
    bytes: [std::collections::BTreeMap<u64, u8>; 2],
}

impl Expectations {
    fn derive(world: &World, capture: &[TestSegment]) -> Expectations {
        let mut walks: Vec<Walk> = world
            .connections
            .iter()
            .enumerate()
            .map(|(i, _)| Walk {
                incarnation: i as u32,
                visible: false,
                end: None,
                replaced: None,
                fins_seen: [false; 2],
                fins_acked: [false; 2],
                first_offset: [None; 2],
                acked: [0; 2],
                bytes: [Default::default(), Default::default()],
            })
            .collect();
        for segment in capture {
            let k = segment.incarnation as usize;
            let script = &world.connections[k];
            let sender = role_index(segment.sender);
            let other = role_index(segment.sender.other());
            // a starting segment of a later connection replaces every open
            // connection before it (the pool may still let their close or
            // reset finish them, when it takes the new SYN for a late one);
            // bytes start a connection only while no later one started: on a
            // key a later connection holds, they are late segments
            let later_started = walks[k + 1..].iter().any(|later| later.visible);
            let starts = segment.header.syn
                || (false == segment.payload.is_empty()
                    && segment.header.ack
                    && false == later_started);
            if starts && false == walks[k].visible {
                for earlier in &mut walks[..k] {
                    if earlier.visible && earlier.end.is_none() && earlier.replaced.is_none() {
                        earlier.replaced = Some(earlier.bytes.clone());
                    }
                }
                walks[k].visible = true;
            }
            let walk = &mut walks[k];
            if false == walk.visible || walk.end.is_some() {
                continue;
            }
            if segment.header.rst {
                walk.end = Some(TcpConnectionEnd::Reset { by: segment.sender });
                continue;
            }
            if segment.header.syn {
                walk.first_offset[sender].get_or_insert(0);
            }
            // a single byte right before the other side's ACK, arriving at a
            // stream without a start, looks like the filler byte of a
            // keep-alive, which starts no stream (D3; in a started stream
            // it only drops out of an overdue hole, which the simulator's
            // bounded skew never leaves)
            let keep_alive_shaped = walk.first_offset[sender].is_none()
                && 1 == segment.payload.len()
                && segment.offset + 1 == walk.acked[sender];
            if false == segment.payload.is_empty() && false == keep_alive_shaped {
                let first = *walk.first_offset[sender].get_or_insert(segment.offset);
                for (i, byte) in segment.payload.iter().enumerate() {
                    let offset = segment.offset + i as u64;
                    if offset >= first {
                        walk.bytes[sender].entry(offset).or_insert(*byte);
                    }
                }
            }
            if segment.header.fin {
                walk.fins_seen[sender] = true;
            }
            if let Some(ack) = segment.ack {
                walk.acked[other] = walk.acked[other].max(ack);
            }
            // the FIN of the other side is ACKed once the ACK covers the
            // number after it
            let fin_end = script.next_offset(segment.sender.other());
            if segment.ack.is_some_and(|ack| ack >= fin_end)
                && script_sent_fin(script, segment.sender.other())
            {
                walk.fins_acked[other] = true;
            }
            if walk.fins_seen == [true, true] && walk.fins_acked == [true, true] {
                walk.end = Some(TcpConnectionEnd::Finished);
            }
        }
        let connections = walks
            .into_iter()
            .filter(|walk| walk.visible)
            .map(|walk| {
                let collect = |bytes: [std::collections::BTreeMap<u64, u8>; 2]| {
                    bytes.map(|bytes| bytes.into_values().collect::<Vec<u8>>())
                };
                let mut ends = Vec::new();
                let mut bytes = Vec::new();
                if let Some(at_replacement) = walk.replaced {
                    ends.push(TcpConnectionEnd::Reconnect);
                    bytes.push(collect(at_replacement));
                    if let Some(end) = walk.end {
                        ends.push(end);
                    }
                } else {
                    ends.push(walk.end.unwrap_or(TcpConnectionEnd::Evicted));
                }
                bytes.push(collect(walk.bytes));
                ExpectedConnection {
                    incarnation: walk.incarnation,
                    ends,
                    bytes,
                }
            })
            .collect();
        Expectations { connections }
    }
}

/// Returns true if `role` sent a FIN in `script`.
fn script_sent_fin(script: &ConnectionScript, role: TcpRole) -> bool {
    script
        .segments
        .iter()
        .any(|segment| segment.header.fin && segment.sender == role)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_gens::*;
    use proptest::prelude::*;

    /// The pool's configuration for the simulator: the defaults, but holes
    /// without limit, as the capture layer's loss of single bytes leaves
    /// more holes than the default allows and the limits are the reference
    /// model's domain, not the simulator's.
    fn config() -> TcpReassemblyConfig {
        TcpReassemblyConfig {
            max_holes_per_stream: usize::MAX,
            ..Default::default()
        }
    }

    /// Builds the world and the capture, runs the pool and checks, unless
    /// the capture hits a known limit of the spec (see [`known_limit`]).
    fn simulate(
        isns: [u32; 2],
        plans: &[ConnectionPlan],
        late_positions: &[usize],
        capture: &Capture,
        config: TcpReassemblyConfig,
    ) -> Result<(), String> {
        let world = World::build(isns, plans, late_positions);
        let captured = capture.apply(&world.segments);
        if known_limit(&world, &captured, &config) {
            return Ok(());
        }
        let outcome = Oracle::run(&captured, config);
        Oracle::check(&world, &captured, &outcome)?;
        Oracle::check_bytes(&world, &captured, &outcome)
    }

    /// Every reuse kind after every close kind, with the late segments at
    /// every position, the close's last ACK lost on the wire or not, bytes
    /// in flight after a reset, in both capture orders of the TIME-WAIT
    /// pair and with the new SYN-ACK lost, with and without a wrap of the
    /// sequence numbers.
    #[test]
    fn reconnect_matrix() {
        let mut failures = Vec::new();
        for isns in [[1000, 2000], [u32::MAX - 20, u32::MAX - 5000]] {
            for close in Close::ALL {
                for reuse in Reuse::ALL {
                    for late_position in [0, 1, 2, 4] {
                        for variant in 0..4 {
                            let mut old = ConnectionPlan::simple(Reuse::Far, close);
                            old.last_ack_lost_on_wire =
                                matches!(close, Close::By(_)) && 1 == variant;
                            old.in_flight_after_reset =
                                usize::from(matches!(close, Close::Reset(_)) && 1 == variant);
                            let new = ConnectionPlan::simple(reuse, Close::By(Responder));
                            let capture = match variant {
                                2 => Capture {
                                    // the responder's segments two positions late
                                    skew: vec![2],
                                    ..Capture::default()
                                },
                                3 => Capture {
                                    // the new SYN-ACK lost (the 2nd SYN segment)
                                    lost: lost_syn_ack_of(
                                        1,
                                        &World::build(
                                            isns,
                                            &[old.clone(), new.clone()],
                                            &[late_position],
                                        ),
                                    ),
                                    ..Capture::default()
                                },
                                _ => Capture::default(),
                            };
                            if let Err(failure) =
                                simulate(isns, &[old, new], &[late_position], &capture, config())
                            {
                                failures.push(format!(
                                    "isns {isns:?}, old close {close:?}, reuse {reuse:?}, late at {late_position}, variant {variant}:\n{failure}"
                                ));
                            }
                        }
                    }
                }
            }
        }
        for failure in &failures {
            std::eprintln!("FAILED {}", failure.lines().next().unwrap_or(""));
        }
        assert!(
            failures.is_empty(),
            "{} scenarios failed, the first:\n{}",
            failures.len(),
            failures[0]
        );
    }

    /// Returns true if the capture hits a known limit of the spec that no
    /// passive observer can resolve:
    ///
    /// - C4: a half of a connection's handshake whose ISN + 1 lies within k
    ///   windows (of the fallback window, as a pickup knows none) before
    ///   the first captured byte of the stream of the same role in the
    ///   connection before (or before the position the other side's ACKs
    ///   put a stream without bytes at, K1), which the capture picked up
    ///   without that stream's handshake half and without a FIN before the
    ///   new half: the pool takes the half for the pickup's own late SYN or
    ///   SYN-ACK, and the new connection starts at its other half or not at
    ///   all.
    /// - C1: late segments of a connection the pool never saw (the capture
    ///   shows none of its handshake and none of its bytes, e.g. it starts
    ///   at the connection's close) arrive after the next connection's SYN:
    ///   the pool has no replaced connection to tell them by, so the ACK of
    ///   a server that still held the old connection answers the new SYN
    ///   (S5) and the client's RST to it resets the new connection (F4).
    /// - C1: the number a stream of the old connection reached is the new
    ///   ISN + 1 of the same endpoint, so a late segment of the other side
    ///   that ACKs the old end ACKs the new SYN as well: the numbers can't
    ///   tell the two apart.
    /// - C1: both new ISNs lie within the old spans and a half of the new
    ///   handshake is lost: a segment of the stream that half would have
    ///   started, whose ACK number lies beyond what the other new stream
    ///   sent in the capture (bytes it lost), is the old connection's by
    ///   its numbers.
    fn known_limit(world: &World, captured: &[TestSegment], config: &TcpReassemblyConfig) -> bool {
        let range = u64::from(config.fallback_window)
            * u64::from(config.hole_give_up_window_factor.unwrap_or(2).max(1));
        for (k, script) in world.connections.iter().enumerate().skip(1) {
            let previous = &world.connections[k - 1];
            let of = |incarnation: usize, role: TcpRole| {
                captured
                    .iter()
                    .filter(move |s| s.incarnation as usize == incarnation && s.sender == role)
            };
            let first_of_k = captured.iter().position(|s| s.incarnation as usize == k);
            // the connection before is visible to the pool if the capture
            // shows a half of its handshake, or bytes of it before the next
            // connection's first segment
            let previous_visible = captured.iter().enumerate().any(|(i, s)| {
                s.incarnation as usize == k - 1
                    && (s.header.syn
                        || (false == s.payload.is_empty()
                            && s.header.ack
                            && first_of_k.is_none_or(|at| i < at)))
            });
            let previous_late = first_of_k.is_some_and(|at| {
                captured[at..]
                    .iter()
                    .any(|s| s.incarnation as usize == k - 1 && false == s.header.syn)
            });
            if false == previous_visible && previous_late {
                return true;
            }
            let inside_spans = [Initiator, Responder].iter().all(|role| {
                let first = previous.seq(*role, 0);
                let span = previous.next_offset(*role) + range;
                u64::from(script.seq(*role, 0).wrapping_sub(first)) <= span
            });
            let half_lost = [Initiator, Responder]
                .iter()
                .any(|role| false == of(k, *role).any(|s| s.header.syn));
            if inside_spans && half_lost {
                return true;
            }
            for role in [Initiator, Responder] {
                let old_end = previous.seq(role, previous.next_offset(role));
                let late_of_other = first_of_k.is_some_and(|at| {
                    captured[at..].iter().any(|s| {
                        s.incarnation as usize == k - 1
                            && s.sender == role.other()
                            && false == s.header.syn
                    })
                });
                if old_end == script.seq(role, 0) && late_of_other {
                    return true;
                }
            }
            for role in [Initiator, Responder] {
                let half_captured = of(k, role).any(|s| s.header.syn);
                let previous_pickup = of(k - 1, role).all(|s| false == s.header.syn);
                // where the pickup's stream starts: its first captured byte,
                // or, without bytes, where the other side's ACKs put it (K1)
                let first_offset = of(k - 1, role)
                    .filter(|s| false == s.payload.is_empty())
                    .map(|s| s.offset)
                    .min()
                    .or_else(|| of(k - 1, role.other()).filter_map(|s| s.ack).min());
                // a FIN of the old connection before the half tells the pool
                // the half is no late SYN of the pickup (C4)
                let fin_before = first_of_k.is_some_and(|at| {
                    captured[..at]
                        .iter()
                        .any(|s| s.incarnation as usize == k - 1 && s.header.fin)
                });
                if let (true, true, Some(first_offset), false) =
                    (half_captured, previous_pickup, first_offset, fin_before)
                {
                    let first_seq = previous.seq(role, first_offset);
                    let distance = first_seq.wrapping_sub(script.seq(role, 0));
                    if u64::from(distance) <= range {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// A `lost` vector that loses the SYN-ACK of connection `incarnation`.
    fn lost_syn_ack_of(incarnation: u32, world: &World) -> Vec<bool> {
        world
            .segments
            .iter()
            .map(|segment| {
                segment.incarnation == incarnation && segment.header.syn && segment.header.ack
            })
            .collect()
    }

    fn reuse_any() -> impl Strategy<Value = Reuse> {
        prop_oneof![
            Just(Reuse::Far),
            Just(Reuse::TimeWait),
            (1u32..100_000).prop_map(Reuse::NearBelow),
            (1u32..5000).prop_map(Reuse::ClockAhead),
            Just(Reuse::InsideSpans),
        ]
    }

    fn close_any() -> impl Strategy<Value = Close> {
        prop_oneof![
            Just(Close::None),
            Just(Close::By(Initiator)),
            Just(Close::By(Responder)),
            Just(Close::Simultaneous),
            Just(Close::Reset(Initiator)),
            Just(Close::Reset(Responder)),
        ]
    }

    prop_compose! {
        fn plan_any()(
            reuse in reuse_any(),
            data in [stream_data_any(3000), stream_data_any(3000)],
            segment_lens in prop::collection::vec(1usize..600, 1..8),
            directions in prop::collection::vec(any::<bool>(), 1..8),
            close in close_any(),
            last_ack_lost_on_wire in any::<bool>(),
            in_flight_after_reset in 0usize..3,
        ) -> ConnectionPlan {
            ConnectionPlan {
                reuse,
                data,
                segment_lens,
                directions,
                close,
                last_ack_lost_on_wire,
                in_flight_after_reset,
            }
        }
    }

    prop_compose! {
        fn capture_any()(
            lost in prop::collection::vec(prop::bool::weighted(0.05), 1..64),
            skew in prop::collection::vec(0usize..4, 1..16),
            duplicated in prop::collection::vec(prop::bool::weighted(0.05), 1..64),
            one_direction in prop_oneof![8 => Just(None), 1 => Just(Some(Initiator)), 1 => Just(Some(Responder))],
            start in prop_oneof![4 => Just(0usize), 1 => 1usize..6],
        ) -> Capture {
            Capture { lost, skew, duplicated, one_direction, start }
        }
    }

    proptest! {
        /// Histories of two or three connections on one four-tuple with
        /// every reuse and close kind, captured with loss, skew,
        /// duplicates, a late start or one direction only.
        #[test]
        fn reconnect_histories(
            isns in [tcp_isn_any(), tcp_isn_any()],
            plans in prop::collection::vec(plan_any(), 2..4),
            late_positions in prop::collection::vec(0usize..6, 1..4),
            capture in capture_any(),
        ) {
            if let Err(failure) = simulate(isns, &plans, &late_positions, &capture, config()) {
                let summary: Vec<_> = plans
                    .iter()
                    .map(|plan| (plan.reuse, plan.close, plan.last_ack_lost_on_wire, plan.in_flight_after_reset))
                    .collect();
                prop_assert!(
                    false,
                    "plans (reuse, close, last ACK lost on wire, in flight) {:?}, late positions {:?}, capture {:?}\n{}",
                    summary, late_positions, capture, failure
                );
            }
        }
    }
}
