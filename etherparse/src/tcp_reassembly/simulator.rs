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
//! loss, a delay of either direction against the other (merged taps), a
//! start in the middle of the history, one direction only, duplicates.
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

/// Time between a segment and the next one an endpoint sends after a
/// retransmission timeout, in units of one segment: more than any delay of
/// a tap, so that a capture can't show a segment after one its endpoint
/// sent a timeout later.
const TIMEOUT: u64 = 1000;

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
    /// When each segment was sent, in units of one segment, with a jump of
    /// [`TIMEOUT`] before a retransmission after a timeout.
    pub times: Vec<u64>,
}

impl World {
    /// Builds the world of `plans`, one connection each in order, with the
    /// first connection's ISNs `isns`. `late_positions` are cycled to place
    /// a connection's late segments among the next connection's first
    /// segments (0 is before its SYN).
    pub fn build(isns: [u32; 2], plans: &[ConnectionPlan], late_positions: &[usize]) -> World {
        let endpoints = [addr("10.0.0.1:50000"), addr("10.0.0.2:80")];
        let mut connections: Vec<ConnectionScript> = Vec::new();
        // the segments, each with whether a timeout comes before it
        let mut segments: Vec<(TestSegment, bool)> = Vec::new();
        // late segments of the connection before, with the position among
        // the next connection's segments they arrive at
        let mut late: Vec<(TestSegment, usize, bool)> = Vec::new();
        let mut late_position = 0;
        let mut next_late_position = |late: &mut Vec<_>, segment, timeout| {
            let at = late_positions[late_position % late_positions.len()];
            late_position += 1;
            late.push((segment, at, timeout));
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
            // the SYN the client retransmits after a timeout
            let mut retransmitted_at = None;
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
                    retransmitted_at = Some(script.segments.len() - 1);
                }
            }
            script.syn_ack().ack(Initiator);
            send_interleaved(
                &mut script,
                &plan.data,
                &plan.segment_lens,
                &plan.directions,
            );
            // segments arriving after the connection's end, each with whether
            // a timeout comes before it
            let mut tail: Vec<(TestSegment, bool)> = Vec::new();
            match plan.close {
                Close::None => {}
                Close::By(first) => {
                    script.fin(first).fin(first.other());
                    if plan.last_ack_lost_on_wire {
                        // the passive closer retransmits its FIN in LAST-ACK
                        tail.push((script.segments.last().unwrap().clone(), true));
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
                        tail.push((copy.segments.pop().unwrap(), false));
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
            for (segment, at, _) in &mut inserts {
                let first_own = script
                    .segments
                    .iter()
                    .position(|own| own.sender == segment.sender)
                    .unwrap_or(script.segments.len());
                *at = (*at).min(first_own);
            }
            inserts.extend(
                triggered
                    .into_iter()
                    .map(|(segment, at)| (segment, at, false)),
            );
            inserts.sort_by_key(|(_, at, _)| *at);
            let mut inserts = inserts.into_iter().peekable();
            for (at, segment) in script.segments.iter().enumerate() {
                while let Some((late_segment, _, timeout)) =
                    inserts.next_if(|(_, late_at, _)| *late_at <= at)
                {
                    segments.push((late_segment, timeout));
                }
                segments.push((segment.clone(), Some(at) == retransmitted_at));
            }
            segments.extend(inserts.map(|(segment, _, timeout)| (segment, timeout)));
            for (segment, timeout) in tail {
                next_late_position(&mut late, segment, timeout);
            }
            connections.push(script);
        }
        segments.extend(
            late.into_iter()
                .map(|(segment, _, timeout)| (segment, timeout)),
        );
        let mut time = 0;
        let times = segments
            .iter()
            .map(|(_, timeout)| {
                time += if *timeout { TIMEOUT } else { 1 };
                time
            })
            .collect();
        World {
            connections,
            segments: segments.into_iter().map(|(segment, _)| segment).collect(),
            times,
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
    /// How much later than it was sent each segment of the initiator and of
    /// the responder arrives, in units of one segment (indexed by role, each
    /// cycled): a capture merged from two taps, one of which lags. The
    /// segments of one direction keep their order (one tap sees one path;
    /// reordering within a direction is the reference model's domain, but
    /// see `half_delay`), and no delay reaches past a [`TIMEOUT`].
    pub skew: [Vec<usize>; 2],
    /// How much later than the rest of its direction each handshake half of
    /// the initiator and of the responder arrives (indexed by role): the
    /// network reordered it behind its sender's next segments, as a tap in
    /// the middle of the path can see, but not past its sender's first
    /// segment of the next connection, nor past a [`TIMEOUT`].
    pub half_delay: [u64; 2],
    /// Whether each segment is captured twice (cycled).
    pub duplicated: Vec<bool>,
    /// Only the segments of this role are captured.
    pub one_direction: Option<TcpRole>,
    /// Number of segments before the capture starts.
    pub start: usize,
}

impl Capture {
    /// The captured segments of `world`.
    pub fn apply(&self, world: &World) -> Vec<TestSegment> {
        let (times, world) = (&world.times, &world.segments);
        let cycled = |values: &[bool], i: usize| values.get(i % values.len().max(1)).copied();
        // a segment the capture doesn't show: lost, or of the direction
        // the capture doesn't see
        let lost = |i: usize, segment: &TestSegment| {
            cycled(&self.lost, i).unwrap_or(false)
                || self
                    .one_direction
                    .is_some_and(|role| role != segment.sender)
        };
        let mut kept: Vec<(u64, TestSegment)> = Vec::new();
        // when the last segment of each role arrived
        let mut last_at = [0u64; 2];
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
            let role = role_index(segment.sender);
            let skew = &self.skew[role];
            let delay = skew.get(i % skew.len().max(1)).copied().unwrap_or(0) as u64;
            let at = (times[i] + delay.min(TIMEOUT - 1)).max(last_at[role]);
            last_at[role] = at;
            // a handshake half the network held back arrives after its
            // sender's next segments, which keep their times, but before
            // its sender's first segment of the next connection
            let at = if segment.header.syn && false == segment.header.rst {
                let next_connection = world
                    .iter()
                    .zip(times)
                    .skip(i + 1)
                    .find(|(later, _)| {
                        later.sender == segment.sender && later.incarnation != segment.incarnation
                    })
                    .map_or(u64::MAX, |(_, time)| *time);
                let held = at + self.half_delay[role].min(TIMEOUT - 1);
                held.min(next_connection.saturating_sub(1)).max(at)
            } else {
                at
            };
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

/// What a reader got from one stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Delivered {
    /// The bytes, in order.
    pub bytes: Vec<u8>,
    /// The gaps: the offset among the bytes they lie at (the number of
    /// bytes read before them) and their length; adjacent gaps are one.
    pub gaps: Vec<(usize, u64)>,
}

impl Delivered {
    /// Records a gap of `len` bytes after the bytes read so far, joining it
    /// with a gap that ends there.
    fn add_gap(&mut self, len: u64) {
        let at = self.bytes.len();
        match self.gaps.last_mut() {
            Some((last_at, last_len)) if *last_at == at => *last_len += len,
            _ => self.gaps.push((at, len)),
        }
    }
}

/// Everything the pool produced for a capture.
pub(crate) struct Outcome {
    /// All connections, ended or evicted, by id.
    pub connections: Vec<TcpConnection<u32>>,
    /// What an eager reader got from each connection's streams (by id):
    /// the bytes, and the gaps with their lengths where they lie among the
    /// bytes; read after every segment, and to the end once the connection
    /// ended.
    pub delivered: Vec<[Delivered; 2]>,
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
        let mut delivered: Vec<[Delivered; 2]> = Vec::new();
        let mut trace = Trace::default();
        // an eager reader: reads after every segment
        let read = |connection: &mut TcpConnection<u32>, delivered: &mut Vec<[Delivered; 2]>| {
            let id = connection.id().0 as usize;
            while delivered.len() <= id {
                delivered.push([Delivered::default(), Delivered::default()]);
            }
            for role in [Initiator, Responder] {
                read_to_end(
                    connection.stream_mut(role),
                    &mut delivered[id][role_index(role)],
                );
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
        let empty = Delivered::default();
        for (index, expected) in expected.connections.iter().enumerate() {
            for role in [Initiator, Responder] {
                let delivered = outcome
                    .delivered
                    .get(index)
                    .map_or(&empty, |streams| &streams[role_index(role)]);
                let wanted: Vec<&Delivered> = expected
                    .bytes
                    .iter()
                    .map(|streams| &streams[role_index(role)])
                    .collect();
                if false == wanted.iter().any(|wanted| &delivered == wanted) {
                    let shown = |got: &Delivered| {
                        let n = got.bytes.len().min(60);
                        format!(
                            "{} bytes, starting {:?}, gaps (after byte, len) {:?}",
                            got.bytes.len(),
                            String::from_utf8_lossy(&got.bytes[..n]),
                            got.gaps
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

/// Reads `stream` as far as it goes, stepping over gaps, and appends what
/// it got to `delivered`.
fn read_to_end(stream: &mut TcpStream, delivered: &mut Delivered) {
    for _ in 0..100_000 {
        match stream.read_received() {
            TcpRead::Data(data) => {
                let len = data.len();
                delivered.bytes.extend_from_slice(data);
                stream.consume(len);
            }
            TcpRead::Gap { len } => {
                // a gap of unknown length comes from a resync, which the
                // oracle rejects separately
                delivered.add_gap(len.unwrap_or(0));
                stream.consume_gap();
            }
            TcpRead::Pending | TcpRead::End(_) => break,
        }
    }
}

/// What the pool has to show for one visible real connection.
#[derive(Clone, Debug)]
struct ExpectedConnection {
    incarnation: u32,
    /// The ends the pool may report: the one the capture shows, and
    /// `Reconnect` as well if a later connection started before the close
    /// or the reset was captured completely.
    ends: Vec<TcpConnectionEnd>,
    /// What the pool may deliver for each stream: the captured bytes, in
    /// order, that arrived before the connection's end and not before the
    /// stream's start (its SYN, or its first captured byte if the SYN came
    /// later or not at all: an eager reader read that byte already, so
    /// nothing can be put in front of it), with a gap wherever bytes are
    /// missing between them or up to the end the pool knows (the FIN, or
    /// the furthest byte the other side ACKed). If a later connection
    /// started before the close or the reset was captured completely, the
    /// pool may have replaced the connection there or let it finish, so the
    /// delivery up to the replacement is a second possibility.
    bytes: Vec<[Delivered; 2]>,
}

/// What the truth and the capture say the pool has to produce.
#[derive(Clone, Debug)]
struct Expectations {
    connections: Vec<ExpectedConnection>,
}

/// What the capture had shown of a connection at some point: where each
/// stream started, the captured bytes of each stream, the furthest offsets
/// the other side ACKed and the FINs.
#[derive(Clone, Debug)]
struct Snapshot {
    first_offset: [Option<u64>; 2],
    bytes: [std::collections::BTreeMap<u64, u8>; 2],
    acked: [u64; 2],
    fin: [Option<u64>; 2],
}

/// State of a real connection while walking the capture.
#[derive(Clone, Debug)]
struct Walk {
    incarnation: u32,
    visible: bool,
    end: Option<TcpConnectionEnd>,
    /// Whether a later connection started while this one was open, and what
    /// the capture had shown of this one by then.
    replaced: Option<Snapshot>,
    fins_seen: [bool; 2],
    fins_acked: [bool; 2],
    /// Offset each stream starts at: 0 if its SYN was captured before its
    /// bytes, else the offset of its first captured byte.
    first_offset: [Option<u64>; 2],
    /// Whether each stream started at a handshake half (its own, or for the
    /// initiator the SYN-ACK's ACK number, A2).
    observed: [bool; 2],
    /// Furthest offset of each stream the other side ACKed so far.
    acked: [u64; 2],
    /// Offset of each stream's FIN, if captured.
    fin: [Option<u64>; 2],
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
                observed: [false; 2],
                acked: [0; 2],
                fin: [None; 2],
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
                        earlier.replaced = Some(Snapshot {
                            first_offset: earlier.first_offset,
                            bytes: earlier.bytes.clone(),
                            acked: earlier.acked,
                            fin: earlier.fin,
                        });
                    }
                }
                walks[k].visible = true;
            }
            let walk = &mut walks[k];
            if false == walk.visible || walk.end.is_some() {
                continue;
            }
            // a late handshake half of a stream that started from bytes or a
            // FIN changes nothing: the eager reader read that pickup, so A5
            // ignores the half with its ACK number (C4)
            if segment.header.syn
                && false == segment.header.rst
                && false == walk.observed[sender]
                && walk.first_offset[sender].is_some()
            {
                continue;
            }
            // an accepted RST's ACK counts (F4)
            if let Some(ack) = segment.ack {
                walk.acked[other] = walk.acked[other].max(ack);
            }
            if segment.header.rst {
                walk.end = Some(TcpConnectionEnd::Reset { by: segment.sender });
                continue;
            }
            if segment.header.syn {
                walk.first_offset[sender].get_or_insert(0);
                walk.observed[sender] = true;
                // the ACK number of a SYN-ACK starts the other stream too (A2)
                if segment.header.ack && walk.first_offset[other].is_none() {
                    walk.first_offset[other] = Some(0);
                    walk.observed[other] = true;
                }
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
                let fin = segment.offset + segment.payload.len() as u64;
                // a FIN starts a stream without a start (A4)
                walk.first_offset[sender].get_or_insert(fin);
                walk.fins_seen[sender] = true;
                walk.fin[sender] = Some(fin);
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
                // the delivery: the bytes in order, a gap wherever bytes are
                // missing between the stream's start and the end the pool
                // knows (the furthest byte, or what the other side ACKed,
                // which is no byte beyond a captured FIN)
                let collect = |first_offset: [Option<u64>; 2],
                               bytes: [std::collections::BTreeMap<u64, u8>; 2],
                               acked: [u64; 2],
                               fin: [Option<u64>; 2]| {
                    let mut streams = [Delivered::default(), Delivered::default()];
                    for (i, bytes) in bytes.into_iter().enumerate() {
                        // a stream without a start and without bytes shows
                        // nothing, one with a start shows the bytes it knows
                        // were sent as a gap
                        let Some(first) = bytes
                            .first_key_value()
                            .map(|(&first_byte, _)| {
                                first_offset[i].unwrap_or(first_byte).min(first_byte)
                            })
                            .or(first_offset[i])
                        else {
                            continue;
                        };
                        let last = bytes.last_key_value().map_or(first, |(k, _)| *k + 1);
                        let acked = fin[i].map_or(acked[i], |fin| acked[i].min(fin));
                        let end = last.max(acked).max(fin[i].unwrap_or(0));
                        let mut expected_offset = first;
                        for (&offset, &byte) in &bytes {
                            if offset > expected_offset {
                                streams[i].add_gap(offset - expected_offset);
                            }
                            streams[i].bytes.push(byte);
                            expected_offset = offset + 1;
                        }
                        if end > expected_offset {
                            streams[i].add_gap(end - expected_offset);
                        }
                    }
                    streams
                };
                let mut ends = Vec::new();
                let mut bytes = Vec::new();
                if let Some(then) = walk.replaced {
                    ends.push(TcpConnectionEnd::Reconnect);
                    bytes.push(collect(then.first_offset, then.bytes, then.acked, then.fin));
                    if let Some(end) = walk.end {
                        ends.push(end);
                    }
                } else {
                    ends.push(walk.end.unwrap_or(TcpConnectionEnd::Evicted));
                }
                bytes.push(collect(walk.first_offset, walk.bytes, walk.acked, walk.fin));
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

    /// Builds the world and the capture, runs the pool and checks. Returns
    /// the known limit of the spec the capture hits instead, if any (see
    /// [`known_limit`]): the oracle can't judge such a capture.
    fn simulate(
        isns: [u32; 2],
        plans: &[ConnectionPlan],
        late_positions: &[usize],
        capture: &Capture,
        config: TcpReassemblyConfig,
    ) -> Result<Option<&'static str>, String> {
        let world = World::build(isns, plans, late_positions);
        let captured = capture.apply(&world);
        if let Some(limit) = known_limit(&world, &captured, &config) {
            return Ok(Some(limit));
        }
        let outcome = Oracle::run(&captured, config);
        Oracle::check(&world, &captured, &outcome)?;
        Oracle::check_bytes(&world, &captured, &outcome)?;
        Ok(None)
    }

    /// Every reuse kind after every close kind, with the late segments at
    /// every position and with and without a wrap of the sequence numbers,
    /// in these variants: a clean capture; the old close's last ACK lost on
    /// the wire, or bytes in flight after a reset; the responder's or the
    /// initiator's tap lagging; the new SYN-ACK or SYN lost; and either of
    /// those with the initiator's tap lagging. No scenario may hit a known
    /// limit but the one listed (a lagging client tap after a lost SYN-ACK
    /// when both new streams begin in the old spans, or in the slack past
    /// them after a close without FINs).
    #[test]
    fn reconnect_matrix() {
        let mut failures = Vec::new();
        let mut skipped = Vec::new();
        for isns in [[1000, 2000], [u32::MAX - 20, u32::MAX - 5000]] {
            for close in Close::ALL {
                for reuse in Reuse::ALL {
                    for late_position in [0, 1, 2, 4] {
                        for variant in 0..8 {
                            let mut old = ConnectionPlan::simple(Reuse::Far, close);
                            old.last_ack_lost_on_wire =
                                matches!(close, Close::By(_)) && 1 == variant;
                            old.in_flight_after_reset =
                                usize::from(matches!(close, Close::Reset(_)) && 1 == variant);
                            let new = ConnectionPlan::simple(reuse, Close::By(Responder));
                            let plans = [old, new];
                            let (lost_half, lagging) = match variant {
                                2 => (None, Some((Responder, 2))),
                                3 => (None, Some((Initiator, 2))),
                                4 => (Some(Responder), None),
                                5 => (Some(Initiator), None),
                                6 => (Some(Responder), Some((Initiator, 3))),
                                7 => (Some(Initiator), Some((Initiator, 3))),
                                _ => (None, None),
                            };
                            let mut capture = Capture::default();
                            if let Some(role) = lost_half {
                                let world = World::build(isns, &plans, &[late_position]);
                                capture.lost = lost_half_of(1, role, &world);
                            }
                            if let Some((role, delay)) = lagging {
                                capture.skew[role_index(role)] = vec![delay];
                            }
                            let scenario = format!(
                                "isns {isns:?}, old close {close:?}, reuse {reuse:?}, late at {late_position}, variant {variant}"
                            );
                            // both new streams begin in the old spans, or in
                            // the slack past them (a reuse 1 ms after a close
                            // without FINs): once the capture lost a half and
                            // the client's tap lags, the server's first
                            // segments are the old connection's by their
                            // numbers
                            let in_spans = Reuse::InsideSpans == reuse
                                || (Reuse::ClockAhead(1) == reuse
                                    && false
                                        == matches!(close, Close::By(_) | Close::Simultaneous));
                            let allowed =
                                (in_spans && 6 == variant).then_some("C1 new taken for old");
                            match simulate(isns, &plans, &[late_position], &capture, config()) {
                                Ok(None) => {}
                                Ok(limit) if limit == allowed => {}
                                Ok(Some(limit)) => skipped.push(format!("{scenario}: {limit}")),
                                Err(failure) => failures.push(format!("{scenario}:\n{failure}")),
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
        assert!(
            skipped.is_empty(),
            "{} scenarios hit a known limit:\n{}",
            skipped.len(),
            skipped.join("\n")
        );
    }

    /// Returns the known limit of the spec that the capture hits, if any:
    /// what no passive observer can resolve, so the oracle can't judge it.
    ///
    /// - `C1 unseen connection`: late segments of a connection the pool
    ///   never saw (the capture shows none of its handshake and none of its
    ///   bytes, e.g. it starts at the connection's close) arrive after the
    ///   next connection's first segment: the pool has no replaced
    ///   connection to tell them by, so the ACK of a server that still held
    ///   the old connection answers the new SYN (S5) and the client's RST
    ///   to it resets the new connection (F4).
    /// - `C1 segments before the handshake`: the capture shows bytes of a
    ///   connection before either half of its handshake (it lost one half,
    ///   and the other is late, as a tap lags, or lost too), or another of
    ///   its segments while the connection before is still open, while the
    ///   connection before it is visible: the bytes arrive on that
    ///   connection's tombstone or in that connection, which can't start a
    ///   new one from them (P3), and the open connection takes the ACK
    ///   numbers for its own, so it can refuse its own later segments.
    /// - `C1 new taken for old`: the capture lost a half of the new
    ///   handshake or shows it late, both new streams begin within their old
    ///   spans (or within k windows past the end of one whose FIN the capture
    ///   lost), and a segment of that half's stream before it ACKs bytes of
    ///   the other stream the capture doesn't show yet (lost, or late as a
    ///   tap lags): it is the old connection's by its numbers (see
    ///   [`inside_spans`]).
    /// - `C1 old taken for new`: a late segment of the connection before,
    ///   from a side that sent nothing in the new connection yet, has
    ///   numbers within what the new connection's streams sent (by
    ///   position where the new connection knows where the side's stream
    ///   begins, else by ACK): it is the new connection's own by its
    ///   numbers (see [`overlapping_numbers`]).
    /// - `C1 late pickup handshake`: the capture shows a handshake half of a
    ///   connection after the connection ended or the next one started,
    ///   while the pool knew it as a pickup without the SYNs that tell the
    ///   half apart, and the half doesn't lie right at a stream's first byte
    ///   (see [`late_pickup_handshake`]): it starts a new connection.
    /// - `C4 late own half`: the capture shows a connection's own handshake
    ///   half after its sender's first bytes and after a FIN of the
    ///   connection, while no observed SYN tells the pool whose it is (see
    ///   [`late_own_half`]): it starts a reconnect.
    /// - `C1 coinciding start`: a new stream begins right at the first byte
    ///   or FIN of an old pickup stream, whose SYN the capture didn't show:
    ///   the new handshake looks like the old pickup's own late one.
    /// - `C1 coinciding end`: the number a stream of the old connection
    ///   reached is the new ISN + 1 of the same endpoint, so a late segment
    ///   of the other side that ACKs the old end ACKs the new SYN as well.
    /// - `C4 pickup`: the first captured half of a connection's handshake
    ///   lies where the pool takes it for a late own SYN or SYN-ACK of the
    ///   connection before: that connection, visible and not reset, is a
    ///   pickup for the half's role (the capture showed neither the role's
    ///   SYN nor, for the initiator, the SYN-ACK), and the half's ISN + 1
    ///   lies within k windows (fallback windows: a pickup knows no window
    ///   scale) before the stream's first captured byte or FIN while no FIN
    ///   of the connection was captured, or, for a stream without either, at
    ///   or before the last ACK of its peer and within k windows of it (K1):
    ///   the new connection starts at its other half or not at all.
    fn known_limit(
        world: &World,
        captured: &[TestSegment],
        config: &TcpReassemblyConfig,
    ) -> Option<&'static str> {
        let range = u64::from(config.fallback_window)
            * u64::from(config.hole_give_up_window_factor.unwrap_or(2).max(1));
        if late_pickup_handshake(world, captured) {
            return Some("C1 late pickup handshake");
        }
        if late_own_half(captured) {
            return Some("C4 late own half");
        }
        for (k, script) in world.connections.iter().enumerate().skip(1) {
            let previous = &world.connections[k - 1];
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
                return Some("C1 unseen connection");
            }
            let half_at = captured
                .iter()
                .position(|s| s.incarnation as usize == k && s.header.syn);
            // the connection before is open until the capture shows its RST
            // (one that closed with FINs counts as open, which only widens
            // the exclusion)
            let previous_end = captured
                .iter()
                .position(|s| s.incarnation as usize == k - 1 && s.header.rst)
                .unwrap_or(captured.len());
            // an ACK number of the connection that the open connection before
            // takes for its own: the kept ACK of a stream without a start
            // there, or, within k windows past what the capture showed of
            // that stream, an ACK of bytes it lost
            let takes_ack = |segment: &TestSegment, i: usize| {
                let role = segment.sender.other();
                let shown: Vec<u32> = captured[..i]
                    .iter()
                    .filter(|s| s.incarnation as usize == k - 1)
                    .filter_map(|s| {
                        let end = |offset: u64| previous.seq(role, offset);
                        if s.sender == role
                            && (s.header.syn || s.header.fin || false == s.payload.is_empty())
                        {
                            Some(end(s.offset
                                + s.payload.len() as u64
                                + u64::from(s.header.fin)))
                        } else if s.sender != role && s.header.syn && s.header.ack {
                            // A2
                            Some(end(0))
                        } else {
                            None
                        }
                    })
                    .collect();
                let ack = segment.ack.map(|ack| script.seq(role, ack));
                match (
                    shown
                        .iter()
                        .max_by_key(|end| end.wrapping_sub(previous.seq(role, 0))),
                    ack,
                ) {
                    (None, Some(_)) => true,
                    (Some(end), Some(ack)) => {
                        let ahead = ack.wrapping_sub(*end) as i32;
                        0 < ahead && u64::from(ahead.unsigned_abs()) <= range
                    }
                    _ => false,
                }
            };
            // bytes before the handshake are lost, and an ACK number the open
            // connection takes misleads it
            let before_handshake = captured.iter().enumerate().any(|(i, s)| {
                s.incarnation as usize == k
                    && half_at.is_none_or(|at| i < at)
                    && (false == s.payload.is_empty()
                        || (s.header.ack && i < previous_end && takes_ack(s, i)))
            });
            if before_handshake && previous_visible {
                return Some("C1 segments before the handshake");
            }
            for lost in [Initiator, Responder] {
                if inside_spans(previous, script, captured, k, lost, range) {
                    return Some("C1 new taken for old");
                }
            }
            if overlapping_numbers(previous, script, captured, k) {
                return Some("C1 old taken for new");
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
                    return Some("C1 coinciding end");
                }
            }
            // a new stream that begins right at the first byte or FIN of an
            // old pickup stream, whose SYN the pool didn't observe, looks
            // like that stream's own late handshake
            let old: Vec<&TestSegment> = captured
                .iter()
                .filter(|s| s.incarnation as usize + 1 == k)
                .collect();
            for role in [Initiator, Responder] {
                let pickup_start = old
                    .iter()
                    .find(|s| s.sender == role && (false == s.payload.is_empty() || s.header.fin))
                    .map(|s| previous.seq(role, s.offset));
                if false == observed_start(&old, role) && Some(script.seq(role, 0)) == pickup_start
                {
                    return Some("C1 coinciding start");
                }
            }
            // the first captured half of the new handshake meets the open
            // connection before
            let Some(at) = captured
                .iter()
                .position(|s| s.incarnation as usize == k && s.header.syn)
            else {
                continue;
            };
            let role = captured[at].sender;
            // what the pool's connection took of the connection before: its
            // segments from the first one that creates a connection on (a
            // SYN, or bytes with ACK, A6)
            let before: Vec<&TestSegment> = captured[..at]
                .iter()
                .filter(|s| s.incarnation as usize == k - 1)
                .skip_while(|s| {
                    false == (s.header.syn || (false == s.payload.is_empty() && s.header.ack))
                })
                .collect();
            let of_role = |r: TcpRole| before.iter().filter(move |s| s.sender == r);
            let observed = observed_start(&before, role);
            let reset = before.iter().any(|s| s.header.rst);
            let fin_seen = before.iter().any(|s| s.header.fin);
            let half_next = script.seq(role, 0);
            let start = of_role(role)
                .find(|s| false == s.payload.is_empty() || s.header.fin)
                .map(|s| previous.seq(role, s.offset));
            let own = match start {
                Some(start) => {
                    (false == fin_seen || start == half_next)
                        && u64::from(start.wrapping_sub(half_next)) <= range
                }
                // the peer's last ACK is what the pool kept for the stream
                None => of_role(role.other())
                    .filter_map(|s| s.ack)
                    .next_back()
                    .is_none_or(|ack| {
                        let kept = previous.seq(role, ack);
                        u64::try_from(kept.wrapping_sub(half_next) as i32)
                            .is_ok_and(|distance| distance <= range)
                    }),
            };
            if previous_visible && false == observed && false == reset && own {
                return Some("C4 pickup");
            }
        }
        None
    }

    /// Returns true if the capture of the connection `k` (after `previous`)
    /// shows the handshake half of `lost` only after the first other
    /// segments of its stream, or not at all, both new streams begin within
    /// their old spans (or the reach `range` past one whose FIN the capture
    /// didn't show before `k` started), and a segment of `lost`'s stream
    /// that the pool checks against the old spans (captured after the kept
    /// half started the new connection, as the connection before takes the
    /// ones before it, and before one of its segments is the new
    /// connection's own by position or ACK) ACKs bytes of the other stream
    /// the capture doesn't show yet.
    fn inside_spans(
        previous: &ConnectionScript,
        script: &ConnectionScript,
        captured: &[TestSegment],
        k: usize,
        lost: TcpRole,
        range: u64,
    ) -> bool {
        let of_k = |s: &&TestSegment| s.incarnation as usize == k;
        let kept = lost.other();
        // an old span reaches past its end unless the capture showed the
        // stream's FIN before the new connection started
        let started_at = captured
            .iter()
            .position(|s| s.incarnation as usize == k && s.header.syn)
            .unwrap_or(captured.len());
        let reach = |role: TcpRole| {
            let fin = captured[..started_at]
                .iter()
                .any(|s| s.incarnation as usize + 1 == k && s.sender == role && s.header.fin);
            if fin {
                0
            } else {
                range
            }
        };
        // the kept half's new stream begins before the end of its old span
        // or the reach past it
        let kept_end = previous.seq(kept, previous.next_offset(kept) + reach(kept));
        if 0 < script.seq(kept, 0).wrapping_sub(kept_end) as i32 {
            return false;
        }
        // the lost half's new stream begins within its old span or the
        // reach past it
        let lost_len = u64::from(previous.next_offset(lost) as u32);
        let distance = u64::from(script.seq(lost, 0).wrapping_sub(previous.seq(lost, 0)));
        if distance > lost_len + reach(lost) {
            return false;
        }
        // the first segments of the lost half's stream once the kept half
        // started the new connection (the connection before takes the ones
        // before it), until one is the new connection's own: by position once
        // the SYN-ACK gave the initiator's stream its start (A2), within what
        // the kept stream's ACKs showed it sent, else by ACK (of bytes of the
        // kept stream captured before it)
        let (mut kept_sent, mut lost_sent) = (0, 0);
        let (mut started, mut begin_known) = (false, false);
        for s in captured.iter().filter(of_k) {
            // once the half arrived, its stream's segments are the new
            // connection's by position
            if s.sender == lost && s.header.syn {
                return false;
            }
            started |= s.header.syn;
            if s.sender == kept {
                let end = s.offset + s.payload.len() as u64 + u64::from(s.header.fin);
                kept_sent = kept_sent.max(end);
                lost_sent = lost_sent.max(s.ack.unwrap_or(0));
                begin_known |= Initiator == lost && s.header.syn;
            } else if started {
                let own = if begin_known {
                    s.offset <= lost_sent
                } else {
                    s.ack.is_some_and(|ack| ack <= kept_sent)
                };
                return false == own;
            }
        }
        false
    }

    /// Returns true if a late segment of the connection before `k` (whose
    /// script is `previous`), from a side that sent nothing in `k` yet, has
    /// numbers within what the streams of `k` sent (the precedence of C1):
    /// by position where `k` knows where the side's stream begins (its SYN,
    /// or the SYN-ACK's ACK number for the initiator, A2), within what that
    /// stream is known to have sent; else by ACK, within what the other
    /// stream sent in `k`.
    fn overlapping_numbers(
        previous: &ConnectionScript,
        script: &ConnectionScript,
        captured: &[TestSegment],
        k: usize,
    ) -> bool {
        let Some(first_of_k) = captured.iter().position(|s| s.incarnation as usize == k) else {
            return false;
        };
        let mut sent = [false; 2];
        let mut begin_known = [false; 2];
        // what each stream of `k` is known to have sent: its bytes, or what
        // the other side ACKed of it, as offsets in `k`
        let mut sent_end = [0u64; 2];
        let mut known_end = [0u64; 2];
        for s in &captured[first_of_k..] {
            let (own, other) = (role_index(s.sender), role_index(s.sender.other()));
            if s.incarnation as usize == k {
                sent[own] = true;
                if s.header.syn {
                    begin_known[own] = true;
                    begin_known[other] |= s.header.ack;
                }
                let end = s.offset + s.payload.len() as u64 + u64::from(s.header.fin);
                sent_end[own] = sent_end[own].max(end);
                known_end[own] = known_end[own].max(end);
                known_end[other] = known_end[other].max(s.ack.unwrap_or(0));
            } else if s.incarnation as usize + 1 == k && false == sent[own] && false == s.header.syn
            {
                let within = |role: TcpRole, offset: u64, end: u64| {
                    let seq = previous.seq(role, offset);
                    u64::from(seq.wrapping_sub(script.seq(role, 0))) <= end
                };
                let as_new = if begin_known[own] {
                    within(s.sender, s.offset, known_end[own])
                } else {
                    (sent[other] || begin_known[other])
                        && s.ack
                            .is_some_and(|ack| within(s.sender.other(), ack, sent_end[other]))
                };
                if as_new {
                    return true;
                }
            }
        }
        false
    }

    /// Returns true if the capture shows a handshake half of a connection
    /// after the connection's RST or the next connection's first handshake
    /// half, while the pool knew none of the SYNs that tell the half apart
    /// (the half's own, or, for a SYN-ACK, the SYN, captured before the
    /// stream's first byte or FIN), and the half doesn't lie right at the
    /// first captured byte of its stream or, for a SYN-ACK, of the stream it
    /// ACKs.
    fn late_pickup_handshake(world: &World, captured: &[TestSegment]) -> bool {
        (0..world.connections.len()).any(|j| {
            let of_j = |s: &TestSegment| s.incarnation as usize == j;
            let end_at = captured
                .iter()
                .position(|s| {
                    (of_j(s) && s.header.rst) || (s.incarnation as usize == j + 1 && s.header.syn)
                })
                .unwrap_or(captured.len());
            let before = &captured[..end_at];
            let of_connection: Vec<&TestSegment> = before.iter().filter(|s| of_j(s)).collect();
            let observed = |role: TcpRole| observed_start(&of_connection, role);
            let first_byte = |role: TcpRole| {
                before
                    .iter()
                    .find(|s| of_j(s) && s.sender == role && false == s.payload.is_empty())
                    .map(|s| s.offset)
            };
            captured[end_at..].iter().any(|s| {
                let acks = s.header.ack;
                of_j(s)
                    && s.header.syn
                    && false == s.header.rst
                    && false == observed(s.sender)
                    && false == (acks && observed(s.sender.other()))
                    && Some(0) != first_byte(s.sender)
                    && false == (acks && Some(0) == first_byte(s.sender.other()))
            })
        })
    }

    /// Returns true if the capture shows a handshake half of a connection
    /// after its sender's stream started from bytes or a FIN (as a pickup,
    /// its own SYN not captured before) and after a FIN of the connection,
    /// before the connection ended or the next one started, while no
    /// observed SYN speaks (the half is a SYN, or the initiator's stream is a
    /// pickup or has no start), and the half doesn't lie right at its
    /// stream's first captured byte.
    fn late_own_half(captured: &[TestSegment]) -> bool {
        captured.iter().enumerate().any(|(i, half)| {
            if false == half.header.syn || half.header.rst {
                return false;
            }
            let j = half.incarnation;
            let before: Vec<&TestSegment> = captured[..i]
                .iter()
                .filter(|s| s.incarnation == j)
                .collect();
            if captured[..i].iter().any(|s| {
                (s.incarnation == j && s.header.rst) || (s.incarnation > j && s.header.syn)
            }) {
                return false;
            }
            let started = before.iter().any(|s| {
                s.sender == half.sender && (false == s.payload.is_empty() || s.header.fin)
            });
            let observed = |role: TcpRole| observed_start(&before, role);
            let first_byte = before
                .iter()
                .find(|s| s.sender == half.sender && false == s.payload.is_empty())
                .map(|s| s.offset);
            started
                && false == observed(half.sender)
                && before.iter().any(|s| s.header.fin)
                && false == (half.header.ack && observed(half.sender.other()))
                && Some(0) != first_byte
        })
    }

    /// Returns true if the stream of `role` has an observed start after the
    /// captured `segments` of one connection: a handshake half (its own, or
    /// for the initiator the SYN-ACK's ACK number, A2) came before the
    /// stream's first byte or FIN, and before its own sender's first byte
    /// or FIN. After them, the eager reader read that pickup, so A5 ignores
    /// the half with its ACK number (C4).
    fn observed_start(segments: &[&TestSegment], role: TcpRole) -> bool {
        let started_at = |r: TcpRole| {
            segments
                .iter()
                .position(|s| s.sender == r && (false == s.payload.is_empty() || s.header.fin))
                .unwrap_or(segments.len())
        };
        segments.iter().enumerate().any(|(i, s)| {
            s.header.syn
                && false == s.header.rst
                && i < started_at(s.sender)
                && (s.sender == role || (Initiator == role && s.header.ack))
                && i < started_at(role)
        })
    }

    /// A `lost` vector that loses the handshake half of `role` in the
    /// connection `incarnation`: its SYNs (with retransmissions) or its
    /// SYN-ACK.
    fn lost_half_of(incarnation: u32, role: TcpRole, world: &World) -> Vec<bool> {
        world
            .segments
            .iter()
            .map(|segment| {
                segment.incarnation == incarnation && segment.header.syn && segment.sender == role
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

    /// How much one tap lags: not at all, or up to 7 segments, varying.
    fn skew_any() -> impl Strategy<Value = Vec<usize>> {
        prop_oneof![Just(vec![0]), prop::collection::vec(0usize..8, 1..16)]
    }

    prop_compose! {
        fn capture_any()(
            lost in prop_oneof![
                prop::collection::vec(prop::bool::weighted(0.03), 1..64),
                prop::collection::vec(prop::bool::weighted(0.15), 1..64),
            ],
            skew in [skew_any(), skew_any()],
            duplicated in prop::collection::vec(prop::bool::weighted(0.05), 1..64),
            one_direction in prop_oneof![8 => Just(None), 1 => Just(Some(Initiator)), 1 => Just(Some(Responder))],
            start in prop_oneof![4 => Just(0usize), 1 => 1usize..6],
            half_delay in prop_oneof![
                14 => Just([0, 0]),
                1 => (1u64..8).prop_map(|delay| [delay, 0]),
                1 => (1u64..8).prop_map(|delay| [0, delay]),
            ],
        ) -> Capture {
            Capture { lost, skew, half_delay, duplicated, one_direction, start }
        }
    }

    /// A history of two or three connections on one four-tuple: the first
    /// connection's ISNs, the plans, the positions of late segments among
    /// the next connection's, and the capture.
    fn history_any() -> impl Strategy<Value = ([u32; 2], Vec<ConnectionPlan>, Vec<usize>, Capture)>
    {
        (
            [tcp_isn_any(), tcp_isn_any()],
            prop::collection::vec(plan_any(), 2..4),
            prop::collection::vec(0usize..6, 1..4),
            capture_any(),
        )
    }

    /// Number of proptest cases the run asks for (`PROPTEST_CASES`, 256
    /// without it), which sizes the censuses: a run under emulation asks for
    /// few.
    fn proptest_cases() -> usize {
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|cases| cases.parse().ok())
            .unwrap_or(256)
    }

    /// A census of a deterministic sample of histories: none fails, and few
    /// hit a known limit (rare coincidences), so the oracle judges almost
    /// all. Unlike the proptest, it doesn't stop at the first failure. The
    /// share of limits is checked on the full sample of 2000 histories, which
    /// a run with fewer than 256 proptest cases shrinks.
    #[test]
    fn history_census() {
        use proptest::strategy::ValueTree;
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strategy = history_any();
        let cases = if proptest_cases() < 256 {
            8 * proptest_cases()
        } else {
            2000
        };
        let mut hits = std::collections::BTreeMap::new();
        let mut failures = Vec::new();
        for case in 0..cases {
            let (isns, plans, late_positions, capture) =
                strategy.new_tree(&mut runner).unwrap().current();
            match simulate(isns, &plans, &late_positions, &capture, config()) {
                Ok(None) => {}
                Ok(Some(limit)) => *hits.entry(limit).or_insert(0usize) += 1,
                Err(failure) => failures.push(format!(
                    "case {case}: {}",
                    failure.lines().next().unwrap_or("")
                )),
            }
        }
        let total: usize = hits.values().sum();
        std::eprintln!("known limits in {cases} histories: {hits:?}");
        assert!(
            failures.is_empty(),
            "{} of {cases} histories failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
        assert!(
            cases < 2000 || total * 100 <= cases * 5,
            "{total} of {cases} histories hit a known limit: {hits:?}"
        );
    }

    /// A small xorshift generator for the bulk census, whose worlds are
    /// built step by step rather than by proptest strategies.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }

        /// Returns true with a chance of `per_mille` in 1000.
        fn chance(&mut self, per_mille: u64) -> bool {
            self.below(1000) < per_mille
        }
    }

    /// A bulk transfer from the server to the client (see [`bulk_world`]).
    #[derive(Clone, Debug)]
    struct Bulk {
        /// Number of server segments.
        segments: usize,
        /// Bytes per server segment.
        len: usize,
        /// Window scale of both sides, if any.
        scale: Option<u8>,
        /// Window field of every segment.
        window_field: u16,
        /// Chance in 1000 that a server segment is lost on the wire; it is
        /// retransmitted `retransmit_after` positions later.
        wire_loss: u64,
        /// Positions after which a segment lost on the wire is retransmitted.
        retransmit_after: u64,
        /// Whether the tap sits before the point of the wire loss, so it sees
        /// the segments lost there.
        tap_before_loss: bool,
        /// Chance in 1000 that the capture loses a segment.
        capture_loss: u64,
        /// Positions each tap lags behind, indexed by role: the server's
        /// within K4(b)'s tolerance, counting the ACKs in between, the
        /// client's also past k windows.
        lag: [u64; 2],
        /// Server segments the capture misses in a row (a burst), from the
        /// first one on, if any.
        burst: Option<(usize, usize)>,
        /// Whether the taps lag from the start, the server's SYN-ACK and
        /// the client's handshake ACK and request included (but not the
        /// client's SYN); otherwise the lag starts after the handshake.
        lag_from_start: bool,
        /// Whether the client closes first.
        client_closes_first: bool,
    }

    impl Bulk {
        /// A random bulk transfer, or `None` if its sender would keep more
        /// than a window in flight: while it waits for a retransmission, or
        /// with the two segments the client ACKs at a time.
        fn any(rng: &mut Rng) -> Option<Bulk> {
            let scale = [None, Some(2), Some(7)][rng.below(3) as usize];
            let bulk = Bulk {
                segments: 50 + rng.below(1500) as usize,
                len: [1460, 536, 1448, 100][rng.below(4) as usize],
                scale,
                window_field: [65535, 30000, 8192, 4096, 512][rng.below(5) as usize],
                wire_loss: [0, 10, 30][rng.below(3) as usize],
                retransmit_after: 0,
                tap_before_loss: rng.chance(500),
                capture_loss: [0, 5, 20, 50][rng.below(4) as usize],
                // a server tap that lags 100 segments keeps a hole the
                // client's ACK covers about 200 packets before its bytes
                // arrive, within K4(b)'s tolerance of 256 (a longer lag
                // gives such a hole up as a gap, by design); the client's
                // ACKs trail the bytes, so its tap can lag past k windows
                lag: [
                    [0, 0],
                    [0, rng.below(100)],
                    [rng.below(60), 0],
                    [0, 60 + rng.below(40)],
                    [100 + rng.below(150), 0],
                ][rng.below(5) as usize],
                burst: None,
                lag_from_start: rng.chance(500),
                client_closes_first: rng.chance(500),
            };
            let burst = rng.chance(250).then(|| {
                (
                    rng.below(bulk.segments as u64) as usize,
                    50 + rng.below(100) as usize,
                )
            });
            let bulk = Bulk {
                retransmit_after: 3 + rng.below(20),
                burst,
                ..bulk
            };
            let window = u64::from(bulk.window_field) << bulk.scale.unwrap_or(0);
            let in_flight = if 0 == bulk.wire_loss {
                2
            } else {
                (bulk.retransmit_after + 10) * 2
            };
            (window >= in_flight * bulk.len as u64).then_some(bulk)
        }
    }

    /// Runs the bulk transfer `bulk` from the server to the client with the
    /// ISNs, losses and capture decisions of `rng`: the client ACKs every
    /// second segment it received in order (and each one out of order, as a
    /// duplicate ACK), the server retransmits a segment the wire lost, and
    /// the capture loses segments and lags per tap. An eager reader of the
    /// server's stream must get the captured bytes in order, with a gap of
    /// the right length for each run of segments the capture missed, in one
    /// connection that finishes. Returns true if the reader lost segments
    /// with a run of missing ones instead, as a known limit of S4 allows.
    fn bulk_world(bulk: &Bulk, rng: &mut Rng) -> Result<bool, String> {
        let mut script = ConnectionScript::with_isns(rng.next() as u32, rng.next() as u32);
        script.window_scales = [bulk.scale; 2];
        script.window_size = bulk.window_field;
        // what the capture shows, by the time it shows it
        let mut events: Vec<(u64, TestSegment)> = Vec::new();
        script.syn().syn_ack();
        // a SYN shows the window as far as its field can (it is never
        // scaled), like the stacks do
        let window = u64::from(bulk.window_field) << bulk.scale.unwrap_or(0);
        for syn in &mut script.segments {
            syn.header.window_size = u16::try_from(window).unwrap_or(u16::MAX);
        }
        // the client's SYN comes first either way (a SYN-ACK before it is
        // a known limit, C4), but its handshake ACK, which shows the scaled
        // window, can come late
        let start_lag = if bulk.lag_from_start {
            bulk.lag
        } else {
            [0, 0]
        };
        events.push((0, script.segments[0].clone()));
        events.push((1 + start_lag[1], script.segments[1].clone()));
        script.ack(Initiator).send(Initiator, b"GET /");
        events.push((2 + start_lag[0], script.segments[2].clone()));
        events.push((2 + start_lag[0], script.segments[3].clone()));
        let start = 3;
        // the server's transmissions: when, which segment, a retransmission
        let mut sends: Vec<(u64, usize, bool)> = Vec::new();
        let mut lost_on_wire = Vec::new();
        for i in 0..bulk.segments {
            let lost = rng.chance(bulk.wire_loss);
            lost_on_wire.push(lost);
            sends.push((start + i as u64, i, false));
            if lost {
                sends.push((start + i as u64 + bulk.retransmit_after, i, true));
            }
        }
        sends.sort();
        let data_of =
            |i: usize| -> Vec<u8> { (0..bulk.len).map(|j| ((i * 7 + j) % 251) as u8).collect() };
        let mut received = vec![false; bulk.segments];
        let mut captured = vec![false; bulk.segments];
        let (mut acked, mut since_ack) = (0, 0);
        for &(at, i, retransmission) in &sends {
            let mut sending = script.clone();
            sending.send_at(Responder, (i * bulk.len) as u64, &data_of(i));
            let segment = sending.segments.pop().unwrap();
            let lost = lost_on_wire[i] && false == retransmission;
            let in_burst = bulk
                .burst
                .is_some_and(|(first, len)| (first..first + len).contains(&i));
            if (false == lost || bulk.tap_before_loss)
                && false == in_burst
                && false == rng.chance(bulk.capture_loss)
            {
                captured[i] = true;
                events.push((at + bulk.lag[1], segment));
            }
            if lost {
                continue;
            }
            received[i] = true;
            while acked < bulk.segments && received[acked] {
                acked += 1;
            }
            since_ack += 1;
            if since_ack >= 2 || false == received.get(acked).copied().unwrap_or(true) {
                since_ack = 0;
                let mut acking = script.clone();
                acking.ack_to(Initiator, (acked * bulk.len) as u64);
                let ack = acking.segments.pop().unwrap();
                if false == rng.chance(bulk.capture_loss) {
                    events.push((at + bulk.lag[0], ack));
                }
            }
        }
        // the close, after all bytes
        for i in 0..bulk.segments {
            script.send_at(Responder, (i * bulk.len) as u64, &data_of(i));
        }
        script.segments.clear();
        let end_at = start + bulk.segments as u64 + bulk.retransmit_after + 2;
        let roles = if bulk.client_closes_first {
            [Initiator, Responder]
        } else {
            [Responder, Initiator]
        };
        script.fin(roles[0]).fin(roles[1]).ack(roles[0]);
        for (k, segment) in script.segments.iter().enumerate() {
            let lag = bulk.lag[role_index(segment.sender)];
            events.push((end_at + k as u64 + lag, segment.clone()));
        }
        events.sort_by_key(|(at, _)| *at);

        let mut pool = TcpReassemblyPool::<u32, ()>::new(config());
        let (mut got, mut gaps) = (Vec::new(), Vec::new());
        let mut end = None;
        let mut ids = std::collections::BTreeSet::new();
        let read = |connection: &mut TcpConnection<u32>,
                    got: &mut Vec<u8>,
                    gaps: &mut Vec<(usize, Option<u64>)>| {
            let stream = connection.stream_mut(Responder);
            loop {
                match stream.read_received() {
                    TcpRead::Data(data) => {
                        got.extend_from_slice(data);
                        let len = data.len();
                        stream.consume(len);
                    }
                    TcpRead::Gap { len } => {
                        gaps.push((got.len(), len));
                        stream.consume_gap();
                    }
                    _ => break,
                }
            }
        };
        for (_, segment) in &events {
            let processed = segment.feed(&mut pool, 1);
            if let Some(mut connection) = processed.ended {
                ids.insert(connection.id().0);
                read(&mut connection, &mut got, &mut gaps);
                end = connection.end();
            } else if let Some((connection, _)) = processed.active {
                ids.insert(connection.id().0);
                read(connection, &mut got, &mut gaps);
            }
        }
        pool.evict_all(|connection| {
            read(connection, &mut got, &mut gaps);
            end = connection.end();
        });
        if 1 != ids.len() {
            return Err(format!("{} connections", ids.len()));
        }
        // the shown segments in order, a gap for each run of missing ones
        let expect = |shown: &[bool]| {
            let (mut expected, mut expected_gaps) = (Vec::new(), Vec::new());
            let mut missing = 0u64;
            for (i, &shown) in shown.iter().enumerate() {
                if shown {
                    if 0 < missing {
                        expected_gaps.push((expected.len(), Some(missing)));
                        missing = 0;
                    }
                    expected.extend_from_slice(&data_of(i));
                } else {
                    missing += bulk.len as u64;
                }
            }
            if 0 < missing {
                expected_gaps.push((expected.len(), Some(missing)));
            }
            (expected, expected_gaps)
        };
        let (expected, expected_gaps) = expect(&captured);
        if got == expected && gaps == expected_gaps {
            return match end {
                Some(TcpConnectionEnd::Finished) => Ok(false),
                _ => Err(format!("end {end:?}")),
            };
        }
        let mismatch = format!(
            "got {} bytes (expected {}), gaps {:?} (expected {:?})",
            got.len(),
            expected.len(),
            &gaps[..gaps.len().min(5)],
            &expected_gaps[..expected_gaps.len().min(5)]
        );
        // a known limit (S4): while the client's tap lags past k windows, the
        // segments the capture shows after a run of missing ones longer than
        // k windows lie after the window until an ACK moves the stream
        // forward towards them, and are lost with the run (the lag and two
        // more at most), a FIN among them too
        let window = u64::from(bulk.window_field) << bulk.scale.unwrap_or(0);
        let k_windows = 2 * window.min(u64::from(u16::MAX));
        if bulk.lag[0] * (bulk.len as u64) <= k_windows {
            return Err(mismatch);
        }
        let Some(read) = segments_read(&got, &gaps, bulk.len, &data_of) else {
            return Err(mismatch);
        };
        let mut shown = vec![false; bulk.segments];
        for i in read {
            shown[i] = true;
        }
        // a client ACK that moves the ACKs forward past a run's start moves
        // the stream forward too: a segment after the run is lost if the
        // capture showed it only before the first such ACK after the first
        // segment after the run
        let (mut first_shown, mut last_shown) = (vec![None; bulk.segments], vec![0; bulk.segments]);
        let (mut acks, mut highest_ack) = (Vec::new(), 0);
        for (index, (_, segment)) in events.iter().enumerate() {
            if Initiator == segment.sender {
                if let Some(ack) = segment.ack.filter(|ack| *ack > highest_ack) {
                    acks.push((index, ack));
                    highest_ack = ack;
                }
            } else if false == segment.payload.is_empty() {
                let i = segment.offset as usize / bulk.len;
                first_shown[i] = first_shown[i].or(Some(index));
                last_shown[i] = index;
            }
        }
        let (mut run_start, mut lost_before) = (None, 0);
        for i in 0..bulk.segments {
            let Some(first) = first_shown[i] else {
                run_start = run_start.or(Some(i));
                continue;
            };
            if let Some(start) = run_start.take() {
                if (i - start) as u64 * bulk.len as u64 > k_windows {
                    let start = (start * bulk.len) as u64;
                    lost_before = acks
                        .iter()
                        .find(|(index, ack)| *index > first && *ack > start)
                        .map_or(usize::MAX, |(index, _)| *index);
                }
            }
            if false == shown[i] && last_shown[i] > lost_before {
                return Err(mismatch);
            }
        }
        // the ACK of a lost FIN ACKs one more byte
        let (expected, mut expected_gaps) = expect(&shown);
        let fin_lost = false == shown[bulk.segments - 1];
        let one_more = gaps.last().map(|(at, len)| (*at, len.map(|len| len - 1)));
        if fin_lost && one_more.as_ref() == expected_gaps.last() {
            expected_gaps.pop();
            expected_gaps.extend(gaps.last());
        }
        if got != expected || gaps != expected_gaps {
            return Err(mismatch);
        }
        match end {
            Some(TcpConnectionEnd::Finished) => Ok(true),
            _ if fin_lost => Ok(true),
            _ => Err(format!("end {end:?}")),
        }
    }

    /// Segments of a bulk transfer with `len` bytes each, by the order in
    /// which an eager reader got them as the bytes `got`, with the gaps
    /// `gaps`; `None` unless they are whole segments at their offsets, with
    /// the bytes of `data_of`.
    fn segments_read(
        got: &[u8],
        gaps: &[(usize, Option<u64>)],
        len: usize,
        data_of: impl Fn(usize) -> Vec<u8>,
    ) -> Option<Vec<usize>> {
        let mut read = Vec::new();
        let (mut offset, mut gaps) = (0, gaps.iter().peekable());
        let mut i = 0;
        while i < got.len() {
            while let Some((_, gap)) = gaps.next_if(|(at, _)| *at == i) {
                offset += usize::try_from((*gap)?).ok()?;
            }
            let segment = offset / len;
            if 0 != offset % len || got.get(i..i + len)? != data_of(segment).as_slice() {
                return None;
            }
            read.push(segment);
            (i, offset) = (i + len, offset + len);
        }
        Some(read)
    }

    /// A census of bulk transfers at a volume the histories don't reach:
    /// hundreds of segments, small, large and scaled windows, loss on the
    /// wire with retransmissions (the tap before or after the loss), capture
    /// loss, also in bursts, and a lag of up to 100 segments for the
    /// server's tap and 250 for the client's (see [`bulk_world`]).
    #[test]
    fn bulk_census() {
        let mut failures = Vec::new();
        let (mut worlds, mut hits) = (0, 0);
        let seeds = 2 * proptest_cases() as u64;
        for seed in 1..=seeds {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let Some(bulk) = Bulk::any(&mut rng) else {
                continue;
            };
            worlds += 1;
            match bulk_world(&bulk, &mut rng) {
                Ok(limit) => hits += usize::from(limit),
                Err(failure) => failures.push(format!("seed {seed}, {bulk:?}: {failure}")),
            }
        }
        assert!(seeds < 4 * worlds, "only {worlds} worlds");
        assert!(
            failures.is_empty(),
            "{} of {worlds} bulk transfers failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
        // the known limit of a lagging client tap is rare
        assert!(
            worlds < 1000 || hits * 100 <= worlds as usize * 5,
            "{hits} of {worlds} bulk transfers lost bytes with a burst"
        );
    }

    /// Bulk transfers whose server tap lags further behind than k windows of
    /// an unscaled window, with retransmissions: the client's ACKs lead the
    /// bytes by more than the implied ACK's distance, so only what the
    /// capture showed of the server may imply ACKs (K2), and the holes of
    /// the late retransmissions stay fillable (K4(b)).
    #[test]
    fn bulk_lag_beyond_windows() {
        let bulk = Bulk {
            segments: 400,
            len: 1448,
            scale: None,
            window_field: 65535,
            wire_loss: 30,
            retransmit_after: 6,
            tap_before_loss: false,
            capture_loss: 0,
            lag: [0, 95],
            burst: None,
            lag_from_start: false,
            client_closes_first: false,
        };
        for seed in 1..=20u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            if let Err(failure) = bulk_world(&bulk, &mut rng) {
                panic!("seed {seed}: {failure}");
            }
        }
    }

    proptest! {
        /// Histories of two or three connections on one four-tuple with
        /// every reuse and close kind, captured with loss, either tap
        /// lagging, duplicates, a late start or one direction only.
        #[test]
        fn reconnect_histories(
            (isns, plans, late_positions, capture) in history_any(),
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
