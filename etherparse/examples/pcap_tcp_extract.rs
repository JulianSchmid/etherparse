//! Reads a PCAP file, re-assembles fragmented IP packets, reconstructs the
//! payload byte streams of all TCP connections and writes them to disk
//! together with an index & a per connection log of what every packet did:
//!
//! ```sh
//! cargo run --example pcap_tcp_extract -- capture.pcap --output extracted
//! ```
//!
//! # Output layout
//!
//! ```text
//! extracted/
//!   index.jsonl        one JSON object per connection (see below)
//!   data/1_orig.bin    reconstructed byte stream originator -> responder
//!   data/1_resp.bin    reconstructed byte stream responder -> originator
//!   info/1.txt         what every packet of connection 1 contributed
//! ```
//!
//! The file name prefix is the connection id, which is also the `id` field of
//! the index. Ids are handed out in the order the connections are first seen.
//! Data files are only created if the direction actually carried data (see the
//! `files` field of the index).
//!
//! ## `index.jsonl`
//!
//! One JSON object per line ("JSON Lines" / NDJSON), written as soon as a
//! connection is finished (so the file is usable while a long capture is still
//! being processed and nothing has to be kept in memory). The records are
//! therefore ordered by *end* time, not by id.
//!
//! The field names follow [Zeek](https://docs.zeek.org)'s `conn.log`, which is
//! the de facto standard for "one record per connection" logs and is what
//! existing tooling (jq recipes, pandas, SIEM ingests, ...) expects:
//!
//! | field                                            | meaning                                          |
//! |--------------------------------------------------|--------------------------------------------------|
//! | `ts`, `ts_iso`                                   | time of the first packet of the connection       |
//! | `ts_end`, `ts_end_iso`, `duration`               | time of the last packet & the time in between    |
//! | `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | endpoints ("originator" = sender of the first packet seen) |
//! | `proto`, `vlan`, `inner_vlan`                    | `"tcp"` & the VLAN ids of the packets            |
//! | `orig_pkts`, `resp_pkts`                         | number of segments per direction                 |
//! | `orig_bytes`, `resp_bytes`                       | reconstructed payload bytes per direction        |
//! | `conn_state`                                     | Zeek connection state (`SF`, `S1`, `REJ`, ...)   |
//! | `history`                                        | Zeek history string (see `History` below)        |
//!
//! Everything Zeek has no field for is added under its own name: `id`,
//! `midstream`, `closed_by`, `files` and the per direction
//! `*_syn_observed` / `*_fin_observed` / `*_complete` / `*_missing_bytes`.
//!
//! ## `data/<id>_<orig|resp>.bin`
//!
//! The raw reconstructed byte stream, one file per direction (the convention
//! [tcpflow](https://github.com/simsong/tcpflow) uses, which encodes the
//! endpoints in the file name instead of using an index file).
//!
//! Bytes that were never captured (a segment that is missing from the capture
//! and never re-transmitted) are **skipped**, so the file only contains bytes
//! that were really observed. The number of missing bytes ends up in the index
//! (`*_missing_bytes`) and their position in the info file. Note that tcpflow
//! makes the opposite choice and fills gaps with zero bytes, which keeps "file
//! offset == stream offset" at the price of fabricating data.
//!
//! ## `info/<id>.txt`
//!
//! One line per packet of the connection, stating what it changed about the
//! reconstruction: new bytes, re-transmits, gaps, acknowledgments, how much
//! data it released & how the connection was started and ended. Useful to
//! understand why a reconstructed stream looks the way it does.
//!
//! # Notes
//!
//! Only the classic `.pcap` format is supported (not `.pcapng`, convert via
//! `tshark -r capture.pcapng -F pcap -w capture.pcap`) with the link types
//! "Ethernet" and "Raw IP". To keep the example small there is no extra
//! handling for captures with a limited snapshot length (truncated packets are
//! reported as parse errors and skipped).
//!
//! Connections whose end is never observed (no `FIN`, no `RST`, e.g. because
//! one side crashed or the capture does not contain the rest of them) would
//! occupy memory until the end of the capture, so connections that have been
//! inactive for too long are finished early (`--timeout`, in seconds of
//! capture time, `0` disables it).
//!
//! See the `pcap_tcp_reassembly` example for a smaller introduction that just
//! prints the reconstructed streams.

use clap::Parser;
use etherparse::{defrag::*, tcp_reassembly::*, *};
use rpcap::{read::PcapReader, Linktype};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Extracts the payload byte streams of all TCP connections in a pcap file
/// (re-assembling fragmented IP packets on the way) into a directory.
#[derive(Parser)]
struct Args {
    /// Pcap file to read (classic pcap format, not pcapng).
    file: PathBuf,

    /// Directory the index, the streams & the packet infos are written to
    /// (created if it does not exist).
    #[arg(short, long, default_value = "extracted")]
    output: PathBuf,

    /// Finish connections that have not seen a segment for this many seconds
    /// of capture time (0 disables it).
    #[arg(short, long, default_value_t = DEFAULT_TCP_CONNECTION_TIMEOUT.as_secs())]
    timeout: u64,
}

/// Set if writing any of the output files failed (the process then ends with
/// a non zero exit code, so a truncated result is not mistaken for a
/// successful extraction).
static WRITE_FAILED: AtomicBool = AtomicBool::new(false);

/// How often the inactive connections are looked for (in capture time).
///
/// The check runs over all tracked connections, so it is done in intervals
/// instead of once per packet.
const EVICTION_INTERVAL: Duration = Duration::from_secs(1);

/// Time after which the fragments of an IP packet that was never completed
/// are discarded.
///
/// RFC 791 recommends 15 seconds for the re-assembly of a packet, real
/// implementations tend to use more (e.g. 30 seconds on Linux).
const IP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let args = Args::parse();
    let path = args.file.display().to_string();

    let file = match std::fs::File::open(&args.file) {
        Ok(v) => v,
        Err(err) => exit_with(&format!("Error opening '{path}': {err}")),
    };
    let (file_options, mut pcap_reader) = match PcapReader::new(std::io::BufReader::new(file)) {
        Ok(v) => v,
        Err(err) => exit_with(&format!("Error parsing '{path}': {err}")),
    };
    let is_ethernet = match file_options.linktype {
        l if l == Linktype::ETHERNET as u32 => true,
        l if l == Linktype::RAW as u32 => false,
        other => exit_with(&format!("Unsupported pcap link type {other}")),
    };

    // pool re-assembling fragmented IPv4 & IPv6 packets (the capture time of
    // the packets is used to discard incomplete ones later on)
    let mut defrag_pool = IpDefragPool::<SystemTime, ()>::new();

    // pool reconstructing the payload streams of the TCP connections (by
    // default only data that the receiver acknowledged is handed out)
    let mut tcp_pool = TcpStreamReassemblyPool::<SystemTime, ()>::new();

    // writes the index, the stream data & the per packet infos
    let mut out = match Output::new(&args.output) {
        Ok(v) => v,
        Err(err) => exit_with(&format!(
            "Error preparing the output directory '{}': {err}",
            args.output.display()
        )),
    };

    // capture time at which the next check for inactive connections is due
    let timeout = Duration::from_secs(args.timeout);
    let mut next_eviction: Option<SystemTime> = None;

    let mut frame = 0u64;
    let mut parse_errors = 0u64;

    loop {
        // the packet data is borrowed from the reader's internal buffer, so
        // reading the next packet does not allocate or copy
        let packet = match pcap_reader.next() {
            Ok(Some(v)) => v,
            Ok(None) => break,
            Err(err) => {
                eprintln!("Error reading pcap packet record: {err}");
                break;
            }
        };
        frame += 1;

        // finish the connections that have been inactive for too long (before
        // the packet is processed, so a connection is never discarded because
        // of the time that passed while it was being processed)
        if false == timeout.is_zero() && next_eviction.is_none_or(|next| packet.time >= next) {
            next_eviction = packet.time.checked_add(EVICTION_INTERVAL);
            evict_inactive(
                &mut tcp_pool,
                &mut defrag_pool,
                &mut out,
                packet.time,
                timeout,
            );
        }

        // slice the packet into its different header components
        let sliced = if is_ethernet {
            SlicedPacket::from_ethernet(packet.data)
        } else {
            SlicedPacket::from_ip(packet.data)
        };
        let sliced = match sliced {
            Ok(v) => v,
            Err(err) => {
                eprintln!("Error parsing packet {frame}: {err}");
                parse_errors += 1;
                continue;
            }
        };

        if sliced.is_ip_payload_fragmented() {
            // the TCP layer of a fragmented packet is not decoded, the IP
            // payload has to be re-assembled from all fragments first
            match defrag_pool.process_sliced_packet(&sliced, packet.time, ()) {
                Ok(Some(finished)) => {
                    if finished.ip_number == IpNumber::TCP {
                        // the re-assembled payload is the TCP segment, while
                        // the addresses are taken from the (last) fragment
                        match TcpSegmentInfo::from_defragmented_payload(
                            &sliced,
                            &finished.payload,
                            (),
                        ) {
                            Ok(Some(info)) => {
                                out.feed(&mut tcp_pool, info, packet.time, frame);
                            }
                            Ok(None) => {
                                // no IP header (cannot happen for a re-assembled packet)
                            }
                            Err(err) => {
                                eprintln!("Error parsing re-assembled TCP segment: {err}");
                                parse_errors += 1;
                            }
                        }
                    }
                    // return the buffer to avoid unneeded allocations
                    defrag_pool.return_buf(finished);
                }
                Ok(None) => {
                    // not all fragments received yet
                }
                Err(err) => eprintln!("Error re-assembling fragmented IP packet: {err}"),
            }
        } else if let Some(info) = TcpSegmentInfo::from_sliced_packet(&sliced, ()) {
            out.feed(&mut tcp_pool, info, packet.time, frame);
        }
    }

    // At the end of a capture: drain whatever is left. The last data of a
    // capture is usually never acknowledged (the capture ends before the ACK
    // arrives), so the acknowledgment requirement is ignored here.
    for (id, connection, _timestamp) in tcp_pool.iter_mut() {
        out.close(id, Some(connection), CloseReason::CaptureEnd);
    }

    out.flush();
    println!(
        "{frame} packets read ({parse_errors} not parsable), \
         {} connections & {} reconstructed bytes written to '{}'",
        out.finished,
        out.written_bytes,
        args.output.display(),
    );
    if WRITE_FAILED.load(Ordering::Relaxed) {
        exit_with("Some of the output could not be written (see the errors above)");
    }
}

/// Finishes the connections that have not seen a segment for `timeout` (and
/// discards the fragments of IP packets that were never completed).
///
/// Every segment refreshes the timestamp of its connection, also the ones that
/// carry no data (keep alive probes, the acknowledgments answering them,
/// window updates & re-transmits), so a connection that is idle on the
/// application layer but alive on the wire is not finished here.
fn evict_inactive(
    tcp_pool: &mut TcpStreamReassemblyPool<SystemTime>,
    defrag_pool: &mut IpDefragPool<SystemTime>,
    out: &mut Output,
    now: SystemTime,
    timeout: Duration,
) {
    // pcap timestamps are not guaranteed to be monotonic (and the capture may
    // start before the timeout has passed since the unix epoch)
    if let Some(cutoff) = now.checked_sub(timeout) {
        tcp_pool.evict_older_than_with(&cutoff, |id, connection| {
            // last chance to get at the data of the connection
            out.close(id, Some(connection), CloseReason::Timeout);
        });
    }

    if let Some(cutoff) = now.checked_sub(IP_FRAGMENT_TIMEOUT) {
        defrag_pool.retain(|timestamp| *timestamp >= cutoff);
    }
}

/// Prints an error & ends the process.
fn exit_with(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// Why a connection was finished (the `closed_by` field of the index).
#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    /// Both directions reached their FIN.
    Fin,

    /// A RST ended the connection.
    Rst,

    /// A SYN with a new initial sequence number started a new connection
    /// re-using the same endpoints.
    Reconnect,

    /// No segment was seen for `--timeout`.
    Timeout,

    /// The connection was still open when the capture ended.
    CaptureEnd,
}

impl CloseReason {
    fn as_str(&self) -> &'static str {
        match self {
            CloseReason::Fin => "fin",
            CloseReason::Rst => "rst",
            CloseReason::Reconnect => "reconnect",
            CloseReason::Timeout => "timeout",
            CloseReason::CaptureEnd => "capture_end",
        }
    }
}

/// Writes the index, the reconstructed streams & the per packet infos.
struct Output {
    /// Directory everything is written to.
    dir: PathBuf,

    /// `index.jsonl`, one record per finished connection.
    index: Sink,

    /// Id handed out to the next connection.
    next_id: u64,

    /// Connections that are currently being reconstructed.
    conns: HashMap<TcpConnectionId, Conn>,

    /// Number of connections that were written to the index.
    finished: u64,

    /// Number of reconstructed stream bytes that were written.
    written_bytes: u64,
}

impl Output {
    fn new(dir: &Path) -> Result<Output, std::io::Error> {
        std::fs::create_dir_all(dir.join("data"))?;
        std::fs::create_dir_all(dir.join("info"))?;
        Ok(Output {
            dir: dir.to_path_buf(),
            index: Sink::new(dir.join("index.jsonl")),
            next_id: 1,
            conns: HashMap::new(),
            finished: 0,
            written_bytes: 0,
        })
    }

    /// Feeds a segment into the reassembly & records what it did.
    fn feed(
        &mut self,
        pool: &mut TcpStreamReassemblyPool<SystemTime>,
        info: TcpSegmentInfo<'_>,
        time: SystemTime,
        frame: u64,
    ) {
        // The id is built here (instead of taking the one the events carry)
        // so it is available before & after the segment is processed.
        let (id, direction) =
            TcpConnectionId::new(info.source, info.destination, info.vlan_ids.clone(), ());

        // values that are needed after `info` was moved into the pool
        let segment = Segment {
            frame,
            time,
            direction,
            seq: info.sequence_number,
            ack: info.acknowledgment_number,
            syn: info.syn,
            fin: info.fin,
            rst: info.rst,
            len: info.payload.len() as u64,
        };

        // state of the connection before the segment is added (what the
        // segment changes is derived by comparing against it afterwards)
        let before = Before::capture(pool.connection(&id), &segment);

        let mut effects = describe(&before, &segment);
        // set if the follow up work has to happen after the borrow of the
        // event ended (see the `Closed` case below)
        let mut started_after_close = false;
        // set once both directions ended (the connection can be finished)
        let mut completed = false;

        match pool.process_tcp(info, time) {
            Ok(TcpReassemblyEvent::Segment {
                sender, receiver, ..
            }) => {
                // A SYN with a new initial sequence number replaces the
                // connection. The pool only reports that via `Closed` if the
                // replaced connection still held undelivered data, so the
                // (already detected) reconnect is finished here.
                if before.reconnect {
                    self.close(&id, None, CloseReason::Reconnect);
                }

                if let Some(released) = acknowledged(&before, receiver) {
                    effects.push(format!(
                        "acknowledges {released} more bytes of the reverse stream"
                    ));
                }
                // both directions ended, so nothing can arrive anymore
                completed = sender.is_fin_reached() && receiver.is_fin_reached();
                if completed {
                    effects.push("both directions reached their FIN".to_string());
                }

                let conn = self.record(&id, direction, time);
                conn.observe(&segment, &before);

                // the segment added its payload to "sender", while its
                // acknowledgment number may have released data of "receiver"
                deliver(conn, direction, sender, &mut effects);
                deliver(conn, direction.reverse(), receiver, &mut effects);
                conn.update_state(direction, sender, receiver);
            }
            Ok(TcpReassemblyEvent::Closed { connection, .. }) => {
                // The connection ended (RST) or was replaced by a new one
                // (SYN with a new initial sequence number): drain the data
                // that was never consumed. The closing segment is usually not
                // acknowledged anymore, so the unacknowledged data is taken
                // as well.
                let reason = if segment.rst {
                    CloseReason::Rst
                } else {
                    CloseReason::Reconnect
                };
                if let Some(conn) = self.conns.get_mut(&id) {
                    if segment.rst {
                        // the RST is the last packet of the connection that is
                        // ending, so it belongs into its info file (while the
                        // reconnecting SYN belongs to the new connection)
                        conn.observe(&segment, &before);
                        effects.push("connection reset".to_string());
                        conn.info(&segment_line(&segment, conn.orig, &effects));
                    }
                    for d in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                        final_drain(conn, d, connection.stream_mut(d));
                    }
                    let (first, second) = connection.streams_mut(TcpDirection::FirstToSecond);
                    conn.update_state(TcpDirection::FirstToSecond, first, second);
                }
                self.close(&id, None, reason);
                started_after_close = false == segment.rst;
            }
            Ok(TcpReassemblyEvent::Ignored) => {
                // The segment did not affect any connection. For a connection
                // that is tracked this only happens for a RST that is not
                // plausible for the stream it was sent in, so that a blindly
                // injected RST cannot tear the connection down (segments of
                // untracked connections end up here as well, but those have
                // no info file the line below could be written to).
                effects = vec![
                    "ignored, no effect on the reconstruction (a RST outside of the \
                     window of this stream, or a segment of an untracked connection)"
                        .to_string(),
                ];
            }
            Err(err) => {
                if false == self.conns.contains_key(&id) {
                    // the segment did not create a connection, so there is no
                    // info file it could be documented in
                    eprintln!("Error reconstructing TCP stream (packet {frame}): {err}");
                    return;
                }
                let conn = self.record(&id, direction, time);
                conn.observe(&segment, &before);
                // the reassembly leaves the streams unmodified on an error,
                // so what the segment would have contributed did not happen
                effects = vec![format!("rejected, the streams are unchanged: {err}")];
            }
        }

        if started_after_close {
            // the reconnect case: the SYN was added to the *new* connection,
            // which is tracked under the same id (the borrow of the closed
            // connection ended, so the pool can be accessed again)
            let conn = self.record(&id, direction, time);
            conn.observe(&segment, &before);
            if let Some(connection) = pool.connection_mut(&id) {
                let (sender, receiver) = connection.streams_mut(direction);
                deliver(conn, direction, sender, &mut effects);
                conn.update_state(direction, sender, receiver);
            }
        }

        // write the line describing the packet (in the RST case it was
        // already written into the connection that ended)
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.info(&segment_line(&segment, conn.orig, &effects));
        }

        // a connection whose both directions reached their FIN is finished
        // right away (the pool keeps it around otherwise, as a FIN does not
        // guarantee that nothing follows)
        if completed {
            self.close(&id, pool.connection_mut(&id), CloseReason::Fin);
            pool.end_connection(&id);
        }
    }

    /// Returns the record of a connection, creating it if it is the first
    /// segment (which also decides what the "originator" of the connection
    /// is & hands out the id used in the file names).
    fn record(
        &mut self,
        id: &TcpConnectionId,
        direction: TcpDirection,
        time: SystemTime,
    ) -> &mut Conn {
        let next_id = &mut self.next_id;
        let dir = &self.dir;
        let conn = self.conns.entry(id.clone()).or_insert_with(|| {
            let new_id = *next_id;
            *next_id += 1;
            Conn::new(new_id, dir, id, direction, time)
        });
        conn.last_time = time;
        conn
    }

    /// Finishes a connection: drains what is left (if the connection is still
    /// available), writes its index record & closes its files.
    fn close(
        &mut self,
        id: &TcpConnectionId,
        connection: Option<&mut TcpConnection>,
        reason: CloseReason,
    ) {
        let Some(mut conn) = self.conns.remove(id) else {
            return;
        };
        if let Some(connection) = connection {
            for d in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                final_drain(&mut conn, d, connection.stream_mut(d));
            }
            let (first, second) = connection.streams_mut(TcpDirection::FirstToSecond);
            conn.update_state(TcpDirection::FirstToSecond, first, second);
        }

        // a connection that ended normally but was only noticed later (e.g.
        // because a gap kept it from reaching its FIN earlier)
        let reason = if (reason == CloseReason::CaptureEnd || reason == CloseReason::Timeout)
            && conn.fin_observed[0]
            && conn.fin_observed[1]
        {
            CloseReason::Fin
        } else {
            reason
        };

        self.written_bytes += conn.bytes[0] + conn.bytes[1];
        self.finished += 1;
        self.index.write(conn.index_record(id, reason).as_bytes());
        conn.finish();
    }

    /// Finishes everything that is still open & flushes the index.
    fn flush(&mut self) {
        let open: Vec<TcpConnectionId> = self.conns.keys().cloned().collect();
        for id in open {
            self.close(&id, None, CloseReason::CaptureEnd);
        }
        self.index.flush();
    }
}

/// Hands the in-order data of one direction to its data file.
///
/// The data has to be consumed continuously, otherwise the buffer of the
/// stream fills up until segments get rejected with
/// [`TcpReassembleError::SegmentBeyondMaxWindow`].
fn deliver(
    conn: &mut Conn,
    direction: TcpDirection,
    stream: &mut TcpStreamReassemblyBuf,
    effects: &mut Vec<String>,
) {
    let index = direction_index(direction);
    let start = stream.base_offset();
    let consumed = stream.drain(|bytes| {
        conn.data[index].write(bytes);
        bytes.len()
    }) as u64;

    if consumed > 0 {
        conn.bytes[index] += consumed;
        conn.data_written[index] = true;
        effects.push(format!(
            "wrote {consumed} bytes to {} (stream offset {start})",
            conn.data[index].name(),
        ));
    }
}

/// Last chance to get at the data of a stream (the connection ended or the
/// capture is over).
///
/// In addition to [`deliver`] this hands out the data that was never
/// acknowledged and gives up on the bytes that were never captured (see
/// [`TcpStreamReassemblyBuf::skip_gap`]), which would otherwise hold back
/// everything behind them.
///
/// What it did is written to the info file directly, as there is no packet
/// the data could be attributed to anymore.
fn final_drain(conn: &mut Conn, direction: TcpDirection, stream: &mut TcpStreamReassemblyBuf) {
    let index = direction_index(direction);
    let role = role_name(direction, conn.orig);
    loop {
        let start = stream.base_offset();
        let consumed = stream.drain_unacked(|bytes| {
            conn.data[index].write(bytes);
            bytes.len()
        }) as u64;

        if consumed > 0 {
            conn.bytes[index] += consumed;
            conn.data_written[index] = true;
            conn.info(&format!(
                "# {role}: wrote {consumed} bytes to {} (stream offset {start})",
                conn.data[index].name(),
            ));
        }

        // give up on the bytes that were never captured & continue behind them
        // (the drain above may have moved the read cursor, so the position of
        // the gap is taken after it)
        let gap_start = stream.base_offset();
        let skipped = stream.skip_gap();
        if skipped == 0 {
            return;
        }
        conn.missing[index] += skipped;
        conn.history.add(direction, conn.orig, 'G');
        conn.info(&format!(
            "# {role}: gave up on {skipped} bytes that were never captured \
             (stream offset {gap_start})",
        ));
    }
}

/// Describes what a segment contributed to the reconstruction (derived from
/// the state of the streams before it was added).
fn describe(before: &Before, segment: &Segment) -> Vec<String> {
    if before.reconnect {
        // the offsets of the previous connection say nothing about this one
        return vec![
            "new connection re-using the same endpoints (SYN with a new initial \
             sequence number)"
                .to_string(),
        ];
    }

    let mut effects = Vec::new();
    if false == before.known {
        effects.push(
            if segment.syn {
                "new connection, stream start taken from the SYN"
            } else {
                "new connection, no SYN captured (stream anchored on this segment)"
            }
            .to_string(),
        );
    } else if segment.syn {
        // the connection is known, but this may still be the first segment of
        // this direction (e.g. the SYN+ACK answering the initial SYN)
        effects.push(
            if before.offset.is_none() {
                "stream start taken from the SYN"
            } else {
                "duplicated or re-ordered SYN"
            }
            .to_string(),
        );
    }

    // the stream offset the payload of the segment starts at (a direction
    // that has no base yet is anchored on this segment, so it starts at 0)
    let start = before.offset.unwrap_or(0);
    if segment.len > 0 {
        let new = before.new_bytes(segment.len);
        if new == segment.len {
            effects.push(format!("{new} new bytes at stream offset {start}"));
        } else if new == 0 {
            effects.push(format!(
                "{} bytes that were already received (re-transmit)",
                segment.len
            ));
        } else {
            effects.push(format!(
                "{new} new bytes at stream offset {start} ({} already received, \
                 {} in front of the read cursor)",
                before.duplicate, before.stale,
            ));
        }
        if before.gap > 0 {
            effects.push(format!(
                "{} bytes in front of it were not received yet",
                before.gap
            ));
        }
    } else if false == segment.syn && false == segment.fin && false == segment.rst {
        effects.push("no payload (acknowledgment, window update or keep alive)".to_string());
    }

    if segment.fin {
        effects.push(format!(
            "stream ends (FIN) at stream offset {}",
            start + segment.len as i128
        ));
    }
    effects
}

/// Number of additional bytes of the reverse stream that the acknowledgment
/// number of the segment released (`None` if it released nothing).
fn acknowledged(before: &Before, receiver: &TcpStreamReassemblyBuf) -> Option<u64> {
    let after = receiver.ack_offset()?;
    let released = after.saturating_sub(before.reverse_ack.unwrap_or(0));
    if released > 0 {
        Some(released)
    } else {
        None
    }
}

/// State of a connection before a segment was processed (used to describe
/// what the segment changed).
#[derive(Default)]
struct Before {
    /// True if the connection was already tracked.
    known: bool,

    /// True if this segment is the SYN of a **new** connection re-using the
    /// same endpoints (the pool will replace the tracked connection).
    reconnect: bool,

    /// Stream offset the payload of the segment starts at (`None` if the
    /// direction has no base yet, i.e. the segment establishes it).
    offset: Option<i128>,

    /// Payload bytes that were already received before.
    duplicate: u64,

    /// Payload bytes that lie before the read cursor (already delivered or
    /// skipped, so they are dropped).
    stale: u64,

    /// Number of bytes between the last received byte & the start of this
    /// segment (a re-ordered or lost segment).
    gap: u64,

    /// Stream offset up to which the **reverse** direction was acknowledged.
    reverse_ack: Option<u64>,
}

impl Before {
    fn capture(connection: Option<&TcpConnection>, segment: &Segment) -> Before {
        let Some(connection) = connection else {
            return Before::default();
        };
        let stream = connection.stream(segment.direction);

        // the SYN flag consumes one sequence number, the payload starts after it
        let payload_seq = if segment.syn {
            segment.seq.wrapping_add(1)
        } else {
            segment.seq
        };
        let offset = stream.seq_stream_offset(payload_seq);

        // Mirrors the rule the reassembly itself uses: if the start of the
        // stream is known only an exact match is a duplicated SYN (initial
        // sequence numbers are random, so any other value belongs to a new
        // connection), otherwise the buffer anchored itself on the first seen
        // segment and a SYN at or before that anchor starts the same stream.
        let reconnect = segment.syn
            && match offset {
                Some(start) => {
                    if stream.syn_observed() {
                        start != 0
                    } else {
                        start > 0
                    }
                }
                None => false,
            };

        let mut result = Before {
            known: true,
            reconnect,
            offset,
            reverse_ack: connection.stream(segment.direction.reverse()).ack_offset(),
            ..Default::default()
        };

        if let Some(start) = offset {
            let end = start + segment.len as i128;
            let cursor = stream.base_offset() as i128;
            result.stale = (core::cmp::min(end, cursor) - start).max(0) as u64;

            // bytes that were already received (a re-transmit or an overlap)
            let from = core::cmp::max(start, cursor);
            for section in stream.sections() {
                let overlap = core::cmp::min(end, section.end as i128)
                    - core::cmp::max(from, section.start as i128);
                if overlap > 0 {
                    result.duplicate += overlap as u64;
                }
            }

            // distance to the data that was received so far
            let received_end = stream
                .sections()
                .last()
                .map(|section| section.end as i128)
                .unwrap_or(cursor);
            if start > received_end {
                result.gap = (start - received_end) as u64;
            }
        }

        result
    }

    /// Payload bytes of the segment that are new for the reconstruction.
    fn new_bytes(&self, len: u64) -> u64 {
        len.saturating_sub(self.duplicate)
            .saturating_sub(self.stale)
    }
}

/// Zeek style history string of a connection.
///
/// Each letter stands for the first occurrence of an event, upper case for
/// the originator & lower case for the responder:
///
/// | letter | event                                        |
/// |--------|----------------------------------------------|
/// | `S`    | `SYN` without `ACK`                          |
/// | `H`    | `SYN` + `ACK` (the answer of the handshake)  |
/// | `A`    | `ACK`                                        |
/// | `D`    | segment carrying payload                     |
/// | `T`    | re-transmitted payload                       |
/// | `G`    | a gap of never captured bytes                |
/// | `F`    | `FIN`                                        |
/// | `R`    | `RST`                                        |
#[derive(Default)]
struct History(String);

impl History {
    /// Records the first occurrence of an event.
    fn add(&mut self, direction: TcpDirection, orig: TcpDirection, letter: char) {
        let letter = if direction == orig {
            letter.to_ascii_uppercase()
        } else {
            letter.to_ascii_lowercase()
        };
        if false == self.0.contains(letter) {
            self.0.push(letter);
        }
    }
}

/// Everything that is collected about a connection while it is reconstructed.
///
/// The data of a stream is handed out (and freed) piece by piece while the
/// capture is processed, so anything about the connection as a whole has to be
/// accumulated on the way.
struct Conn {
    /// Id of the connection (index in the file names).
    id: u64,

    /// Direction of the first segment that was seen ("originator" in the
    /// Zeek sense, which is the sender of the SYN for a connection whose
    /// start was captured).
    orig: TcpDirection,

    /// Capture time of the first & the last segment.
    first_time: SystemTime,
    last_time: SystemTime,

    /// Number of segments per direction (see [`direction_index`]).
    pkts: [u64; 2],

    /// Reconstructed bytes that were written per direction.
    bytes: [u64; 2],

    /// Bytes that were never captured & had to be skipped per direction.
    missing: [u64; 2],

    /// True once a data file was created for the direction.
    data_written: [bool; 2],

    /// State of the two stream directions (kept up to date on every segment
    /// so it is still available once the streams themselves are gone).
    syn_observed: [bool; 2],
    fin_observed: [bool; 2],
    complete: [bool; 2],
    ack_observed: [bool; 2],

    /// Zeek style history of the connection.
    history: History,

    /// Files the reconstructed streams are written to.
    data: [Sink; 2],

    /// File the per packet infos are written to.
    info: Sink,
}

impl Conn {
    fn new(
        id: u64,
        dir: &Path,
        conn_id: &TcpConnectionId,
        orig: TcpDirection,
        time: SystemTime,
    ) -> Conn {
        let mut data = [
            Sink::new(dir.join(format!("data/{id}_resp.bin"))),
            Sink::new(dir.join(format!("data/{id}_resp.bin"))),
        ];
        data[direction_index(orig)] = Sink::new(dir.join(format!("data/{id}_orig.bin")));

        let mut result = Conn {
            id,
            orig,
            first_time: time,
            last_time: time,
            pkts: [0; 2],
            bytes: [0; 2],
            missing: [0; 2],
            data_written: [false; 2],
            syn_observed: [false; 2],
            fin_observed: [false; 2],
            complete: [false; 2],
            ack_observed: [false; 2],
            history: History::default(),
            data,
            info: Sink::new(dir.join(format!("info/{id}.txt"))),
        };

        // same column widths as `segment_line`
        let columns = format!(
            "#{:>6}  {:<27}  {:<12}  {:<12} {:>10}  {:>10} {:>4}  {}",
            "frame", "time", "direction", "flags", "seq", "ack", "len", "effect",
        );
        let vlan_ids = conn_id.vlan_ids();
        result.info(&format!(
            "# connection {id}\n\
             # originator: {}\n\
             # responder:  {}\n\
             # vlan ids:   {}\n\
             # data:       {} (originator -> responder)\n\
             #             {} (responder -> originator)\n\
             #\n\
             # sequence & acknowledgment numbers are the raw values of the segments,\n\
             # stream offsets count the bytes of the reconstructed stream\n\
             #\n\
             {}",
            endpoint(conn_id.source(orig)),
            endpoint(conn_id.destination(orig)),
            if vlan_ids.is_empty() {
                "-".to_string()
            } else {
                vlan_ids
                    .iter()
                    .map(|v| v.value().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            result.data[direction_index(orig)].name(),
            result.data[direction_index(orig.reverse())].name(),
            columns,
        ));
        result
    }

    /// Records the flags & payload of a segment.
    fn observe(&mut self, segment: &Segment, before: &Before) {
        let direction = segment.direction;
        self.pkts[direction_index(direction)] += 1;
        if segment.ack.is_some() && false == segment.syn {
            // the ACK of a SYN is part of the handshake ('H'), not a plain
            // acknowledgment (same as Zeek)
            self.history.add(direction, self.orig, 'A');
        }
        if segment.syn {
            // a SYN answering a SYN is the second half of the handshake
            self.history.add(
                direction,
                self.orig,
                if direction == self.orig { 'S' } else { 'H' },
            );
        }
        if segment.len > 0 {
            self.history.add(direction, self.orig, 'D');
            if before.new_bytes(segment.len) == 0 {
                self.history.add(direction, self.orig, 'T');
            }
        }
        if segment.fin {
            self.history.add(direction, self.orig, 'F');
        }
        if segment.rst {
            self.history.add(direction, self.orig, 'R');
        }
    }

    /// Copies the state of the two stream directions into the record.
    fn update_state(
        &mut self,
        direction: TcpDirection,
        sender: &TcpStreamReassemblyBuf,
        receiver: &TcpStreamReassemblyBuf,
    ) {
        for (index, stream) in [
            (direction_index(direction), sender),
            (direction_index(direction.reverse()), receiver),
        ] {
            self.syn_observed[index] = stream.syn_observed();
            self.fin_observed[index] |= stream.fin_offset().is_some();
            self.complete[index] |= stream.is_fin_reached();
            self.ack_observed[index] = stream.ack_observed();
        }
    }

    /// Adds a line to the info file of the connection.
    fn info(&mut self, line: &str) {
        self.info.write(line.as_bytes());
        self.info.write(b"\n");
    }

    /// Builds the index record of the connection.
    fn index_record(&self, id: &TcpConnectionId, reason: CloseReason) -> String {
        let o = direction_index(self.orig);
        let r = direction_index(self.orig.reverse());
        let vlan_ids = id.vlan_ids();
        let midstream = false == self.syn_observed[o] && false == self.syn_observed[r];

        let mut result = String::new();
        result.push('{');
        json_field(&mut result, "id", &self.id.to_string());
        json_field(&mut result, "ts", &epoch(self.first_time));
        json_field(&mut result, "ts_iso", &json_str(&iso_time(self.first_time)));
        json_field(&mut result, "ts_end", &epoch(self.last_time));
        json_field(
            &mut result,
            "ts_end_iso",
            &json_str(&iso_time(self.last_time)),
        );
        json_field(
            &mut result,
            "duration",
            &format!(
                "{:.6}",
                self.last_time
                    .duration_since(self.first_time)
                    .unwrap_or_default()
                    .as_secs_f64()
            ),
        );
        json_field(&mut result, "proto", "\"tcp\"");
        json_field(
            &mut result,
            "id.orig_h",
            &json_str(&id.source(self.orig).ip.to_string()),
        );
        json_field(
            &mut result,
            "id.orig_p",
            &id.source(self.orig).port.to_string(),
        );
        json_field(
            &mut result,
            "id.resp_h",
            &json_str(&id.destination(self.orig).ip.to_string()),
        );
        json_field(
            &mut result,
            "id.resp_p",
            &id.destination(self.orig).port.to_string(),
        );
        // Zeek logs the outer & the first inner VLAN id
        json_field(
            &mut result,
            "vlan",
            &vlan_ids
                .first()
                .map(|v| v.value().to_string())
                .unwrap_or("null".to_string()),
        );
        json_field(
            &mut result,
            "inner_vlan",
            &vlan_ids
                .get(1)
                .map(|v| v.value().to_string())
                .unwrap_or("null".to_string()),
        );
        json_field(&mut result, "conn_state", &json_str(self.conn_state()));
        json_field(&mut result, "history", &json_str(&self.history.0));
        json_field(&mut result, "closed_by", &json_str(reason.as_str()));
        json_field(&mut result, "midstream", &midstream.to_string());
        json_field(&mut result, "orig_pkts", &self.pkts[o].to_string());
        json_field(&mut result, "resp_pkts", &self.pkts[r].to_string());
        json_field(&mut result, "orig_bytes", &self.bytes[o].to_string());
        json_field(&mut result, "resp_bytes", &self.bytes[r].to_string());
        json_field(
            &mut result,
            "orig_missing_bytes",
            &self.missing[o].to_string(),
        );
        json_field(
            &mut result,
            "resp_missing_bytes",
            &self.missing[r].to_string(),
        );
        json_field(
            &mut result,
            "orig_syn_observed",
            &self.syn_observed[o].to_string(),
        );
        json_field(
            &mut result,
            "resp_syn_observed",
            &self.syn_observed[r].to_string(),
        );
        json_field(
            &mut result,
            "orig_fin_observed",
            &self.fin_observed[o].to_string(),
        );
        json_field(
            &mut result,
            "resp_fin_observed",
            &self.fin_observed[r].to_string(),
        );
        json_field(&mut result, "orig_complete", &self.complete[o].to_string());
        json_field(&mut result, "resp_complete", &self.complete[r].to_string());
        // a stream that never saw an acknowledgment only hands out data via
        // `contiguous_unacked` (see `TcpAckPolicy::Required`)
        json_field(
            &mut result,
            "orig_ack_observed",
            &self.ack_observed[o].to_string(),
        );
        json_field(
            &mut result,
            "resp_ack_observed",
            &self.ack_observed[r].to_string(),
        );
        result.push_str("\"files\":{");
        result.push_str(&format!("\"info\":{}", json_str(self.info.name())));
        for (name, index) in [("orig", o), ("resp", r)] {
            result.push(',');
            if self.data_written[index] {
                result.push_str(&format!("\"{name}\":{}", json_str(self.data[index].name())));
            } else {
                result.push_str(&format!("\"{name}\":null"));
            }
        }
        result.push_str("}}\n");
        result
    }

    /// Zeek style connection state.
    ///
    /// See the [Zeek documentation](https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html)
    /// for the meaning of the individual states. Note that this is derived
    /// from the reconstruction state and not from a full TCP state machine,
    /// so it is an approximation of what Zeek would report.
    fn conn_state(&self) -> &'static str {
        let o = direction_index(self.orig);
        let r = direction_index(self.orig.reverse());
        let syn = self.history.0.contains('S');
        let syn_ack = self.history.0.contains('h');
        let rst_orig = self.history.0.contains('R');
        let rst_resp = self.history.0.contains('r');

        if syn && syn_ack {
            // the handshake was captured
            if rst_orig {
                "RSTO"
            } else if rst_resp {
                "RSTR"
            } else if self.fin_observed[o] && self.fin_observed[r] {
                "SF"
            } else if self.fin_observed[o] {
                "S2"
            } else if self.fin_observed[r] {
                "S3"
            } else {
                "S1"
            }
        } else if syn {
            // no answer of the responder was captured
            if rst_resp {
                "REJ"
            } else if rst_orig {
                "RSTOS0"
            } else if self.fin_observed[o] {
                "SH"
            } else {
                "S0"
            }
        } else if syn_ack {
            // the SYN of the originator is missing from the capture
            if rst_resp {
                "RSTRH"
            } else if self.fin_observed[r] {
                "SHR"
            } else {
                "OTH"
            }
        } else {
            "OTH"
        }
    }

    /// Writes out everything that is still buffered.
    fn finish(mut self) {
        self.info(&format!(
            "# {} bytes reconstructed originator -> responder, {} bytes responder -> originator",
            self.bytes[direction_index(self.orig)],
            self.bytes[direction_index(self.orig.reverse())],
        ));
        self.info.flush();
        for sink in self.data.iter_mut() {
            sink.flush();
        }
    }
}

/// Values of a received TCP segment that are needed after the segment itself
/// was moved into the reassembly.
struct Segment {
    /// Number of the packet in the capture (1 based, so it matches the frame
    /// numbers of Wireshark & tshark).
    frame: u64,

    /// Capture time of the packet.
    time: SystemTime,

    /// Direction the segment was travelling in.
    direction: TcpDirection,

    /// Sequence number (of the SYN if the flag is set, otherwise of the first
    /// payload byte).
    seq: u32,

    /// Acknowledgment number (`None` if the ACK flag was not set).
    ack: Option<u32>,

    /// Flags that are relevant for the reconstruction.
    syn: bool,
    fin: bool,
    rst: bool,

    /// Number of payload bytes.
    len: u64,
}

/// Builds the info file line describing a segment.
fn segment_line(segment: &Segment, orig: TcpDirection, effects: &[String]) -> String {
    let mut flags = Vec::new();
    if segment.syn {
        flags.push("SYN");
    }
    if segment.fin {
        flags.push("FIN");
    }
    if segment.rst {
        flags.push("RST");
    }
    if segment.ack.is_some() {
        flags.push("ACK");
    }

    // same column widths as the header written by `Conn::new`
    format!(
        "{:>7}  {:<27}  {:<12}  {:<12} {:>10}  {:>10} {:>4}  {}",
        segment.frame,
        iso_time(segment.time),
        role_name(segment.direction, orig),
        flags.join(","),
        segment.seq,
        segment
            .ack
            .map(|v| v.to_string())
            .unwrap_or("-".to_string()),
        segment.len,
        if effects.is_empty() {
            "nothing new".to_string()
        } else {
            effects.join("; ")
        },
    )
}

/// Buffers output & appends it to a file.
///
/// The file is only opened while something is written to it: a capture can
/// contain a lot more parallel connections (three files each) than the process
/// is allowed to keep open at the same time.
struct Sink {
    /// File the buffered data is written to.
    path: PathBuf,

    /// Path as it ends up in the index & the info files (relative to the
    /// output directory).
    name: String,

    /// Data that was not written to the file yet.
    buf: Vec<u8>,

    /// True once the file was created (further writes append to it).
    created: bool,
}

/// Number of bytes that are buffered before a [`Sink`] writes them out.
const SINK_BUF_SIZE: usize = 8 * 1024;

impl Sink {
    fn new(path: PathBuf) -> Sink {
        // the last two components are the ones inside the output directory
        let name = match path.parent().and_then(|p| p.file_name()) {
            Some(dir) => format!(
                "{}/{}",
                dir.to_string_lossy(),
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
            None => path.to_string_lossy().to_string(),
        };
        Sink {
            path,
            name,
            buf: Vec::new(),
            created: false,
        }
    }

    /// Path of the file relative to the output directory.
    fn name(&self) -> &str {
        &self.name
    }

    fn write(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() >= SINK_BUF_SIZE {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        // a re-run into the same directory has to overwrite the old files
        let file = OpenOptions::new()
            .write(true)
            .append(self.created)
            .truncate(false == self.created)
            .create(true)
            .open(&self.path);
        match file {
            Ok(mut file) => {
                self.created = true;
                if let Err(err) = file.write_all(&self.buf) {
                    eprintln!("Error writing '{}': {err}", self.path.display());
                    WRITE_FAILED.store(true, Ordering::Relaxed);
                }
            }
            Err(err) => {
                eprintln!("Error opening '{}': {err}", self.path.display());
                WRITE_FAILED.store(true, Ordering::Relaxed);
            }
        }
        self.buf.clear();
    }
}

/// Index of a direction in the per direction arrays.
fn direction_index(direction: TcpDirection) -> usize {
    match direction {
        TcpDirection::FirstToSecond => 0,
        TcpDirection::SecondToFirst => 1,
    }
}

/// Name of a direction relative to the originator of the connection.
fn role_name(direction: TcpDirection, orig: TcpDirection) -> &'static str {
    if direction == orig {
        "orig > resp"
    } else {
        "resp > orig"
    }
}

/// Formats an endpoint as "ip:port".
fn endpoint(endpoint: &TcpEndpoint) -> String {
    match endpoint.ip {
        IpAddr::V4(ip) => format!("{}:{}", ip, endpoint.port),
        IpAddr::V6(ip) => format!("[{}]:{}", ip, endpoint.port),
    }
}

/// Adds a `"name":value,` pair to a JSON object.
fn json_field(out: &mut String, name: &str, value: &str) {
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
    out.push_str(value);
    out.push(',');
}

/// Escapes & quotes a JSON string.
fn json_str(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ if c.is_control() => result.push_str(&format!("\\u{:04x}", c as u32)),
            _ => result.push(c),
        }
    }
    result.push('"');
    result
}

/// Formats a capture time as seconds since the unix epoch (the format Zeek
/// uses for its `ts` fields).
fn epoch(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(value) => format!("{:.6}", value.as_secs_f64()),
        Err(_) => "null".to_string(),
    }
}

/// Formats a capture time as an ISO 8601 / RFC 3339 timestamp in UTC.
fn iso_time(time: SystemTime) -> String {
    let Ok(duration) = time.duration_since(UNIX_EPOCH) else {
        return "?".to_string();
    };
    let secs = duration.as_secs();
    let (days, time_of_day) = ((secs / 86400) as i64, secs % 86400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
        duration.subsec_micros(),
    )
}

/// Converts days since the unix epoch into a year, month & day (algorithm
/// from Howard Hinnant's "chrono-Compatible Low-Level Date Algorithms").
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
