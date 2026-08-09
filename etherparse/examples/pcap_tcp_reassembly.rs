//! Reads a PCAP file, re-assembles fragmented IP packets and reconstructs
//! the payload byte streams of all TCP connections, printing the data as it
//! becomes available:
//!
//! ```sh
//! cargo run --example pcap_tcp_reassembly -- capture.pcap
//! ```
//!
//! Data that decodes as UTF-8 is printed as text with the characters escaped
//! that could otherwise mess up the terminal (captured data is attacker
//! controlled, so an unescaped ANSI sequence could change colors, move the
//! cursor or overwrite previously printed lines), everything else is printed
//! as a hex dump.
//!
//! Pass `--metadata` to print a summary of the connections (endpoints,
//! reconstructed byte counts & the state of both directions) instead of the
//! stream contents:
//!
//! ```sh
//! cargo run --example pcap_tcp_reassembly -- --metadata capture.pcap
//! ```
//!
//! Connections whose end is never observed (no `FIN`, no `RST`, e.g. because
//! one side crashed or the capture does not contain the rest of them) would
//! occupy memory until the end of the capture, so connections that have been
//! inactive for too long are discarded (`--timeout`, in seconds of capture
//! time, `0` disables it).
//!
//! Only the classic `.pcap` format is supported (not `.pcapng`, convert via
//! `tshark -r capture.pcapng -F pcap -w capture.pcap`) with the link types
//! "Ethernet" and "Raw IP". To keep the example small there is no extra
//! handling for captures with a limited snapshot length (truncated packets
//! are reported as parse errors and skipped).

use clap::Parser;
use etherparse::{defrag::*, tcp_reassembly::*, *};
use rpcap::{read::PcapReader, Linktype};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Reconstructs the payload byte streams of all TCP connections in a pcap
/// file (re-assembling fragmented IP packets on the way).
#[derive(Parser)]
struct Args {
    /// Pcap file to read (classic pcap format, not pcapng).
    file: PathBuf,

    /// Print a summary of the connections (endpoints, byte counts & the
    /// state of both directions) instead of the stream data.
    #[arg(short, long)]
    metadata: bool,

    /// Discard connections that have not seen a segment for this many seconds
    /// of capture time (0 disables it).
    #[arg(short, long, default_value_t = DEFAULT_TCP_CONNECTION_TIMEOUT.as_secs())]
    timeout: u64,
}

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
    let mode = if args.metadata {
        OutputMode::Metadata
    } else {
        OutputMode::Data
    };
    let path = args.file.display();

    let file = match std::fs::File::open(&args.file) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Error opening '{path}': {err}");
            std::process::exit(1);
        }
    };
    let (file_options, mut pcap_reader) = match PcapReader::new(std::io::BufReader::new(file)) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Error parsing '{path}': {err}");
            std::process::exit(1);
        }
    };
    let is_ethernet = match file_options.linktype {
        l if l == Linktype::ETHERNET as u32 => true,
        l if l == Linktype::RAW as u32 => false,
        other => {
            eprintln!("Unsupported pcap link type {other}");
            std::process::exit(1);
        }
    };

    // pool re-assembling fragmented IPv4 & IPv6 packets (the capture time of
    // the packets is used to discard incomplete ones later on)
    let mut defrag_pool = IpDefragPool::<SystemTime, ()>::new();

    // pool reconstructing the payload streams of the TCP connections (by
    // default only data that the receiver acknowledged is handed out)
    let mut tcp_pool = TcpStreamReassemblyPool::<SystemTime, ()>::new();

    // decides what is printed & collects the per connection statistics
    let mut output = Output::new(mode);

    // capture time at which the next check for inactive connections is due
    let timeout = Duration::from_secs(args.timeout);
    let mut next_eviction: Option<SystemTime> = None;

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

        // get rid of the connections that have been inactive for too long
        // (before the packet is processed, so a connection is never discarded
        // because of the time that passed while it was being processed)
        if false == timeout.is_zero() && next_eviction.is_none_or(|next| packet.time >= next) {
            next_eviction = packet.time.checked_add(EVICTION_INTERVAL);
            evict_inactive(
                &mut tcp_pool,
                &mut defrag_pool,
                &mut output,
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
                eprintln!("Error parsing packet: {err}");
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
                                output.handle_event(tcp_pool.process_tcp(info, packet.time))
                            }
                            Ok(None) => {
                                // no IP header (cannot happen for a re-assembled packet)
                            }
                            Err(err) => {
                                eprintln!("Error parsing re-assembled TCP segment: {err}")
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
        } else {
            output.handle_event(tcp_pool.process_sliced_packet(&sliced, packet.time, ()));
        }
    }

    // At the end of a capture: drain whatever is left. The last data of a
    // capture is usually never acknowledged (the capture ends before the ACK
    // arrives), so the acknowledgment requirement is ignored here.
    for (id, connection, _timestamp) in tcp_pool.iter_mut() {
        for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
            output.consume_stream(id, direction, connection.stream_mut(direction), true);
        }
        output.finish_connection(id, connection, "still open at the end of the capture");
    }
}

/// Discards the connections that have not seen a segment for `timeout` (and
/// the fragments of IP packets that were never completed).
///
/// Every segment refreshes the timestamp of its connection, also the ones
/// that carry no data (keep alive probes, the acknowledgments answering them,
/// window updates & re-transmits), so a connection that is idle on the
/// application layer but alive on the wire is not discarded here.
fn evict_inactive(
    tcp_pool: &mut TcpStreamReassemblyPool<SystemTime>,
    defrag_pool: &mut IpDefragPool<SystemTime>,
    output: &mut Output,
    now: SystemTime,
    timeout: Duration,
) {
    // pcap timestamps are not guaranteed to be monotonic (and the capture may
    // start before the timeout has passed since the unix epoch)
    if let Some(cutoff) = now.checked_sub(timeout) {
        tcp_pool.evict_older_than_with(&cutoff, |id, connection| {
            // last chance to get at the data of the connection, so the
            // unacknowledged data is taken as well
            for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                output.consume_stream(id, direction, connection.stream_mut(direction), true);
            }
            output.finish_connection(id, connection, "discarded after being inactive");
        });
    }

    if let Some(cutoff) = now.checked_sub(IP_FRAGMENT_TIMEOUT) {
        defrag_pool.retain(|timestamp| *timestamp >= cutoff);
    }
}

/// What the example prints for the reconstructed streams.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    /// Print the reconstructed stream data.
    Data,

    /// Only print metadata about the connections.
    Metadata,
}

/// Numbers collected over the lifetime of a connection.
///
/// The data of a stream is handed out (and freed) piece by piece while the
/// capture is processed, so anything about the data as a whole has to be
/// accumulated on the way.
///
/// Note that a connection that is replaced by a new one re-using the same
/// addresses & ports is only reported via [`TcpReassemblyEvent::Closed`] if
/// it still held undelivered data. As this example drains everything
/// immediately, the statistics of such a reconnect continue the ones of the
/// previous connection instead of starting fresh.
#[derive(Default, Clone, Copy)]
struct ConnectionStats {
    /// Reconstructed bytes per direction (see [`direction_index`]).
    bytes: [u64; 2],

    /// Number of processed segments (both directions).
    segments: u64,
}

/// Prints the reconstructed streams (or just metadata about them) & collects
/// the per connection statistics.
struct Output {
    mode: OutputMode,

    /// Statistics of the connections that were seen so far.
    stats: HashMap<TcpConnectionId, ConnectionStats>,
}

impl Output {
    fn new(mode: OutputMode) -> Output {
        Output {
            mode,
            stats: HashMap::new(),
        }
    }

    /// Handles the data that became available through a processed segment.
    fn handle_event(&mut self, event: Result<TcpReassemblyEvent<'_>, TcpReassembleError>) {
        match event {
            Ok(TcpReassemblyEvent::Segment {
                id,
                direction,
                sender,
                receiver,
            }) => {
                self.stats.entry(id.clone()).or_default().segments += 1;
                // the segment added its payload to "sender", while its
                // acknowledgment number may have released data of "receiver"
                self.consume_stream(&id, direction, sender, false);
                self.consume_stream(&id, direction.reverse(), receiver, false);
            }
            Ok(TcpReassemblyEvent::Closed { id, connection }) => {
                // a RST ended the connection (or a new connection replaced
                // it): drain the data that was never consumed (the closing
                // segment is usually not acknowledged anymore, so the
                // unacknowledged data is taken as well)
                for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                    self.consume_stream(&id, direction, connection.stream_mut(direction), true);
                }
                self.finish_connection(&id, connection, "closed by a RST or a new connection");
            }
            Ok(TcpReassemblyEvent::Ignored) => {
                // not a TCP segment (or a segment of an unknown connection
                // that carries nothing to reconstruct)
            }
            Err(err) => eprintln!("Error reconstructing TCP stream: {err}"),
        }
    }

    /// Consumes the in-order data of one stream direction, printing it unless
    /// only metadata was requested.
    ///
    /// `final_drain` marks the last chance to get at the data of the stream
    /// (the connection ended or the capture is over). It additionally hands
    /// out the data that was never acknowledged.
    ///
    /// The data has to be consumed in both modes, otherwise the buffer of the
    /// stream fills up until segments get rejected with
    /// [`TcpReassembleError::SegmentBeyondMaxWindow`].
    fn consume_stream(
        &mut self,
        id: &TcpConnectionId,
        direction: TcpDirection,
        stream: &mut TcpStreamReassemblyBuf,
        final_drain: bool,
    ) {
        let mode = self.mode;
        let print = |bytes: &[u8]| {
            if mode == OutputMode::Metadata {
                // only the amount of data is of interest
                bytes.len()
            } else {
                print_stream_data(id, direction, bytes, final_drain)
            }
        };
        // `drain` returns the number of bytes the closure consumed
        let consumed = if final_drain {
            stream.drain_unacked(print)
        } else {
            stream.drain(print)
        };

        if consumed > 0 {
            let stats = self.stats.entry(id.clone()).or_default();
            stats.bytes[direction_index(direction)] += consumed as u64;
        }
    }

    /// Reports a connection that ended (or that is still open at the end of
    /// the capture) & drops its collected statistics.
    fn finish_connection(&mut self, id: &TcpConnectionId, connection: &TcpConnection, note: &str) {
        let stats = self.stats.remove(id).unwrap_or_default();

        if self.mode == OutputMode::Metadata {
            println!(
                "{} <-> {} ({} segments, {note})",
                endpoint(id.first()),
                endpoint(id.second()),
                stats.segments,
            );
            for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                let stream = connection.stream(direction);
                let mut state = Vec::new();
                if stream.syn_observed() {
                    state.push("start observed");
                } else {
                    state.push("start missing");
                }
                if stream.is_fin_reached() {
                    state.push("fin reached");
                }
                if false == stream.ack_observed() {
                    // under the default `TcpAckPolicy::Required` such a
                    // stream only hands out data via `contiguous_unacked`
                    state.push("no acknowledgments seen");
                }
                println!(
                    "  {} -> {}: {} bytes ({})",
                    endpoint(id.source(direction)),
                    endpoint(id.destination(direction)),
                    stats.bytes[direction_index(direction)],
                    state.join(", "),
                );
            }
        } else if false == connection.is_bidirectional() {
            // only one direction was seen, so nothing could be acknowledged
            println!(
                "warning: only one direction captured for {} <-> {}",
                endpoint(id.first()),
                endpoint(id.second()),
            );
        }
    }
}

/// Prints stream data & returns the number of bytes that were printed (which
/// is what the caller then consumes).
///
/// Valid UTF-8 is printed as text with the characters that could mess up the
/// terminal escaped, anything else as a hex dump.
///
/// A multi byte UTF-8 character can be split across two segments, so data
/// ending in the middle of one is not printed (and not consumed) yet: the
/// rest of the character arrives with one of the following segments. Only if
/// `flush` is set (the last chance to print the data) the incomplete
/// character is dumped as it is.
fn print_stream_data(
    id: &TcpConnectionId,
    direction: TcpDirection,
    bytes: &[u8],
    flush: bool,
) -> usize {
    match core::str::from_utf8(bytes) {
        Ok(text) => {
            print_text(id, direction, flush, text);
            bytes.len()
        }
        // `error_len() == None` means the data just ends in the middle of a
        // character (in contrast to containing an invalid byte sequence)
        Err(err) if err.error_len().is_none() && false == flush => {
            let valid = err.valid_up_to();
            if valid > 0 {
                // the prefix was already checked to be valid UTF-8
                print_text(
                    id,
                    direction,
                    flush,
                    core::str::from_utf8(&bytes[..valid]).unwrap(),
                );
            }
            // keep the incomplete character buffered
            valid
        }
        Err(_) => {
            println!(
                "{}: {} bytes of non UTF-8 data",
                stream_prefix(id, direction, flush),
                bytes.len(),
            );
            print_hex_dump(bytes);
            bytes.len()
        }
    }
}

/// Prints reconstructed text with the characters escaped that could mess up
/// the terminal.
fn print_text(id: &TcpConnectionId, direction: TcpDirection, flush: bool, text: &str) {
    if false == text.is_empty() {
        println!(
            "{}: \"{}\"",
            stream_prefix(id, direction, flush),
            escape_text(text),
        );
    }
}

/// "source -> destination" prefix of a line of stream data.
fn stream_prefix(id: &TcpConnectionId, direction: TcpDirection, flush: bool) -> String {
    format!(
        "{} -> {}{}",
        endpoint(id.source(direction)),
        endpoint(id.destination(direction)),
        if flush { " (incl. unacknowledged)" } else { "" },
    )
}

/// Escapes the characters of a reconstructed string that could mess up the
/// terminal it is printed to.
///
/// Never print captured data unescaped: it is attacker controlled and the
/// control characters would otherwise be interpreted by the terminal (e.g.
/// an escape character starting an ANSI sequence that changes colors, moves
/// the cursor or overwrites previously printed lines).
fn escape_text(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            // C0 & C1 control characters (including the escape character
            // that starts an ANSI sequence) and the bidirectional overrides
            // (which allow visually re-ordering the printed text)
            _ if c.is_control()
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c) =>
            {
                if (c as u32) < 0x100 {
                    result.push_str(&format!("\\x{:02x}", c as u32));
                } else {
                    result.push_str(&format!("\\u{{{:04x}}}", c as u32));
                }
            }
            _ => result.push(c),
        }
    }
    result
}

/// Prints data that is not valid UTF-8 as a hex dump (16 bytes per line
/// together with the printable ASCII characters).
fn print_hex_dump(bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::with_capacity(3 * 16);
        let mut ascii = String::with_capacity(16);
        for byte in chunk {
            hex.push_str(&format!("{byte:02x} "));
            ascii.push(if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            });
        }
        // 16 bytes are 48 characters of hex, so shorter last lines line up
        println!("  {:08x}  {:<48}|{}|", index * 16, hex, ascii);
    }
}

/// Index of a direction in [`ConnectionStats::bytes`].
fn direction_index(direction: TcpDirection) -> usize {
    match direction {
        TcpDirection::FirstToSecond => 0,
        TcpDirection::SecondToFirst => 1,
    }
}

/// Formats an endpoint as "ip:port".
fn endpoint(endpoint: &TcpEndpoint) -> String {
    match endpoint.ip {
        IpAddr::V4(ip) => format!("{}:{}", ip, endpoint.port),
        IpAddr::V6(ip) => format!("[{}]:{}", ip, endpoint.port),
    }
}
