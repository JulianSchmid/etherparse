//! Reads a PCAP file, re-assembles fragmented IP packets and reconstructs
//! the payload byte streams of all TCP connections, printing the data as it
//! becomes available:
//!
//! ```sh
//! cargo run --example pcap_tcp_reassembly -- capture.pcap
//! ```
//!
//! Only the classic `.pcap` format is supported (not `.pcapng`, convert via
//! `tshark -r capture.pcapng -F pcap -w capture.pcap`) with the link types
//! "Ethernet" and "Raw IP". To keep the example small there is no extra
//! handling for captures with a limited snapshot length (truncated packets
//! are reported as parse errors and skipped).

use etherparse::{defrag::*, tcp_reassembly::*, *};
use rpcap::{read::PcapReader, Linktype};
use std::net::IpAddr;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Usage: pcap_tcp_reassembly <file.pcap>");
        std::process::exit(1);
    };
    let file = match std::fs::File::open(&path) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Error opening '{path}': {err}");
            std::process::exit(1);
        }
    };
    let (file_options, mut pcap_reader) =
        match PcapReader::new(std::io::BufReader::new(file)) {
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

    // pool re-assembling fragmented IPv4 & IPv6 packets
    let mut defrag_pool = IpDefragPool::<(), ()>::new();

    // pool reconstructing the payload streams of the TCP connections (by
    // default only data that the receiver acknowledged is handed out)
    let mut tcp_pool = TcpStreamReassemblyPool::<(), ()>::new();

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
            match defrag_pool.process_sliced_packet(&sliced, (), ()) {
                Ok(Some(finished)) => {
                    if finished.ip_number == IpNumber::TCP {
                        // the re-assembled payload is the TCP segment, while
                        // the addresses are taken from the (last) fragment
                        match TcpSegmentInfo::from_defragmented_payload(
                            &sliced,
                            &finished.payload,
                            (),
                        ) {
                            Ok(Some(info)) => handle_tcp_event(tcp_pool.process_tcp(info, ())),
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
            handle_tcp_event(tcp_pool.process_sliced_packet(&sliced, (), ()));
        }
    }

    // At the end of a capture: drain whatever is left. The last data of a
    // capture is usually never acknowledged (the capture ends before the ACK
    // arrives), so the acknowledgment requirement is ignored here.
    for (id, connection, _timestamp) in tcp_pool.iter_mut() {
        if false == connection.is_bidirectional() {
            println!(
                "warning: only one direction captured for {} <-> {} (no data can be acknowledged)",
                endpoint(id.first()),
                endpoint(id.second()),
            );
        }
        for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
            print_stream_data(id, direction, connection.stream_mut(direction), true);
        }
    }
}

/// Prints the stream data that became available through a processed segment.
fn handle_tcp_event(event: Result<TcpReassemblyEvent<'_>, TcpReassembleError>) {
    match event {
        Ok(TcpReassemblyEvent::Segment {
            id,
            direction,
            sender,
            receiver,
        }) => {
            // the segment added its payload to "sender", while its
            // acknowledgment number may have released data of "receiver"
            print_stream_data(&id, direction, sender, false);
            print_stream_data(&id, direction.reverse(), receiver, false);
        }
        Ok(TcpReassemblyEvent::Closed { id, connection }) => {
            // a RST ended the connection (or a new connection replaced it):
            // drain the data that was never consumed (the closing segment is
            // usually not acknowledged anymore, so unacknowledged data is
            // printed as well)
            for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                print_stream_data(&id, direction, connection.stream_mut(direction), true);
            }
            println!(
                "connection {} <-> {} closed",
                endpoint(id.first()),
                endpoint(id.second()),
            );
        }
        Ok(TcpReassemblyEvent::Ignored) => {
            // not a TCP segment (or a segment of an unknown connection that
            // carries nothing to reconstruct)
        }
        Err(err) => eprintln!("Error reconstructing TCP stream: {err}"),
    }
}

/// Prints & consumes the in-order data of one stream direction (including
/// the not yet acknowledged data if `include_unacked` is set).
fn print_stream_data(
    id: &TcpConnectionId,
    direction: TcpDirection,
    stream: &mut TcpStreamReassemblyBuf,
    include_unacked: bool,
) {
    let print = |bytes: &[u8]| {
        if false == bytes.is_empty() {
            println!(
                "{} -> {}{}: {:?}",
                endpoint(id.source(direction)),
                endpoint(id.destination(direction)),
                if include_unacked {
                    " (incl. unacknowledged)"
                } else {
                    ""
                },
                String::from_utf8_lossy(bytes),
            );
        }
        // consume everything (returning less would keep the rest buffered,
        // e.g. for a parser that only handles complete messages)
        bytes.len()
    };
    if include_unacked {
        stream.drain_unacked(print);
    } else {
        stream.drain(print);
    }
}

/// Formats an endpoint as "ip:port".
fn endpoint(endpoint: &TcpEndpoint) -> String {
    match endpoint.ip {
        IpAddr::V4(ip) => format!("{}:{}", ip, endpoint.port),
        IpAddr::V6(ip) => format!("[{}]:{}", ip, endpoint.port),
    }
}

