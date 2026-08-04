use etherparse::{tcp_reassembly::*, *};

const CLIENT_IP: [u8; 4] = [1, 2, 3, 4];
const SERVER_IP: [u8; 4] = [2, 3, 4, 5];
const CLIENT_PORT: u16 = 1234;
const SERVER_PORT: u16 = 80;

/// Builds an ethernet + ipv4 + tcp packet of one of the two directions.
fn build_packet(
    from_client: bool,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    fin: bool,
    payload: &[u8],
) -> Vec<u8> {
    let (source, destination, source_port, destination_port) = if from_client {
        (CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT)
    } else {
        (SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT)
    };

    let mut builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4(source, destination, 20)
        .tcp(source_port, destination_port, seq, 4096);
    if syn {
        builder = builder.syn();
    }
    if fin {
        builder = builder.fin();
    }
    if let Some(ack) = ack {
        builder = builder.ack(ack);
    }

    let mut serialized = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut serialized, payload).unwrap();
    serialized
}

fn main() {
    // Pool that manages the different TCP connections & re-uses the memory
    // buffers. By default only data that the receiver acknowledged is handed
    // out, which requires both directions of the connection to be present.
    let mut pool = TcpStreamReassemblyPool::<(), ()>::new();

    // A small exchange between a client (isn 1000) and a server (isn 5000).
    // The segments arrive out of order (the middle one is delayed) and one is
    // duplicated - the reassembly handles all of that.
    let packets = [
        // handshake
        build_packet(true, 1000, None, true, false, &[]),
        build_packet(false, 5000, Some(1001), true, false, &[]),
        // client sends its request in three chunks, the middle one is delayed
        build_packet(true, 1001, Some(5001), false, false, b"Hello, "),
        build_packet(true, 1020, Some(5001), false, true, b"stream!"),
        build_packet(true, 1008, Some(5001), false, false, b"reassembled "),
        // duplicate of the middle chunk (replay)
        build_packet(true, 1008, Some(5001), false, false, b"reassembled "),
        // the server acknowledges the first 19 bytes ...
        build_packet(false, 5001, Some(1020), false, false, &[]),
        // ... and then the rest
        build_packet(false, 5001, Some(1027), false, false, &[]),
    ];

    for packet in &packets {
        let sliced_packet = match SlicedPacket::from_ethernet(packet) {
            Ok(v) => v,
            Err(err) => {
                println!("Err {:?}", err);
                continue;
            }
        };

        match pool.process_sliced_packet(&sliced_packet, (), ()) {
            Ok(TcpReassemblyEvent::Segment {
                sender, receiver, ..
            }) => {
                // A segment adds its payload to the "sender" stream, while its
                // acknowledgment number can release data of the "receiver"
                // stream, so both are worth draining.
                for stream in [sender, receiver] {
                    let available = stream.contiguous();
                    if false == available.is_empty() {
                        println!(
                            "acknowledged data{}: {:?}",
                            if stream.syn_observed() {
                                ""
                            } else {
                                " (stream start not observed, prefix missing)"
                            },
                            core::str::from_utf8(available).unwrap_or("<non utf8>")
                        );

                        // ... process the data here ...

                        // "clean" the processed bytes so the memory is freed
                        let len = available.len();
                        stream.consume(len);
                    }
                }
            }
            Ok(TcpReassemblyEvent::Closed(connection)) => {
                // a RST ended the connection (or a new connection replaced
                // it): the not yet consumed data can still be drained here
                for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
                    let leftover = connection.stream(direction).contiguous_unacked();
                    if false == leftover.is_empty() {
                        println!(
                            "connection closed, leftover data: {:?}",
                            core::str::from_utf8(leftover).unwrap_or("<non utf8>")
                        );
                    }
                }
            }
            Ok(TcpReassemblyEvent::Ignored) => {
                // not a TCP packet (or a segment of an unknown connection that
                // carries nothing to reconstruct)
            }
            Err(err) => {
                println!("Error reassembling TCP stream: {err}");
            }
        }
    }

    // At the end of a capture: drain whatever is left. Note that the last data
    // of a capture is usually never acknowledged (the capture ends before the
    // ACK arrives), so `contiguous_unacked` has to be used here.
    for (id, connection, _timestamp) in pool.iter_mut() {
        if false == connection.is_bidirectional() {
            // only one direction was seen, so nothing could be acknowledged
            println!(
                "warning: only one direction captured for {:?} <-> {:?}",
                id.first(),
                id.second()
            );
        }
        for direction in [TcpDirection::FirstToSecond, TcpDirection::SecondToFirst] {
            let stream = connection.stream_mut(direction);
            let leftover = stream.contiguous_unacked();
            if false == leftover.is_empty() {
                println!(
                    "unacknowledged data at end of capture: {:?}",
                    core::str::from_utf8(leftover).unwrap_or("<non utf8>")
                );
                let len = leftover.len();
                stream.consume_unacked(len);
            }
        }
    }
}
