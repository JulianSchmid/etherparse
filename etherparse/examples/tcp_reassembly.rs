use etherparse::{tcp_reassembly::*, *};

/// Small helper that builds an ethernet + ipv4 + tcp packet with the given
/// sequence number, flags and payload.
fn build_packet(seq: u32, syn: bool, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([1, 2, 3, 4], [2, 3, 4, 5], 20)
        .tcp(1234, 80, seq, 4096);
    if syn {
        builder = builder.syn();
    }
    if fin {
        builder = builder.fin();
    }
    let mut serialized = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut serialized, payload).unwrap();
    serialized
}

fn main() {
    // pool that manages the different TCP streams & re-uses the memory buffers
    let mut pool = TcpStreamReassemblyPool::<(), ()>::new();

    // The segments below arrive out of order (the middle segment is delayed)
    // and one segment is duplicated - the reassembly handles all of that.
    let packets = [
        build_packet(1000, true, false, &[]), // SYN (isn = 1000, data starts at 1001)
        build_packet(1001, false, false, b"Hello, "), // first chunk (seq 1001..1008)
        build_packet(1020, false, true, b"stream!"), // last chunk (seq 1020..1027, arrives early, FIN)
        build_packet(1008, false, false, b"reassembled "), // middle chunk (seq 1008..1020, delayed)
        build_packet(1008, false, false, b"reassembled "), // duplicate of the middle chunk (replay)
    ];

    let mut fin_announced = false;
    for packet in &packets {
        let sliced_packet = match SlicedPacket::from_ethernet(packet) {
            Ok(v) => v,
            Err(err) => {
                println!("Err {:?}", err);
                continue;
            }
        };

        match pool.process_sliced_packet(&sliced_packet, (), ()) {
            Ok(TcpReassemblyEvent::Stream(stream)) => {
                // collect the in-order data that is available so far
                let available = stream.contiguous();
                if false == available.is_empty() {
                    println!(
                        "in-order data available{}: {:?}",
                        if stream.syn_observed() {
                            ""
                        } else {
                            " (stream start not observed, prefix missing)"
                        },
                        core::str::from_utf8(available).unwrap_or("<non utf8>")
                    );

                    // ... process the data here ...

                    // "clean" the processed bytes so the buffer memory is freed
                    let len = available.len();
                    stream.consume(len);
                }

                if stream.is_fin_reached() && false == fin_announced {
                    println!("stream finished (FIN reached)");
                    fin_announced = true;
                }
            }
            Ok(TcpReassemblyEvent::Closed(stream)) => {
                // a RST ended the stream (or a new connection replaced it):
                // the not yet consumed data can still be drained here
                println!(
                    "stream closed, leftover data: {:?}",
                    core::str::from_utf8(stream.contiguous()).unwrap_or("<non utf8>")
                );
            }
            Ok(TcpReassemblyEvent::Ignored) => {
                // not a TCP packet (or an empty segment of an unknown stream)
            }
            Err(err) => {
                println!("Error reassembling TCP stream: {err}");
            }
        }
    }

    // at the end of the capture: drain whatever is left in the still
    // tracked streams
    for (_id, stream, _timestamp) in pool.iter_mut() {
        let leftover = stream.contiguous();
        if false == leftover.is_empty() {
            println!(
                "leftover data at end of capture: {:?}",
                core::str::from_utf8(leftover).unwrap_or("<non utf8>")
            );
        }
    }
}
