use etherparse::*;

fn main() {
    //setup some network data to parse
    let builder = PacketBuilder::ethernet2(
        //source mac
        [1, 2, 3, 4, 5, 6],
        //destionation mac
        [7, 8, 9, 10, 11, 12],
    )
    .ipv4(
        //source ip
        [192, 168, 1, 1],
        //desitionation ip
        [192, 168, 1, 2],
        //time to life
        20,
    )
    .udp(
        21,   //source port
        1234, //desitnation port
    );

    //payload of the udp packet
    let payload = [1, 2, 3, 4, 5, 6, 7, 8];

    //get some memory to store the serialized data
    let mut serialized = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut serialized, &payload).unwrap();

    //slice the packet into the different header components
    let sliced_packet = SlicedPacket::from_ethernet(&serialized);

    //print some informations about the sliced packet
    match sliced_packet {
        Err(value) => println!("Err {:?}", value),
        Ok(value) => {
            println!("Ok");
            use etherparse::{InternetSlice::*, LinkSlice::*, TransportSlice::*, VlanSlice::*};

            match value.link {
                Some(Ethernet2(value)) => println!(
                    "  Ethernet2 {:?} => {:?}",
                    value.source(),
                    value.destination()
                ),
                None => {}
            }

            match value.vlan {
                Some(SingleVlan(value)) => println!("  SingleVlan {:?}", value.vlan_identifier()),
                Some(DoubleVlan(value)) => println!(
                    "  DoubleVlan {:?}, {:?}",
                    value.outer().vlan_identifier(),
                    value.inner().vlan_identifier()
                ),
                None => {}
            }

            match value.ip {
                Some(Ipv4(value, extensions)) => {
                    println!(
                        "  Ipv4 {:?} => {:?}",
                        value.source_addr(),
                        value.destination_addr()
                    );
                    if false == extensions.is_empty() {
                        println!("    {:?}", extensions);
                    }
                }
                Some(Ipv6(value, extensions)) => {
                    println!(
                        "  Ipv6 {:?} => {:?}",
                        value.source_addr(),
                        value.destination_addr()
                    );
                    if false == extensions.is_empty() {
                        println!("    {:?}", extensions);
                    }
                }
                None => {}
            }

            match value.transport {
                Some(Icmpv4(value)) => println!(" Icmpv4 {:?}", value),
                Some(Icmpv6(value)) => println!(" Icmpv6 {:?}", value),
                Some(Udp(value)) => println!(
                    "  UDP {:?} -> {:?}",
                    value.source_port(),
                    value.destination_port()
                ),
                Some(Tcp(value)) => {
                    println!(
                        "  TCP {:?} -> {:?}",
                        value.source_port(),
                        value.destination_port()
                    );
                    let options: Vec<Result<TcpOptionElement, TcpOptionReadError>> =
                        value.options_iterator().collect();
                    println!("    {:?}", options);
                }
                Some(Unknown(ip_protocol)) => {
                    println!("  Unknwon Protocol (ip protocol number {:?}", ip_protocol)
                }
                None => {}
            }
        }
    }
}
