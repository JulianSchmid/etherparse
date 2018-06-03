extern crate etherparse;
use etherparse::*;

fn main() {

    //setup some network data to parse
    let builder = PacketBuilder::
    ethernet2([1,2,3,4,5,6],     //source mac
               [7,8,9,10,11,12]) //destionation mac
    .ipv4([192,168,1,1], //source ip
          [192,168,1,2], //desitionation ip
          20)            //time to life
    .udp(21,    //source port 
         1234); //desitnation port

    //payload of the udp packet
    let payload = [1,2,3,4,5,6,7,8];
    
    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(
                    builder.size(payload.len()));
    builder.write(&mut result, &payload).unwrap();

    //start seperating the packet in different memory regions based on its content
    for element in PacketSliceIterator::from_ethernet(&result) {
        use PacketSlices::*;
        match element {
            Ok(value) => {
                match value {
                    //link layer
                    Ethernet2Header(slice) => {
                        println!("Ethernet2 {:?} => {:?}", slice.source(), slice.destination());
                    },
                    SingleVlanHeader(slice) => {
                        println!("Vlan {:?}", slice.vlan_identifier());
                    },
                    DoubleVlanHeader(slice) => {
                        println!("Double Vlan {:?}, {:?}", slice.outer().vlan_identifier(), slice.inner().vlan_identifier());
                    },
                    
                    //this element is generated when an unknown ethernet 2 payload is encountered
                    Ethernet2Payload(ether_type, payload) => {
                        println!("Ethernet2 unknown payload (ether_type: {:?})", ether_type);
                        println!("Payload: {:?}", payload);
                    },

                    //internet layer
                    Ipv4Header(slice) => {
                        println!("IPv4 {:?} => {:?}", slice.source_addr(), slice.destination_addr());
                    },
                    Ipv6Header(slice) => {
                        println!("IPv6 {:?} => {:?}", slice.source_addr(), slice.destination_addr());
                    },
                    Ipv6ExtensionHeader(header_type, _slice) => {
                        println!("IPv6 Extension Header {:?}", header_type);
                    },

                    //this element is generated when an unknown ip payload is encountered
                    IpPayload(protocol, _payload) => {
                        println!("IP unknown payload (id: {:?})", protocol);
                    },

                    //transport layer
                    UdpHeader(slice) => {
                        println!("UDP {:?} -> {:?}", slice.source_port(), slice.destination_port());
                    },
                    UdpPayload(payload) => {
                        println!("UDP payload: {:?}", payload);
                    },
                }
            },
            Err(value) => {
                println!("Err {:?}", value);
            }
        }
    }
}