extern crate etherparse;
use etherparse::*;

fn main() {

    let with_udp_checksum = true;

    //Any struct implementing the "Write" trait can be used to write to (e.g. File).
    //For this example lets use a simple Vec as it implements the write trait.
    let mut out = Vec::<u8>::with_capacity(
        //lets reserve enough memory to avoid unnecessary allocations
        Ethernet2Header::SERIALIZED_SIZE +
        Ipv4Header::SERIALIZED_SIZE +
        UdpHeader::SERIALIZED_SIZE +
        8 //payload
    );

    //setup the actual payload of the udp packet
    let udp_payload = [1,2,3,4,5,6,7,8];

    //Lets start out with an ethernet II header containing the mac addresses
    Ethernet2Header{
        destination: [1,2,3,4,5,6],
        source: [11,12,13,14,15,16],
        ether_type: EtherType::Ipv4 as u16
    }.write(&mut out).unwrap();

    //create the ipv4 header with the helper function
    //Note: It is also possible to define the rest of the header values via Ipv4Header {...}
    let ip_header = Ipv4Header::new(
        //payload length
        (UdpHeader::SERIALIZED_SIZE + udp_payload.len()) as u16,
        //time to live
        20,
        //contained protocol is udp
        IpNumber::Udp,
        //source ip address
        [192,168,1,42],
        //destination ip address
        [192,168,1,1]
    );

    //write the ipv4 header
    //The "write" call automatically calculates the ipv4 checksum.
    //Alternatively "write_raw" can be used to skip the checksum 
    //calculation and just write out the checksum set in the header.
    ip_header.write(&mut out).unwrap();

    //write the udp header
    //There is the option to write it with a checksum or without.
    //If yes, the ipv4 header & payload are needed to calculate the header
    if with_udp_checksum {
        UdpHeader::with_ipv4_checksum(
            //source port
            0,
            //destination port
            42,
            //ip header
            &ip_header,
            //udp payload
            &udp_payload
        ).unwrap().write(&mut out).unwrap();
    } else {
        //write the header with the checksum disabled
        UdpHeader::without_ipv4_checksum(
            //source port
            0,
            //destination port
            42,
            //payload length
            udp_payload.len()
        ).unwrap().write(&mut out).unwrap();
    }

    println!("{:?}", &out);
}