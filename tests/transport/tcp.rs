use super::super::*;

use std::io::Cursor;
use proptest::prelude::*;
use self::byteorder::{ByteOrder, BigEndian};
use std::slice;

#[test]
fn options() {
    let base : TcpHeader = Default::default();

    let dummy = [ 1, 2, 3, 4, 5,
                  6, 7, 8, 9,10,
                 11,12,13,14,15,
                 16,17,18,19,20,
                 21,22,23,24,25,
                 26,27,28,29,30,
                 31,32,33,34,35,
                 36,37,38,39,40,
                 41 ];

    //ok size -> expect output based on options size
    for i in 0..40 {
        let mut header = base.clone();
        println!("{}",i);
        //set the options
        header.set_options_raw(&dummy[..i]).unwrap();

        //determine the expected options length
        let mut options_length = i / 4;
        if i % 4 != 0 {
            options_length += 1;
        }
        options_length = options_length * 4;

        //expecetd data
        let mut expected_options = [0;40];
        expected_options[..i].copy_from_slice(&dummy[..i]);

        assert_eq!(options_length, header.options_len());
        assert_eq!((options_length / 4) as u8 + TCP_MINIMUM_DATA_OFFSET, header.data_offset());
        assert_eq!(&expected_options[..options_length], header.options());
    }

    //too big -> expect error
    let mut header = base.clone();
    use TcpOptionWriteError::*;
    assert_eq!(Err(NotEnoughSpace(dummy.len())), header.set_options_raw(&dummy[..]));
}

fn write_options(elements: &[TcpOptionElement]) -> TcpHeader {
    let mut result : TcpHeader = Default::default();
    result.set_options(elements).unwrap();
    result
}

proptest! {
    #[test]
    fn set_options_maximum_segment_size(arg in any::<u16>()) {
        use TcpOptionElement::*;
        assert_eq!(write_options(&[Nop, Nop, MaximumSegmentSize(arg), Nop]).options(), 
           &{
                let mut options = [
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_MAXIMUM_SEGMENT_SIZE, 4,
                    0, 0, TCP_OPTION_ID_NOP, TCP_OPTION_ID_END
                ];
                BigEndian::write_u16(&mut options[4..6], arg);
                options
            }
        );
    }
}

proptest! {
    #[test]
    fn set_options_window_scale(arg in any::<u8>()) {
        use TcpOptionElement::*;
        assert_eq!(write_options(&[Nop, Nop, WindowScale(arg), Nop]).options(), 
           &[
                TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_WINDOW_SCALE, 3,
                arg, TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0
            ]
        );
    }
}

#[test]
fn set_options_selective_ack_perm() {
    use TcpOptionElement::*;
    assert_eq!(write_options(&[Nop, Nop, SelectiveAcknowledgementPermitted, Nop]).options(), 
       &[
            TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_SELECTIVE_ACK_PERMITTED, 2,
            TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0, 0
        ]
    );
}

proptest! {
    #[test]
    fn set_options_selective_ack(args in proptest::collection::vec(any::<u32>(), 4*2)) {
        use TcpOptionElement::*;
        //1
        assert_eq!(write_options(&[Nop, Nop, SelectiveAcknowledgement((args[0], args[1]), [None, None, None]), Nop]).options(), 
           &{
                let mut options = [
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_SELECTIVE_ACK, 10,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], args[0]);
                BigEndian::write_u32(&mut options[8..12], args[1]);
                options
            }
        );

        //2
        assert_eq!(write_options(&[Nop, Nop, SelectiveAcknowledgement((args[0], args[1]), 
                                                                      [Some((args[2], args[3])), 
                                                                       None, None]), 
                                   Nop]).options(), 
           &{
                let mut options = [
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_SELECTIVE_ACK, 18,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], args[0]);
                BigEndian::write_u32(&mut options[8..12], args[1]);
                BigEndian::write_u32(&mut options[12..16], args[2]);
                BigEndian::write_u32(&mut options[16..20], args[3]);
                options
            }
        );

        //3
        assert_eq!(write_options(&[Nop, Nop, SelectiveAcknowledgement((args[0], args[1]), 
                                                                      [Some((args[2], args[3])), 
                                                                       Some((args[4], args[5])), 
                                                                       None]), 
                                   Nop]).options(), 
           &{
                let mut options = [
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_SELECTIVE_ACK, 26,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], args[0]);
                BigEndian::write_u32(&mut options[8..12], args[1]);
                BigEndian::write_u32(&mut options[12..16], args[2]);
                BigEndian::write_u32(&mut options[16..20], args[3]);
                BigEndian::write_u32(&mut options[20..24], args[4]);
                BigEndian::write_u32(&mut options[24..28], args[5]);
                options
            }
        );

        //4
        assert_eq!(write_options(&[Nop, Nop, SelectiveAcknowledgement((args[0], args[1]), 
                                                                      [Some((args[2], args[3])), 
                                                                       Some((args[4], args[5])), 
                                                                       Some((args[6], args[7]))]), 
                                   Nop]).options(), 
           &{
                let mut options = [
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_SELECTIVE_ACK, 34,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], args[0]);
                BigEndian::write_u32(&mut options[8..12], args[1]);
                BigEndian::write_u32(&mut options[12..16], args[2]);
                BigEndian::write_u32(&mut options[16..20], args[3]);
                BigEndian::write_u32(&mut options[20..24], args[4]);
                BigEndian::write_u32(&mut options[24..28], args[5]);
                BigEndian::write_u32(&mut options[28..32], args[6]);
                BigEndian::write_u32(&mut options[32..36], args[7]);
                options
            }[..]
        );
    }
}

proptest! {
    #[test]
    fn set_options_timestamp(arg0 in any::<u32>(),
                                        arg1 in any::<u32>()) {
        use TcpOptionElement::*;
        assert_eq!(write_options(&[Nop, Nop, Timestamp(arg0, arg1), Nop]).options(), 
           &{
                let mut options = [
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_NOP, TCP_OPTION_ID_TIMESTAMP, 10,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    TCP_OPTION_ID_NOP, TCP_OPTION_ID_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], arg0);
                BigEndian::write_u32(&mut options[8..12], arg1);
                options
            }
        );
    }
}

#[test]
fn set_options_not_enough_memory_error() {
    use TcpOptionElement::*;
    assert_eq!(Err(TcpOptionWriteError::NotEnoughSpace(41)),
               TcpHeader::default().set_options(
                    &[MaximumSegmentSize(1), //4
                      WindowScale(2), //+3 = 7
                      SelectiveAcknowledgementPermitted, //+2 = 9
                      SelectiveAcknowledgement((3,4), [Some((5,6)), None, None]), // + 18 = 27
                      Timestamp(5, 6), // + 10 = 37
                      Nop, Nop, Nop  // + 3 + 1 (for end)
                    ]));
    //test with all fields filled of the selective ack
    assert_eq!(Err(TcpOptionWriteError::NotEnoughSpace(41)),
           TcpHeader::default().set_options(
                &[Nop, // 1
                  SelectiveAcknowledgement((3,4), [Some((5,6)), Some((5,6)), Some((5,6))]), // + 34 = 35
                  MaximumSegmentSize(1), // + 4 = 39 
                  Nop // + 1 + 1 (for end) = 41
                ]));

    //test with all fields filled of the selective ack
    assert_eq!(Err(TcpOptionWriteError::NotEnoughSpace(41)),
           TcpHeader::default().set_options(
                &[Nop, // 1
                  SelectiveAcknowledgement((3,4), [None, None, None]), // + 10 = 11
                  Timestamp(1,2), // + 10 = 21
                  Timestamp(1,2), // + 10 = 31
                  MaximumSegmentSize(1), // + 4 = 35
                  Nop, Nop, Nop, Nop, Nop // + 5 + 1 (for end) = 41
                ]));
}

proptest! {
    #[test]
    fn read_write(ref input in tcp_any())
    {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //check length
        assert_eq!(input.data_offset() as usize * 4, buffer.len());
        assert_eq!(input.header_len() as usize, buffer.len());
        //deserialize
        let result = TcpHeader::read(&mut Cursor::new(&buffer)).unwrap();
        //check equivalence
        assert_eq!(input, &result);
    }
}

proptest! {
    #[test]
    fn read_data_offset_too_small(ref input in tcp_any(),
                  data_offset in 0..TCP_MINIMUM_DATA_OFFSET)
    {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //insert the too small data offset into the raw stream
        buffer[12] = (buffer[12] & 0xf) | ((data_offset << 4) & 0xf0);
        //deserialize
        assert_matches!(TcpHeader::read(&mut Cursor::new(&buffer)),
                        Err(ReadError::TcpDataOffsetTooSmall(_)));
    }
}

proptest! {
    #[test]
    fn read_unexpected_eof(ref input in tcp_any())
    {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //deserialize
        let len = buffer.len() - 1;
        assert_matches!(TcpHeader::read(&mut Cursor::new(&buffer[..len])),
                        Err(ReadError::IoError(_)));
    }
}

proptest! {
    #[test]
    fn packet_slice_from_slice(ref input in tcp_any()) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //create slice
        let slice = PacketSlice::<TcpHeader>::from_slice(&buffer).unwrap();
        //check all fields
        assert_eq!(input.source_port, slice.source_port());
        assert_eq!(input.destination_port, slice.destination_port());
        assert_eq!(input.sequence_number, slice.sequence_number());
        assert_eq!(input.acknowledgment_number, slice.acknowledgment_number());
        assert_eq!(input.data_offset(), slice.data_offset());
        assert_eq!(input.ns, slice.ns());
        assert_eq!(input.fin, slice.fin());
        assert_eq!(input.syn, slice.syn());
        assert_eq!(input.rst, slice.rst());
        assert_eq!(input.psh, slice.psh());
        assert_eq!(input.ack, slice.ack());
        assert_eq!(input.ece, slice.ece());
        assert_eq!(input.urg, slice.urg());
        assert_eq!(input.cwr, slice.cwr());
        assert_eq!(input.window_size, slice.window_size());
        assert_eq!(input.checksum, slice.checksum());
        assert_eq!(input.urgent_pointer, slice.urgent_pointer());
        assert_eq!(input.options(), slice.options());

        //check the to_header result
        assert_eq!(input, &slice.to_header());
    }
}

proptest! {
    #[test]
    fn packet_slice_from_slice_data_offset_too_small(ref input in tcp_any(),
                  data_offset in 0..TCP_MINIMUM_DATA_OFFSET)
    {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //insert the too small data offset into the raw stream
        buffer[12] = (buffer[12] & 0xf) | ((data_offset << 4) & 0xf0);
        //deserialize
        assert_matches!(PacketSlice::<TcpHeader>::from_slice(&buffer),
                        Err(ReadError::TcpDataOffsetTooSmall(_)));
    }
}

proptest! {
    #[test]
    fn debug_fmt(ref input in tcp_any())
    {
        assert_eq!(&format!("TcpHeader {{ source_port: {}, destination_port: {}, sequence_number: {}, acknowledgment_number: {}, data_offset: {}, ns: {}, fin: {}, syn: {}, rst: {}, psh: {}, ack: {}, urg: {}, ece: {}, cwr: {}, window_size: {}, checksum: {}, urgent_pointer: {} }}",
                input.source_port,
                input.destination_port,
                input.sequence_number,
                input.acknowledgment_number,
                input.data_offset(),
                input.ns,
                input.fin,
                input.syn,
                input.rst,
                input.psh,
                input.ack,
                input.urg,
                input.ece,
                input.cwr,
                input.window_size,
                input.checksum,
                input.urgent_pointer
            ),
            &format!("{:?}", input)
        );
    }
}

#[test]
fn calc_header_checksum_ipv4() {
    use TcpOptionElement::*;
    //checksum == 0xf (no carries) (aka sum == 0xffff)
    {
        let tcp_payload = [1,2,3,4,5,6,7,8];
        //write the udp header
        let tcp = TcpHeader::new(
            //source port
            0,
            //destination port
            0,
            40905,
            0
        );
        let ip_header = Ipv4Header::new(
            //size of the payload
            tcp.header_len() as usize + tcp_payload.len(),
            //time to live
            0,
            //contained protocol is udp
            IpTrafficClass::Tcp,
            //source ip address
            [0;4],
            //destination ip address
            [0;4]
        ).unwrap();
        assert_eq!(Ok(0x0), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        assert_eq!(Ok(0x0), tcp.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, &tcp_payload));
    }
    //a header with options
    {
        let tcp_payload = [1,2,3,4,5,6,7,8];

        let mut tcp = TcpHeader::new(
            //source port
            69,
            //destination port
            42,
            0x24900448,
            0x3653
        );
        tcp.urgent_pointer = 0xE26E;
        tcp.ns = true;
        tcp.fin = true;
        tcp.syn = true;
        tcp.rst = true;
        tcp.psh = true;
        tcp.ack = true;
        tcp.ece = true;
        tcp.urg = true;
        tcp.cwr = true;

        tcp.set_options(&[
            Nop, Nop, Nop, Nop,
            Timestamp(0x4161008, 0x84161708)
        ]).unwrap();

        let ip_header = Ipv4Header::new(
            //size of the payload
            tcp.header_len() as usize + tcp_payload.len(),
            //time to live
            20,
            //contained protocol is udp
            IpTrafficClass::Tcp,
            //source ip address
            [192,168,1,42],
            //destination ip address
            [192,168,1,1]
        ).unwrap();

        //check checksum
        assert_eq!(Ok(0xdeeb), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        assert_eq!(Ok(0xdeeb), tcp.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, &tcp_payload));
    }

    //a header with an uneven number of options
    {
        let tcp_payload = [1,2,3,4,5,6,7,8,9];

        let mut tcp = TcpHeader::new(
            //source port
            69,
            //destination port
            42,
            0x24900448,
            0x3653
        );
        tcp.urgent_pointer = 0xE26E;
        tcp.ns = true;
        tcp.fin = true;
        tcp.syn = true;
        tcp.rst = true;
        tcp.psh = true;
        tcp.ack = true;
        tcp.ece = true;
        tcp.urg = true;
        tcp.cwr = true;

        tcp.set_options(&[
            Nop, Nop, Nop, Nop,
            Timestamp(0x4161008, 0x84161708)
        ]).unwrap();

        let ip_header = Ipv4Header::new(
            //size of the payload
            tcp.header_len() as usize + tcp_payload.len(),
            //time to live
            20,
            //contained protocol is udp
            IpTrafficClass::Tcp,
            //source ip address
            [192,168,1,42],
            //destination ip address
            [192,168,1,1]
        ).unwrap();

        //check checksum
        assert_eq!(Ok(0xd5ea), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        assert_eq!(Ok(0xd5ea), tcp.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, &tcp_payload));
    }
}

#[test]
fn calc_header_checksum_ipv6() {
   let tcp_payload = [51,52,53,54,55,56,57,58];

    //write the tcp header
    let mut tcp = TcpHeader::new(
        //source port
        69,
        //destination port
        42,
        0x24900448,
        0x3653
    );
    tcp.urgent_pointer = 0xE26E;

    tcp.ns = true;
    tcp.fin = true;
    tcp.syn = true;
    tcp.rst = true;
    tcp.psh = true;
    tcp.ack = true;
    tcp.ece = true;
    tcp.urg = true;
    tcp.cwr = true;

    use TcpOptionElement::*;
    tcp.set_options(&[
        Nop, Nop, Nop, Nop,
        Timestamp(0x4161008, 0x84161708)
    ]).unwrap();

    let ip_header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: tcp_payload.len() as u16 + tcp.header_len(),
        next_header: IpTrafficClass::Tcp as u8,
        hop_limit: 40,
        source: [1,2,3,4,5,6,7,8,
                 9,10,11,12,13,14,15,16],
        destination: [21,22,23,24,25,26,27,28,
                      29,30,31,32,33,34,35,36]
    };
    //check checksum
    assert_eq!(Ok(0x786e), tcp.calc_checksum_ipv6(&ip_header, &tcp_payload));
    assert_eq!(Ok(0x786e), tcp.calc_checksum_ipv6_raw(&ip_header.source, &ip_header.destination, &tcp_payload));
}

#[test]
fn calc_header_checksum_ipv4_error() {
    //write the udp header
    let tcp: TcpHeader = Default::default();
    let len = (std::u16::MAX - tcp.header_len()) as usize +
            1;
    let mut tcp_payload = Vec::with_capacity(len);
    tcp_payload.resize(len, 0); 
    let ip_header = Ipv4Header::new(20, 0, IpTrafficClass::Tcp, [0;4], [0;4]).unwrap();
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), tcp.calc_checksum_ipv4_raw(&ip_header.source, &ip_header.destination, &tcp_payload));
}

//this test can only run on 64bit systems as we can not represent slices that are too big on 32 bit and bellow
#[test]
#[cfg(target_pointer_width = "64")] 
fn calc_header_checksum_ipv6_error() {
    //write the udp header
    let tcp: TcpHeader = Default::default();
    let len = (std::u32::MAX - tcp.header_len() as u32) as usize +
            1;
    
    //lets create a slice of that size that points to zero 
    //(as most systems can not allocate blocks of the size of u32::MAX)
    let ptr = 0x0 as *const u8;
    let tcp_payload = unsafe {
        slice::from_raw_parts(ptr, len)
    };
    let ip_header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 0, //lets assume jumbograms behavior (set to 0, as bigger then u16)
        next_header: IpTrafficClass::Tcp as u8,
        hop_limit: 40,
        source: [1,2,3,4,5,6,7,8,
                 9,10,11,12,13,14,15,16],
        destination: [21,22,23,24,25,26,27,28,
                      29,30,31,32,33,34,35,36]
    };
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), tcp.calc_checksum_ipv6(&ip_header, &tcp_payload));
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), tcp.calc_checksum_ipv6_raw(&ip_header.source, &ip_header.destination, &tcp_payload));
}