use super::super::*;

use std::io::Cursor;
use proptest::prelude::*;
use self::byteorder::{ByteOrder, BigEndian};
use std::slice;

#[test]
fn default() {
    let default : TcpHeader = Default::default();

    assert_eq!(0, default.source_port);
    assert_eq!(0, default.destination_port);
    assert_eq!(0, default.sequence_number);
    assert_eq!(0, default.acknowledgment_number);
    assert_eq!(5, default.data_offset());
    assert_eq!(false, default.ns);
    assert_eq!(false, default.fin);
    assert_eq!(false, default.syn);
    assert_eq!(false, default.rst);
    assert_eq!(false, default.psh);
    assert_eq!(false, default.ack);
    assert_eq!(false, default.ece);
    assert_eq!(false, default.urg);
    assert_eq!(false, default.cwr);
    assert_eq!(0, default.window_size);
    assert_eq!(0, default.checksum);
    assert_eq!(0, default.urgent_pointer);
    assert_eq!(&[0;40][0..0], &default.options()[..]);
}

#[test]
fn eq()
{
    let options = [
        TcpOptionElement::Timestamp(0x00102030, 0x01112131), //10
        TcpOptionElement::SelectiveAcknowledgement((0x02122232,0x03132333), [None, None, None]), //20
        TcpOptionElement::Timestamp(0x04142434, 0x05152535), //30
        TcpOptionElement::Timestamp(0x06162636, 0x07172737), //40
    ];

    let base : TcpHeader = {
        let mut base : TcpHeader = Default::default();
        base.source_port = 1;
        base.destination_port = 2;
        base.sequence_number = 3;
        base.acknowledgment_number = 4;
        base.window_size = 6;
        base.checksum = 7;
        base.urgent_pointer = 8;
        base.set_options(&options[..]).unwrap();

        base
    };
    
    //equal
    {
        let other = base.clone();
        assert_eq!(other, base);
    }
    //change every field anc check for neq
    //source_port
    {
        let mut other = base.clone();
        other.source_port = 10;
        assert_ne!(other, base);
    }
    //destination_port
    {
        let mut other = base.clone();
        other.destination_port = 10;
        assert_ne!(other, base);
    }
    //sequence_number
    {
        let mut other = base.clone();
        other.sequence_number = 10;
        assert_ne!(other, base);
    }
    //acknowledgment_number
    {
        let mut other = base.clone();
        other.acknowledgment_number = 10;
        assert_ne!(other, base);
    }
    //data_offset
    {
        let mut other = base.clone();
        other.set_options(&[TcpOptionElement::MaximumSegmentSize(16)]).unwrap();
        assert_ne!(other, base);
    }
    //ns
    {
        let mut other = base.clone();
        other.ns = true;
        assert_ne!(other, base);
    }
    //fin
    {
        let mut other = base.clone();
        other.fin = true;
        assert_ne!(other, base);
    }
    //syn
    {
        let mut other = base.clone();
        other.syn = true;
        assert_ne!(other, base);
    }
    //rst
    {
        let mut other = base.clone();
        other.rst = true;
        assert_ne!(other, base);
    }
    //psh
    {
        let mut other = base.clone();
        other.psh = true;
        assert_ne!(other, base);
    }
    //ack
    {
        let mut other = base.clone();
        other.ack = true;
        assert_ne!(other, base);
    }
    //ece
    {
        let mut other = base.clone();
        other.ece = true;
        assert_ne!(other, base);
    }
    //urg
    {
        let mut other = base.clone();
        other.urg = true;
        assert_ne!(other, base);
    }
    //cwr
    {
        let mut other = base.clone();
        other.cwr = true;
        assert_ne!(other, base);
    }
    //window_size
    {
        let mut other = base.clone();
        other.window_size = 10;
        assert_ne!(other, base);
    }
    //checksum
    {
        let mut other = base.clone();
        other.checksum = 10;
        assert_ne!(other, base);
    }
    //urgent_pointer
    {
        let mut other = base.clone();
        other.urgent_pointer = 10;
        assert_ne!(other, base);
    }
    //options (first element different)
    {
        let mut other = base.clone();
        other.set_options(&{
            let mut other_options = options.clone();
            other_options[0] = TcpOptionElement::Timestamp(0x00102039, 0x01112131);
            other_options
        }).unwrap();

        assert_ne!(other, base);
    }
    //options (last element)
    {
        let mut other = base.clone();
        other.set_options(&options).unwrap();

        let mut other2 = base.clone();
        other2.set_options(&{
            let mut options2 = options.clone();
            options2[3] = TcpOptionElement::Timestamp(0x06162636, 0x97172737);
            options2
        }).unwrap();

        assert_ne!(other, other2);
    }
    //options (check only relevant data is compared)
    {
        let mut other = base.clone();
        other.set_options(&options).unwrap();

        let mut other2 = base.clone();
        other2.set_options(&{
            let mut options2 = options.clone();
            options2[3] = TcpOptionElement::Timestamp(0x06162636, 0x97172737);
            options2
        }).unwrap();

        // reset the data
        let new_options = [
            TcpOptionElement::Timestamp(0x00102030, 0x01112131)
        ];
        other.set_options(&new_options).unwrap();
        other2.set_options(&new_options).unwrap();

        assert_eq!(other, other2);
    }
    // slice (auto generated)
    {
        let header = base.clone();
        let buffer = {
            let mut buffer = Vec::with_capacity(header.header_len().into());
            header.write(&mut buffer).unwrap();
            buffer
        };
        let slice = TcpHeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(slice, slice.clone());
    }
    // TcpOptionReadError
    {
        use TcpOptionReadError::*;
        let value = UnexpectedEndOfSlice(123);
        assert_eq!(value, value.clone());
    }
    // TcpOptionWriteError
    {
        use TcpOptionWriteError::*;
        let value = NotEnoughSpace(123);
        assert_eq!(value, value.clone());
    }
}

#[test]
fn debug()
{
    // header
    {
        let header: TcpHeader = Default::default();

        // normal debug printing
        assert_eq!(
            format!(
                "TcpHeader {{ source_port: {}, destination_port: {}, sequence_number: {}, acknowledgment_number: {}, data_offset: {}, ns: {}, fin: {}, syn: {}, rst: {}, psh: {}, ack: {}, urg: {}, ece: {}, cwr: {}, window_size: {}, checksum: {}, urgent_pointer: {}, options: [] }}", 
                header.source_port,
                header.destination_port,
                header.sequence_number,
                header.acknowledgment_number,
                header.data_offset(),
                header.ns,
                header.fin,
                header.syn,
                header.rst,
                header.psh,
                header.ack,
                header.urg,
                header.ece,
                header.cwr,
                header.window_size,
                header.checksum,
                header.urgent_pointer
            ),
            format!("{:?}", header)
        );

        // multi line debug printing
        assert_eq!(
            format!(
                "TcpHeader {{
    source_port: {},
    destination_port: {},
    sequence_number: {},
    acknowledgment_number: {},
    data_offset: {},
    ns: {},
    fin: {},
    syn: {},
    rst: {},
    psh: {},
    ack: {},
    urg: {},
    ece: {},
    cwr: {},
    window_size: {},
    checksum: {},
    urgent_pointer: {},
    options: [],
}}", 
                header.source_port,
                header.destination_port,
                header.sequence_number,
                header.acknowledgment_number,
                header.data_offset(),
                header.ns,
                header.fin,
                header.syn,
                header.rst,
                header.psh,
                header.ack,
                header.urg,
                header.ece,
                header.cwr,
                header.window_size,
                header.checksum,
                header.urgent_pointer
            ),
            format!("{:#?}", header)
        );
    }
    // slice (auto generated, just make sure the implementation is there)
    {
        let header: TcpHeader = Default::default();
        println!("{:?}", header);
        let buffer = {
            let mut buffer = Vec::with_capacity(header.header_len().into());
            header.write(&mut buffer).unwrap();
            buffer
        };
        let slice = TcpHeaderSlice::from_slice(&buffer).unwrap();
        println!("{:?}", slice);
        assert_eq!(slice, slice.clone());
    }
    // TcpOptionElement
    {
        use TcpOptionElement::*;
        assert_eq!("Noop", format!("{:?}", Noop));
        assert_eq!(
            "MaximumSegmentSize(123)",
            format!("{:?}", MaximumSegmentSize(123))
        );
        assert_eq!(
            "WindowScale(123)",
            format!("{:?}", WindowScale(123))
        );
        assert_eq!(
            "SelectiveAcknowledgementPermitted",
            format!("{:?}", SelectiveAcknowledgementPermitted)
        );
        assert_eq!(
            "SelectiveAcknowledgement((1, 2), [Some((3, 4)), Some((5, 6)), None])",
            format!("{:?}",
                SelectiveAcknowledgement((1, 2), [Some((3,4)), Some((5,6)), None])
            )
        );
        assert_eq!(
            "Timestamp(123, 456)",
            format!("{:?}", Timestamp(123,456))
        );
    }
    // TcpOptionReadError
    {
        use TcpOptionReadError::*;
        assert_eq!(
            "UnexpectedEndOfSlice(0)",
            format!("{:?}", UnexpectedEndOfSlice(0))
        );
    }
    // TcpOptionWriteError
    {
        use TcpOptionWriteError::*;
        assert_eq!(
            "NotEnoughSpace(0)",
            format!("{:?}", NotEnoughSpace(0))
        );
    }
    // TcpOptionsIterator
    {
        use tcp_option::*;
        assert_eq!(
            "[MaximumSegmentSize(0), WindowScale(0)]",
            format!(
                "{:?}",
                TcpOptionsIterator::from_slice(&[
                    KIND_MAXIMUM_SEGMENT_SIZE, 4, 0, 0,
                    KIND_WINDOW_SCALE, 3, 0, KIND_END,
                ])
            )
        );
        assert_eq!(
            "[MaximumSegmentSize(0), Err(UnexpectedSize { option_id: 3, size: 0 })]",
            format!(
                "{:?}",
                TcpOptionsIterator::from_slice(&[
                    KIND_MAXIMUM_SEGMENT_SIZE, 4, 0, 0,
                    KIND_WINDOW_SCALE, 0, 0, 0,
                ])
            )
        );
    }
}

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
    use crate::TcpOptionWriteError::*;
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
        use crate::TcpOptionElement::*;
        assert_eq!(write_options(&[Noop, Noop, MaximumSegmentSize(arg), Noop]).options(), 
           &{
                use tcp_option::*;
                let mut options = [
                    KIND_NOOP, KIND_NOOP, KIND_MAXIMUM_SEGMENT_SIZE, 4,
                    0, 0, KIND_NOOP, KIND_END
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
        use crate::TcpOptionElement::*;
        use tcp_option::*;
        assert_eq!(write_options(&[Noop, Noop, WindowScale(arg), Noop]).options(), 
           &[
                KIND_NOOP, KIND_NOOP, KIND_WINDOW_SCALE, 3,
                arg, KIND_NOOP, KIND_END, 0
            ]
        );
    }
}

#[test]
fn set_options_selective_ack_perm() {
    use crate::TcpOptionElement::*;
    use tcp_option::*;
    assert_eq!(write_options(&[Noop, Noop, SelectiveAcknowledgementPermitted, Noop]).options(), 
       &[
            KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK_PERMITTED, 2,
            KIND_NOOP, KIND_END, 0, 0
        ]
    );
}

proptest! {
    #[test]
    fn set_options_selective_ack(args in proptest::collection::vec(any::<u32>(), 4*2)) {
        use crate::TcpOptionElement::*;
        use tcp_option::*;
        //1
        assert_eq!(write_options(&[Noop, Noop, SelectiveAcknowledgement((args[0], args[1]), [None, None, None]), Noop]).options(), 
           &{
                let mut options = [
                    KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 10,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    KIND_NOOP, KIND_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], args[0]);
                BigEndian::write_u32(&mut options[8..12], args[1]);
                options
            }
        );

        //2
        assert_eq!(write_options(&[Noop, Noop, SelectiveAcknowledgement((args[0], args[1]), 
                                                                      [Some((args[2], args[3])), 
                                                                       None, None]), 
                                   Noop]).options(), 
           &{
                let mut options = [
                    KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 18,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    KIND_NOOP, KIND_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], args[0]);
                BigEndian::write_u32(&mut options[8..12], args[1]);
                BigEndian::write_u32(&mut options[12..16], args[2]);
                BigEndian::write_u32(&mut options[16..20], args[3]);
                options
            }
        );

        //3
        assert_eq!(write_options(&[Noop, Noop, SelectiveAcknowledgement((args[0], args[1]), 
                                                                      [Some((args[2], args[3])), 
                                                                       Some((args[4], args[5])), 
                                                                       None]), 
                                   Noop]).options(), 
           &{
                let mut options = [
                    KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 26,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    KIND_NOOP, KIND_END, 0, 0
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
        assert_eq!(write_options(&[Noop, Noop, SelectiveAcknowledgement((args[0], args[1]), 
                                                                      [Some((args[2], args[3])), 
                                                                       Some((args[4], args[5])), 
                                                                       Some((args[6], args[7]))]), 
                                   Noop]).options(), 
           &{
                let mut options = [
                    KIND_NOOP, KIND_NOOP, KIND_SELECTIVE_ACK, 34,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    KIND_NOOP, KIND_END, 0, 0
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
        use crate::TcpOptionElement::*;
        use tcp_option::*;
        assert_eq!(write_options(&[Noop, Noop, Timestamp(arg0, arg1), Noop]).options(), 
           &{
                let mut options = [
                    KIND_NOOP, KIND_NOOP, KIND_TIMESTAMP, 10,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    KIND_NOOP, KIND_END, 0, 0
                ];
                BigEndian::write_u32(&mut options[4..8], arg0);
                BigEndian::write_u32(&mut options[8..12], arg1);
                options
            }
        );
    }
}
#[test]
fn set_option_padding() {
    use crate::TcpOptionElement::*;
    let mut tcp_header = TcpHeader::default();
    tcp_header.set_options(&[MaximumSegmentSize(1400), // 4
                            SelectiveAcknowledgementPermitted, // 2
                            Timestamp(2661445915, 0), // 10
                            Noop, // 1
                            WindowScale(7)]).unwrap(); // 3 
                            // total 20
                            // + header 20 = 40 byte
    assert_eq!(40, tcp_header.header_len());
}

#[test]
fn set_options_not_enough_memory_error() {
    use crate::TcpOptionElement::*;
    assert_eq!(Err(TcpOptionWriteError::NotEnoughSpace(41)),
               TcpHeader::default().set_options(
                    &[MaximumSegmentSize(1), //4
                      WindowScale(2), //+3 = 7
                      SelectiveAcknowledgementPermitted, //+2 = 9
                      SelectiveAcknowledgement((3,4), [Some((5,6)), None, None]), // + 18 = 27
                      Timestamp(5, 6), // + 10 = 37
                      Noop, Noop, Noop, Noop  // + 4
                    ]));
    //test with all fields filled of the selective ack
    assert_eq!(Err(TcpOptionWriteError::NotEnoughSpace(41)),
           TcpHeader::default().set_options(
                &[Noop, // 1
                  SelectiveAcknowledgement((3,4), [Some((5,6)), Some((5,6)), Some((5,6))]), // + 34 = 35
                  MaximumSegmentSize(1), // + 4 = 39 
                  Noop,
                  Noop // + 2 = 41
                ]));

    //test with all fields filled of the selective ack
    assert_eq!(Err(TcpOptionWriteError::NotEnoughSpace(41)),
           TcpHeader::default().set_options(
                &[Noop, // 1
                  SelectiveAcknowledgement((3,4), [None, None, None]), // + 10 = 11
                  Timestamp(1,2), // + 10 = 21
                  Timestamp(1,2), // + 10 = 31
                  MaximumSegmentSize(1), // + 4 = 35
                  Noop, Noop, Noop, Noop, Noop, Noop // + 6 = 41
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
        //deserialize with read
        {
            let result = TcpHeader::read(&mut Cursor::new(&buffer)).unwrap();
            //check equivalence (read)
            assert_eq!(input, &result);
        }
        //deserialize with read_from_slice
        {
            //add some more data to check the returning slice
            buffer.push(1);

            let result = TcpHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(input, &result.0);
            assert_eq!(&buffer[buffer.len()-1..], result.1);
        }
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

#[test]
fn write_and_read_length_error() {
    let headers = {
        let base_header = TcpHeader::new(1234,4567,9876,789);
        use TcpOptionElement::*;
        [
            {
                let mut header = base_header.clone();
                header.ns = true;
                header.fin = true;
                header.syn = true;
                header.rst = true;
                header.psh = true;
                header.ack = true;
                header.urg = true;
                header.ece = true;
                header.cwr = true;
                header
            }, {
                let mut header = base_header.clone();
                header.set_options(&[
                    MaximumSegmentSize(111),
                    WindowScale(222),
                    SelectiveAcknowledgementPermitted,
                    Timestamp(12,23)
                ]).unwrap();
                header
            }, {
                let mut header = base_header.clone();
                header.set_options(&[
                    SelectiveAcknowledgement(
                        (1,2), [Some((3,4)),Some((5,6)), Some((7,8))]
                    ),
                ]).unwrap();
                header
            }
        ]
    };
    
    for header in &headers {

        // write not enough space
        for len in 0..usize::from(header.header_len()) {
            let mut writer = TestWriter::with_max_size(len);
            assert_eq!(
                writer.error_kind(),
                header.write(&mut writer).unwrap_err().kind()
            );
        }

        let buffer = {
            let mut buffer = Vec::with_capacity(header.header_len().into());
            header.write(&mut buffer).unwrap();
            buffer
        };

        for len in 0..buffer.len() {
            use ReadError::*;
            // read
            assert_matches!(
                TcpHeader::read(&mut Cursor::new(&buffer[0..len])),
                Err(IoError(_))
            );

            // read_from_slice
            assert_matches!(
                TcpHeader::read_from_slice(&buffer[0..len]),
                Err(UnexpectedEndOfSlice(_))
            );

            // from_slice
            assert_matches!(
                TcpHeaderSlice::from_slice(&buffer[0..len]),
                Err(UnexpectedEndOfSlice(_))
            );
        }
    }
}

proptest! {
    #[test]
    fn packet_slice_from_slice(ref input in tcp_any()) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //create slice
        let slice = TcpHeaderSlice::from_slice(&buffer).unwrap();
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
        assert_matches!(TcpHeaderSlice::from_slice(&buffer),
                        Err(ReadError::TcpDataOffsetTooSmall(_)));
    }
}

proptest! {
    #[test]
    fn debug_fmt(ref input in tcp_any())
    {
        assert_eq!(&format!("TcpHeader {{ source_port: {}, destination_port: {}, sequence_number: {}, acknowledgment_number: {}, data_offset: {}, ns: {}, fin: {}, syn: {}, rst: {}, psh: {}, ack: {}, urg: {}, ece: {}, cwr: {}, window_size: {}, checksum: {}, urgent_pointer: {}, options: {:?} }}",
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
                input.urgent_pointer,
                input.options_iterator(),
            ),
            &format!("{:?}", input)
        );
    }
}

#[test]
fn calc_header_checksum_ipv4() {
    use crate::TcpOptionElement::*;
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
            //payload length
            tcp.header_len() + (tcp_payload.len() as u16),
            //time to live
            0,
            //contained protocol is udp
            IpNumber::Tcp,
            //source ip address
            [0;4],
            //destination ip address
            [0;4]
        );
        assert_eq!(Ok(0x0), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        assert_eq!(Ok(0x0), tcp.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &tcp_payload));
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
            Noop, Noop, Noop, Noop,
            Timestamp(0x4161008, 0x84161708)
        ]).unwrap();

        let ip_header = Ipv4Header::new(
            //payload length
            tcp.header_len() + (tcp_payload.len() as u16),
            //time to live
            20,
            //contained protocol is udp
            IpNumber::Tcp,
            //source ip address
            [192,168,1,42],
            //destination ip address
            [192,168,1,1]
        );

        //check checksum
        assert_eq!(Ok(0xdeeb), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        assert_eq!(Ok(0xdeeb), tcp.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &tcp_payload));

        //test PacketSlice version
        let mut ip_buffer = Vec::new();
        ip_header.write(&mut ip_buffer).unwrap();
        let ip_slice = Ipv4HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

        let mut tcp_buffer = Vec::new();
        tcp.write(&mut tcp_buffer).unwrap();
        let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

        assert_eq!(Ok(0xdeeb), tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload));
        assert_eq!(Ok(0xdeeb), tcp_slice.calc_checksum_ipv4_raw(ip_slice.source(), ip_slice.destination(), &tcp_payload));
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
            Noop, Noop, Noop, Noop,
            Timestamp(0x4161008, 0x84161708)
        ]).unwrap();

        let ip_header = Ipv4Header::new(
            //payload length
            tcp.header_len() + (tcp_payload.len() as u16),
            //time to live
            20,
            //contained protocol is udp
            IpNumber::Tcp,
            //source ip address
            [192,168,1,42],
            //destination ip address
            [192,168,1,1]
        );

        //check checksum
        assert_eq!(Ok(0xd5ea), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
        assert_eq!(Ok(0xd5ea), tcp.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &tcp_payload));

        //test PacketSlice version
        let mut ip_buffer = Vec::new();
        ip_header.write(&mut ip_buffer).unwrap();
        let ip_slice = Ipv4HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

        let mut tcp_buffer = Vec::new();
        tcp.write(&mut tcp_buffer).unwrap();
        let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

        assert_eq!(Ok(0xd5ea), tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload));
        assert_eq!(Ok(0xd5ea), tcp_slice.calc_checksum_ipv4_raw(ip_slice.source(), ip_slice.destination(), &tcp_payload));
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

    use crate::TcpOptionElement::*;
    tcp.set_options(&[
        Noop, Noop, Noop, Noop,
        Timestamp(0x4161008, 0x84161708)
    ]).unwrap();

    let ip_header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: tcp_payload.len() as u16 + tcp.header_len(),
        next_header: ip_number::TCP,
        hop_limit: 40,
        source: [1,2,3,4,5,6,7,8,
                 9,10,11,12,13,14,15,16],
        destination: [21,22,23,24,25,26,27,28,
                      29,30,31,32,33,34,35,36]
    };
    //check checksum
    assert_eq!(Ok(0x786e), tcp.calc_checksum_ipv6(&ip_header, &tcp_payload));
    assert_eq!(Ok(0x786e), tcp.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, &tcp_payload));

    //test PacketSlice version
    let mut ip_buffer = Vec::new();
    ip_header.write(&mut ip_buffer).unwrap();
    let ip_slice = Ipv6HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

    let mut tcp_buffer = Vec::new();
    tcp.write(&mut tcp_buffer).unwrap();
    let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

    assert_eq!(Ok(0x786e), tcp_slice.calc_checksum_ipv6(&ip_slice, &tcp_payload));
    assert_eq!(Ok(0x786e), tcp_slice.calc_checksum_ipv6_raw(ip_slice.source(), ip_slice.destination(), &tcp_payload));
}

#[test]
fn calc_header_checksum_ipv4_error() {
    //write the udp header
    let tcp: TcpHeader = Default::default();
    let len = (std::u16::MAX - tcp.header_len()) as usize + 1;
    let mut tcp_payload = Vec::with_capacity(len);
    tcp_payload.resize(len, 0); 
    let ip_header = Ipv4Header::new(0, 0, IpNumber::Tcp, [0;4], [0;4]);
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), tcp.calc_checksum_ipv4(&ip_header, &tcp_payload));
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), tcp.calc_checksum_ipv4_raw(ip_header.source, ip_header.destination, &tcp_payload));

    //test PacketSlice version
    let mut ip_buffer = Vec::new();
    ip_header.write(&mut ip_buffer).unwrap();
    let ip_slice = Ipv4HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

    let mut tcp_buffer = Vec::new();
    tcp.write(&mut tcp_buffer).unwrap();
    let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), tcp_slice.calc_checksum_ipv4(&ip_slice, &tcp_payload));
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u16::MAX as usize + 1)), tcp_slice.calc_checksum_ipv4_raw(ip_slice.source(), ip_slice.destination(), &tcp_payload));
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
    let tcp_payload = unsafe {
        //NOTE: The pointer must be initialized with a non null value
        //      otherwise a key constraint of slices is not fullfilled
        //      which can lead to crashes in release mode.
        use std::ptr::NonNull;
        slice::from_raw_parts(
            NonNull::<u8>::dangling().as_ptr(),
            len
        )
    };
    let ip_header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 0, //lets assume jumbograms behavior (set to 0, as bigger then u16)
        next_header: ip_number::TCP,
        hop_limit: 40,
        source: [1,2,3,4,5,6,7,8,
                 9,10,11,12,13,14,15,16],
        destination: [21,22,23,24,25,26,27,28,
                      29,30,31,32,33,34,35,36]
    };
    
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), tcp.calc_checksum_ipv6(&ip_header, &tcp_payload));
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), tcp.calc_checksum_ipv6_raw(ip_header.source, ip_header.destination, &tcp_payload));

    //test PacketSlice version
    let mut ip_buffer = Vec::new();
    ip_header.write(&mut ip_buffer).unwrap();
    let ip_slice = Ipv6HeaderSlice::from_slice(&ip_buffer[..]).unwrap();

    let mut tcp_buffer = Vec::new();
    tcp.write(&mut tcp_buffer).unwrap();
    let tcp_slice = TcpHeaderSlice::from_slice(&tcp_buffer[..]).unwrap();

    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), tcp_slice.calc_checksum_ipv6(&ip_slice, &tcp_payload));
    assert_eq!(Err(ValueError::TcpLengthTooLarge(std::u32::MAX as usize + 1)), tcp_slice.calc_checksum_ipv6_raw(ip_slice.source(), ip_slice.destination(), &tcp_payload));
}

#[test]
fn options_iterator_method() {
    let options = [
        TcpOptionElement::Timestamp(0x00102030, 0x01112131), //10
        TcpOptionElement::SelectiveAcknowledgement((0x02122232,0x03132333), [None, None, None]), //20
        TcpOptionElement::Timestamp(0x04142434, 0x05152535), //30
        TcpOptionElement::Timestamp(0x06162636, 0x07172737), //40
    ];

    let base : TcpHeader = {
        let mut base : TcpHeader = Default::default();
        base.set_options(&options[..]).unwrap();
        base
    };

    assert_eq!(
        &options[..], 
        &base
        .options_iterator()
        .map(|x| x.unwrap())
        .collect::<Vec<TcpOptionElement>>()[..]
    );
}

#[test]
fn options_iterator() {
    use crate::TcpOptionElement::*;
    use tcp_option::*;

    let header = {
        let mut header : TcpHeader = Default::default();
        header.set_options_raw(&[
            KIND_NOOP, KIND_NOOP,
            KIND_MAXIMUM_SEGMENT_SIZE, 4,
            0, 1,
            KIND_END, 0, 0, 0
        ]).unwrap();
        header
    };

    // TcpHeader::options_iterator
    {
        let mut it = header.options_iterator();
        let expected = [
            Noop,
            Noop,
            MaximumSegmentSize(1),
        ];
        for element in expected.iter() {
            assert_eq!(element, &it.next().unwrap().unwrap());
        }
        assert_eq!(None, it.next());
        assert_eq!(0, it.rest().len());
    }

    // TcpHeaderSlice::options_iterator
    {
        let mut buffer = Vec::with_capacity(header.header_len().into());
        header.write(&mut buffer).unwrap();
        let slice = TcpHeaderSlice::from_slice(&buffer).unwrap();

        let mut it = slice.options_iterator();
        let expected = [
            Noop,
            Noop,
            MaximumSegmentSize(1),
        ];
        for element in expected.iter() {
            assert_eq!(element, &it.next().unwrap().unwrap());
        }
        assert_eq!(None, it.next());
        assert_eq!(0, it.rest().len());
    }
}

#[test]
fn options_iterator_from_slice() {
    fn expect_elements(buffer: &[u8], expected: &[TcpOptionElement]) {
        // options iterator via from_slice()
        let mut it = TcpOptionsIterator::from_slice(buffer);
        for element in expected.iter() {
            assert_eq!(element, &it.next().unwrap().unwrap());
        }

        //expect no more elements
        assert_eq!(None, it.next());
        assert_eq!(0, it.rest().len());
    }

    use crate::TcpOptionElement::*;
    use tcp_option::*;

    //nop & max segment size
    expect_elements(&[
            KIND_NOOP, 
            KIND_NOOP,
            KIND_MAXIMUM_SEGMENT_SIZE, 4, 
            0, 1,
            KIND_WINDOW_SCALE, 3, 2,
            KIND_SELECTIVE_ACK_PERMITTED, 2,
            KIND_SELECTIVE_ACK, 10,
            0, 0, 0, 10,
            0, 0, 0, 11,
            KIND_SELECTIVE_ACK, 18, 
            0, 0, 0, 12,
            0, 0, 0, 13,
            0, 0, 0, 14,
            0, 0, 0, 15,
            KIND_SELECTIVE_ACK, 26, 
            0, 0, 0, 16,
            0, 0, 0, 17,
            0, 0, 0, 18,
            0, 0, 0, 19,
            0, 0, 0, 20,
            0, 0, 0, 21,
            KIND_SELECTIVE_ACK, 34, 
            0, 0, 0, 22,
            0, 0, 0, 23,
            0, 0, 0, 24,
            0, 0, 0, 25,
            0, 0, 0, 26,
            0, 0, 0, 27,
            0, 0, 0, 28,
            0, 0, 0, 29,
            KIND_TIMESTAMP, 10, 
            0, 0, 0, 30, 
            0, 0, 0, 31,
            KIND_END, 0, 0, 0, 0
        ],
        &[
            Noop,
            Noop,
            MaximumSegmentSize(1),
            WindowScale(2),
            SelectiveAcknowledgementPermitted,
            SelectiveAcknowledgement((10,11), [None, None, None]),
            SelectiveAcknowledgement((12,13), [Some((14,15)), None, None]),
            SelectiveAcknowledgement((16,17), [Some((18,19)), Some((20,21)), None]),
            SelectiveAcknowledgement((22,23), [Some((24,25)), Some((26,27)), Some((28,29))]),
            Timestamp(30,31)
        ]);
}

#[test]
fn options_iterator_unexpected_eos() {
    fn expect_unexpected_eos(slice: &[u8]) {
        for i in 1..slice.len()-1 {
            let mut it = TcpOptionsIterator::from_slice(&slice[..i]);
            assert_eq!(Some(Err(TcpOptionReadError::UnexpectedEndOfSlice(slice[0]))), it.next());
            //expect the iterator slice to be moved to the end
            assert_eq!(0, it.rest().len());
            assert_eq!(None, it.next());
        }
    }
    use tcp_option::*;
    expect_unexpected_eos(&[KIND_MAXIMUM_SEGMENT_SIZE, 4, 0, 0]);
    expect_unexpected_eos(&[KIND_WINDOW_SCALE, 3, 0]);
    expect_unexpected_eos(&[KIND_MAXIMUM_SEGMENT_SIZE, 4, 0, 0]);
    expect_unexpected_eos(&[KIND_SELECTIVE_ACK_PERMITTED, 2]);
    expect_unexpected_eos(&[KIND_SELECTIVE_ACK, 10, 0, 0, 0,
                            0, 0, 0, 0, 0]);
    expect_unexpected_eos(&[KIND_SELECTIVE_ACK, 18, 0, 0, 0,
                            0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0,
                            0, 0, 0]);
    expect_unexpected_eos(&[KIND_SELECTIVE_ACK, 26, 0, 0, 0,
                            0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0,
                            0]);
    expect_unexpected_eos(&[KIND_SELECTIVE_ACK, 34, 0, 0, 0,
                            0, 0, 0, 0, 0, //10
                            0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, //20
                            0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, //30
                            0, 0, 0, 0]);
    expect_unexpected_eos(&[KIND_TIMESTAMP, 10, 0, 0, 0,
                            0, 0, 0, 0, 0]);
}
#[test]
fn options_iterator_unexpected_length() {
    fn expect_unexpected_size(id: u8, size: u8) {
        let data = [id, size, 0, 0, 0,
                    0, 0, 0, 0, 0, //10
                    0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, //20
                    0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, //30
                    0, 0, 0, 0];
        let mut it = TcpOptionsIterator::from_slice(&data);
        assert_eq!(Some(Err(TcpOptionReadError::UnexpectedSize {option_id: data[0], size: data[1] })), it.next());
        //expect the iterator slice to be moved to the end
        assert_eq!(0, it.rest().len());
        assert_eq!(None, it.next());
        assert_eq!(0, it.rest().len());
    }
    use tcp_option::*;
    expect_unexpected_size(KIND_MAXIMUM_SEGMENT_SIZE, 3);
    expect_unexpected_size(KIND_MAXIMUM_SEGMENT_SIZE, 5);

    expect_unexpected_size(KIND_WINDOW_SCALE, 2);
    expect_unexpected_size(KIND_WINDOW_SCALE, 4);

    expect_unexpected_size(KIND_MAXIMUM_SEGMENT_SIZE, 3);
    expect_unexpected_size(KIND_MAXIMUM_SEGMENT_SIZE, 5);

    expect_unexpected_size(KIND_SELECTIVE_ACK_PERMITTED, 1);
    expect_unexpected_size(KIND_SELECTIVE_ACK_PERMITTED, 3);

    expect_unexpected_size(KIND_SELECTIVE_ACK, 9);
    expect_unexpected_size(KIND_SELECTIVE_ACK, 11);

    expect_unexpected_size(KIND_SELECTIVE_ACK, 17);
    expect_unexpected_size(KIND_SELECTIVE_ACK, 19);

    expect_unexpected_size(KIND_SELECTIVE_ACK, 25);
    expect_unexpected_size(KIND_SELECTIVE_ACK, 27);

    expect_unexpected_size(KIND_SELECTIVE_ACK, 33);
    expect_unexpected_size(KIND_SELECTIVE_ACK, 35);

    expect_unexpected_size(KIND_TIMESTAMP, 9);
    expect_unexpected_size(KIND_TIMESTAMP, 11);
}

#[test]
fn options_iterator_unexpected_id() {
    let data = [255, 2, 0, 0, 0,
                0, 0, 0, 0, 0, //10
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, //20
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, //30
                0, 0, 0, 0];
    let mut it = TcpOptionsIterator::from_slice(&data);
    assert_eq!(Some(Err(TcpOptionReadError::UnknownId(255))), it.next());
    //expect the iterator slice to be moved to the end
    assert_eq!(0, it.rest().len());
    assert_eq!(None, it.next());
    assert_eq!(0, it.rest().len());
}

#[test]
fn options_iterator_debug() {
    fn expect_elements(buffer: &[u8], expected: &[TcpOptionElement]) {
        // options iterator via from_slice()
        let mut it = TcpOptionsIterator::from_slice(buffer);
        for element in expected.iter() {
            assert_eq!(element, &it.next().unwrap().unwrap());
        }

        //expect no more elements
        assert_eq!(None, it.next());
        assert_eq!(0, it.rest().len());
    }

    use crate::TcpOptionElement::*;
    use tcp_option::*;

    //nop & max segment size
    expect_elements(&[
            KIND_NOOP, 
            KIND_NOOP,
            KIND_MAXIMUM_SEGMENT_SIZE, 4, 
            0, 1,
            KIND_WINDOW_SCALE, 3, 2,
            KIND_SELECTIVE_ACK_PERMITTED, 2,
            KIND_SELECTIVE_ACK, 10,
            0, 0, 0, 10,
            0, 0, 0, 11,
            KIND_SELECTIVE_ACK, 18, 
            0, 0, 0, 12,
            0, 0, 0, 13,
            0, 0, 0, 14,
            0, 0, 0, 15,
            KIND_SELECTIVE_ACK, 26, 
            0, 0, 0, 16,
            0, 0, 0, 17,
            0, 0, 0, 18,
            0, 0, 0, 19,
            0, 0, 0, 20,
            0, 0, 0, 21,
            KIND_SELECTIVE_ACK, 34, 
            0, 0, 0, 22,
            0, 0, 0, 23,
            0, 0, 0, 24,
            0, 0, 0, 25,
            0, 0, 0, 26,
            0, 0, 0, 27,
            0, 0, 0, 28,
            0, 0, 0, 29,
            KIND_TIMESTAMP, 10, 
            0, 0, 0, 30, 
            0, 0, 0, 31,
            KIND_END, 0, 0, 0, 0
        ],
        &[
            Noop,
            Noop,
            MaximumSegmentSize(1),
            WindowScale(2),
            SelectiveAcknowledgementPermitted,
            SelectiveAcknowledgement((10,11), [None, None, None]),
            SelectiveAcknowledgement((12,13), [Some((14,15)), None, None]),
            SelectiveAcknowledgement((16,17), [Some((18,19)), Some((20,21)), None]),
            SelectiveAcknowledgement((22,23), [Some((24,25)), Some((26,27)), Some((28,29))]),
            Timestamp(30,31)
        ]
    );
}


