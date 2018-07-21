use super::super::*;

use std::io::Cursor;

#[test]
fn options() {
    let base = TcpHeader {
        source_port: 0,
        destination_port: 0,
        sequence_number: 0,
        acknowledgment_number: 0,
        data_offset: 0,
        ns: false, fin: false, syn: false, rst: false,
        psh: false, ack: false, urg: false, ece: false,
        cwr: false,
        window_size: 0,
        checksum: 0,
        urgent_pointer: 0,
        options_buffer: [0;40]
    };
    //too small -> expect None
    for i in 0..TCP_MINIMUM_DATA_OFFSET {
        let mut header = base.clone();
        header.data_offset = i;
        assert_eq!(None, header.options_size());
        assert_eq!(None, header.options());
    }
    //ok size -> expect output based on options size
    for i in TCP_MINIMUM_DATA_OFFSET..TCP_MAXIMUM_DATA_OFFSET + 1 {
        let mut header = base.clone();
        header.data_offset = i;
        assert_eq!(Some((i - TCP_MINIMUM_DATA_OFFSET) as usize *4), header.options_size());
        assert_eq!(Some(&header.options_buffer[..(i-TCP_MINIMUM_DATA_OFFSET) as usize *4]), header.options());
    }
    //too big -> expect None
    for i in TCP_MAXIMUM_DATA_OFFSET + 1..std::u8::MAX {
        let mut header = base.clone();
        header.data_offset = i;
        assert_eq!(None, header.options_size());
        assert_eq!(None, header.options());
    }
}

proptest! {
    #[test]
    fn read_write(ref input in tcp_any())
    {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        input.write(&mut buffer).unwrap();
        //check length
        assert_eq!(input.data_offset as usize * 4, buffer.len());
        //deserialize
        let result = TcpHeader::read(&mut Cursor::new(&buffer)).unwrap();
        //check equivalence
        assert_eq!(input, &result);
    }
}

proptest! {
    #[test]
    fn write_data_offset_too_small(ref base in tcp_any(),
                                   data_offset in 0..TCP_MINIMUM_DATA_OFFSET)
    {
        let mut input = base.clone();
        input.data_offset = data_offset;
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        assert_matches!(input.write(&mut buffer), Err(
              WriteError::ValueError(_)));
        assert_eq!(0, buffer.len());
    }
}

proptest! {
    #[test]
    fn write_data_offset_too_large(ref base in tcp_any(),
                                   data_offset in (TCP_MAXIMUM_DATA_OFFSET + 1)..255)
    {
        let mut input = base.clone();
        input.data_offset = data_offset;
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(60);
        assert_matches!(input.write(&mut buffer), Err(
              WriteError::ValueError(_)));
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
        assert_eq!(input.data_offset, slice.data_offset());
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
        assert_eq!(&input.options_buffer[..input.options_size().unwrap()], slice.options());

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

#[test]
fn eq()
{
    let base = TcpHeader {
        source_port: 1,
        destination_port: 2,
        sequence_number: 3,
        acknowledgment_number: 4,
        data_offset: 5,
        ns: false,
        fin: false,
        syn: false,
        rst: false,
        psh: false,
        ack: false,
        ece: false,
        urg: false,
        cwr: false,
        window_size: 6,
        checksum: 7,
        urgent_pointer: 8,
        options_buffer: [0;40]
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
        other.data_offset = 10;
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
    //options (first element)
    {
        let mut other = base.clone();
        other.options_buffer[0] = 10;
        assert_ne!(other, base);
    }
    //options (last element)
    {
        let mut other = base.clone();
        other.options_buffer[39] = 10;
        assert_ne!(other, base);
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
                input.data_offset,
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
