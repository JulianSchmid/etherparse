use super::super::*;

#[test]
fn read() {
    use std::io::Cursor;
    const INPUT: Ipv6Header = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 0x8021,
        next_header: 30,
        hop_limit: 40,
        source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        destination: [
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        ],
    };
    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(20);
    INPUT.write(&mut buffer).unwrap();
    assert_eq!(40, buffer.len());

    //deserialize
    let mut cursor = Cursor::new(&buffer);
    let result = IpHeader::read(&mut cursor).unwrap();
    assert_eq!(40, cursor.position());

    assert_eq!(result.0, IpHeader::Version6(INPUT, Default::default()));
    assert_eq!(result.1, INPUT.next_header);
}

#[test]
fn read_write() {
    use std::io::Cursor;

    let input = Ipv6Header {
        traffic_class: 1,
        flow_label: 0x81806,
        payload_length: 0x8021,
        next_header: 30,
        hop_limit: 40,
        source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        destination: [
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        ],
    };
    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(20);
    input.write(&mut buffer).unwrap();

    //deserialize (with read)
    {
        let result = Ipv6Header::read(&mut Cursor::new(&buffer)).unwrap();
        //check equivalence
        assert_eq!(input, result);
    }

    //deserialize (with from_slice)
    {
        let result = Ipv6Header::from_slice(&buffer).unwrap();
        assert_eq!(input, result.0);
        assert_eq!(&buffer[buffer.len()..], result.1);
    }

    //deserialize (with read_from_slice)
    #[allow(deprecated)]
    {
        let result = Ipv6Header::read_from_slice(&buffer).unwrap();
        assert_eq!(input, result.0);
        assert_eq!(&buffer[buffer.len()..], result.1);
    }
}

#[test]
fn write_errors() {
    use crate::ErrorField::*;
    use crate::ValueError::*;
    use crate::WriteError::ValueError;
    fn base() -> Ipv6Header {
        Ipv6Header {
            traffic_class: 1,
            flow_label: 0x0,
            payload_length: 0x8021,
            next_header: 30,
            hop_limit: 40,
            source: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            destination: [
                21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            ],
        }
    }

    fn test_write(input: &Ipv6Header) -> Result<(), WriteError> {
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer)
    }
    //flow label
    assert_matches!(
        test_write(&{
            let mut value = base();
            value.flow_label = 0x100000;
            value
        }),
        Err(ValueError(U32TooLarge {
            value: 0x100000,
            max: 0xFFFFF,
            field: Ipv6FlowLabel
        }))
    );

    //io error (not enough space)
    {
        let header = base();
        for len in 0..Ipv6Header::LEN {
            let mut writer = TestWriter::with_max_size(len);
            assert_eq!(
                writer.error_kind(),
                header
                    .write(&mut writer)
                    .unwrap_err()
                    .io_error()
                    .unwrap()
                    .kind()
            );
        }
    }
}

#[test]
fn read_error() {
    //wrong ip version
    {
        let buffer: [u8; 20] = [0; 20];
        let result = Ipv6Header::read(&mut io::Cursor::new(&buffer));
        assert_matches!(result, Err(ReadError::Ipv6UnexpectedVersion(0)))
    }
    //io error and unexpected end of slice
    {
        let buffer = {
            let mut buffer: [u8; Ipv6Header::LEN] = [0; Ipv6Header::LEN];
            buffer[0] = 0x60; //ip number is needed
            buffer
        };
        for len in 0..Ipv6Header::LEN {
            // read
            assert_matches!(
                Ipv6Header::read(&mut io::Cursor::new(&buffer[0..len])),
                Err(ReadError::IoError(_))
            );

            // read from slice
            assert_eq!(
                Ipv6Header::from_slice(&buffer[0..len])
                    .unwrap_err()
                    .unexpected_end_of_slice()
                    .unwrap(),
                err::UnexpectedEndOfSliceError {
                    expected_min_len: Ipv6Header::LEN,
                    actual_len: len,
                    layer: err::Layer::Ipv6Header
                }
            );
        }
    }
}

#[test]
fn header_len() {
    let header: Ipv6Header = Default::default();
    assert_eq!(Ipv6Header::LEN, header.header_len());
}


#[test]
fn set_payload_lengt() {
    let mut header = Ipv6Header {
        traffic_class: 0,
        flow_label: 0,
        payload_length: 0,
        next_header: 0,
        hop_limit: 0,
        source: [0; 16],
        destination: [0; 16],
    };
    assert_matches!(header.set_payload_length(0), Ok(()));
    assert_eq!(header.payload_length, 0);

    const MAX: usize = std::u16::MAX as usize;
    assert_matches!(header.set_payload_length(MAX), Ok(()));
    assert_eq!(header.payload_length, MAX as u16);

    const OVER_MAX: usize = MAX + 1;
    assert_matches!(
        header.set_payload_length(OVER_MAX),
        Err(ValueError::Ipv6PayloadLengthTooLarge(OVER_MAX))
    );
}

proptest! {
    #[test]
    fn from_slice(ref input in ipv6_any()) {
        //serialize
        let mut buffer: Vec<u8> = Vec::with_capacity(20);
        input.write(&mut buffer).unwrap();

        //check that a too small slice triggers an error
        assert_eq!(
            Ipv6HeaderSlice::from_slice(&buffer[..buffer.len()-1]).unwrap_err().unexpected_end_of_slice().unwrap(),
            err::UnexpectedEndOfSliceError{
                expected_min_len: Ipv6Header::LEN,
                actual_len: buffer.len() - 1,
                layer: err::Layer::Ipv6Header
            }
        );

        //check that all the values are read correctly
        use std::net::Ipv6Addr;
        let slice = Ipv6HeaderSlice::from_slice(&buffer).unwrap();
        assert_eq!(slice.slice(), &buffer[..]);
        assert_eq!(slice.version(), 6);
        assert_eq!(slice.traffic_class(), input.traffic_class);
        assert_eq!(slice.flow_label(), input.flow_label);
        assert_eq!(slice.payload_length(), input.payload_length);
        assert_eq!(slice.next_header(), input.next_header);
        assert_eq!(slice.hop_limit(), input.hop_limit);
        assert_eq!(slice.source(), input.source);
        assert_eq!(slice.source_addr(), Ipv6Addr::from(input.source));
        assert_eq!(slice.destination(), input.destination);
        assert_eq!(slice.destination_addr(), Ipv6Addr::from(input.destination));

        //test for derive
        assert_eq!(slice.clone(), slice);

        //check that the convertion back to a header struct results in the same struct
        assert_eq!(&slice.to_header(), input);
    }
}

#[test]
fn from_slice_bad_version() {
    //write an ipv4 header and check that the bad version number is detected
    let input = {
        let mut input: crate::Ipv4Header = Default::default();
        //set the options to increase the size,
        //otherwise an unexpected end of slice error is returned
        input.set_options(&[0; 24]).unwrap();
        input
    };

    //serialize
    let mut buffer: Vec<u8> = Vec::with_capacity(44);
    input.write_raw(&mut buffer).unwrap();

    //check that the unexpected version id is detected
    use crate::ReadError::*;
    assert_matches!(
        Ipv6HeaderSlice::from_slice(&buffer[..]),
        Err(Ipv6UnexpectedVersion(4))
    );
}
