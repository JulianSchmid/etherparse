use super::super::*;

mod ip_header {
    use super::*;

    #[test]
    fn read_ip_header_version_error() {
        use err::ip::{HeaderError::*, HeaderSliceError::*};

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
        assert_eq!(40, buffer.len());

        //corrupt the version
        buffer[0] = 0xff;

        //deserialize with read
        {
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(
                IpHeader::read(&mut cursor)
                    .unwrap_err()
                    .content_error()
                    .unwrap(),
                UnsupportedIpVersion {
                    version_number: 0xf
                }
            );
        }

        //deserialize with read_from_slice
        assert_eq!(
            IpHeader::from_slice(&buffer).unwrap_err(),
            Content(UnsupportedIpVersion {
                version_number: 0xf
            })
        );
        //also check that an error is thrown when the slice is too small
        //to even read the version
        assert_eq!(
            IpHeader::from_slice(&buffer[buffer.len()..]).unwrap_err(),
            Len(err::LenError {
                required_len: 1,
                len: 0,
                len_source: err::LenSource::Slice,
                layer: err::Layer::IpHeader,
                layer_start_offset: 0,
            })
        );
    }
} // mod ip_header
