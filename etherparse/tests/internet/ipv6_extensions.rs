use super::super::*;

use crate::ip_number::*;
use std::io::Cursor;

// IP numbers that are assigned ipv6 header extensions.
const EXTESION_KNOWN_IP_NUMBERS: [u8; 5] = [
    AUTH,
    IPV6_DEST_OPTIONS,
    IPV6_HOP_BY_HOP,
    IPV6_FRAG,
    IPV6_ROUTE,
];

/// Helper struct that generates test data with dummy
/// extension header data.
struct ExtensionTestPayload {
    ip_numbers: Vec<u8>,
    data: Vec<u8>,
}

impl ExtensionTestPayload {
    pub fn new(ip_numbers: &[u8], header_sizes: &[u8]) -> ExtensionTestPayload {
        assert!(ip_numbers.len() > 1);
        assert!(header_sizes.len() > 0);

        let mut result = ExtensionTestPayload {
            ip_numbers: ip_numbers.to_vec(),
            data: Vec::with_capacity((ip_numbers.len() - 1) * (0xff * 8 + 8)),
        };
        for i in 0..ip_numbers.len() - 1 {
            result.add_payload(
                ip_numbers[i],
                ip_numbers[i + 1],
                header_sizes[i % header_sizes.len()],
            )
        }
        result
    }

    pub fn slice(&self) -> &[u8] {
        &self.data
    }

    fn add_payload(&mut self, ip_number: u8, next_header: u8, header_ext_len: u8) {
        match ip_number {
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS => {
                // insert next header & size
                let mut raw: [u8; 0xff * 8 + 8] = [0; 0xff * 8 + 8];
                raw[0] = next_header;
                raw[1] = header_ext_len;

                // insert payload
                self.data
                    .extend_from_slice(&raw[..8 + usize::from(header_ext_len) * 8]);
            }
            IPV6_FRAG => {
                // generate payload
                let mut raw: [u8; 8] = [0; 8];
                raw[0] = next_header;
                raw[1] = 0;

                // insert payload
                self.data.extend_from_slice(&raw[..8]);
            }
            AUTH => {
                let mut raw: [u8; 0xff * 4 + 8] = [0; 0xff * 4 + 8];
                raw[0] = next_header;
                // authentfication header len is defined as
                // '32-bit words (4-byteunits), minus "2"'
                let len = if header_ext_len > 0 {
                    raw[1] = header_ext_len;
                    usize::from(header_ext_len) * 4
                } else {
                    // auth has a minimum size of 1
                    raw[1] = 1;
                    4
                } + 8;
                self.data.extend_from_slice(&raw[..len]);
            }
            _ => unreachable!(),
        }
    }

    /// Returns true of the payload will trigger a "hop by hop not
    /// at start" error which is not ignored because of an early
    /// parsing abort.
    pub fn exts_hop_by_hop_error(&self) -> bool {
        struct ReadState {
            dest_opt: bool,
            routing: bool,
            final_dest_opt: bool,
            frag: bool,
            auth: bool,
        }

        // state if a header type has already been read
        let mut read = ReadState {
            dest_opt: false,
            routing: false,
            final_dest_opt: false,
            frag: false,
            auth: false,
        };

        for i in 0..self.ip_numbers.len() {
            match self.ip_numbers[i] {
                IPV6_HOP_BY_HOP => {
                    if i != 0 {
                        return true;
                    }
                }
                IPV6_ROUTE => {
                    if read.routing {
                        return false;
                    } else {
                        read.routing = true;
                    }
                }
                IPV6_DEST_OPTIONS => {
                    // check the kind of destination options (aka is it before or after the routing header)
                    if read.routing {
                        // final dest opt
                        if read.final_dest_opt {
                            return false;
                        } else {
                            read.final_dest_opt = true;
                        }
                    } else {
                        // dst opt
                        if read.dest_opt {
                            return false;
                        } else {
                            read.dest_opt = true;
                        }
                    }
                }
                IPV6_FRAG => {
                    if read.frag {
                        return false;
                    } else {
                        read.frag = true;
                    }
                }
                AUTH => {
                    if read.auth {
                        return false;
                    } else {
                        read.auth = true;
                    }
                }
                _ => return false,
            }
        }
        return false;
    }

    /// Checks the if the extensions match the expected values based
    /// on this test payload.
    pub fn assert_extensions(&self, exts: &Ipv6Extensions) -> (usize, u8) {
        struct ReadState {
            hop_by_hop: bool,
            dest_opt: bool,
            routing: bool,
            final_dest_opt: bool,
            frag: bool,
            auth: bool,
        }

        // state if a header type has already been read
        let mut read = ReadState {
            hop_by_hop: false,
            dest_opt: false,
            routing: false,
            final_dest_opt: false,
            frag: false,
            auth: false,
        };

        let mut slice = &self.data[..];
        let mut post_header = self.ip_numbers[0];

        for i in 0..self.ip_numbers.len() - 1 {
            let mut stop = false;
            match self.ip_numbers[i] {
                IPV6_HOP_BY_HOP => {
                    assert!(false == read.hop_by_hop);
                    let (header, rest) = Ipv6RawExtensionHeader::from_slice(slice).unwrap();
                    assert_eq!(&header, exts.hop_by_hop_options.as_ref().unwrap());
                    slice = rest;
                    read.hop_by_hop = true;
                }
                IPV6_ROUTE => {
                    if read.routing {
                        stop = true;
                    } else {
                        let (header, rest) = Ipv6RawExtensionHeader::from_slice(slice).unwrap();
                        assert_eq!(&header, &exts.routing.as_ref().unwrap().routing);
                        slice = rest;
                        read.routing = true;
                    }
                }
                IPV6_DEST_OPTIONS => {
                    // check the kind of destination options (aka is it before or after the routing header)
                    if read.routing {
                        // final dest opt
                        if read.final_dest_opt {
                            stop = true;
                        } else {
                            let (header, rest) = Ipv6RawExtensionHeader::from_slice(slice).unwrap();
                            assert_eq!(
                                &header,
                                exts.routing
                                    .as_ref()
                                    .unwrap()
                                    .final_destination_options
                                    .as_ref()
                                    .unwrap()
                            );
                            slice = rest;
                            read.final_dest_opt = true;
                        }
                    } else {
                        // dst opt
                        if read.dest_opt {
                            stop = true;
                        } else {
                            let (header, rest) = Ipv6RawExtensionHeader::from_slice(slice).unwrap();
                            assert_eq!(&header, exts.destination_options.as_ref().unwrap());
                            slice = rest;
                            read.dest_opt = true;
                        }
                    }
                }
                IPV6_FRAG => {
                    if read.frag {
                        // duplicate header -> stop
                        stop = true;
                    } else {
                        let (header, rest) = Ipv6FragmentHeader::from_slice(slice).unwrap();
                        assert_eq!(&header, exts.fragment.as_ref().unwrap());
                        slice = rest;
                        read.frag = true;
                    }
                }
                AUTH => {
                    if read.auth {
                        // duplicate header -> stop
                        stop = true;
                    } else {
                        let (header, rest) = IpAuthHeader::from_slice(slice).unwrap();
                        assert_eq!(&header, exts.auth.as_ref().unwrap());
                        slice = rest;
                        read.auth = true;
                    }
                }
                _ => {
                    // non extension header -> stop
                    stop = true;
                }
            }
            if stop {
                post_header = self.ip_numbers[i];
                break;
            } else {
                post_header = self.ip_numbers[i + 1];
            }
        }

        // check the non parsed headers are not present
        if false == read.hop_by_hop {
            assert!(exts.hop_by_hop_options.is_none());
        }
        if false == read.dest_opt {
            assert!(exts.destination_options.is_none());
        }
        if false == read.routing {
            assert!(exts.routing.is_none());
        } else {
            if false == read.final_dest_opt {
                assert!(exts
                    .routing
                    .as_ref()
                    .unwrap()
                    .final_destination_options
                    .is_none());
            }
        }
        if false == read.frag {
            assert!(exts.fragment.is_none());
        }
        if false == read.auth {
            assert!(exts.auth.is_none());
        }

        (self.data.len() - slice.len(), post_header)
    }
}

/// extension header data.
#[derive(Clone)]
struct ExtensionTestHeaders {
    ip_numbers: Vec<u8>,
    data: Ipv6Extensions,
}

impl ExtensionTestHeaders {
    pub fn new(ip_numbers: &[u8], header_sizes: &[u8]) -> ExtensionTestHeaders {
        assert!(ip_numbers.len() > 1);
        assert!(header_sizes.len() > 0);

        let mut result = ExtensionTestHeaders {
            ip_numbers: ip_numbers.to_vec(),
            data: Default::default(),
        };
        for i in 0..ip_numbers.len() - 1 {
            let succ = result.add_payload(
                ip_numbers[i],
                ip_numbers[i + 1],
                header_sizes[i % header_sizes.len()],
            );
            if false == succ {
                // write was not possible (duplicate)
                // reduce the list so the current ip number
                // is the final one
                result.ip_numbers.truncate(i + 1);
                break;
            }
        }
        result
    }

    pub fn introduce_missing_ref(&mut self, new_header: u8) -> IpNumber {
        assert!(self.ip_numbers.len() >= 2);

        // set the next_header of the last extension header and return the id
        use IpNumber::*;
        if self.ip_numbers.len() >= 3 {
            match self.ip_numbers[self.ip_numbers.len() - 3] {
                IPV6_HOP_BY_HOP => {
                    self.data.hop_by_hop_options.as_mut().unwrap().next_header = new_header;
                }
                IPV6_DEST_OPTIONS => {
                    if self.ip_numbers[..self.ip_numbers.len() - 3]
                        .iter()
                        .any(|&x| x == IPV6_ROUTE)
                    {
                        self.data
                            .routing
                            .as_mut()
                            .unwrap()
                            .final_destination_options
                            .as_mut()
                            .unwrap()
                            .next_header = new_header;
                    } else {
                        self.data.destination_options.as_mut().unwrap().next_header = new_header;
                    }
                }
                IPV6_ROUTE => {
                    self.data.routing.as_mut().unwrap().routing.next_header = new_header;
                }
                IPV6_FRAG => {
                    self.data.fragment.as_mut().unwrap().next_header = new_header;
                }
                AUTH => {
                    self.data.auth.as_mut().unwrap().next_header = new_header;
                }
                _ => unreachable!(),
            }
            match self.ip_numbers[self.ip_numbers.len() - 2] {
                IPV6_HOP_BY_HOP => IPv6HeaderHopByHop,
                IPV6_DEST_OPTIONS => IPv6DestinationOptions,
                IPV6_ROUTE => IPv6RouteHeader,
                IPV6_FRAG => IPv6FragmentationHeader,
                AUTH => AuthenticationHeader,
                _ => unreachable!(),
            }
        } else {
            // rewrite start number in case it is just one extension header
            let missing = self.ip_numbers[0];
            self.ip_numbers[0] = new_header;
            match missing {
                IPV6_HOP_BY_HOP => IPv6HeaderHopByHop,
                IPV6_DEST_OPTIONS => IPv6DestinationOptions,
                IPV6_ROUTE => IPv6RouteHeader,
                IPV6_FRAG => IPv6FragmentationHeader,
                AUTH => AuthenticationHeader,
                _ => unreachable!(),
            }
        }
    }

    fn add_payload(&mut self, ip_number: u8, next_header: u8, header_ext_len: u8) -> bool {
        match ip_number {
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS => {
                use Ipv6RawExtensionHeader as R;
                let payload: [u8; R::MAX_PAYLOAD_LEN] = [0; R::MAX_PAYLOAD_LEN];
                let len = usize::from(header_ext_len) * 8 + 6;

                let raw = Ipv6RawExtensionHeader::new_raw(next_header, &payload[..len]).unwrap();
                match ip_number {
                    IPV6_HOP_BY_HOP => {
                        if self.data.hop_by_hop_options.is_none() {
                            self.data.hop_by_hop_options = Some(raw);
                            true
                        } else {
                            false
                        }
                    }
                    IPV6_ROUTE => {
                        if self.data.routing.is_none() {
                            self.data.routing = Some(Ipv6RoutingExtensions {
                                routing: raw,
                                final_destination_options: None,
                            });
                            true
                        } else {
                            false
                        }
                    }
                    IPV6_DEST_OPTIONS => {
                        if let Some(ref mut route) = self.data.routing {
                            if route.final_destination_options.is_none() {
                                route.final_destination_options = Some(raw);
                                true
                            } else {
                                false
                            }
                        } else {
                            // dest option
                            if self.data.destination_options.is_none() {
                                self.data.destination_options = Some(raw);
                                true
                            } else {
                                false
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            IPV6_FRAG => {
                if self.data.fragment.is_none() {
                    self.data.fragment = Some(Ipv6FragmentHeader::new(next_header, 0, true, 123));
                    true
                } else {
                    false
                }
            }
            AUTH => {
                if self.data.auth.is_none() {
                    use IpAuthHeader as A;

                    let mut len = usize::from(header_ext_len) * 4;
                    if len > A::MAX_ICV_LEN {
                        len = A::MAX_ICV_LEN;
                    }
                    let raw_icv: [u8; A::MAX_ICV_LEN] = [0; A::MAX_ICV_LEN];
                    self.data.auth = Some(
                        IpAuthHeader::new(next_header, 123, 234, &raw_icv[..len])
                            .unwrap(),
                    );
                    true
                } else {
                    false
                }
            }
            _ => unreachable!(),
        }
    }
}

pub mod header {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(
            header_size in any::<u8>(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                )
        ) {
            // no extension headers filled
            {
                let some_data = [1,2,3,4];
                let actual = Ipv6Extensions::from_slice(post_header, &some_data).unwrap();
                assert_eq!(actual.0, Default::default());
                assert_eq!(actual.1, post_header);
                assert_eq!(actual.2, &some_data);
            }

            /// Run a test with the given ip numbers
            fn run_test(ip_numbers: &[u8], header_sizes: &[u8]) {
                // setup test payload
                let e = ExtensionTestPayload::new(
                    ip_numbers,
                    header_sizes
                );

                if e.exts_hop_by_hop_error() {
                    // a hop by hop header that is not at the start triggers an error
                    assert_matches!(
                        Ipv6Extensions::from_slice(ip_numbers[0], e.slice()).unwrap_err(),
                        ReadError::Ipv6HopByHopHeaderNotAtStart
                    );
                } else {
                    // normal read
                    let (header, next, rest) = Ipv6Extensions::from_slice(ip_numbers[0], e.slice()).unwrap();
                    let (read_len, expected_post_header) = e.assert_extensions(&header);
                    assert_eq!(next, expected_post_header);
                    assert_eq!(rest, &e.slice()[read_len..]);

                    // unexpected end of slice
                    assert_matches!(
                        Ipv6Extensions::from_slice(ip_numbers[0], &e.slice()[..read_len - 1]).unwrap_err(),
                        ReadError::UnexpectedEndOfSlice(_)
                    );
                }
            }

            // test the parsing of different extension header combinations
            for first_header in &EXTESION_KNOWN_IP_NUMBERS {

                // single header parsing
                run_test(
                    &[*first_header, post_header],
                    &[header_size],
                );

                for second_header in &EXTESION_KNOWN_IP_NUMBERS {

                    // double header parsing
                    run_test(
                        &[*first_header, *second_header, post_header],
                        &[header_size],
                    );

                    for third_header in &EXTESION_KNOWN_IP_NUMBERS {
                        // tripple header parsing
                        run_test(
                            &[*first_header, *second_header, *third_header, post_header],
                            &[header_size],
                        );
                    }
                }
            }
        }
    }

    proptest! {
        #[test]
        fn read(
            header_size in any::<u8>(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                )
        ) {
            // no extension headers filled
            {
                let mut cursor = Cursor::new(&[]);
                let actual = Ipv6Extensions::read(&mut cursor, post_header).unwrap();
                assert_eq!(actual.0, Default::default());
                assert_eq!(actual.1, post_header);
                assert_eq!(0, cursor.position());
            }

            /// Run a test with the given ip numbers
            fn run_test(ip_numbers: &[u8], header_sizes: &[u8]) {
                // setup test payload
                let e = ExtensionTestPayload::new(
                    ip_numbers,
                    header_sizes
                );
                let mut cursor = Cursor::new(e.slice());

                if e.exts_hop_by_hop_error() {
                    // a hop by hop header that is not at the start triggers an error
                    assert_matches!(
                        Ipv6Extensions::read(&mut cursor, ip_numbers[0]).unwrap_err(),
                        ReadError::Ipv6HopByHopHeaderNotAtStart
                    );
                } else {
                    // normal read
                    let (header, next) = Ipv6Extensions::read(&mut cursor, ip_numbers[0]).unwrap();
                    let (read_len, expected_post_header) = e.assert_extensions(&header);
                    assert_eq!(next, expected_post_header);
                    assert_eq!(cursor.position() as usize, read_len);

                    // unexpected end of slice
                    {
                        let mut short_cursor = Cursor::new(&e.slice()[..read_len - 1]);
                        assert_matches!(
                            Ipv6Extensions::read(&mut short_cursor, ip_numbers[0]).unwrap_err(),
                            ReadError::IoError(_)
                        );
                    }
                }
            }

            // test the parsing of different extension header combinations
            for first_header in &EXTESION_KNOWN_IP_NUMBERS {

                // single header parsing
                run_test(
                    &[*first_header, post_header],
                    &[header_size],
                );

                for second_header in &EXTESION_KNOWN_IP_NUMBERS {

                    // double header parsing
                    run_test(
                        &[*first_header, *second_header, post_header],
                        &[header_size],
                    );

                    for third_header in &EXTESION_KNOWN_IP_NUMBERS {
                        // tripple header parsing
                        run_test(
                            &[*first_header, *second_header, *third_header, post_header],
                            &[header_size],
                        );
                    }
                }
            }
        }
    }

    proptest! {
        #[test]
        fn write(
            header_size in any::<u8>(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                )
        ) {
            // no extension headers filled
            {
                let exts : Ipv6Extensions = Default::default();
                let mut buffer = Vec::new();
                exts.write(&mut buffer, post_header).unwrap();
                assert_eq!(0, buffer.len());
            }

            /// Run a test with the given ip numbers
            fn run_test(ip_numbers: &[u8], header_sizes: &[u8], post_header: u8) {
                use ValueError::*;

                // setup test header
                let e = ExtensionTestHeaders::new(
                    ip_numbers,
                    header_sizes
                );

                if e.ip_numbers[1..e.ip_numbers.len()-1].iter().any(|&x| x == IPV6_HOP_BY_HOP) {
                    // a hop by hop header that is not at the start triggers an error
                    let mut writer = Vec::with_capacity(e.data.header_len());
                    assert_eq!(
                        e.data.write(&mut writer, e.ip_numbers[0]).unwrap_err().value_error().unwrap(),
                        Ipv6ExtensionHopByHopNotAtStart
                    );
                } else {
                    // normal write
                    {
                        let mut writer = Vec::with_capacity(e.data.header_len());
                        e.data.write(&mut writer, e.ip_numbers[0]).unwrap();

                        if *e.ip_numbers.last().unwrap() != IPV6_HOP_BY_HOP {
                            // decoding if there will be no duplicate hop by hop error
                            // will be triggered
                            let (read, read_next, _) = Ipv6Extensions::from_slice(
                                e.ip_numbers[0],
                                &writer
                            ).unwrap();
                            assert_eq!(e.data, read);
                            assert_eq!(*e.ip_numbers.last().unwrap(), read_next);
                        }
                    }

                    // write error
                    {
                        let mut writer = TestWriter::with_max_size(
                            e.data.header_len() - 1
                        );
                        let err = e.data.write(
                            &mut writer,
                            e.ip_numbers[0]
                        ).unwrap_err();

                        assert_eq!(
                            std::io::ErrorKind::UnexpectedEof,
                            err.io_error().unwrap().kind()
                        );
                    }

                    // missing reference (skip the last header)
                    {
                        let mut missing_ref = e.clone();
                        let missing_ip_number = missing_ref.introduce_missing_ref(post_header);

                        let mut writer = Vec::with_capacity(e.data.header_len());
                        let err = missing_ref.data.write(
                            &mut writer,
                            missing_ref.ip_numbers[0]
                        ).unwrap_err();

                        assert_eq!(
                            err.value_error().unwrap(),
                            Ipv6ExtensionNotReferenced(missing_ip_number)
                        );
                    }
                }
            }

            // test the parsing of different extension header combinations
            for first_header in &EXTESION_KNOWN_IP_NUMBERS {

                // single header parsing
                run_test(
                    &[*first_header, post_header],
                    &[header_size],
                    post_header,
                );

                for second_header in &EXTESION_KNOWN_IP_NUMBERS {

                    // double header parsing
                    run_test(
                        &[*first_header, *second_header, post_header],
                        &[header_size],
                        post_header,
                    );

                    for third_header in &EXTESION_KNOWN_IP_NUMBERS {
                        // tripple header parsing
                        run_test(
                            &[*first_header, *second_header, *third_header, post_header],
                            &[header_size],
                            post_header,
                        );
                    }
                }
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            hop_by_hop_options in ipv6_raw_extension_any(),
            destination_options in ipv6_raw_extension_any(),
            routing in ipv6_raw_extension_any(),
            fragment in ipv6_fragment_any(),
            auth in ip_auth_any(),
            final_destination_options in ipv6_raw_extension_any(),
        ) {
            // None
            {
                let exts : Ipv6Extensions = Default::default();
                assert_eq!(0, exts.header_len());
            }

            // All filled
            {
                let exts = Ipv6Extensions{
                    hop_by_hop_options: Some(hop_by_hop_options.clone()),
                    destination_options: Some(destination_options.clone()),
                    routing: Some(
                        Ipv6RoutingExtensions{
                            routing: routing.clone(),
                            final_destination_options: Some(final_destination_options.clone()),
                        }
                    ),
                    fragment: Some(fragment.clone()),
                    auth: Some(auth.clone()),
                };
                assert_eq!(
                    exts.header_len(),
                    (
                        hop_by_hop_options.header_len() +
                        destination_options.header_len() +
                        routing.header_len() +
                        final_destination_options.header_len() +
                        fragment.header_len() +
                        auth.header_len()
                    )
                );
            }

            // Routing without final destination options
            {
                let exts = Ipv6Extensions{
                    hop_by_hop_options: Some(hop_by_hop_options.clone()),
                    destination_options: Some(destination_options.clone()),
                    routing: Some(
                        Ipv6RoutingExtensions{
                            routing: routing.clone(),
                            final_destination_options: None,
                        }
                    ),
                    fragment: Some(fragment.clone()),
                    auth: Some(auth.clone()),
                };
                assert_eq!(
                    exts.header_len(),
                    (
                        hop_by_hop_options.header_len() +
                        destination_options.header_len() +
                        routing.header_len() +
                        fragment.header_len() +
                        auth.header_len()
                    )
                );
            }
        }
    }

    proptest! {
        #[test]
        fn set_next_headers(
            hop_by_hop_options in ipv6_raw_extension_any(),
            destination_options in ipv6_raw_extension_any(),
            routing in ipv6_raw_extension_any(),
            fragment in ipv6_fragment_any(),
            auth in ip_auth_any(),
            final_destination_options in ipv6_raw_extension_any(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                ),
        ) {
            // none filled
            {
                let mut exts : Ipv6Extensions = Default::default();
                assert_eq!(post_header, exts.set_next_headers(post_header));
                assert!(exts.hop_by_hop_options.is_none());
                assert!(exts.destination_options.is_none());
                assert!(exts.routing.is_none());
                assert!(exts.fragment.is_none());
                assert!(exts.auth.is_none());
            }

            // all filled
            {
                let mut exts = Ipv6Extensions{
                    hop_by_hop_options: Some(hop_by_hop_options.clone()),
                    destination_options: Some(destination_options.clone()),
                    routing: Some(
                        Ipv6RoutingExtensions{
                            routing: routing.clone(),
                            final_destination_options: Some(final_destination_options.clone()),
                        }
                    ),
                    fragment: Some(fragment.clone()),
                    auth: Some(auth.clone()),
                };
                assert_eq!(IPV6_HOP_BY_HOP, exts.set_next_headers(post_header));

                assert_eq!(IPV6_DEST_OPTIONS, exts.hop_by_hop_options.as_ref().unwrap().next_header);
                assert_eq!(IPV6_ROUTE, exts.destination_options.as_ref().unwrap().next_header);
                assert_eq!(IPV6_FRAG, exts.routing.as_ref().unwrap().routing.next_header);
                assert_eq!(AUTH, exts.fragment.as_ref().unwrap().next_header);
                assert_eq!(IPV6_DEST_OPTIONS, exts.auth.as_ref().unwrap().next_header);
                assert_eq!(post_header, exts.routing.as_ref().unwrap().final_destination_options.as_ref().unwrap().next_header);
            }
        }
    }

    proptest! {
        #[test]
        fn next_header(
            header_size in any::<u8>(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                ),)
        {
            // test empty
            {
                let exts : Ipv6Extensions = Default::default();
                assert_eq!(post_header, exts.next_header(post_header).unwrap());
            }

            /// Run a test with the given ip numbers
            fn run_test(ip_numbers: &[u8], header_sizes: &[u8], post_header: u8) {
                use ValueError::*;

                // setup test header
                let e = ExtensionTestHeaders::new(
                    ip_numbers,
                    header_sizes
                );

                if e.ip_numbers[1..e.ip_numbers.len()-1].iter().any(|&x| x == IPV6_HOP_BY_HOP) {
                    // a hop by hop header that is not at the start triggers an error
                    assert_eq!(
                        e.data.next_header(e.ip_numbers[0]).unwrap_err(),
                        Ipv6ExtensionHopByHopNotAtStart
                    );
                } else {
                    // normal header
                    assert_eq!(
                        *e.ip_numbers.last().unwrap(),
                        e.data.next_header(e.ip_numbers[0]).unwrap()
                    );

                    // missing reference (skip the last header)
                    {
                        let mut missing_ref = e.clone();
                        let missing_ip_number = missing_ref.introduce_missing_ref(post_header);
                        assert_eq!(
                            missing_ref.data.next_header(missing_ref.ip_numbers[0]).unwrap_err(),
                            Ipv6ExtensionNotReferenced(missing_ip_number)
                        );
                    }
                }
            }

            // test the parsing of different extension header combinations
            for first_header in &EXTESION_KNOWN_IP_NUMBERS {

                // single header parsing
                run_test(
                    &[*first_header, post_header],
                    &[header_size],
                    post_header,
                );

                for second_header in &EXTESION_KNOWN_IP_NUMBERS {

                    // double header parsing
                    run_test(
                        &[*first_header, *second_header, post_header],
                        &[header_size],
                        post_header,
                    );

                    for third_header in &EXTESION_KNOWN_IP_NUMBERS {
                        // tripple header parsing
                        run_test(
                            &[*first_header, *second_header, *third_header, post_header],
                            &[header_size],
                            post_header,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn is_fragmenting_payload() {
        // empty
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: None,
                destination_options: None,
                routing: None,
                fragment: None,
                auth: None,
            }
            .is_fragmenting_payload()
        );

        // non fragmenting frag header
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: None,
                destination_options: None,
                routing: None,
                fragment: Some(Ipv6FragmentHeader::new(ip_number::UDP, 0, false, 0)),
                auth: None,
            }
            .is_fragmenting_payload()
        );

        // fragmenting frag header
        assert!(Ipv6Extensions {
            hop_by_hop_options: None,
            destination_options: None,
            routing: None,
            fragment: Some(Ipv6FragmentHeader::new(ip_number::UDP, 0, true, 0)),
            auth: None,
        }
        .is_fragmenting_payload());
    }

    #[test]
    fn is_empty() {
        // empty
        assert!(Ipv6Extensions {
            hop_by_hop_options: None,
            destination_options: None,
            routing: None,
            fragment: None,
            auth: None,
        }
        .is_empty());

        // hop_by_hop_options
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: Some(
                    Ipv6RawExtensionHeader::new_raw(ip_number::UDP, &[1, 2, 3, 4, 5, 6]).unwrap()
                ),
                destination_options: None,
                routing: None,
                fragment: None,
                auth: None,
            }
            .is_empty()
        );

        // destination_options
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: None,
                destination_options: Some(
                    Ipv6RawExtensionHeader::new_raw(ip_number::UDP, &[1, 2, 3, 4, 5, 6]).unwrap()
                ),
                routing: None,
                fragment: None,
                auth: None,
            }
            .is_empty()
        );

        // routing
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: None,
                destination_options: None,
                routing: Some(Ipv6RoutingExtensions {
                    routing: Ipv6RawExtensionHeader::new_raw(ip_number::UDP, &[1, 2, 3, 4, 5, 6])
                        .unwrap(),
                    final_destination_options: None,
                }),
                fragment: None,
                auth: None,
            }
            .is_empty()
        );

        // fragment
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: None,
                destination_options: None,
                routing: None,
                fragment: Some(Ipv6FragmentHeader::new(ip_number::UDP, 0, true, 0)),
                auth: None,
            }
            .is_empty()
        );

        // auth
        assert_eq!(
            false,
            Ipv6Extensions {
                hop_by_hop_options: None,
                destination_options: None,
                routing: None,
                fragment: None,
                auth: Some(IpAuthHeader::new(ip_number::UDP, 0, 0, &[]).unwrap()),
            }
            .is_empty()
        );
    }

    #[test]
    fn debug() {
        let a: Ipv6Extensions = Default::default();
        assert_eq!(
            &format!(
                "Ipv6Extensions {{ hop_by_hop_options: {:?}, destination_options: {:?}, routing: {:?}, fragment: {:?}, auth: {:?} }}",
                a.hop_by_hop_options,
                a.destination_options,
                a.routing,
                a.fragment,
                a.auth,
            ),
            &format!("{:?}", a)
        );
    }

    #[test]
    fn clone_eq() {
        let a: Ipv6Extensions = Default::default();
        assert_eq!(a, a.clone());
    }

    #[test]
    fn default() {
        let a: Ipv6Extensions = Default::default();
        assert_eq!(a.hop_by_hop_options, None);
        assert_eq!(a.destination_options, None);
        assert_eq!(a.routing, None);
        assert_eq!(a.fragment, None);
        assert_eq!(a.auth, None);
    }
}

pub mod slice {
    use super::*;

    proptest! {
        #[test]
        fn from_slice(
            header_size in any::<u8>(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                )
        ) {
            // no extension headers filled
            {
                let some_data = [1,2,3,4];
                let actual = Ipv6ExtensionsSlice::from_slice(UDP, &some_data).unwrap();
                assert_eq!(actual.0.is_fragmenting_payload(), false);
                assert_eq!(actual.0.first_header(), None);
                assert_eq!(actual.0.slice().len(), 0);
                assert_eq!(actual.1, UDP);
                assert_eq!(actual.2, &some_data);
            }

            /// Run a test with the given ip numbers
            fn run_test(ip_numbers: &[u8], header_sizes: &[u8]) {
                // setup test payload
                let e = ExtensionTestPayload::new(
                    ip_numbers,
                    header_sizes
                );

                if e.ip_numbers[1..].iter().any(|&x| x == IPV6_HOP_BY_HOP) {
                    // a hop by hop header that is not at the start triggers an error
                    assert_matches!(
                        Ipv6ExtensionsSlice::from_slice(ip_numbers[0], e.slice()).unwrap_err(),
                        ReadError::Ipv6HopByHopHeaderNotAtStart
                    );
                } else {
                    // normal read
                    let (header, next, rest) = Ipv6ExtensionsSlice::from_slice(ip_numbers[0], e.slice()).unwrap();
                    assert_eq!(header.first_header(), Some(ip_numbers[0]));
                    assert_eq!(header.slice(), e.slice());
                    assert_eq!(next, *ip_numbers.last().unwrap());
                    assert_eq!(rest, &e.slice()[e.slice().len()..]);

                    // unexpected end of slice
                    assert_matches!(
                        Ipv6ExtensionsSlice::from_slice(ip_numbers[0], &e.slice()[..e.slice().len() - 1]).unwrap_err(),
                        ReadError::UnexpectedEndOfSlice(_)
                    );
                }
            }

            // test the parsing of different extension header combinations
            for first_header in &EXTESION_KNOWN_IP_NUMBERS {

                // single header parsing
                run_test(
                    &[*first_header, post_header],
                    &[header_size],
                );

                for second_header in &EXTESION_KNOWN_IP_NUMBERS {

                    // double header parsing
                    run_test(
                        &[*first_header, *second_header, post_header],
                        &[header_size],
                    );

                    for third_header in &EXTESION_KNOWN_IP_NUMBERS {
                        // tripple header parsing
                        run_test(
                            &[*first_header, *second_header, *third_header, post_header],
                            &[header_size],
                        );
                    }
                }
            }
        }
    }

    proptest! {
        #[test]
        fn is_fragmenting_payload(
            hop_by_hop_options in ipv6_raw_extension_any(),
            destination_options in ipv6_raw_extension_any(),
            routing in ipv6_raw_extension_any(),
            auth in ip_auth_any(),
            final_destination_options in ipv6_raw_extension_any()
        ) {
            // no fragment header
            {
                let mut exts = Ipv6Extensions{
                    hop_by_hop_options: Some(hop_by_hop_options),
                    destination_options: Some(destination_options),
                    routing: Some(
                        Ipv6RoutingExtensions {
                            routing,
                            final_destination_options: Some(final_destination_options),
                        }
                    ),
                    fragment: None,
                    auth: Some(auth),
                };
                let first_ip_number = exts.set_next_headers(UDP);

                let mut bytes = Vec::with_capacity(exts.header_len());
                exts.write(&mut bytes, first_ip_number).unwrap();

                let (header, _, _) = Ipv6ExtensionsSlice::from_slice(first_ip_number, &bytes).unwrap();
                assert_eq!(false, header.is_fragmenting_payload());
            }

            // different variants of the fragment header with
            // variants that fragment and variants that don't fragment
            const FRAG_VARIANTS : [(bool, Ipv6FragmentHeader);4] = [
                (false, Ipv6FragmentHeader::new(UDP, 0, false, 123)),
                (true, Ipv6FragmentHeader::new(UDP, 2, false, 123)),
                (true, Ipv6FragmentHeader::new(UDP, 0, true, 123)),
                (true, Ipv6FragmentHeader::new(UDP, 3, true, 123)),
            ];

            for (first_expected, first_header) in FRAG_VARIANTS.iter() {
                // single fragment header
                {
                    let bytes = first_header.to_bytes().unwrap();
                    let (header, _, _) = Ipv6ExtensionsSlice::from_slice(IPV6_FRAG, &bytes).unwrap();
                    assert_eq!(*first_expected, header.is_fragmenting_payload());
                }
                // two fragment headers
                for (second_expected, second_header) in FRAG_VARIANTS.iter() {
                    let mut first_mod = first_header.clone();
                    first_mod.next_header = IPV6_FRAG;
                    let mut bytes = Vec::with_capacity(first_mod.header_len() + second_header.header_len());
                    bytes.extend_from_slice(&first_mod.to_bytes().unwrap());
                    bytes.extend_from_slice(&second_header.to_bytes().unwrap());

                    let (header, _, _) = Ipv6ExtensionsSlice::from_slice(IPV6_FRAG, &bytes).unwrap();
                    assert_eq!(
                        *first_expected || *second_expected,
                        header.is_fragmenting_payload()
                    );
                }
            }
        }
    }

    #[test]
    fn is_empty() {
        // empty
        {
            let slice = Ipv6ExtensionsSlice::from_slice(ip_number::UDP, &[])
                .unwrap()
                .0;
            assert!(slice.is_empty());
        }

        // fragment
        {
            let bytes = Ipv6FragmentHeader::new(ip_number::UDP, 0, true, 0)
                .to_bytes()
                .unwrap();
            let slice = Ipv6ExtensionsSlice::from_slice(ip_number::IPV6_FRAG, &bytes)
                .unwrap()
                .0;
            assert_eq!(false, slice.is_empty());
        }
    }

    #[test]
    fn debug() {
        let a: Ipv6ExtensionsSlice = Default::default();
        assert_eq!(
            "Ipv6ExtensionsSlice { first_header: None, fragmented: false, slice: [] }",
            &format!("{:?}", a)
        );
    }

    #[test]
    fn clone_eq() {
        let a: Ipv6ExtensionsSlice = Default::default();
        assert_eq!(a, a.clone());
    }

    #[test]
    fn default() {
        let a: Ipv6ExtensionsSlice = Default::default();
        assert_eq!(a.is_fragmenting_payload(), false);
        assert_eq!(a.first_header(), None);
        assert_eq!(a.slice().len(), 0);
    }
}

pub mod ipv6_routing_extension {
    use super::*;

    #[test]
    fn debug() {
        let a: Ipv6RoutingExtensions = Ipv6RoutingExtensions {
            routing: Ipv6RawExtensionHeader::new_raw(0, &[0; 6]).unwrap(),
            final_destination_options: None,
        };
        assert_eq!(
            &format!(
                "Ipv6RoutingExtensions {{ routing: {:?}, final_destination_options: {:?} }}",
                a.routing, a.final_destination_options,
            ),
            &format!("{:?}", a)
        );
    }

    #[test]
    fn clone_eq() {
        let a: Ipv6RoutingExtensions = Ipv6RoutingExtensions {
            routing: Ipv6RawExtensionHeader::new_raw(0, &[0; 6]).unwrap(),
            final_destination_options: None,
        };
        assert_eq!(a, a.clone());
    }
}

pub mod ipv6_extension_slice {
    use super::*;

    #[test]
    fn debug() {
        use Ipv6ExtensionSlice::*;
        {
            let header = Ipv6RawExtensionHeader::new_raw(UDP, &[1, 2, 3, 4, 5, 6]).unwrap();
            let mut buffer = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            let slice = Ipv6RawExtensionHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                format!("HopByHop({:?})", slice),
                format!("{:?}", HopByHop(slice.clone()))
            );
            assert_eq!(
                format!("Routing({:?})", slice),
                format!("{:?}", Routing(slice.clone()))
            );
            assert_eq!(
                format!("DestinationOptions({:?})", slice),
                format!("{:?}", DestinationOptions(slice.clone()))
            );
        }
        {
            let header = Ipv6FragmentHeader::new(UDP, 1, true, 2);
            let mut buffer = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            let slice = Ipv6FragmentHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                format!("Fragment({:?})", slice),
                format!("{:?}", Fragment(slice))
            );
        }
        {
            let header = IpAuthHeader::new(UDP, 1, 2, &[1, 2, 3, 4]).unwrap();
            let mut buffer = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();
            let slice = IpAuthHeaderSlice::from_slice(&buffer).unwrap();
            assert_eq!(
                format!("Authentication({:?})", slice),
                format!("{:?}", Authentication(slice.clone()))
            );
        }
    }

    #[test]
    fn clone_eq() {
        use Ipv6ExtensionSlice::*;

        let header = Ipv6RawExtensionHeader::new_raw(UDP, &[1, 2, 3, 4, 5, 6]).unwrap();
        let mut buffer = Vec::with_capacity(header.header_len());
        header.write(&mut buffer).unwrap();
        let slice = Ipv6RawExtensionHeaderSlice::from_slice(&buffer).unwrap();

        let hop = HopByHop(slice.clone());
        assert_eq!(hop.clone(), hop.clone());

        let route = Routing(slice.clone());
        assert_eq!(route.clone(), route.clone());

        assert_ne!(route, hop);
    }
}

pub mod slice_iter {
    use super::*;

    #[test]
    fn into_iter() {
        let a: Ipv6ExtensionsSlice = Default::default();
        let mut iter = a.into_iter();
        assert_eq!(None, iter.next());
    }

    proptest! {
        #[test]
        fn next(
            header_size in any::<u8>(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                )
        ) {
            /// Run a test with the given ip numbers
            fn run_test(ip_numbers: &[u8], header_sizes: &[u8]) {
                // setup test payload
                let e = ExtensionTestPayload::new(
                    ip_numbers,
                    header_sizes
                );

                // a hop by hop header that is not at the start triggers an error
                if false == e.ip_numbers[1..].iter().any(|&x| x == IPV6_HOP_BY_HOP) {
                    // normal read
                    let (header, _, _) = Ipv6ExtensionsSlice::from_slice(ip_numbers[0], e.slice()).unwrap();
                    let mut iter = header.into_iter();
                    let mut slice = e.slice();

                    // go through all expected headers
                    for i in 0..e.ip_numbers.len() - 1 {
                        use Ipv6ExtensionSlice::*;

                        // iterate and check all results
                        let next = iter.next().unwrap();
                        match e.ip_numbers[i] {
                            IPV6_HOP_BY_HOP => {
                                let header = Ipv6RawExtensionHeaderSlice::from_slice(slice).unwrap();
                                assert_eq!(next, HopByHop(header.clone()));
                                slice = &slice[header.slice().len()..];
                            },
                            IPV6_ROUTE => {
                                let header = Ipv6RawExtensionHeaderSlice::from_slice(slice).unwrap();
                                assert_eq!(next, Routing(header.clone()));
                                slice = &slice[header.slice().len()..];
                            },
                            IPV6_DEST_OPTIONS => {
                                let header = Ipv6RawExtensionHeaderSlice::from_slice(slice).unwrap();
                                assert_eq!(next, DestinationOptions(header.clone()));
                                slice = &slice[header.slice().len()..];
                            }
                            IPV6_FRAG => {
                                let header = Ipv6FragmentHeaderSlice::from_slice(slice).unwrap();
                                assert_eq!(next, Fragment(header.clone()));
                                slice = &slice[header.slice().len()..];
                            },
                            AUTH => {
                                let header = IpAuthHeaderSlice::from_slice(slice).unwrap();
                                assert_eq!(next, Authentication(header.clone()));
                                slice = &slice[header.slice().len()..];
                            },
                            _ => unreachable!()
                        }
                    }

                    // expect that all headers have been visited
                    assert_eq!(None, iter.next());
                }
            }

            // test the parsing of different extension header combinations
            for first_header in &EXTESION_KNOWN_IP_NUMBERS {

                // single header parsing
                run_test(
                    &[*first_header, post_header],
                    &[header_size],
                );

                for second_header in &EXTESION_KNOWN_IP_NUMBERS {

                    // double header parsing
                    run_test(
                        &[*first_header, *second_header, post_header],
                        &[header_size],
                    );

                    for third_header in &EXTESION_KNOWN_IP_NUMBERS {
                        // tripple header parsing
                        run_test(
                            &[*first_header, *second_header, *third_header, post_header],
                            &[header_size],
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn debug() {
        let a: Ipv6ExtensionSliceIter = Default::default();
        assert_eq!(
            "Ipv6ExtensionSliceIter { next_header: 59, rest: [] }",
            &format!("{:?}", a)
        );
    }

    #[test]
    fn clone_eq() {
        let a: Ipv6ExtensionSliceIter = Default::default();
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn default() {
        let mut a: Ipv6ExtensionSliceIter = Default::default();
        assert_eq!(None, a.next());
    }
}
