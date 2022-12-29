use crate::*;

/// IPv6 header according to rfc8200.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    /// If non 0 serves as a hint to router and switches with multiple outbound paths that these packets should stay on the same path, so that they will not be reordered.
    pub flow_label: u32,
    ///The length of the payload and extension headers in bytes (0 in case of jumbo payloads).
    pub payload_length: u16,
    /// IP protocol number specifying the next header or transport layer protocol.
    ///
    /// See [IpNumber] or [ip_number] for a definitions of ids.
    pub next_header: u8,
    /// The number of hops the packet can take before it is discarded.
    pub hop_limit: u8,
    /// IPv6 source address
    pub source: [u8; 16],
    /// IPv6 destination address
    pub destination: [u8; 16],
}

impl Ipv6Header {
    /// Serialized size of an IPv6 header in bytes/octets.
    pub const LEN: usize = 40;

    #[deprecated(since = "0.14.0", note = "Use `Ipv6Header::LEN` instead")]
    pub const SERIALIZED_SIZE: usize = Ipv6Header::LEN;

    /// Renamed to `Ipv6Header::from_slice`
    #[deprecated(since = "0.10.1", note = "Renamed to `Ipv6Header::from_slice`")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(Ipv6Header, &[u8]), ReadError> {
        Ipv6Header::from_slice(slice)
    }

    /// Read an Ipv6Header from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(Ipv6Header, &[u8]), ReadError> {
        Ok((
            Ipv6HeaderSlice::from_slice(slice)?.to_header(),
            &slice[Ipv6Header::LEN..],
        ))
    }

    ///Reads an IPv6 header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T) -> Result<Ipv6Header, ReadError> {
        let mut value: [u8; 1] = [0; 1];
        reader.read_exact(&mut value)?;
        let version = value[0] >> 4;
        if 6 != version {
            return Err(ReadError::Ipv6UnexpectedVersion(version));
        }
        match Ipv6Header::read_without_version(reader, value[0] & 0xf) {
            Ok(value) => Ok(value),
            Err(err) => Err(ReadError::IoError(err)),
        }
    }

    ///Reads an IPv6 header assuming the version & flow_label field have already been read.
    pub fn read_without_version<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
        version_rest: u8,
    ) -> Result<Ipv6Header, io::Error> {
        let mut buffer: [u8; 8 + 32 - 1] = [0; 8 + 32 - 1];
        reader.read_exact(&mut buffer[..])?;

        Ok(Ipv6Header {
            traffic_class: (version_rest << 4) | (buffer[0] >> 4),
            flow_label: u32::from_be_bytes([0, buffer[0] & 0xf, buffer[1], buffer[2]]),
            payload_length: u16::from_be_bytes([buffer[3], buffer[4]]),
            next_header: buffer[5],
            hop_limit: buffer[6],
            #[rustfmt::skip]
            source: [
                buffer[7],   buffer[8],  buffer[9], buffer[10],
                buffer[11], buffer[12], buffer[13], buffer[14],
                buffer[15], buffer[16], buffer[17], buffer[18],
                buffer[19], buffer[20], buffer[21], buffer[22],
            ],
            #[rustfmt::skip]
            destination: [
                buffer[23], buffer[24], buffer[25], buffer[26],
                buffer[27], buffer[28], buffer[29], buffer[30],
                buffer[31], buffer[32], buffer[33], buffer[34],
                buffer[35], buffer[36], buffer[37], buffer[38],
            ],
        })
    }

    ///Takes a slice and skips an ipv6 header extensions and returns the next_header ip number & the slice past the header.
    pub fn skip_header_extension_in_slice(
        slice: &[u8],
        next_header: u8,
    ) -> Result<(u8, &[u8]), ReadError> {
        use crate::ip_number::*;

        if slice.len() >= 2 {
            //determine the length
            let len = match next_header {
                IPV6_FRAG => 8,
                AUTH => (usize::from(slice[1]) + 2) * 4,
                IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => {
                    (usize::from(slice[1]) + 1) * 8
                }
                // not a ipv6 header extension that can be skipped
                _ => return Ok((next_header, slice)),
            };

            if slice.len() < len {
                Err(ReadError::UnexpectedEndOfSlice(
                    err::UnexpectedEndOfSliceError {
                        expected_min_len: len,
                        actual_len: slice.len(),
                        layer: err::Layer::Ipv6ExtHeader,
                    },
                ))
            } else {
                Ok((slice[0], &slice[len..]))
            }
        } else {
            Err(ReadError::UnexpectedEndOfSlice(
                err::UnexpectedEndOfSliceError {
                    expected_min_len: 2,
                    actual_len: slice.len(),
                    layer: err::Layer::Ipv6ExtHeader,
                },
            ))
        }
    }

    /// Returns true if the given ip protocol number is a skippable header extension.
    ///
    /// A skippable header extension is an extension header for which it is known how
    /// to determine the protocol number of the following header as well as how many
    /// octets have to be skipped to reach the start of the following header.
    pub fn is_skippable_header_extension(ip_protocol_number: u8) -> bool {
        use crate::ip_number::*;
        //Note: EncapsulatingSecurityPayload & ExperimentalAndTesting0 can not be skipped
        matches!(
            ip_protocol_number,
            IPV6_HOP_BY_HOP
                | IPV6_ROUTE
                | IPV6_FRAG
                | AUTH
                | IPV6_DEST_OPTIONS
                | MOBILITY
                | HIP
                | SHIM6
        )
    }

    ///Takes a slice & ip protocol number (identifying the first header type) and returns next_header id & the slice past after all ipv6 header extensions.
    pub fn skip_all_header_extensions_in_slice(
        slice: &[u8],
        next_header: u8,
    ) -> Result<(u8, &[u8]), ReadError> {
        let mut next_header = next_header;
        let mut rest = slice;

        loop {
            let (n_id, n_rest) = Ipv6Header::skip_header_extension_in_slice(rest, next_header)?;

            if n_rest.len() == rest.len() {
                return Ok((next_header, rest));
            } else {
                next_header = n_id;
                rest = n_rest;
            }
        }
    }

    ///Skips the ipv6 header extension and returns the next ip protocol number
    pub fn skip_header_extension<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
        next_header: u8,
    ) -> Result<u8, io::Error> {
        use crate::ip_number::*;

        let (next_header, rest_length) = match next_header {
            IPV6_FRAG => {
                let mut buf = [0; 1];
                reader.read_exact(&mut buf)?;
                (buf[0], 7)
            }
            AUTH => {
                let mut buf = [0; 2];
                reader.read_exact(&mut buf)?;
                (buf[0], i64::from(buf[1]) * 4 + 6)
            }
            IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_DEST_OPTIONS | MOBILITY | HIP | SHIM6 => {
                let mut buf = [0; 2];
                reader.read_exact(&mut buf)?;
                (buf[0], i64::from(buf[1]) * 8 + 6)
            }
            // not a ipv6 header extension that can be skipped
            _ => return Ok(next_header),
        };

        //Sadly seek does not return an error if the seek could not be fullfilled.
        //Some implementations do not even truncate the returned position to the
        //last valid one. std::io::Cursor for example just moves the position
        //over the border of the given slice (e.g. returns position 15 even when
        //the given slice contains only 1 element).
        //The only option, to detect that we are in an invalid state, is to move the
        //seek offset to one byte before the end and then execute a normal read to
        //trigger an error.
        reader.seek(io::SeekFrom::Current(rest_length - 1))?;
        {
            let mut buf = [0; 1];
            reader.read_exact(&mut buf)?;
        }
        Ok(next_header)
    }

    ///Skips all ipv6 header extensions and returns the next ip protocol number
    pub fn skip_all_header_extensions<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
        next_header: u8,
    ) -> Result<u8, ReadError> {
        let mut next_header = next_header;

        loop {
            if Ipv6Header::is_skippable_header_extension(next_header) {
                next_header = Ipv6Header::skip_header_extension(reader, next_header)?;
            } else {
                return Ok(next_header);
            }
        }
    }

    ///Writes a given IPv6 header to the current position.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()?)?;
        Ok(())
    }

    /// Return the ipv6 source address as an std::net::Ipv6Addr
    #[inline]
    pub fn source_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.source)
    }

    /// Return the ipv6 destination address as an std::net::Ipv6Addr
    #[inline]
    pub fn destination_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.destination)
    }

    /// Length of the serialized header in bytes.
    ///
    /// The function always returns the constant Ipv6Header::LEN
    /// and exists to keep the methods consistent with other headers.
    #[inline]
    pub fn header_len(&self) -> usize {
        Ipv6Header::LEN
    }

    /// Sets the field total_length based on the size of the payload and the options. Returns an error if the payload is too big to fit.
    pub fn set_payload_length(&mut self, size: usize) -> Result<(), ValueError> {
        //check that the total length fits into the field
        const MAX_PAYLOAD_LENGTH: usize = std::u16::MAX as usize;
        if MAX_PAYLOAD_LENGTH < size {
            return Err(ValueError::Ipv6PayloadLengthTooLarge(size));
        }

        self.payload_length = size as u16;
        Ok(())
    }

    /// Returns the serialized form of the header as a statically
    /// sized byte array.
    #[rustfmt::skip]
    pub fn to_bytes(&self) -> Result<[u8;Ipv6Header::LEN], ValueError> {
        use crate::ErrorField::*;
        fn max_check_u32(value: u32, max: u32, field: ErrorField) -> Result<(), ValueError> {
            if value <= max {
                Ok(())
            } else {
                Err(ValueError::U32TooLarge {
                    value,
                    max,
                    field,
                })
            }
        }

        // serialize header
        let flow_label_be = self.flow_label.to_be_bytes();
        let payload_len_be = self.payload_length.to_be_bytes();

        // check value ranges
        max_check_u32(self.flow_label, 0xfffff, Ipv6FlowLabel)?;

        Ok([
            (6 << 4) | (self.traffic_class >> 4),
            (self.traffic_class << 4) | flow_label_be[1],
            flow_label_be[2],
            flow_label_be[3],
            payload_len_be[0],
            payload_len_be[1],
            self.next_header,
            self.hop_limit,
            self.source[0], self.source[1], self.source[2], self.source[3],
            self.source[4], self.source[5], self.source[6], self.source[7],
            self.source[8], self.source[9], self.source[10], self.source[11],
            self.source[12], self.source[13], self.source[14], self.source[15],
            self.destination[0], self.destination[1], self.destination[2], self.destination[3],
            self.destination[4], self.destination[5], self.destination[6], self.destination[7],
            self.destination[8], self.destination[9], self.destination[10], self.destination[11],
            self.destination[12], self.destination[13], self.destination[14], self.destination[15],
        ])
    }
}

#[cfg(test)]
mod test {
    use crate::{*, test_gens::*, ip_number::*};
    use proptest::*;
    use std::io::Cursor;

    #[test]
    fn default() {
        let header: Ipv6Header = Default::default();
        assert_eq!(0, header.traffic_class);
        assert_eq!(0, header.flow_label);
        assert_eq!(0, header.payload_length);
        assert_eq!(0, header.next_header);
        assert_eq!(0, header.hop_limit);
        assert_eq!([0u8;16], header.source);
        assert_eq!([0u8;16], header.destination);
    }

    #[test]
    fn debug() {
        let header: Ipv6Header = Default::default();
        assert_eq!(
            format!("{:?}", header),
            format!(
                "Ipv6Header {{ traffic_class: {}, flow_label: {}, payload_length: {}, next_header: {}, hop_limit: {}, source: {:?}, destination: {:?} }}",
                header.traffic_class,
                header.flow_label,
                header.payload_length,
                header.next_header,
                header.hop_limit,
                header.source,
                header.destination
            )
        );
    }

    proptest!{
        #[test]
        fn clone_eq(header in ipv6_any()) {
            assert_eq!(header.clone(), header);
        }
    }

    proptest!{
        #[test]
        fn read_from_slice(header in ipv6_any()) {
            todo!()
        }
    }

    proptest!{
        #[test]
        fn from_slice(header in ipv6_any()) {
            todo!()
        }
    }

    proptest!{
        #[test]
        fn read(header in ipv6_any()) {
            // ok read
            {
                let bytes = header.to_bytes().unwrap();
                let mut cursor = Cursor::new(&bytes[..]);
                let actual = Ipv6Header::read(&mut cursor).unwrap();
                assert_eq!(header, actual);
                assert_eq!(cursor.position(), bytes.len() as u64);
            }

            // version error
            // TODO

            // io error
            {
                let bytes = header.to_bytes().unwrap();
                for len in 0..bytes.len() {
                    let mut cursor = Cursor::new(&bytes[..len]);
                    assert!(Ipv6Header::read(&mut cursor).is_err());
                }
            }
        }
    }

    proptest!{
        #[test]
        fn read_without_version(header in ipv6_any()) {
            // ok read
            {
                let bytes = header.to_bytes().unwrap();
                let mut cursor = Cursor::new(&bytes[1..]);
                let actual = Ipv6Header::read_without_version(&mut cursor, bytes[0] & 0xf).unwrap();
                assert_eq!(header, actual);
                assert_eq!(cursor.position(), bytes.len() as u64 - 1);
            }

            // io error
            {
                let bytes = header.to_bytes().unwrap();
                for len in 1..bytes.len() {
                    let mut cursor = Cursor::new(&bytes[1..len]);
                    assert!(Ipv6Header::read_without_version(&mut cursor, bytes[0] & 0xf).is_err());
                }
            }
        }
    }

    proptest!{
        #[test]
        fn skip_header_extension_in_slice(header in ipv6_any()) {
            todo!()
        }
    }

    #[test]
    fn is_skippable_header_extension() {
        use crate::ip_number::*;

        for i in 0..0xffu8 {
            let expected = match i {
                IPV6_HOP_BY_HOP | IPV6_ROUTE | IPV6_FRAG | AUTH | IPV6_DEST_OPTIONS | MOBILITY
                | HIP | SHIM6 => true,
                _ => false,
            };
            assert_eq!(expected, Ipv6Header::is_skippable_header_extension(i));
        }
    }

    proptest!{
        #[test]
        fn skip_all_header_extensions_in_slice(header in ipv6_any()) {
            todo!()
        }
    }

    #[test]
    fn skip_header_extension() {
        use crate::ip_number::*;
        {
            let buffer: [u8; 8] = [0; 8];
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(
                Ipv6Header::skip_header_extension(&mut cursor, ICMP).unwrap(),
                ICMP
            );
            assert_eq!(0, cursor.position());
        }
        {
            let buffer: [u8; 8] = [0; 8];
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(
                Ipv6Header::skip_header_extension(&mut cursor, IPV6_HOP_BY_HOP).unwrap(),
                0
            );
            assert_eq!(8, cursor.position());
        }
        {
            #[rustfmt::skip]
            let buffer: [u8; 8 * 3] = [
                4, 2, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(
                Ipv6Header::skip_header_extension(&mut cursor, IPV6_ROUTE).unwrap(),
                4
            );
            assert_eq!(8 * 3, cursor.position());
        }
        {
            //fragmentation header has a fixed size -> the 2 should be ignored
            #[rustfmt::skip]
            let buffer: [u8; 8 * 3] = [
                4, 2, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let mut cursor = Cursor::new(&buffer);
            assert_eq!(
                Ipv6Header::skip_header_extension(&mut cursor, IPV6_FRAG).unwrap(),
                4
            );
            assert_eq!(8, cursor.position());
        }
    }

    proptest!{
        #[test]
        fn skip_all_extensions(
            exts in ipv6_extensions_with(UDP)
        ) {

        }
    }
    /*
        use crate::io::Cursor;
        //extension header values
        use crate::ip_number::*;
        //based on RFC 8200 4.1. Extension Header Order
        // & IANA https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
        const EXTENSION_IDS: [u8; 9] = [
            IPV6_HOP_BY_HOP,
            IPV6_DEST_OPTIONS,
            IPV6_ROUTE,
            IPV6_FRAG,
            AUTH,
            IPV6_DEST_OPTIONS,
            MOBILITY,
            HIP,
            SHIM6,
        ];
    
        // note the following ids are extensions but are not skippable:
        //
        // - EncapsulatingSecurityPayload
        // - ExperimentalAndTesting0
        // - ExperimentalAndTesting0
    
        //no & single skipping
        {
            #[rustfmt::skip]
            let buffer: [u8; 8 * 4] = [
                UDP, 2, 0, 0, 0, 0, 0, 0, //set next to udp
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 2, 3, 4, 5, 6, 7, 8,
            ];
    
            for i in 0..=u8::max_value() {
                let mut cursor = Cursor::new(&buffer);
                let reader_result = Ipv6Header::skip_all_header_extensions(&mut cursor, i);
                let slice_result = Ipv6Header::skip_all_header_extensions_in_slice(&buffer, i).unwrap();
                match EXTENSION_IDS.iter().find(|&&x| x == i) {
                    Some(_) => {
                        //ipv6 header extension -> expect skip
                        assert_eq!(reader_result.unwrap(), UDP);
                        assert_eq!(slice_result.0, UDP);
    
                        let len = if i == IPV6_FRAG {
                            //fragmentation header has a fixed size
                            8
                        } else if i == AUTH {
                            //authentification headers use 4-octets to describe the length
                            8 + 2 * 4
                        } else {
                            buffer.len() - 8
                        };
                        assert_eq!(len, cursor.position() as usize);
                        assert_eq!(&buffer[len..], slice_result.1);
                    }
                    None => {
                        //non ipv6 header expect no read movement and direct return
                        assert_eq!(reader_result.unwrap(), i);
                        assert_eq!(0, cursor.position());
    
                        assert_eq!(i, slice_result.0);
                        assert_eq!(&buffer, slice_result.1);
                    }
                }
            }
        }
    
        //creates an buffer filled with extension headers with the given ids
        fn create_buffer(ids: &[u8]) -> Vec<u8> {
            use crate::ip_number::*;
    
            let mut prev: u8 = ids[0];
            let mut result = Vec::with_capacity(ids.len() * 8 * 4);
            for (index, value) in ids[1..].iter().enumerate() {
                let len: u8 = if prev == IPV6_FRAG {
                    0
                } else {
                    (index % 3) as u8
                };
    
                //write first line
                result.extend_from_slice(&[*value, len, 0, 0, 0, 0, 0, 0]);
    
                //fill rest with dummy data
                for _ in 0..len {
                    result.extend_from_slice(if prev == AUTH {
                        // authentification headers interpret the length as in 4-octets
                        &[0; 4]
                    } else {
                        // all other headers (excluding the fragmentation header) interpret the length as in 8-octets
                        &[0; 8]
                    });
                }
    
                //cache prev
                prev = *value;
            }
    
            //add some dummy data to the end (useful for checking that the returned slice are correct)
            result.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    
            result
        }
    
        //skip maximum number
        {
            let ids = {
                let mut ids = Vec::with_capacity(IPV6_MAX_NUM_HEADER_EXTENSIONS);
                while ids.len() < IPV6_MAX_NUM_HEADER_EXTENSIONS {
                    // fill with extension headers until filled
                    ids.extend_from_slice(
                        &EXTENSION_IDS[..std::cmp::min(
                            EXTENSION_IDS.len(),
                            IPV6_MAX_NUM_HEADER_EXTENSIONS - ids.len(),
                        )],
                    );
                }
                ids.push(UDP);
                ids
            };
            let buffer = create_buffer(&ids);
    
            //reader
            {
                let mut cursor = Cursor::new(&buffer);
                let result = Ipv6Header::skip_all_header_extensions(&mut cursor, ids[0]);
                assert_eq!(result.unwrap(), UDP);
                assert_eq!(buffer.len() - 8, cursor.position() as usize);
            }
            //slice
            {
                let result = Ipv6Header::skip_all_header_extensions_in_slice(&buffer, ids[0]).unwrap();
                assert_eq!(result.0, UDP);
                assert_eq!(result.1, &buffer[buffer.len() - 8..]);
            }
        }
        //trigger missing unexpected eof
        {
            let ids = {
                let mut ids = Vec::with_capacity(EXTENSION_IDS.len() + 1);
                ids.extend_from_slice(&EXTENSION_IDS);
                ids.push(UDP);
                ids
            };
            let buffer = create_buffer(&ids);
    
            // check for all offsets
            for len in 0..buffer.len() - 8 {
                // minus 8 for the dummy data
                //reader
                {
                    let mut cursor = TestReader::new(&buffer[..len]);
                    let result = Ipv6Header::skip_all_header_extensions(&mut cursor, ids[0]);
                    assert_matches!(result, Err(ReadError::IoError(_)));
                }
                //slice
                {
                    let result =
                        Ipv6Header::skip_all_header_extensions_in_slice(&buffer[..len], ids[0]);
                    assert_matches!(result, Err(ReadError::UnexpectedEndOfSlice(_)));
                }
            }
        }
    }*/

    proptest!{
        #[test]
        fn write(header in ipv6_any()) {
            todo!()
        }
    }

    proptest!{
        #[test]
        fn source_addr(header in ipv6_any()) {
            assert_eq!(
                header.source_addr().octets(),
                header.source
            );
        }
    }

    proptest!{
        #[test]
        fn destination_addr(header in ipv6_any()) {
            assert_eq!(
                header.destination_addr().octets(),
                header.destination
            );
        }
    }

    proptest!{
        #[test]
        fn to_bytes(
            header in ipv6_any(),
            bad_flow_label in 0b1_0000_0000_0000_0000_0000..=u32::MAX
        ) {
            // ok case
            {
                let bytes = header.to_bytes().unwrap();
                assert_eq!(
                    Ipv6Header::from_slice(&bytes).unwrap().0,
                    header
                );
            }

            // flow label error
            {
                let mut bad_header = header.clone();
                bad_header.flow_label = bad_flow_label;
                let err = bad_header.to_bytes().unwrap_err();
                assert_eq!(
                    err,
                    ValueError::U32TooLarge {
                        value: bad_flow_label,
                        max: 0b1111_1111_1111_1111_1111,
                        field: ErrorField::Ipv6FlowLabel,
                    }
                );
            }
        }
    }

}