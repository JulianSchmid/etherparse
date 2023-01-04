use super::super::*;

///Internet protocol headers version 4 & 6
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum IpHeader {
    Version4(Ipv4Header, Ipv4Extensions),
    Version6(Ipv6Header, Ipv6Extensions),
}

impl IpHeader {

    /// Maximum summed up length of all extension headers in bytes/octets.
    pub const MAX_LEN: usize = Ipv6Header::LEN + Ipv6Extensions::MAX_LEN;

    /// Renamed to `IpHeader::from_slice`
    #[deprecated(since = "0.10.1", note = "Renamed to `IpHeader::from_slice`")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(IpHeader, u8, &[u8]), ReadError> {
        IpHeader::from_slice(slice)
    }

    /// Read an IpvHeader from a slice and return the header & unused parts of the slice.
    pub fn from_slice(slice: &[u8]) -> Result<(IpHeader, u8, &[u8]), ReadError> {
        if slice.is_empty() {
            use crate::ReadError::SliceLen as U;
            Err(U(err::SliceLenError {
                expected_min_len: 1,
                actual_len: slice.len(),
                layer: err::Layer::IpHeader,
            }))
        } else {
            match slice[0] >> 4 {
                4 => {
                    let (header, rest) = Ipv4Header::from_slice(slice).map_err(|err| {
                        use err::ipv4::HeaderSliceError as I;
                        use ReadError as O;
                        match err {
                            I::SliceLen(err) => O::SliceLen(err),
                            I::Content(err) => O::Ipv4Header(err),
                        }
                    })?;
                    Ipv4Extensions::from_slice(header.protocol, rest)
                        .map(|(ext, next_protocol, rest)| {
                            (IpHeader::Version4(header, ext), next_protocol, rest)
                        })
                        .map_err(|err| {
                            use err::ip_auth::HeaderSliceError as I;
                            use ReadError as O;
                            match err {
                                I::SliceLen(err) => O::SliceLen(err),
                                I::Content(err) => O::IpAuthHeader(err),
                            }
                        })
                }
                6 => {
                    if slice.len() < Ipv6Header::LEN {
                        use ReadError::SliceLen;
                        return Err(SliceLen(err::SliceLenError {
                            expected_min_len: Ipv6Header::LEN,
                            actual_len: slice.len(),
                            layer: err::Layer::Ipv6Header,
                        }));
                    }
                    let header = {
                        // SAFETY:
                        // This is safe as the slice length is checked to be
                        // at least Ipv6Header::LEN (40) befpre this code block.
                        unsafe {
                            Ipv6HeaderSlice::from_slice_unchecked(core::slice::from_raw_parts(
                                slice.as_ptr(),
                                Ipv6Header::LEN,
                            ))
                        }
                    }
                    .to_header();
                    let rest = &slice[Ipv6Header::LEN..];
                    Ipv6Extensions::from_slice(header.next_header, rest).map(
                        |(ext, next_protocol, rest)| {
                            (IpHeader::Version6(header, ext), next_protocol, rest)
                        },
                    ).map_err(|err| {
                        use err::ipv6_exts::HeaderSliceError as I;
                        use ReadError as O;
                        match err {
                            I::SliceLen(err) => O::SliceLen(err),
                            I::Content(err) => O::Ipv6ExtsHeader(err),
                        }
                    })
                }
                version => Err(ReadError::IpUnsupportedVersion(version)),
            }
        }
    }

    ///Reads an IP (v4 or v6) header from the current position.
    pub fn read<T: io::Read + io::Seek + Sized>(
        reader: &mut T,
    ) -> Result<(IpHeader, u8), ReadError> {
        let value = {
            let mut buf = [0; 1];
            reader.read_exact(&mut buf)?;
            buf[0]
        };
        match value >> 4 {
            4 => {
                let header =
                    Ipv4Header::read_without_version(reader, value & 0xf).map_err(|err| {
                        use err::ipv4::HeaderReadError::*;
                        match err {
                            Io(err) => ReadError::IoError(err),
                            Content(err) => ReadError::Ipv4Header(err),
                        }
                    })?;
                Ipv4Extensions::read(reader, header.protocol)
                    .map(|(ext, next)| (IpHeader::Version4(header, ext), next))
                    .map_err(|err| {
                        use err::ip_auth::HeaderReadError as I;
                        use ReadError as O;
                        match err {
                            I::Io(err) => O::IoError(err),
                            I::Content(err) => O::IpAuthHeader(err),
                        }
                    })
            }
            6 => {
                let header = Ipv6Header::read_without_version(reader, value & 0xf)?;
                Ipv6Extensions::read(reader, header.next_header)
                    .map(|(ext, next)| (IpHeader::Version6(header, ext), next))
                    .map_err(|err| {
                        use err::ipv6_exts::HeaderReadError as I;
                        use ReadError as O;
                        match err {
                            I::Io(err) => O::IoError(err),
                            I::Content(err) => O::Ipv6ExtsHeader(err),
                        }
                    })
            }
            version => Err(ReadError::IpUnsupportedVersion(version)),
        }
    }

    ///Writes an IP (v4 or v6) header to the current position
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        use crate::IpHeader::*;
        match *self {
            Version4(ref header, ref extensions) => {
                header.write(writer)?;
                extensions.write(writer, header.protocol)
            }
            Version6(ref header, ref extensions) => {
                header.write(writer)?;
                extensions.write(writer, header.next_header)
            }
        }
    }

    /// Returns the size when the ip header & extensions are serialized
    pub fn header_len(&self) -> usize {
        use crate::IpHeader::*;
        match *self {
            Version4(ref header, ref extensions) => header.header_len() + extensions.header_len(),
            Version6(_, ref extensions) => Ipv6Header::LEN + extensions.header_len(),
        }
    }

    /// Returns the last next header number following the ip header
    /// and header extensions.
    pub fn next_header(&self) -> Result<u8, ValueError> {
        use crate::IpHeader::*;
        match *self {
            Version4(ref header, ref extensions) => extensions.next_header(header.protocol),
            Version6(ref header, ref extensions) => extensions.next_header(header.next_header),
        }
    }

    /// Sets all the next_header fields in the ipv4 & ipv6 header
    /// as well as in all extension headers and returns the ether
    /// type number.
    ///
    /// The given number will be set as the last "next_header" or
    /// protocol number.
    pub fn set_next_headers(&mut self, last_next_header: u8) -> EtherType {
        use IpHeader::*;
        match self {
            Version4(ref mut header, ref mut extensions) => {
                header.protocol = extensions.set_next_headers(last_next_header);
                EtherType::Ipv4
            }
            Version6(ref mut header, ref mut extensions) => {
                header.next_header = extensions.set_next_headers(last_next_header);
                EtherType::Ipv6
            }
        }
    }

    /// Tries to set the length field in the ip header given the length of data
    /// after the ip header and extension header(s).
    ///
    /// If the payload length is too large to be stored in the length fields
    /// of the ip header an error is returned.
    ///
    /// Note that this function will automatically add the length of the extension
    /// headers is they are present.
    pub fn set_payload_len(&mut self, len: usize) -> Result<(), ValueError> {
        use crate::ValueError::*;
        match self {
            IpHeader::Version4(ipv4_hdr, exts) => {
                if let Some(complete_len) = len.checked_add(exts.header_len()) {
                    ipv4_hdr.set_payload_len(complete_len)
                } else {
                    Err(Ipv4PayloadLengthTooLarge(len))
                }
            }
            IpHeader::Version6(ipv6_hdr, exts) => {
                if let Some(complete_len) = len.checked_add(exts.header_len()) {
                    ipv6_hdr.set_payload_length(complete_len)
                } else {
                    Err(Ipv6PayloadLengthTooLarge(len))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{*, ip_number::*, test_gens::*};
    use proptest::prelude::*;
    use std::io::Cursor;

    const EXTESION_KNOWN_IP_NUMBERS: [u8; 5] = [
        AUTH,
        IPV6_DEST_OPTIONS,
        IPV6_HOP_BY_HOP,
        IPV6_FRAG,
        IPV6_ROUTE,
    ];

    fn combine_v4(v4: &Ipv4Header, ext: &Ipv4Extensions) -> IpHeader {
        IpHeader::Version4(
            {
                let mut v4 = v4.clone();
                v4.protocol = if ext.auth.is_some() { AUTH } else { UDP };
                v4.header_checksum = v4.calc_header_checksum().unwrap();
                v4
            },
            ext.clone(),
        )
    }

    fn combine_v6(v6: &Ipv6Header, ext: &Ipv6Extensions) -> IpHeader {
        let (ext, next_header) = {
            let mut ext = ext.clone();
            let next_header = ext.set_next_headers(UDP);
            (ext, next_header)
        };
        IpHeader::Version6(
            {
                let mut v6 = v6.clone();
                v6.next_header = next_header;
                v6
            },
            ext,
        )
    }

    proptest! {
        #[test]
        fn debug(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
        ) {
            assert_eq!(
                format!(
                    "Version4({:?}, {:?})",
                    v4,
                    v4_exts
                ),
                format!("{:?}", IpHeader::Version4(v4, v4_exts))
            );
            assert_eq!(
                format!(
                    "Version6({:?}, {:?})",
                    v6,
                    v6_exts
                ),
                format!("{:?}", IpHeader::Version6(v6, v6_exts))
            );
        }
    }

    proptest! {
        #[test]
        fn clone_eq(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
        ) {
            {
                let v4 = IpHeader::Version4(v4, v4_exts);
                assert_eq!(v4, v4.clone());
            }
            {
                let v6 = IpHeader::Version6(v6, v6_exts);
                assert_eq!(v6, v6.clone());
            }
        }
    }

    proptest! {
        #[test]
        #[allow(deprecated)]
        fn read_from_slice(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
        ) {
            let header = combine_v4(&v4, &v4_exts);
            let mut buffer = Vec::with_capacity(header.header_len());
            header.write(&mut buffer).unwrap();

            let actual = IpHeader::read_from_slice(&buffer).unwrap();
            assert_eq!(actual.0, header);
            assert_eq!(actual.1, header.next_header().unwrap());
            assert_eq!(actual.2, &buffer[buffer.len()..]);
        }
    }

    proptest! {
        #[test]
        fn from_slice(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
        ) {
            // v4
            {
                let header = combine_v4(&v4, &v4_exts);
                let mut buffer = Vec::with_capacity(header.header_len() + 1);
                header.write(&mut buffer).unwrap();
                buffer.push(1); // add some value to check the return slice

                // read
                {
                    let actual = IpHeader::from_slice(&buffer).unwrap();
                    assert_eq!(actual.0, header);
                    assert_eq!(actual.1, header.next_header().unwrap());
                    assert_eq!(actual.2, &buffer[buffer.len() - 1..]);
                }

                // read error ipv4 header
                IpHeader::from_slice(&buffer[..1]).unwrap_err();

                // read error ipv4 extensions
                if v4_exts.header_len() > 0 {
                    IpHeader::from_slice(&buffer[..v4.header_len() + 1]).unwrap_err();
                }
            }

            // v6
            {
                let header = combine_v6(&v6, &v6_exts);
                let mut buffer = Vec::with_capacity(header.header_len() + 1);
                header.write(&mut buffer).unwrap();
                buffer.push(1); // add some value to check the return slice

                // read
                {
                    let actual = IpHeader::from_slice(&buffer).unwrap();
                    assert_eq!(actual.0, header);
                    assert_eq!(actual.1, header.next_header().unwrap());
                    assert_eq!(actual.2, &buffer[buffer.len() - 1..]);
                }

                // read error header
                IpHeader::from_slice(&buffer[..1]).unwrap_err();

                // read error ipv4 extensions
                if v6_exts.header_len() > 0 {
                    IpHeader::from_slice(&buffer[..Ipv6Header::LEN + 1]).unwrap_err();
                }
            }
        }
    }

    proptest! {
        #[test]
        fn read(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
        ) {
            // v4
            {
                let header = combine_v4(&v4, &v4_exts);
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();

                // read
                {
                    let mut cursor = Cursor::new(&buffer);
                    let actual = IpHeader::read(&mut cursor).unwrap();
                    assert_eq!(actual.0, header);
                    assert_eq!(actual.1, header.next_header().unwrap());
                }

                // read error ipv4 header
                {
                    let mut cursor = Cursor::new(&buffer[..1]);
                    IpHeader::read(&mut cursor).unwrap_err();
                }

                // read error ipv4 extensions
                if v4_exts.header_len() > 0 {
                    let mut cursor = Cursor::new(&buffer[..v4.header_len() + 1]);
                    IpHeader::read(&mut cursor).unwrap_err();
                }
            }

            // v6
            {
                let header = combine_v6(&v6, &v6_exts);
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();

                // read
                {
                    let mut cursor = Cursor::new(&buffer);
                    let actual = IpHeader::read(&mut cursor).unwrap();
                    assert_eq!(actual.0, header);
                    assert_eq!(actual.1, header.next_header().unwrap());
                }

                // read error header
                {
                    let mut cursor = Cursor::new(&buffer[..1]);
                    IpHeader::read(&mut cursor).unwrap_err();
                }

                // read error ipv4 extensions
                if v6_exts.header_len() > 0 {
                    let mut cursor = Cursor::new(&buffer[..Ipv6Header::LEN + 1]);
                    IpHeader::read(&mut cursor).unwrap_err();
                }
            }
        }
    }

    proptest! {
        #[test]
        fn write(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
        ) {
            // v4
            {
                let header = combine_v4(&v4, &v4_exts);
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();

                let actual = IpHeader::from_slice(&buffer).unwrap().0;
                assert_eq!(header, actual);

                // write error v4 header
                {
                    let mut buffer = [0u8;1];
                    let mut cursor = Cursor::new(&mut buffer[..]);
                    assert!(
                        header.write(&mut cursor)
                        .unwrap_err()
                        .io_error()
                        .is_some()
                    );
                }

                // write error v6 extension headers
                if v4_exts.header_len() > 0 {
                    let mut buffer = [0u8;Ipv4Header::MAX_LEN + 1];
                    let mut cursor = Cursor::new(&mut buffer[..v4.header_len() + 1]);
                    assert!(
                        header.write(&mut cursor)
                        .unwrap_err()
                        .io_error()
                        .is_some()
                    );
                }
            }

            // v6
            {
                let header = combine_v6(&v6, &v6_exts);

                // normal write
                let mut buffer = Vec::with_capacity(header.header_len());
                header.write(&mut buffer).unwrap();

                let actual = IpHeader::from_slice(&buffer).unwrap().0;
                assert_eq!(header, actual);

                // write error v6 header
                {
                    let mut buffer = [0u8;1];
                    let mut cursor = Cursor::new(&mut buffer[..]);
                    assert!(
                        header.write(&mut cursor)
                        .unwrap_err()
                        .io_error()
                        .is_some()
                    );
                }

                // write error v6 extension headers
                if v6_exts.header_len() > 0 {
                    let mut buffer = [0u8;Ipv6Header::LEN + 1];
                    let mut cursor = Cursor::new(&mut buffer[..]);
                    assert!(
                        header.write(&mut cursor)
                        .unwrap_err()
                        .io_error()
                        .is_some()
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        fn header_len(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
        ) {
            assert_eq!(
                v4.header_len() + v4_exts.header_len(),
                IpHeader::Version4(v4, v4_exts).header_len()
            );
            assert_eq!(
                Ipv6Header::LEN + v6_exts.header_len(),
                IpHeader::Version6(v6, v6_exts).header_len()
            );
        }
    }
    
    proptest! {
        #[test]
        fn next_header(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
            post_header in any::<u8>()
                .prop_filter("Must be a non ipv6 header relevant ip number".to_owned(),
                    |v| !EXTESION_KNOWN_IP_NUMBERS.iter().any(|&x| v == &x)
                )
        ) {
            {
                let mut header = v4.clone();
                let mut exts = v4_exts.clone();
                header.protocol = exts.set_next_headers(post_header);
                assert_eq!(
                    Ok(post_header),
                    IpHeader::Version4(header, exts).next_header()
                );
            }
            {
                let mut header = v6.clone();
                let mut exts = v6_exts.clone();
                header.next_header = exts.set_next_headers(post_header);
                assert_eq!(
                    Ok(post_header),
                    IpHeader::Version6(header, exts).next_header()
                );
            }
        }
    }
    
    // TODO set_next_headers

    proptest! {
        #[test]
        fn set_payload_len(
            v4 in ipv4_any(),
            v4_exts in ipv4_extensions_any(),
            v6 in ipv6_any(),
            v6_exts in ipv6_extensions_any(),
            payload_len in 0usize..10
        ) {
            // ipv4 (with valid payload length)
            {
                let mut actual = IpHeader::Version4(
                    v4.clone(),
                    v4_exts.clone()
                );
                actual.set_payload_len(payload_len).unwrap();

                assert_eq!(
                    actual,
                    IpHeader::Version4(
                        {
                            let mut re = v4.clone();
                            re.set_payload_len(v4_exts.header_len() + payload_len).unwrap();
                            re
                        },
                        v4_exts.clone()
                    )
                );
            }
            // ipv6 (with valid payload length)
            {
                let mut actual = IpHeader::Version6(
                    v6.clone(),
                    v6_exts.clone()
                );
                actual.set_payload_len(payload_len).unwrap();

                assert_eq!(
                    actual,
                    IpHeader::Version6(
                        {
                            let mut re = v6.clone();
                            re.set_payload_length(v6_exts.header_len() + payload_len).unwrap();
                            re
                        },
                        v6_exts.clone()
                    )
                );
            }

            // v4 (with invalid size)
            {
                let mut actual = IpHeader::Version4(
                    v4.clone(),
                    v4_exts.clone()
                );
                assert!(actual.set_payload_len(usize::MAX).is_err());
            }

            // v6 (with invalid size)
            {
                let mut actual = IpHeader::Version6(
                    v6.clone(),
                    v6_exts.clone()
                );
                assert!(actual.set_payload_len(usize::MAX).is_err());
            }
        }
    }

}
