use super::super::*;

///Internet protocol headers version 4 & 6
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum IpHeader {
    Version4(Ipv4Header, Ipv4Extensions),
    Version6(Ipv6Header, Ipv6Extensions),
}

impl IpHeader {
    /// Renamed to `IpHeader::from_slice`
    #[deprecated(since = "0.10.1", note = "Renamed to `IpHeader::from_slice`")]
    #[inline]
    pub fn read_from_slice(slice: &[u8]) -> Result<(IpHeader, u8, &[u8]), ReadError> {
        IpHeader::from_slice(slice)
    }

    /// Read an IpvHeader from a slice and return the header & unused parts of the slice.
    pub fn from_slice(slice: &[u8]) -> Result<(IpHeader, u8, &[u8]), ReadError> {
        if slice.is_empty() {
            use crate::ReadError::UnexpectedEndOfSlice as U;
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
                            I::SliceLen(err) => O::UnexpectedEndOfSlice(err),
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
                                I::SliceLen(err) => O::UnexpectedEndOfSlice(err),
                                I::Content(err) => O::IpAuthHeader(err),
                            }
                        })
                }
                6 => {
                    if slice.len() < Ipv6Header::LEN {
                        use ReadError::UnexpectedEndOfSlice;
                        return Err(UnexpectedEndOfSlice(err::SliceLenError {
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
                    )
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
