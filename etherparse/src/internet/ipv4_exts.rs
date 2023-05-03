use super::super::*;

/// IPv4 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
///
/// Currently not supported:
/// - Encapsulating Security Payload Header (ESP)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv4Extensions {
    pub auth: Option<IpAuthHeader>,
}

impl Ipv4Extensions {
    /// Minimum length required for extension header in bytes/octets.
    /// Which is zero as no extension headers are required.
    pub const MIN_LEN: usize = 0;

    /// Maximum summed up length of all extension headers in bytes/octets.
    pub const MAX_LEN: usize = IpAuthHeader::MAX_LEN;

    /// Read all known ipv4 extensions and return an `Ipv4ExtensionSlices` with the
    /// identified slices, the final ip number and a slice pointing to the non parsed data.
    pub fn from_slice(
        start_protocol: IpNumber,
        slice: &[u8],
    ) -> Result<(Ipv4Extensions, IpNumber, &[u8]), err::ip_auth::HeaderSliceError> {
        Ipv4ExtensionsSlice::from_slice(start_protocol, slice).map(|v| (v.0.to_header(), v.1, v.2))
    }

    /// Reads the known ipv4 extension headers from the reader and returns the
    /// headers together with the internet protocol number identifying the protocol
    /// that will be next.
    #[cfg(feature = "std")]
    pub fn read<T: std::io::Read + Sized>(
        reader: &mut T,
        start_ip_number: IpNumber,
    ) -> Result<(Ipv4Extensions, IpNumber), err::ip_auth::HeaderReadError> {
        use ip_number::*;
        if AUTH == start_ip_number {
            let header = IpAuthHeader::read(reader)?;
            let next_ip_number = header.next_header;
            Ok((Ipv4Extensions { auth: Some(header) }, next_ip_number))
        } else {
            Ok((Default::default(), start_ip_number))
        }
    }

    /// Reads the known ipv4 extension headers from a length limited reader and returns the
    /// headers together with the internet protocol number identifying the protocol
    /// that will be next.
    #[cfg(feature = "std")]
    pub fn read_limited<T: std::io::Read + Sized>(
        reader: &mut crate::io::LimitedReader<T>,
        start_ip_number: IpNumber,
    ) -> Result<(Ipv4Extensions, IpNumber), err::ip_auth::HeaderLimitedReadError> {
        use ip_number::*;
        if AUTH == start_ip_number {
            let header = IpAuthHeader::read_limited(reader)?;
            let next_ip_number = header.next_header;
            Ok((Ipv4Extensions { auth: Some(header) }, next_ip_number))
        } else {
            Ok((Default::default(), start_ip_number))
        }
    }

    /// Write the extensions to the writer.
    #[cfg(feature = "std")]
    pub fn write<T: std::io::Write + Sized>(
        &self,
        writer: &mut T,
        start_ip_number: IpNumber,
    ) -> Result<(), err::ipv4_exts::HeaderWriteError> {
        use ip_number::*;
        use err::ipv4_exts::{HeaderWriteError::*, HeaderSerError::*, ExtNotReferencedError};
        match self.auth {
            Some(ref header) => {
                if AUTH == start_ip_number {
                    header.write(writer).map_err(Io)
                } else {
                    Err(Content(ExtNotReferenced(ExtNotReferencedError{
                        missing_ext: IpNumber::AUTHENTICATION_HEADER
                    })))
                }
            }
            None => Ok(()),
        }
    }

    ///Length of the all present headers in bytes.
    pub fn header_len(&self) -> usize {
        if let Some(ref header) = self.auth {
            header.header_len()
        } else {
            0
        }
    }

    /// Sets all the next_header fields of the headers based on the adviced default order
    /// with the given protocol number as last "next header" value. The return value is the protocol
    /// number of the first existing extension header that should be entered in the ipv4 header as
    /// protocol_number.
    ///
    /// If no extension headers are present the value of the argument is returned.
    pub fn set_next_headers(&mut self, last_protocol_number: IpNumber) -> IpNumber {
        use ip_number::*;

        let mut next = last_protocol_number;

        if let Some(ref mut header) = self.auth {
            header.next_header = next;
            next = AUTH;
        }

        next
    }

    /// Return next header based on the extension headers and
    /// the first ip protocol number.
    ///
    /// In case a header is never
    /// referenced a ValueError::Ipv4ExtensionNotReferenced is returned.
    pub fn next_header(&self, first_next_header: IpNumber) -> Result<IpNumber, ValueError> {
        use ip_number::*;
        if let Some(ref auth) = self.auth {
            if first_next_header == AUTH {
                Ok(auth.next_header)
            } else {
                Err(ValueError::Ipv4ExtensionNotReferenced(
                    IpNumber::AUTHENTICATION_HEADER,
                ))
            }
        } else {
            Ok(first_next_header)
        }
    }

    /// Returns true if no IPv4 extension header is present (all fields `None`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.auth.is_none()
    }
}
