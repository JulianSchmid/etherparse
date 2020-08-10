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
    pub auth: Option<IpAuthenticationHeader>,
}

/// Slices of the IPv4 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
///
/// Currently not supported:
/// * Encapsulating Security Payload Header (ESP)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv4ExtensionSlices<'a> {
    pub auth: Option<IpAuthenticationHeaderSlice<'a>>,
}

impl Ipv4Extensions {
    /// Read all known ipv4 extensions and return an `Ipv4ExtensionSlices` with the
    /// identified slices, the final ip number and a slice pointing to the non parsed data.
    pub fn read_from_slice(start_protocol: u8, slice: &[u8]) -> Result<(Ipv4Extensions, u8, &[u8]), ReadError> {
        Ipv4ExtensionSlices::from_slice(start_protocol, slice).map(
            |v| (v.0.to_header(), v.1, v.2)
        )
    }

    /// Reads the known ipv4 extension headers from the reader and returns the
    /// headers together with the internet protocol number identifying the protocol
    /// that will be next.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T, start_ip_number: u8) -> Result<(Ipv4Extensions, u8), ReadError> {
        use ip_number::*;
        if AUTH == start_ip_number {
            let header = IpAuthenticationHeader::read(reader)?;
            let next_ip_number = header.next_header;
            Ok((
                Ipv4Extensions{
                    auth: Some(header)
                },
                next_ip_number,
            ))
        } else {
            Ok((Default::default(), start_ip_number))
        }
    }

    /// Write the extensions to the writer.
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T, start_ip_number: u8) -> Result<(), WriteError> {
        use ip_number::*;
        use IpNumber::*;
        use ValueError::*;
        match self.auth {
            Some(ref header) => if AUTH == start_ip_number {
                header.write(writer)
            } else {
                Err(Ipv4ExtensionNotReferenced(AuthenticationHeader).into())
            },
            None => Ok(())
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
    pub fn set_next_headers(&mut self, last_protocol_number: u8) -> u8 {
        use ip_number::*;

        let mut next = last_protocol_number;

        if let Some(ref mut header) = self.auth {
            header.next_header = next;
            next = AUTH;
        }

        next
    }
}

impl<'a> Ipv4ExtensionSlices<'a> {

    /// Read all known ipv4 extensions and return an `Ipv4ExtensionSlices` with the
    /// identified slices, the final ip number and a slice pointing to the non parsed data.
    pub fn from_slice(start_ip_number: u8, start_slice: &'a [u8]) -> Result<(Ipv4ExtensionSlices, u8, &[u8]), ReadError> {
        use ip_number::*;
        if AUTH == start_ip_number {
            let header = IpAuthenticationHeaderSlice::from_slice(start_slice)?;
            let rest = &start_slice[header.slice().len()..];
            let next_header = header.next_header();
            Ok((
                Ipv4ExtensionSlices{
                    auth: Some(header)
                },
                next_header,
                rest
            ))
        } else {
            Ok((Default::default(), start_ip_number, start_slice))
        }
    }

    /// Convert the slices into actual headers.
    pub fn to_header(&self) -> Ipv4Extensions {
        Ipv4Extensions {
            auth: self.auth.as_ref().map(|v| v.to_header())
        }
    }
}