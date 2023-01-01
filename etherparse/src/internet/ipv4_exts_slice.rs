use crate::*;

/// Slices of the IPv4 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
///
/// Currently not supported:
/// * Encapsulating Security Payload Header (ESP)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv4ExtensionsSlice<'a> {
    pub auth: Option<IpAuthHeaderSlice<'a>>,
}

impl<'a> Ipv4ExtensionsSlice<'a> {
    /// Read all known ipv4 extensions and return an `Ipv4ExtensionSlices` with the
    /// identified slices, the final ip number and a slice pointing to the non parsed data.
    pub fn from_slice(
        start_ip_number: u8,
        start_slice: &'a [u8],
    ) -> Result<(Ipv4ExtensionsSlice, u8, &[u8]), err::ip_auth::HeaderSliceError> {
        use ip_number::*;
        if AUTH == start_ip_number {
            let header = IpAuthHeaderSlice::from_slice(start_slice)?;
            let rest = &start_slice[header.slice().len()..];
            let next_header = header.next_header();
            Ok((
                Ipv4ExtensionsSlice { auth: Some(header) },
                next_header,
                rest,
            ))
        } else {
            Ok((Default::default(), start_ip_number, start_slice))
        }
    }

    /// Convert the slices into actual headers.
    pub fn to_header(&self) -> Ipv4Extensions {
        Ipv4Extensions {
            auth: self.auth.as_ref().map(|v| v.to_header()),
        }
    }

    /// Returns true if no IPv4 extension header is present (all fields `None`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.auth.is_none()
    }
}
