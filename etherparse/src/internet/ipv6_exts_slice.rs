use crate::*;
use core::slice::from_raw_parts;

/// Slice containing the IPv6 extension headers present after the ip header.
///
/// Currently supported:
/// * Authentication Header
/// * Hop by Hop Options Header
/// * Destination Options Header (before and after routing headers)
/// * Routing Header
/// * Fragment
/// * Authentication Header
///
/// Currently not supported:
/// * Encapsulating Security Payload Header (ESP)
/// * Host Identity Protocol (HIP)
/// * IP Mobility
/// * Site Multihoming by IPv6 Intermediation (SHIM6)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv6ExtensionsSlice<'a> {
    /// IP protocol number of the first header present in the slice.
    first_header: Option<u8>,
    /// True if a fragment header is present in the ipv6 header extensions that causes the payload to be fragmented.
    fragmented: bool,
    /// Slice containing ipv6 extension headers.
    slice: &'a [u8],
}

impl<'a> Ipv6ExtensionsSlice<'a> {
    /// Collects all ipv6 extension headers in a slice & checks if
    /// a fragmentation header that fragments the packet is present.
    pub fn from_slice(
        start_ip_number: u8,
        start_slice: &'a [u8],
    ) -> Result<(Ipv6ExtensionsSlice, u8, &'a [u8]), err::ipv6_exts::HeaderSliceError> {
        let mut rest = start_slice;
        let mut next_header = start_ip_number;
        let mut fragmented = false;

        use ip_number::*;
        use err::ipv6_exts::{HeaderError::*, HeaderSliceError::*};

        // the hop by hop header is required to occur directly after the ipv6 header
        if IPV6_HOP_BY_HOP == next_header {
            let slice =
                Ipv6RawExtHeaderSlice::from_slice(rest).map_err(Len)?;
            rest = &rest[slice.slice().len()..];
            next_header = slice.next_header();
        }

        loop {
            match next_header {
                IPV6_HOP_BY_HOP => {
                    return Err(Content(HopByHopNotAtStart));
                }
                IPV6_DEST_OPTIONS | IPV6_ROUTE => {
                    let slice = Ipv6RawExtHeaderSlice::from_slice(rest)
                        .map_err(|err| Len(err.add_offset(start_slice.len() - rest.len())))?;
                    // SAFETY:
                    // Ipv6RawExtHeaderSlice::from_slice always generates
                    // a subslice from the given slice rest. Therefor it is guranteed
                    // that len is always greater or equal the len of rest.
                    rest = unsafe {
                        let len = slice.slice().len();
                        from_raw_parts(rest.as_ptr().add(len), rest.len() - len)
                    };
                    next_header = slice.next_header();
                }
                IPV6_FRAG => {
                    let slice = Ipv6FragmentHeaderSlice::from_slice(rest)
                        .map_err(|err| Len(err.add_offset(start_slice.len() - rest.len())))?;
                    // SAFETY:
                    // Ipv6FragmentHeaderSlice::from_slice always generates
                    // a subslice from the given slice rest. Therefor it is guranteed
                    // that len is always greater or equal the len of rest.
                    rest = unsafe {
                        let len = slice.slice().len();
                        from_raw_parts(rest.as_ptr().add(len), rest.len() - len)
                    };
                    next_header = slice.next_header();

                    // check if the fragment header actually causes fragmentation
                    fragmented = fragmented || slice.is_fragmenting_payload();
                }
                AUTH => {
                    let slice = IpAuthHeaderSlice::from_slice(rest).map_err(|err| {
                        use err::ip_auth::HeaderSliceError as I;
                        match err {
                            I::Len(err) => Len(err.add_offset(start_slice.len() - rest.len())),
                            I::Content(err) => Content(IpAuth(err)),
                        }
                    })?;
                    // SAFETY:
                    // IpAuthHeaderSlice::from_slice always generates
                    // a subslice from the given slice rest. Therefor it is guranteed
                    // that len is always greater or equal the len of rest.
                    rest = unsafe {
                        let len = slice.slice().len();
                        from_raw_parts(rest.as_ptr().add(len), rest.len() - len)
                    };
                    next_header = slice.next_header();
                }
                // done parsing, the next header is not a known/supported header extension
                _ => break,
            }
        }

        Ok((
            Ipv6ExtensionsSlice {
                first_header: if rest.len() != start_slice.len() {
                    Some(start_ip_number)
                } else {
                    None
                },
                fragmented,
                slice: &start_slice[..start_slice.len() - rest.len()],
            },
            next_header,
            rest,
        ))
    }

    /// Returns true if a fragmentation header is present in
    /// the extensions that fragments the payload.
    ///
    /// Note: A fragmentation header can still be present
    /// even if the return value is false in case the fragmentation
    /// headers don't fragment the payload. This is the case if
    /// the offset of all fragmentation header is 0 and the
    /// more fragment bit is not set.
    #[inline]
    pub fn is_fragmenting_payload(&self) -> bool {
        self.fragmented
    }

    /// Returns the ip protocol number of the first header in the slice
    /// if the slice contains an ipv6 extension header. If no ipv6 header
    /// is present None is returned.
    ///
    /// None is only returned if the slice length of this struct is 0.
    #[inline]
    pub fn first_header(&self) -> Option<u8> {
        self.first_header
    }

    /// Slice containing the ipv6 extension headers.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Returns true if no IPv6 extension header is present (slice is empty).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }
}

impl<'a> IntoIterator for Ipv6ExtensionsSlice<'a> {
    type Item = Ipv6ExtensionSlice<'a>;
    type IntoIter = Ipv6ExtensionSliceIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Ipv6ExtensionSliceIter {
            // map the next header None value to some non ipv6 ext header
            // value.
            next_header: self.first_header.unwrap_or(ip_number::UDP),
            rest: self.slice,
        }
    }
}
