use crate::*;
use core::slice::from_raw_parts;

/// Allows iterating over the IPv6 extension headers present in an [Ipv6ExtensionsSlice].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionSliceIter<'a> {
    pub(crate) next_header: IpNumber,
    pub(crate) rest: &'a [u8],
}

impl<'a> Default for Ipv6ExtensionSliceIter<'a> {
    fn default() -> Self {
        Ipv6ExtensionSliceIter {
            // don't use 0 as this is the reserved value
            // for the hop by hop header
            next_header: IpNumber::IPV6_NO_NEXT_HEADER,
            rest: &[],
        }
    }
}

impl<'a> Iterator for Ipv6ExtensionSliceIter<'a> {
    type Item = Ipv6ExtensionSlice<'a>;

    fn next(&mut self) -> Option<Ipv6ExtensionSlice<'a>> {
        use ip_number::*;
        use Ipv6ExtensionSlice::*;

        match self.next_header {
            // Note on the unsafe calls:
            //
            // As the slice contents & length were previously checked by
            // Ipv6ExtensionsSlice::from_slice the content does not have to be
            // rechecked.
            IPV6_HOP_BY_HOP => unsafe {
                let slice = Ipv6RawExtHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(self.rest.as_ptr().add(len), self.rest.len() - len);
                self.next_header = slice.next_header();
                Some(HopByHop(slice))
            },
            IPV6_ROUTE => unsafe {
                let slice = Ipv6RawExtHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(self.rest.as_ptr().add(len), self.rest.len() - len);
                self.next_header = slice.next_header();
                Some(Routing(slice))
            },
            IPV6_DEST_OPTIONS => unsafe {
                let slice = Ipv6RawExtHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(self.rest.as_ptr().add(len), self.rest.len() - len);
                self.next_header = slice.next_header();
                Some(DestinationOptions(slice))
            },
            IPV6_FRAG => unsafe {
                let slice = Ipv6FragmentHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(self.rest.as_ptr().add(len), self.rest.len() - len);
                self.next_header = slice.next_header();

                Some(Fragment(slice))
            },
            AUTH => unsafe {
                let slice = IpAuthHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(self.rest.as_ptr().add(len), self.rest.len() - len);
                self.next_header = slice.next_header();
                Some(Authentication(slice))
            },
            // done parsing, the next header is not a known/supported header extension
            _ => None,
        }
    }
}
