use core::slice;

use crate::{err::ipv4::SliceError, Ipv4ExtensionsSlice, Ipv4HeaderSlice};

#[derive(Debug)]
pub struct Ipv4Slice<'a> {
    slice: &'a [u8],
    header_len: usize,
    auth_len: usize,
}

impl<'a> Ipv4Slice<'a> {
    ///
    pub fn from_slice(slice: &[u8]) -> Result<Ipv4Slice, SliceError> {
        todo!()
    }

    /// Returns a slice containing the IPv4 header.
    pub fn header(&self) -> Ipv4HeaderSlice {
        // SAFETY: Sizes were verified in the construction function `from_slice`.
        unsafe {
            Ipv4HeaderSlice::from_slice_unchecked(slice::from_raw_parts(
                self.slice.as_ptr(),
                self.header_len,
            ))
        }
    }

    /// Returns a slice containing the IPv4 extension headers.
    pub fn extensions(&self) -> Ipv4ExtensionsSlice {
        todo!()
    }

    /// Returns a slice containing the payload of the IP packet (data after the)
    pub fn payload(&self) -> &[u8] {
        todo!()
    }

    /// Returns
    pub fn payload_ip_number(&self) -> u8 {
        todo!()
    }
}
