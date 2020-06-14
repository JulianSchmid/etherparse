pub mod ip;
pub mod ipsec;
pub mod ipv4;
pub mod ipv6;
pub mod ipv6_ext_hop_by_hop;

use super::ReadError;

/// Ipv6 helper function to extract the size of an ipv6 
/// extension header and checks if the slice is big enough for
/// the header extension.
fn ipv6_generic_ext_len_from_slice(slice: &[u8]) -> Result<usize, ReadError> {
    // check length
    use crate::ReadError::*;
    if slice.len() < 8 {
        return Err(UnexpectedEndOfSlice(8));
    }

    // decode length
    let len = ((slice[1] as usize) + 1)*8;

    //check the length again now that the expected length is known
    if slice.len() < len {
        Err(UnexpectedEndOfSlice(len))
    } else {
        Ok(len)
    }
}