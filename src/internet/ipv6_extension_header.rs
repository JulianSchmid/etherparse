use super::super::*;

extern crate byteorder;
use self::byteorder::{WriteBytesExt};

///Maximum number of header extensions allowed (according to the ipv6 rfc8200, & iana protocol numbers).
pub const IPV6_MAX_NUM_HEADER_EXTENSIONS: usize = 12;

// Note to who is interested:
//
// Why the seperate handling of ipv6 extension headers?
// ----------------------------------------------------
//
// Implementing all header extensions was just not feasable.
// So I decided to implement a "generic" extension header for all
// IPv6 extension header that followed the format of containing a 
// next_header field and a hdr_extension_length field at the beginning.
// All implemented headers like fragmentation header could still use
// their own type, but everything that is not implemented the generic type
// should be used.
//
// The problem came when deciding what the interface for this generic
// extension header should look like. When I looked at it I could see the
// following options (with the following pros & cons):
//
// * Add a field to the struct containing the traffic class id
//     + simple to understand
//     + not a lot of code neccesairy
//     - the traffic class remains constant (gives the optimizer less options)
//     - potentially allows the creation of inconsitant data
//       e.g. an enum containing the different extension header options
//       could be filled with a wrong traffic class id (e.g. HopByHop header with 
//       a DestionationOption id)
//
// * Using a const generic to pass the traffic class id
//     + simple to understand
//     + protocol number const by definition (can be optimized)
//     - currently not availible in stable Rust -> Dealbreaker
//
// * Passing in a trait type that has function that provides the protocol number
//     + Similar to "const generic"
//     - a lot of boiler plate code
//     - very verbose
//
// * Leave the type of the header completely out of the generic header relying on
//   some top encapsualting type (e.g. enum) to providing the type.
//     + Simple to understand
//     + No duplicated information and potential for api missuse
//     - Lost informations (type must be transfered in another way)
//
// So finally I decided on just going back to the basics and leave the 
// traffic class/protocol number out of it. I would have prefered to use const generics
// but the feature is not in stable yet (see https://github.com/rust-lang/rust/issues/44580 )
// and requiring a non stable version of Rust of users is currently not acceptable for me.
//
// I actually first started to implement the version with the trait type, but the amount
// of boiler plate code & the amount of type spam that was required did not sit right with me.
// Plus the length of the type name that you would need to type was just horrible (e.g. 
// Ipv6GenericExtensionHeader<Ipv6DestinationOptionsGenericId>).

/// IPv6 extension header with only minimal data interpretation.
///
/// Can be one of the following headers Ipv6 Eetension headers:
/// * HopbyHop
/// * Destination Options
/// * Routing 
/// * Mobility
/// * Host Identity Protocol
/// * Shim6 Protocol
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionHeader<'a> {
    /// Type of content after this header (traffic class/protocol number)
    pub next_header: u8,
    //// The data contained in the extension header (excluding next_header & hdr length).
    pub data: &'a [u8],
}

impl<'a> Ipv6ExtensionHeader<'a> {
    /// Creates an generic IPv6 extension header with the given data.
    /// # Arguments
    ///
    /// * `next_header` - type of content after this header (protocol number)
    /// * `data` - slice containing the data of the header. This does NOT contain the `next header` and `extended header length`.
    pub fn new_raw(next_header: u8, data: &'a [u8]) -> Ipv6ExtensionHeader<'a> {
        Ipv6ExtensionHeader::<'a>{
            next_header,
            data,
        }
    }

    /// Read an Ipv6ExtensionHeader from a slice and return the header & unused parts of the slice.
    pub fn read_from_slice(header_type: u8, slice: &'a [u8]) -> Result<(Ipv6ExtensionHeader<'a>, &'a[u8]), ReadError> {
        let s = Ipv6ExtensionHeaderSlice::from_slice(header_type, slice)?;
        let rest = &slice[s.slice().len()..];
        let header = s.to_header();
        Ok((
            header, 
            rest
        ))
    }

    /// Writes a given IPv6 extension header to the current position.
    pub fn write<W: io::Write + Sized>(&self, writer: &mut W) -> Result<(), WriteError> {

        use ValueError::*;

        // check if the data are not too big
        // the max length is defined by the max number that can fit into the
        // hdr ext len (+ 6 for the first six octets that are not part of the length).
        const MAX_DATA_LEN: usize = 6 + 8*0xff;

        if self.data.len() > MAX_DATA_LEN {
            Err(WriteError::ValueError(
                Ipv6ExtensionDataTooLarge(self.data.len())
            ))
        } else {
            writer.write_u8(self.next_header)?;

            // + 8 (and -1) to ensure no underflow can happen 
            // - 6 as the first 6 octets are not counted in the length
            // + 7 to ensure the result is round up
            let len: u8 = ((self.data.len() + 8 - 6 + 7) / 8 - 1) as u8;
            writer.write_u8(len)?;
            writer.write_all(&self.data)?;
            // add padding
            let padding_len = (usize::from(len) + 1)*8 - (self.data.len() + 8 - 6);
            if padding_len > 0 {
                const PADDING: [u8;7] = [0;7];
                writer.write_all(&PADDING[..padding_len])?;
            }
            Ok(())
        }
    }

}

/// Slice containing an IPv6 extension header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionHeaderSlice<'a> {
    /// Slice containing the packet data.
    slice: &'a [u8],
}

impl<'a> Ipv6ExtensionHeaderSlice<'a> {

    /// Creates a genric ipv6 extension header slice from a slice.
    pub fn from_slice(header_type: u8, slice: &'a[u8]) -> Result<Ipv6ExtensionHeaderSlice<'a>, ReadError> {

        //check length
        use crate::ReadError::*;
        if slice.len() < 8 {
            return Err(UnexpectedEndOfSlice(8));
        }

        //check length
        const FRAG: u8 = IpTrafficClass::IPv6FragmentationHeader as u8;
        let len = if FRAG == header_type {
            8
        } else {
            ((slice[1] as usize) + 1)*8
        };

        //check the length again now that the expected length is known
        if slice.len() < len {
            return Err(UnexpectedEndOfSlice(len));
        }

        //all good
        Ok(Ipv6ExtensionHeaderSlice {
            slice: &slice[..len]
        })
    }

    /// Returns the slice containing the ipv6 extension header
    #[inline]
    pub fn slice(&self) -> &'a[u8] {
        self.slice
    }

    /// Returns the id of the next header (see IpTrafficClass for a definition of all ids).
    pub fn next_header(&self) -> u8 {
        self.slice[0]
    }

    /// Returns a slice containing the raw data of the header.
    /// This contains all the data after the header length field
    /// until the end of the header (length specified by the
    /// hdr ext length field).
    pub fn data(&self) -> &'a[u8] {
        &self.slice[2..]
    }

    /// Decode some of the fields and copy the results to a 
    /// Ipv6ExtensionHeader struct together with a slice pointing
    /// to the non decoded parts.
    pub fn to_header(&self) -> Ipv6ExtensionHeader<'a> {
        return Ipv6ExtensionHeader{
            next_header: self.next_header(),
            data: self.data(),
        }
    }
}
