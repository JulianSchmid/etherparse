pub mod ethernet;
pub mod vlan_tagging;

/// A slice containing the link layer header (currently only Ethernet II is supported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkSlice<'a> {
    /// A slice containing an Ethernet II header.
    Ethernet2(ethernet::Ethernet2HeaderSlice<'a>),
}

impl<'a> LinkSlice<'a> {
    /// Convert the link slice to a header (currently just the
    /// ethernet2 header as this is the only value it can take).
    pub fn to_header(&self) -> ethernet::Ethernet2Header {
        use LinkSlice::*;
        match self {
            Ethernet2(slice) => slice.to_header(),
        }
    }
}
