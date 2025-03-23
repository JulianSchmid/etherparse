use crate::*;

/// A slice containing the link layer extension header (currently only Ethernet II and
/// SLL are supported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkExtSlice<'a> {
    /// Slice containing a VLAN header & payload.
    Vlan(SingleVlanSlice<'a>),
}

impl<'a> LinkExtSlice<'a> {
    /// Returns the header length of the link extension.
    pub fn header_len(&self) -> usize {
        match self {
            LinkExtSlice::Vlan(s) => s.header_len(),
        }
    }

    /// Convert the header part of the link extension into a [`LinkExtHeader`].
    pub fn to_header(&self) -> LinkExtHeader {
        match self {
            LinkExtSlice::Vlan(s) => LinkExtHeader::Vlan(s.to_header()),
        }
    }

    /// Return the payload of the link extensions.
    pub fn payload(&self) -> EtherPayloadSlice<'a> {
        match self {
            LinkExtSlice::Vlan(s) => s.payload(),
        }
    }
}
