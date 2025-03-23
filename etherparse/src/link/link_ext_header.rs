use super::SingleVlanHeader;

/// The possible headers on the link layer
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkExtHeader {
    /// VLAN header.
    Vlan(SingleVlanHeader),
}

impl LinkExtHeader {
    /// Returns the header length of the link extension.
    pub fn header_len(&self) -> usize {
        match self {
            LinkExtHeader::Vlan(s) => s.header_len(),
        }
    }
}
