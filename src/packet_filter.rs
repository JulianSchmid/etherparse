use super::*;

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ElementFilter<T> {
    Any,
    No,
    Some(T)
}

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LinkFilter {
    Ethernet2 {
        source: Option<[u8;6]>,
        destination: Option<[u8;6]>
    }
}

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VlanFilter {
    Single(Option<u16>),
    Double {
        outer_identifier: Option<u16>,
        inner_identifier: Option<u16>
    }
}

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IpFilter {
    Ipv4 {
        source: Option<[u8;4]>,
        destination: Option<[u8;4]>
    },
    Ipv6 {
        source: Option<[u8;16]>,
        destination: Option<[u8;16]>
    }
}

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TransportFilter {
    Udp {
        source_port: Option<u16>,
        destination_port: Option<u16>
    },
    Tcp {
        source_port: Option<u16>,
        destination_port: Option<u16>
    }
}

#[deprecated(
    since = "0.10.0",
    note = "The module packet_filter will be removed."
)]
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[allow(deprecated)]
pub struct Filter {
    pub link: ElementFilter<LinkFilter>,
    pub vlan: ElementFilter<VlanFilter>,
    pub ip: ElementFilter<IpFilter>,
    pub transport: ElementFilter<TransportFilter>,
}

#[allow(deprecated)]
impl<T> Default for ElementFilter<T> {
    fn default() -> ElementFilter<T> {
        ElementFilter::Any
    }
}

#[allow(deprecated)]
impl LinkFilter {
    #[deprecated(
        since = "0.10.0",
        note = "The module packet_filter will be removed."
    )]
    pub fn applies_to_slice(&self, slice: &LinkSlice) -> bool {
        use crate::LinkSlice::*;
        match self {
            LinkFilter::Ethernet2{
                source: expected_source,
                destination: expected_destination
            } =>  match slice {
                Ethernet2(header) => (match expected_source {
                    Some(e) => header.source() == *e,
                    None => true
                }) && (match expected_destination {
                    Some(e) => header.destination() == *e,
                    None => true
                })
            }
        }
    }
}

#[allow(deprecated)]
impl VlanFilter {
    #[deprecated(
        since = "0.10.0",
        note = "The module packet_filter will be removed."
    )]
    pub fn applies_to_slice(&self, slice: &VlanSlice) -> bool {
        use crate::VlanSlice::*;
        match self {
            VlanFilter::Single(expected_id) => {
                match slice {
                    SingleVlan(header) => {
                        match expected_id {
                            Some(e) => header.vlan_identifier() == *e,
                            None => true
                        }
                    },
                    _ => false //not a single vlan header
                }
            },
            VlanFilter::Double { inner_identifier: expected_inner_id, outer_identifier: expecetd_outer_id } => {
                match slice {
                    DoubleVlan(header) => {
                        (match expecetd_outer_id {
                            Some(e) => header.outer().vlan_identifier() == *e,
                            None => true
                        }) && (match expected_inner_id {
                            Some(e) => header.inner().vlan_identifier() == *e,
                            None => true
                        })
                    },
                    _ => false
                }
            }
        }
    }
}

#[allow(deprecated)]
impl IpFilter {
    #[deprecated(
        since = "0.10.0",
        note = "The module packet_filter will be removed."
    )]
    pub fn applies_to_slice(&self, slice: &InternetSlice) -> bool {
        use crate::InternetSlice::*;
        match self {
            IpFilter::Ipv4 { source: expected_source, destination: expected_destination } => {
                match slice {
                    Ipv4(header, _) => {
                        (match expected_source {
                            Some(e) => header.source() == *e,
                            None => true
                        }) && (match expected_destination {
                            Some(e) => header.destination() == *e,
                            None => true
                        })
                    },
                    _ => false
                }
            },
            IpFilter::Ipv6 { source: expected_source, destination: expected_destination } => {
                match slice {
                    Ipv6(header, _) => {
                        (match expected_source {
                            Some(e) => header.source() == *e,
                            None => true
                        }) && (match expected_destination {
                            Some(e) => header.destination() == *e,
                            None => true
                        })
                    },
                    _ => false
                }
            }
        }
    }
}

#[allow(deprecated)]
impl TransportFilter {
    #[deprecated(
        since = "0.10.0",
        note = "The module packet_filter will be removed."
    )]
    pub fn applies_to_slice(&self, slice: &TransportSlice) -> bool {
        use crate::TransportSlice::*;
        match self {
            TransportFilter::Udp { 
                source_port: expected_source_port, 
                destination_port: expected_destination_port
            } => {
                match slice {
                    Udp(header) => {
                        (match expected_source_port {
                            Some(e) => header.source_port() == *e,
                            None => true
                        }) && (match expected_destination_port {
                            Some(e) => header.destination_port() == *e,
                            None => true
                        })
                    }
                    _ => false
                }
            },
            TransportFilter::Tcp { 
                source_port: expected_source_port, 
                destination_port: expected_destination_port
            } => {
                match slice {
                    Tcp(header) => {
                        (match expected_source_port {
                            Some(e) => header.source_port() == *e,
                            None => true
                        }) && (match expected_destination_port {
                            Some(e) => header.destination_port() == *e,
                            None => true
                        })
                    }
                    _ => false
                }
            }
        }
    }
}

#[allow(deprecated)]
impl Filter {
    ///Returns true if a given sliced network package fullfills all conditions of this filter.
    #[deprecated(
        since = "0.10.0",
        note = "The module packet_filter will be removed."
    )]
    pub fn applies_to_slice(&self, slice: &SlicedPacket) -> bool {
        //TODO link
         (match &self.link {
            ElementFilter::Any => true,
            ElementFilter::No => slice.link.is_none(),
            ElementFilter::Some(filter) => {
                match &slice.link {
                    Some(value) => filter.applies_to_slice(value),
                    None => false
                }
            }
         }) && (match &self.vlan {
            ElementFilter::Any => true,
            ElementFilter::No => slice.vlan.is_none(),
            ElementFilter::Some(filter) => {
                match &slice.vlan {
                    Some(value) => filter.applies_to_slice(value),
                    None => false
                }
            }
        }) && (match &self.ip {
            ElementFilter::Any => true,
            ElementFilter::No => slice.ip.is_none(),
            ElementFilter::Some(filter) => {
                match &slice.ip {
                    Some(value) => filter.applies_to_slice(value),
                    None => false
                }
            }
        }) && (match &self.transport {
            ElementFilter::Any => true,
            ElementFilter::No => slice.transport.is_none(),
            ElementFilter::Some(filter) => {
                match &slice.transport {
                    Some(value) => filter.applies_to_slice(value),
                    None => false
                }
            }
        })
    }
}