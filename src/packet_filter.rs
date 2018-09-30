use super::*;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ElementFilter<T> {
    Any,
    No,
    Some(T)
}

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

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Filter {
    //pub link: ElementFilter<>,
    //pub vlan: ElementFilter<>,
    pub ip: ElementFilter<IpFilter>,
    pub transport: ElementFilter<TransportFilter>,
}

impl<T> Default for ElementFilter<T> {
    fn default() -> ElementFilter<T> {
        ElementFilter::Any
    }
}

impl IpFilter {
    pub fn applies_to_slice(&self, slice: &InternetSlice) -> bool {
        use InternetSlice::*;
        match self {
            IpFilter::Ipv4 { source: expected_source, destination: expected_destination } => {
                match slice {
                    Ipv4(header) => {
                        (match expected_source {
                            Some(e) => header.source() == &e[..],
                            None => true
                        }) && (match expected_destination {
                            Some(e) => header.destination() == &e[..],
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
                            Some(e) => header.source() == &e[..],
                            None => true
                        }) && (match expected_destination {
                            Some(e) => header.destination() == &e[..],
                            None => true
                        })
                    },
                    _ => false
                }
            }
        }
    }
}

impl TransportFilter {
    pub fn applies_to_slice(&self, slice: &TransportSlice) -> bool {
        use TransportSlice::*;
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

impl Filter {
    ///Returns true if a given sliced network package fullfills all conditions of this filter.
    pub fn applies_to_slice(&self, slice: &SlicedPacket) -> bool {
        //TODO
        (match &self.ip {
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