use super::super::*;

/// IPv6 extension headers present after the ip header.
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
pub struct Ipv6Extensions {
    pub hop_by_hop_options: Option<Ipv6GenericExtensionHeader>,
    pub destination_options: Option<Ipv6GenericExtensionHeader>,
    pub routing: Option<Ipv6GenericExtensionHeader>,
    pub fragment: Option<Ipv6FragmentHeader>,
    pub auth: Option<IpAuthenticationHeader>,
    pub final_destination_options: Option<Ipv6GenericExtensionHeader>
}

/// IPv6 extension headers present after the ip header.
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
pub struct Ipv6ExtensionSlices<'a> {
    pub hop_by_hop_options: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    /// Destination options encountered before a routing header.
    pub destination_options: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    pub routing: Option<Ipv6GenericExtensionHeaderSlice<'a>>,
    pub fragment: Option<Ipv6FragmentHeaderSlice<'a>>,
    pub auth: Option<IpAuthenticationHeaderSlice<'a>>,
    /// Destination options enountered after a routing header.
    pub final_destination_options: Option<Ipv6GenericExtensionHeaderSlice<'a>>
}

impl Ipv6Extensions {

    /// Reads as many extension headers as possible from the slice and returns the found
    /// ipv6 extension headers, the next header ip number after the read headers and a slice 
    /// containing the rest of the packet after the read headers.
    ///
    /// Note that this function can only handle ipv6 extensions if each extension header does 
    /// occur at most once, except for destination options headers which are allowed to 
    /// exist once in front of a routing header and once after a routing header.
    ///
    /// In case that more extension headers then can fit into a `Ipv6Extensions` struct are
    /// encountered, the parsing is stoped at the point where the data would no longer fit into
    /// the struct. In such a scenario a struct with the data that could be parsed is returned
    /// together with the next header ip number and slice containing the unparsed data.
    ///
    /// It is in the responsibility of the caller to handle a scenario like this.
    ///
    /// The reason that no error is generated, is that even though according to RFC 8200 packets 
    /// "should" not contain more then one occurence of an extension header the RFC also specifies
    /// that "IPv6 nodes must accept and attempt to process extension headers in any order and 
    /// occurring any number of times in the same packet". So packets with multiple headers "should"
    /// not exist, but are still valid IPv6 packets. As such this function does not generate a
    /// parsing error, as it is not an invalid packet, but if packets like these are encountered
    /// the user of this function has to themself decide how to handle packets like these.
    ///
    /// The only exception is if an hop by hop header is located somewhere else then directly at 
    /// the start. In this case an `ReadError::Ipv6HopByHopHeaderNotAtStart` error is generated as
    /// the hop by hop header is required to be located directly after the IPv6 header according 
    /// to RFC 8200.
    pub fn read_from_slice(start_protocol: u8, slice: &[u8]) -> Result<(Ipv6Extensions, u8, &[u8]), ReadError> {
        Ipv6ExtensionSlices::from_slice(start_protocol, slice).map(
            |v| (v.0.to_header(), v.1, v.2)
        )
    }

    /// Reads as many extension headers as possible from the reader and returns the found ipv6
    /// extension headers, the next header ip number.
    ///
    /// If no extension headers are present an unfilled struct and the original `first_header`
    /// ip number is returned.
    ///
    /// Note that this function can only handle ipv6 extensions if each extension header does 
    /// occur at most once, except for destination options headers which are allowed to 
    /// exist once in front of a routing header and once after a routing header.
    ///
    /// In case that more extension headers then can fit into a `Ipv6Extensions` struct are
    /// encountered, the parsing is stoped at the point where the data would no longer fit into
    /// the struct. In such a scenario a struct with the data that could be parsed is returned
    /// together with the next header ip number that identfies which header could be read next.
    ///
    /// It is in the responsibility of the caller to handle a scenario like this.
    ///
    /// The reason that no error is generated, is that even though according to RFC 8200, packets 
    /// "should" not contain more then one occurence of an extension header, the RFC also specifies
    /// that "IPv6 nodes must accept and attempt to process extension headers in any order and 
    /// occurring any number of times in the same packet". So packets with multiple headers "should"
    /// not exist, but are still valid IPv6 packets. As such this function does not generate a
    /// parsing error, as it is not an invalid packet, but if packets like these are encountered
    /// the user of this function has to themself decide how to handle packets like these.
    ///
    /// The only exception is if an hop by hop header is located somewhere else then directly at 
    /// the start. In this case an `ReadError::Ipv6HopByHopHeaderNotAtStart` error is generated as
    /// the hop by hop header is required to be located directly after the IPv6 header according 
    /// to RFC 8200.
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T, start_protocol: u8) -> Result<(Ipv6Extensions, u8), ReadError> {
        let mut result: Ipv6Extensions = Default::default();
        let mut next_protocol = start_protocol;

        use ip_number::*;
        use ReadError::*;

        // the hop by hop header is required to occur directly after the ipv6 header
        if IPV6_HOP_BY_HOP == next_protocol {
            let header = Ipv6GenericExtensionHeader::read(reader)?;
            next_protocol = header.next_header;
            result.hop_by_hop_options = Some(header);   
        }

        loop {
            match next_protocol {
                IPV6_HOP_BY_HOP => {
                    return Err(Ipv6HopByHopHeaderNotAtStart);
                },
                IPV6_DEST_OPTIONS => {
                    if result.routing.is_some() {
                        // if the routing header is already present
                        // asume this is a "final destination options" header
                        if result.final_destination_options.is_some() {
                            // more then one header of this type found -> abort parsing
                            return Ok((result, next_protocol));
                        } else {
                            let header = Ipv6GenericExtensionHeader::read(reader)?;
                            next_protocol = header.next_header;
                            result.final_destination_options = Some(header);
                        }
                    } else if result.destination_options.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_protocol));
                    } else {
                        let header = Ipv6GenericExtensionHeader::read(reader)?;
                        next_protocol = header.next_header;
                        result.destination_options = Some(header);
                    }
                },
                IPV6_ROUTE => {
                    if result.routing.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_protocol));
                    } else {
                        let header = Ipv6GenericExtensionHeader::read(reader)?;
                        next_protocol = header.next_header;
                        result.routing = Some(header);
                    }
                },
                IPV6_FRAG => {
                    if result.fragment.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_protocol));
                    } else {
                        let header = Ipv6FragmentHeader::read(reader)?;
                        next_protocol = header.next_header;
                        result.fragment = Some(header);
                    }
                },
                AUTH => {
                    if result.fragment.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_protocol));
                    } else {
                        let header = IpAuthenticationHeader::read(reader)?;
                        next_protocol = header.next_header;
                        result.auth = Some(header);
                    }
                },
                _ => {
                    // done parsing, the next header is not a known header extension
                    return Ok((result, next_protocol))
                }
            }
        }

        //should not be hit
    }

    /// Writes the given headers to a writer based on the order defined in the next_header fields of 
    /// the headers and the first header_id passed to this function.
    ///
    /// It is required that all next header are correctly set in the headers and no other ipv6 header 
    /// extensions follow this header. If this is not the case a `ValueError::Ipv6ExtensionNotReferenced`
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T, first_header: u8) -> Result<(), WriteError> {
        use ip_number::*;
        use IpNumber::*;
        use ValueError::*;

        /// Struct flagging if a header needs to be written.
        struct NeedsWrite {
            pub hop_by_hop_options: bool,
            pub destination_options: bool,
            pub routing: bool,
            pub fragment: bool,
            pub auth: bool,
            pub final_destination_options: bool
        }

        impl NeedsWrite {
            fn writes_left(&self) -> bool {
                self.hop_by_hop_options ||
                self.destination_options ||
                self.routing ||
                self.fragment ||
                self.auth ||
                self.final_destination_options
            }
        }

        let mut needs_write = NeedsWrite {
            hop_by_hop_options: self.hop_by_hop_options.is_some(),
            destination_options: self.destination_options.is_some(),
            routing: self.routing.is_some(),
            fragment: self.fragment.is_some(),
            auth: self.auth.is_some(),
            final_destination_options: self.final_destination_options.is_some()
        };

        let mut next_header = first_header;
        let mut route_written = false;

        // check if hop by hop header should be written first
        if IPV6_HOP_BY_HOP == next_header {
            if needs_write.hop_by_hop_options {
                let header = &self.hop_by_hop_options.as_ref().unwrap();
                header.write(writer)?;
                next_header = header.next_header;
                needs_write.hop_by_hop_options = false;
            } else {
                return Err(Ipv6ExtensionNotDefinedReference(IPv6HeaderHopByHop).into());
            }
        }

        while needs_write.writes_left() {
            match next_header {
                IPV6_HOP_BY_HOP => {
                    // the hop by hop header is only allowed at the start
                    return Err(Ipv6ExtensionHopByHopNotAtStart.into());
                },
                IPV6_DEST_OPTIONS => {
                    // the destination options are allowed to be written twice
                    // once before a routing header and once after.
                    if route_written {
                        if needs_write.final_destination_options {
                            let header = &self.final_destination_options.as_ref().unwrap();
                            header.write(writer)?;
                            next_header = header.next_header;
                            needs_write.final_destination_options = false;
                        } else {
                            return Err(Ipv6ExtensionNotDefinedReference(IPv6DestinationOptions).into());
                        }
                    } else if needs_write.destination_options {
                        let header = &self.destination_options.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.destination_options = false;
                    } else {
                        return Err(Ipv6ExtensionNotDefinedReference(IPv6DestinationOptions).into());
                    }
                },
                IPV6_ROUTE => {
                    if needs_write.routing {
                        let header = &self.routing.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.routing = false;
                        // for destination options
                        route_written = true;
                    } else {
                        return Err(Ipv6ExtensionNotDefinedReference(IPv6RouteHeader).into());
                    }
                },
                IPV6_FRAG => {
                    if needs_write.fragment {
                        let header = &self.fragment.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.fragment = false;
                    } else {
                        return Err(Ipv6ExtensionNotDefinedReference(IPv6FragmentationHeader).into());
                    }
                },
                AUTH => {
                    if needs_write.auth {
                        let header = &self.auth.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.auth = false;
                    } else {
                        return Err(Ipv6ExtensionNotDefinedReference(AuthenticationHeader).into());
                    }
                },
                _ => {
                    // reached an unknown next_header id, proceed to check if everything was written
                    break;
                }
            }
        }

        // check that all header have been written
        if needs_write.hop_by_hop_options {
            Err(Ipv6ExtensionNotReferenced(IPv6HeaderHopByHop).into())
        } else if needs_write.destination_options {
            Err(Ipv6ExtensionNotReferenced(IPv6DestinationOptions).into())
        } else if needs_write.routing {
            Err(Ipv6ExtensionNotReferenced(IPv6RouteHeader).into())
        } else if needs_write.fragment {
            Err(Ipv6ExtensionNotReferenced(IPv6FragmentationHeader).into())
        } else if needs_write.auth {
            Err(Ipv6ExtensionNotReferenced(AuthenticationHeader).into())
        } else if needs_write.final_destination_options {
            Err(Ipv6ExtensionNotReferenced(IPv6DestinationOptions).into())
        } else {
            Ok(())
        }
    }

    ///Length of the all present headers in bytes.
    pub fn header_len(&self) -> usize {
        let mut result = 0;

        if let Some(ref header) = self.hop_by_hop_options {
            result += header.header_len();
        }
        if let Some(ref header) = self.destination_options {
            result += header.header_len();
        }
        if let Some(ref header) = self.routing {
            result += header.header_len();
        }
        if let Some(ref header) = self.fragment {
            result += header.header_len();
        }
        if let Some(ref header) = self.auth {
            result += header.header_len();
        }
        if let Some(ref header) = self.final_destination_options {
            result += header.header_len();
        }

        result
    }

    /// Sets all the next_header fields of the headers based on the adviced default order
    /// with the given protocol number as last "next header" value. The return value is the protocol
    /// number of the first existing extension header that should be entered in the ipv6 header as
    /// next_header.
    ///
    /// If no extension headers are present the value of the argument is returned.
    pub fn set_next_headers(&mut self, last_protocol_number: u8) -> u8 {
        use ip_number::*;

        let mut next = last_protocol_number;

        if let Some(ref mut header) = self.hop_by_hop_options {
            header.next_header = next;
            next = IPV6_HOP_BY_HOP;
        }
        if let Some(ref mut header) = self.destination_options {
            header.next_header = next;
            next = IPV6_DEST_OPTIONS;
        }
        if let Some(ref mut header) = self.routing {
            header.next_header = next;
            next = IPV6_ROUTE;
        }
        if let Some(ref mut header) = self.fragment {
            header.next_header = next;
            next = IPV6_FRAG;
        }
        if let Some(ref mut header) = self.auth {
            header.next_header = next;
            next = AUTH;
        }
        if let Some(ref mut header) = self.final_destination_options {
            header.next_header = next;
            next = IPV6_DEST_OPTIONS;
        }

        next
    }
}

impl<'a> Ipv6ExtensionSlices<'a> {
    /// Reads as many extension headers as possible from the slice and returns the found 
    /// ipv6 extension header slices, the next header ip number and the slice that should
    /// contain the content of the next header as well as the rest of the packet.
    ///
    /// Note that this function can only handle ipv6 extensions if each extension header does 
    /// occur at most once, except for destination options headers which are allowed to 
    /// exist once in front of a routing header and once after a routing header.
    ///
    /// In case that more extension headers then can fit into a `Ipv6Extensions` struct are
    /// encountered, the parsing is stoped at the point where the data would no longer fit into
    /// the struct. In such a scenario a struct with the data that could be parsed is returned
    /// together with the next header ip number and slice containing the unparsed data.
    ///
    /// It is in the responsibility of the caller to handle a scenario like this.
    ///
    /// The reason that no error is generated, is that even though according to RFC 8200 packets 
    /// "should" not contain more then one occurence of an extension header the RFC also specifies
    /// that "IPv6 nodes must accept and attempt to process extension headers in any order and 
    /// occurring any number of times in the same packet". So packets with multiple headers "should"
    /// not exist, but are still valid IPv6 packets. As such this function does not generate a
    /// parsing error, as it is not an invalid packet, but if packets like these are encountered
    /// the user of this function has to themself decide how to handle packets like these.
    ///
    /// The only exception is if an hop by hop header is located somewhere else then directly at 
    /// the start. In this case an `ReadError::Ipv6HopByHopHeaderNotAtStart` error is generated as
    /// the hop by hop header is required to be located directly after the IPv6 header according 
    /// to RFC 8200.
    pub fn from_slice(start_ip_number: u8, start_slice: &'a [u8]) -> Result<(Ipv6ExtensionSlices, u8, &'a[u8]), ReadError> {
        let mut result: Ipv6ExtensionSlices = Default::default();
        let mut rest = start_slice;
        let mut next_header = start_ip_number;

        use ip_number::*;
        use ReadError::*;

        // the hop by hop header is required to occur directly after the ipv6 header
        if IPV6_HOP_BY_HOP == next_header {
            let slice = Ipv6GenericExtensionHeaderSlice::from_slice(rest)?;
            rest = &rest[slice.slice().len()..];
            next_header = slice.next_header();
            result.hop_by_hop_options = Some(slice);   
        }

        loop {
            match next_header {
                IPV6_HOP_BY_HOP => {
                    return Err(Ipv6HopByHopHeaderNotAtStart);
                },
                IPV6_DEST_OPTIONS => {
                    if result.routing.is_some() {
                        // if the routing header is already present
                        // this this a "final destination options" header
                        if result.final_destination_options.is_some() {
                            // more then one header of this type found -> abort parsing
                            return Ok((result, next_header, rest))
                        } else {
                            let slice = Ipv6GenericExtensionHeaderSlice::from_slice(rest)?;
                            rest = &rest[slice.slice().len()..];
                            next_header = slice.next_header();
                            result.final_destination_options = Some(slice);
                        }
                    } else if result.destination_options.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest));
                    } else {
                        let slice = Ipv6GenericExtensionHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.destination_options = Some(slice);
                    }
                },
                IPV6_ROUTE => {
                    if result.routing.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest))
                    } else {
                        let slice = Ipv6GenericExtensionHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.routing = Some(slice);
                    }
                },
                IPV6_FRAG => {
                    if result.fragment.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest))
                    } else {
                        let slice = Ipv6FragmentHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.fragment = Some(slice);
                    }
                },
                AUTH => {
                    if result.fragment.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest))
                    } else {
                        let slice = IpAuthenticationHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.auth = Some(slice);
                    }
                },
                _ => {
                    // done parsing, the next header is not a known header extension
                    return Ok((result, next_header, rest))
                }
            }
        }

        //should not be hit
    }

    /// Convert the slices into headers
    pub fn to_header(&self) -> Ipv6Extensions {
        Ipv6Extensions {
            hop_by_hop_options: match self.hop_by_hop_options {
                None => None,
                Some(ref slice) => Some(slice.to_header())
            },
            destination_options: match self.destination_options {
                None => None,
                Some(ref slice) => Some(slice.to_header())
            },
            routing: match self.routing {
                None => None,
                Some(ref slice) => Some(slice.to_header())
            },
            fragment: match self.fragment {
                None => None,
                Some(ref slice) => Some(slice.to_header())
            },
            auth: match self.auth {
                None => None,
                Some(ref slice) => Some(slice.to_header())
            },
            final_destination_options: match self.final_destination_options {
                None => None,
                Some(ref slice) => Some(slice.to_header())
            },
        }
    }
}
