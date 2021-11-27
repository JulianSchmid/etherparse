use super::super::*;
use std::slice::from_raw_parts;

/// IPv6 extension headers present after the ip header.
///
/// Currently supported:
///
/// * Authentication Header
/// * Hop by Hop Options Header
/// * Destination Options Header (before and after routing headers)
/// * Routing Header
/// * Fragment
/// * Authentication Header
///
/// Currently not supported:
////
/// * Encapsulating Security Payload Header (ESP)
/// * Host Identity Protocol (HIP)
/// * IP Mobility
/// * Site Multihoming by IPv6 Intermediation (SHIM6)
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Ipv6Extensions {
    pub hop_by_hop_options: Option<Ipv6RawExtensionHeader>,
    pub destination_options: Option<Ipv6RawExtensionHeader>,
    pub routing: Option<Ipv6RoutingExtensions>,
    pub fragment: Option<Ipv6FragmentHeader>,
    pub auth: Option<IpAuthenticationHeader>,
}

impl Ipv6Extensions {

    /// Reads as many extension headers as possible from the slice.
    ///
    /// Returns the found ipv6 extension headers, the next header ip number after the read
    /// headers and a slice containing the rest of the packet after the read headers.
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
    pub fn from_slice(start_ip_number: u8, slice: &[u8]) -> Result<(Ipv6Extensions, u8, &[u8]), ReadError> {
        let mut result: Ipv6Extensions = Default::default();
        let mut rest = slice;
        let mut next_header = start_ip_number;

        use ip_number::*;
        use ReadError::*;

        // the hop by hop header is required to occur directly after the ipv6 header
        if IPV6_HOP_BY_HOP == next_header {
            let slice = Ipv6RawExtensionHeaderSlice::from_slice(rest)?;
            rest = &rest[slice.slice().len()..];
            next_header = slice.next_header();
            result.hop_by_hop_options = Some(slice.to_header());   
        }

        loop {
            match next_header {
                IPV6_HOP_BY_HOP => {
                    return Err(Ipv6HopByHopHeaderNotAtStart);
                },
                IPV6_DEST_OPTIONS => {
                    if let Some(ref mut routing) = result.routing {
                        // if the routing header is already present
                        // this this a "final destination options" header
                        if routing.final_destination_options.is_some() {
                            // more then one header of this type found -> abort parsing
                            return Ok((result, next_header, rest))
                        } else {
                            let slice = Ipv6RawExtensionHeaderSlice::from_slice(rest)?;
                            rest = &rest[slice.slice().len()..];
                            next_header = slice.next_header();
                            routing.final_destination_options = Some(slice.to_header());
                        }
                    } else if result.destination_options.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest));
                    } else {
                        let slice = Ipv6RawExtensionHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.destination_options = Some(slice.to_header());
                    }
                },
                IPV6_ROUTE => {
                    if result.routing.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest))
                    } else {
                        let slice = Ipv6RawExtensionHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.routing = Some(
                            Ipv6RoutingExtensions {
                                routing: slice.to_header(),
                                final_destination_options: None,
                            }
                        );
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
                        result.fragment = Some(slice.to_header());
                    }
                },
                AUTH => {
                    if result.auth.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_header, rest))
                    } else {
                        let slice = IpAuthenticationHeaderSlice::from_slice(rest)?;
                        rest = &rest[slice.slice().len()..];
                        next_header = slice.next_header();
                        result.auth = Some(slice.to_header());
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

    /// Reads as many extension headers as possible from the reader and returns the found ipv6
    /// extension headers and the next header ip number.
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
    pub fn read<T: io::Read + io::Seek + Sized>(reader: &mut T, start_ip_number: u8) -> Result<(Ipv6Extensions, u8), ReadError> {
        let mut result: Ipv6Extensions = Default::default();
        let mut next_protocol = start_ip_number;

        use ip_number::*;
        use ReadError::*;

        // the hop by hop header is required to occur directly after the ipv6 header
        if IPV6_HOP_BY_HOP == next_protocol {
            let header = Ipv6RawExtensionHeader::read(reader)?;
            next_protocol = header.next_header;
            result.hop_by_hop_options = Some(header);   
        }

        loop {
            match next_protocol {
                IPV6_HOP_BY_HOP => {
                    return Err(Ipv6HopByHopHeaderNotAtStart);
                },
                IPV6_DEST_OPTIONS => {
                    if let Some(ref mut routing) = result.routing {
                        // if the routing header is already present
                        // asume this is a "final destination options" header
                        if routing.final_destination_options.is_some() {
                            // more then one header of this type found -> abort parsing
                            return Ok((result, next_protocol));
                        } else {
                            let header = Ipv6RawExtensionHeader::read(reader)?;
                            next_protocol = header.next_header;
                            routing.final_destination_options = Some(header);
                        }
                    } else if result.destination_options.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_protocol));
                    } else {
                        let header = Ipv6RawExtensionHeader::read(reader)?;
                        next_protocol = header.next_header;
                        result.destination_options = Some(header);
                    }
                },
                IPV6_ROUTE => {
                    if result.routing.is_some() {
                        // more then one header of this type found -> abort parsing
                        return Ok((result, next_protocol));
                    } else {
                        let header = Ipv6RawExtensionHeader::read(reader)?;
                        next_protocol = header.next_header;
                        result.routing = Some(
                            Ipv6RoutingExtensions{
                                routing: header,
                                final_destination_options: None,
                            }
                        );
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
                    if result.auth.is_some() {
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

        let mut needs_write = NeedsWrite {
            hop_by_hop_options: self.hop_by_hop_options.is_some(),
            destination_options: self.destination_options.is_some(),
            routing: self.routing.is_some(),
            fragment: self.fragment.is_some(),
            auth: self.auth.is_some(),
            final_destination_options: if let Some(ref routing) = self.routing {
                routing.final_destination_options.is_some()
            } else {
                false
            }
        };

        let mut next_header = first_header;
        let mut route_written = false;

        // check if hop by hop header should be written first
        if IPV6_HOP_BY_HOP == next_header {
            let header = &self.hop_by_hop_options.as_ref().unwrap();
            header.write(writer)?;
            next_header = header.next_header;
            needs_write.hop_by_hop_options = false;
        }

        loop {
            match next_header {
                IPV6_HOP_BY_HOP => {
                    // Only trigger a "hop by hop not at start" error
                    // if we actually still have to write a hop by hop header.
                    //
                    // The ip number for hop by hop is 0, which could be used
                    // as a placeholder by user and later replaced. So let's
                    // not be overzealous and allow a next header with hop
                    // by hop if it is not part of this extensions struct.
                    if needs_write.hop_by_hop_options {
                        // the hop by hop header is only allowed at the start
                        return Err(Ipv6ExtensionHopByHopNotAtStart.into());
                    } else {
                        break;
                    }
                },
                IPV6_DEST_OPTIONS => {
                    // the destination options are allowed to be written twice
                    // once before a routing header and once after.
                    if route_written {
                        if needs_write.final_destination_options {
                            let header = &self.routing.as_ref().unwrap().final_destination_options.as_ref().unwrap();
                            header.write(writer)?;
                            next_header = header.next_header;
                            needs_write.final_destination_options = false;
                        } else {
                            break;
                        }
                    } else if needs_write.destination_options {
                        let header = &self.destination_options.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.destination_options = false;
                    } else {
                        break;
                    }
                },
                IPV6_ROUTE => {
                    if needs_write.routing {
                        let header = &self.routing.as_ref().unwrap().routing;
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.routing = false;
                        // for destination options
                        route_written = true;
                    } else {
                        break;
                    }
                },
                IPV6_FRAG => {
                    if needs_write.fragment {
                        let header = &self.fragment.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.fragment = false;
                    } else {
                        break;
                    }
                },
                AUTH => {
                    if needs_write.auth {
                        let header = &self.auth.as_ref().unwrap();
                        header.write(writer)?;
                        next_header = header.next_header;
                        needs_write.auth = false;
                    } else {
                        break;
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

    /// Length of the all present headers in bytes.
    pub fn header_len(&self) -> usize {
        let mut result = 0;

        if let Some(ref header) = self.hop_by_hop_options {
            result += header.header_len();
        }
        if let Some(ref header) = self.destination_options {
            result += header.header_len();
        }
        if let Some(ref header) = self.routing {
            result += header.routing.header_len();
            if let Some(ref header) = header.final_destination_options {
                result += header.header_len();
            }
        }
        if let Some(ref header) = self.fragment {
            result += header.header_len();
        }
        if let Some(ref header) = self.auth {
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

        // go through the proposed order of extension headers from
        // RFC 8200 backwards. The header order defined in RFC8200 is:
        //
        // * IPv6 header
        // * Hop-by-Hop Options header
        // * Destination Options header
        // * Routing header
        // * Fragment header
        // * Authentication header
        // * Encapsulating Security Payload header
        // * Destination Options header
        // * Upper-Layer header
        //
        if let Some(ref mut routing) = self.routing {
            if let Some(ref mut header) = routing.final_destination_options {
                header.next_header = next;
                next = IPV6_DEST_OPTIONS;
            }
        }
        if let Some(ref mut header) = self.auth {
            header.next_header = next;
            next = AUTH;
        }
        if let Some(ref mut header) = self.fragment {
            header.next_header = next;
            next = IPV6_FRAG;
        }
        if let Some(ref mut routing) = self.routing {
            routing.routing.next_header = next;
            next = IPV6_ROUTE;
        }
        if let Some(ref mut header) = self.destination_options {
            header.next_header = next;
            next = IPV6_DEST_OPTIONS;
        }
        if let Some(ref mut header) = self.hop_by_hop_options {
            header.next_header = next;
            next = IPV6_HOP_BY_HOP;
        }

        next
    }

    /// Return next header based on the extension headers and
    /// the first ip protocol number.
    pub fn next_header(&self, first_next_header: u8) -> Result<u8, ValueError> {
        use ValueError::*;
        use ip_number::*;

        /// Struct flagging if a header needs to be referenced.
        struct OutstandingRef {
            pub hop_by_hop_options: bool,
            pub destination_options: bool,
            pub routing: bool,
            pub fragment: bool,
            pub auth: bool,
            pub final_destination_options: bool
        }

        let mut outstanding_refs = OutstandingRef {
            hop_by_hop_options: self.hop_by_hop_options.is_some(),
            destination_options: self.destination_options.is_some(),
            routing: self.routing.is_some(),
            fragment: self.fragment.is_some(),
            auth: self.auth.is_some(),
            final_destination_options: if let Some(ref routing) = self.routing {
                routing.final_destination_options.is_some()
            } else {
                false
            }
        };

        let mut next = first_next_header;
        let mut route_refed = false;

        // check if hop by hop header should be written first
        if IPV6_HOP_BY_HOP == next {
            if let Some(ref header) = self.hop_by_hop_options {
                next = header.next_header;
                outstanding_refs.hop_by_hop_options = false;
            }
        }

        loop {
            match next {
                IPV6_HOP_BY_HOP => {
                    // Only trigger a "hop by hop not at start" error
                    // if we actually still have to write a hop by hop header.
                    //
                    // The ip number for hop by hop is 0, which could be used
                    // as a placeholder by user and later replaced. So let's
                    // not be overzealous and allow a next header with hop
                    // by hop if it is not part of this extensions struct.
                    if outstanding_refs.hop_by_hop_options {
                        // the hop by hop header is only allowed at the start
                        return Err(Ipv6ExtensionHopByHopNotAtStart);
                    } else {
                        break;
                    }
                },
                IPV6_DEST_OPTIONS => {
                    // the destination options are allowed to be written twice
                    // once before a routing header and once after.
                    if route_refed {
                        if outstanding_refs.final_destination_options {
                            let header = &self.routing.as_ref().unwrap().final_destination_options.as_ref().unwrap();
                            next = header.next_header;
                            outstanding_refs.final_destination_options = false;
                        } else {
                            break;
                        }
                    } else if outstanding_refs.destination_options {
                        let header = &self.destination_options.as_ref().unwrap();
                        next = header.next_header;
                        outstanding_refs.destination_options = false;
                    } else {
                        break;
                    }
                },
                IPV6_ROUTE => {
                    if outstanding_refs.routing {
                        let header = &self.routing.as_ref().unwrap().routing;
                        next = header.next_header;
                        outstanding_refs.routing = false;
                        // for destination options
                        route_refed = true;
                    } else {
                        break;
                    }
                },
                IPV6_FRAG => {
                    if outstanding_refs.fragment {
                        let header = &self.fragment.as_ref().unwrap();
                        next = header.next_header;
                        outstanding_refs.fragment = false;
                    } else {
                        break;
                    }
                },
                AUTH => {
                    if outstanding_refs.auth {
                        let header = &self.auth.as_ref().unwrap();
                        next = header.next_header;
                        outstanding_refs.auth = false;
                    } else {
                        break;
                    }
                },
                _ => break,
            }
        }

        // assume all done
        if outstanding_refs.hop_by_hop_options {
            return Err(
                Ipv6ExtensionNotReferenced(IpNumber::IPv6HeaderHopByHop)
            );
        }
        if outstanding_refs.destination_options {
            return Err(
                Ipv6ExtensionNotReferenced(IpNumber::IPv6DestinationOptions)
            );
        }
        if outstanding_refs.routing {
            return Err(
                Ipv6ExtensionNotReferenced(IpNumber::IPv6RouteHeader)
            );
        }
        if outstanding_refs.fragment {
            return Err(
                Ipv6ExtensionNotReferenced(IpNumber::IPv6FragmentationHeader)
            );
        }
        if outstanding_refs.auth {
            return Err(
                Ipv6ExtensionNotReferenced(IpNumber::AuthenticationHeader)
            );
        }
        if outstanding_refs.final_destination_options {
            return Err(
                Ipv6ExtensionNotReferenced(IpNumber::IPv6DestinationOptions)
            );
        }

        Ok(next)
    }
}

/// In case a route header is present it is also possible
/// to attach a "final destination" header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6RoutingExtensions {
    pub routing: Ipv6RawExtensionHeader,
    pub final_destination_options: Option<Ipv6RawExtensionHeader>
}

/// Slice containing the IPv6 extension headers present after the ip header.
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
pub struct Ipv6ExtensionsSlice<'a> {
    /// IP protocol number of the first header present in the slice.
    first_header: Option<u8>,
    /// True if a fragment header is present in the ipv6 header extensions that causes the payload to be fragmented.
    fragmented: bool,
    /// Slice containing ipv6 extension headers.
    slice: &'a [u8]
}

impl<'a> Ipv6ExtensionsSlice<'a> {

    /// Collects all ipv6 extension headers in a slice & checks if
    /// a fragmentation header that fragments the packet is present.
    pub fn from_slice(start_ip_number: u8, start_slice: &'a [u8]) -> Result<(Ipv6ExtensionsSlice, u8, &'a[u8]), ReadError> {
        let mut rest = start_slice;
        let mut next_header = start_ip_number;
        let mut fragmented = false;

        use ip_number::*;
        use ReadError::*;

        // the hop by hop header is required to occur directly after the ipv6 header
        if IPV6_HOP_BY_HOP == next_header {
            let slice = Ipv6RawExtensionHeaderSlice::from_slice(rest)?;
            rest = &rest[slice.slice().len()..];
            next_header = slice.next_header();
        }
 
        loop {
            match next_header {
                IPV6_HOP_BY_HOP => {
                    return Err(Ipv6HopByHopHeaderNotAtStart);
                },
                IPV6_DEST_OPTIONS | IPV6_ROUTE => {
                    let slice = Ipv6RawExtensionHeaderSlice::from_slice(rest)?;
                    // SAFETY:
                    // Ipv6RawExtensionHeaderSlice::from_slice always generates
                    // a subslice from the given slice rest. Therefor it is guranteed
                    // that len is always greater or equal the len of rest.
                    rest = unsafe {
                        let len = slice.slice().len();
                        from_raw_parts(
                            rest.as_ptr().add(len),
                            rest.len() - len
                        )
                    };
                    next_header = slice.next_header();
                },
                IPV6_FRAG => {
                    let slice = Ipv6FragmentHeaderSlice::from_slice(rest)?;
                    // SAFETY:
                    // Ipv6FragmentHeaderSlice::from_slice always generates
                    // a subslice from the given slice rest. Therefor it is guranteed
                    // that len is always greater or equal the len of rest.
                    rest = unsafe {
                        let len = slice.slice().len();
                        from_raw_parts(
                            rest.as_ptr().add(len),
                            rest.len() - len
                        )
                    };
                    next_header = slice.next_header();

                    // check if the fragment header actually causes fragmentation
                    fragmented = fragmented || slice.is_fragmenting_payload();
                },
                AUTH => {
                    let slice = IpAuthenticationHeaderSlice::from_slice(rest)?;
                    // SAFETY:
                    // IpAuthenticationHeaderSlice::from_slice always generates
                    // a subslice from the given slice rest. Therefor it is guranteed
                    // that len is always greater or equal the len of rest.
                    rest = unsafe {
                        let len = slice.slice().len();
                        from_raw_parts(
                            rest.as_ptr().add(len),
                            rest.len() - len
                        )
                    };
                    next_header = slice.next_header();
                },
                // done parsing, the next header is not a known/supported header extension
                _ => break,
            }
        }

        Ok((Ipv6ExtensionsSlice{
            first_header: if rest.len() != start_slice.len() {
                Some(start_ip_number)
            } else {
                None
            },
            fragmented,
            slice: &start_slice[..start_slice.len() - rest.len()],
        }, next_header, rest))
    }

    /// Returns true if a fragmentation header is present in
    /// the extensions that fragments the payload.
    ///
    /// Note: A fragmentation header can still be present
    /// even if the return value is false in case the fragmentation
    /// headers don't fragment the payload. This is the case if
    /// the offset of all fragmentation header is 0 and the
    /// more fragment bit is not set.
    #[inline]
    pub fn is_fragmenting_payload(&self) -> bool {
        self.fragmented
    }

    /// Returns the ip protocol number of the first header in the slice
    /// if the slice contains an ipv6 extension header. If no ipv6 header
    /// is present None is returned.
    ///
    /// None is only returned if the slice length of this struct is 0.
    #[inline]
    pub fn first_header(&self) -> Option<u8> {
        self.first_header
    }

    /// Slice containing the ipv6 extension headers.
    #[inline]
    pub fn slice(&self) -> &'a[u8] {
        self.slice
    }
}

/// Enum containing a slice of a supported ipv6 extension header.
///
/// This enum is used as item type when iterating over a list of extension headers
/// with an [Ipv6ExtensionSliceIter].
///
/// Note the following extension headers are missing from
/// this enum and currently not supported (list taken on 2021-07-17
/// from <https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml>):
///
/// * Encapsulating Security Payload \[[RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)\]
/// * Mobility Header \[[RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)\]
/// * Host Identity Protocol \[[RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)\]
/// * Shim6 Protocol \[[RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)\]
/// * 253 Use for experimentation and testing \[[RFC3692](https://datatracker.ietf.org/doc/html/rfc3692)\]\[[RFC4727](https://datatracker.ietf.org/doc/html/rfc4727)\]
/// * 254 Use for experimentation and testing \[[RFC3692](https://datatracker.ietf.org/doc/html/rfc3692)\]\[[RFC4727](https://datatracker.ietf.org/doc/html/rfc4727)\]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ipv6ExtensionSlice<'a> {
    /// IPv6 Hop-by-Hop Option \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    HopByHop(Ipv6RawExtensionHeaderSlice<'a>),
    /// Routing Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\] \[[RFC5095](https://datatracker.ietf.org/doc/html/rfc5095)\]
    Routing(Ipv6RawExtensionHeaderSlice<'a>),
    /// Fragment Header for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    Fragment(Ipv6FragmentHeaderSlice<'a>),
    /// Destination Options for IPv6 \[[RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)\]
    DestinationOptions(Ipv6RawExtensionHeaderSlice<'a>),
    /// Authentication Header \[[RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)\]
    Authentication(IpAuthenticationHeaderSlice<'a>),
}

impl<'a> IntoIterator for Ipv6ExtensionsSlice<'a> {
    type Item = Ipv6ExtensionSlice<'a>;
    type IntoIter = Ipv6ExtensionSliceIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Ipv6ExtensionSliceIter {
            // map the next header None value to some non ipv6 ext header
            // value.
            next_header: self.first_header.unwrap_or(ip_number::UDP),
            rest: self.slice,
        }
    }
}

/// Allows iterating over the IPv6 extension headers present in an [Ipv6ExtensionsSlice].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6ExtensionSliceIter<'a> {
    next_header: u8,
    rest: &'a [u8],
}

impl<'a> Default for Ipv6ExtensionSliceIter<'a> {
    fn default() -> Self {
        Ipv6ExtensionSliceIter {
            // don't use 0 as this is the reserved value
            // for the hop by hop header
            next_header: IpNumber::IPv6NoNextHeader as u8,
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
                let slice = Ipv6RawExtensionHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(
                    self.rest.as_ptr().add(len),
                    self.rest.len() - len
                );
                self.next_header = slice.next_header();
                Some(HopByHop(slice))
            },
            IPV6_ROUTE => unsafe {
                let slice = Ipv6RawExtensionHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(
                    self.rest.as_ptr().add(len),
                    self.rest.len() - len
                );
                self.next_header = slice.next_header();
                Some(Routing(slice))
            },
            IPV6_DEST_OPTIONS => unsafe {
                let slice = Ipv6RawExtensionHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(
                    self.rest.as_ptr().add(len),
                    self.rest.len() - len
                );
                self.next_header = slice.next_header();
                Some(DestinationOptions(slice))
            },
            IPV6_FRAG => unsafe {
                let slice = Ipv6FragmentHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(
                    self.rest.as_ptr().add(len),
                    self.rest.len() - len
                );
                self.next_header = slice.next_header();

                Some(Fragment(slice))
            },
            AUTH => unsafe {
                let slice = IpAuthenticationHeaderSlice::from_slice_unchecked(self.rest);
                let len = slice.slice().len();
                self.rest = from_raw_parts(
                    self.rest.as_ptr().add(len),
                    self.rest.len() - len
                );
                self.next_header = slice.next_header();
                Some(Authentication(slice))
            },
            // done parsing, the next header is not a known/supported header extension
            _ => None,
        }
    }
}
