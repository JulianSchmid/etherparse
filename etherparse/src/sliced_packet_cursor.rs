use crate::{*, err::LenSource, link::ether_payload_slice::EtherPayloadSlice};


/// Helper class for slicing packets
pub(crate) struct SlicedPacketCursor<'a> {
    pub slice: &'a [u8],
    pub offset: usize,
    pub len_source: LenSource,
    pub result: SlicedPacket<'a>,
}

impl<'a> SlicedPacketCursor<'a> {
    pub fn new(slice: &'a [u8]) -> SlicedPacketCursor<'a> {
        SlicedPacketCursor {
            slice,
            offset: 0,
            len_source: LenSource::Slice,
            result: SlicedPacket {
                link: None,
                vlan: None,
                ip: None,
                transport: None,
                payload: PayloadSlice::Ether(EtherPayloadSlice{
                    ether_type: EtherType(0),
                    payload: slice,
                }),
            },
        }
    }

    fn move_by_slice(&mut self, other: &'a [u8]) {
        unsafe {
            use core::slice::from_raw_parts;
            self.slice = from_raw_parts(
                self.slice.as_ptr().add(other.len()),
                self.slice.len() - other.len(),
            );
        }
        self.offset += other.len();
    }

    pub fn slice_ethernet2(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use LinkSlice::*;

        let result = Ethernet2HeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //cache the ether_type for later
        let ether_type = result.ether_type();

        //set the new data
        self.move_by_slice(result.slice());
        self.result.link = Some(Ethernet2(result));

        //continue parsing (if required)
        match ether_type {
            IPV4 => self.slice_ipv4(),
            IPV6 => self.slice_ipv6(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => self.slice_vlan(),
            _ => {
                self.result.payload = PayloadSlice::Ether(EtherPayloadSlice{
                    ether_type,
                    payload: self.slice,
                });
                Ok(self.result)
            },
        }
    }

    pub fn slice_ethernet2_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use LinkSlice::*;

        let result = Ethernet2HeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //cache the ether_type for later
        let ether_type = result.ether_type();

        //set the new data
        self.move_by_slice(result.slice());
        self.result.link = Some(Ethernet2(result));

        //continue parsing (if required)
        match ether_type {
            IPV4 => self.slice_ipv4_lax(),
            IPV6 => self.slice_ipv6_lax(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                self.slice_vlan_lax()
            }
            _ => {
                self.result.payload = PayloadSlice::Ether(EtherPayloadSlice{
                    ether_type,
                    payload: self.slice,
                });
                Ok(self.result)
            },
        }
    }

    pub fn slice_vlan(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use VlanSlice::*;

        // cache the starting slice so the later combining
        // of outer & inner vlan is defined behavior (for miri)
        let outer_start_slice = self.slice;
        let outer = SingleVlanHeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //check if it is a double vlan header
        match outer.ether_type() {
            //in case of a double vlan header continue with the inner
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                self.move_by_slice(outer.slice());
                let inner = SingleVlanHeaderSlice::from_slice(self.slice)
                    .map_err(|err| Len(err.add_offset(self.offset)))?;
                self.move_by_slice(inner.slice());

                let inner_ether_type = inner.ether_type();
                self.result.vlan = Some(DoubleVlan(DoubleVlanHeaderSlice {
                    // SAFETY: Safe as the lenght of the slice was previously verified.
                    slice: unsafe {
                        core::slice::from_raw_parts(
                            outer_start_slice.as_ptr(),
                            outer.slice().len() + inner.slice().len(),
                        )
                    },
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ipv4(),
                    IPV6 => self.slice_ipv6(),
                    ether_type => {
                        self.result.payload = PayloadSlice::Ether(EtherPayloadSlice{
                            ether_type,
                            payload: self.slice,
                        });
                        Ok(self.result)
                    },
                }
            }
            value => {
                //set the vlan header and continue the normal parsing
                self.move_by_slice(outer.slice());
                self.result.vlan = Some(SingleVlan(outer));

                match value {
                    IPV4 => self.slice_ipv4(),
                    IPV6 => self.slice_ipv6(),
                    ether_type => {
                        self.result.payload = PayloadSlice::Ether(EtherPayloadSlice{
                            ether_type,
                            payload: self.slice
                        });
                        Ok(self.result)
                    },
                }
            }
        }
    }

    pub fn slice_vlan_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;
        use ether_type::*;
        use VlanSlice::*;

        let outer = SingleVlanHeaderSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //check if it is a double vlan header
        match outer.ether_type() {
            //in case of a double vlan header continue with the inner
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                self.move_by_slice(outer.slice());
                let inner = SingleVlanHeaderSlice::from_slice(self.slice)
                    .map_err(|err| Len(err.add_offset(self.offset)))?;
                self.move_by_slice(inner.slice());

                let inner_ether_type = inner.ether_type();
                self.result.vlan = Some(DoubleVlan(DoubleVlanHeaderSlice {
                    // SAFETY: Safe as the lenght of the slice was previously verified.
                    slice: unsafe {
                        core::slice::from_raw_parts(
                            outer.slice().as_ptr(),
                            outer.slice().len() + inner.slice().len(),
                        )
                    },
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ipv4_lax(),
                    IPV6 => self.slice_ipv6_lax(),
                    ether_type => {
                        self.result.payload = PayloadSlice::Ether(EtherPayloadSlice{
                            ether_type,
                            payload:self.slice,
                        });
                        Ok(self.result)
                    },
                }
            }
            value => {
                //set the vlan header and continue the normal parsing
                self.move_by_slice(outer.slice());
                self.result.vlan = Some(SingleVlan(outer));

                match value {
                    IPV4 => self.slice_ipv4(),
                    IPV6 => self.slice_ipv6(),
                    ether_type => {
                        self.result.payload = PayloadSlice::Ether(EtherPayloadSlice{
                            ether_type,
                            payload: self.slice,
                        });
                        Ok(self.result)
                    },
                }
            }
        }
    }

    pub fn slice_ip(mut self) -> Result<SlicedPacket<'a>, err::packet::IpSliceError> {
        use err::packet::IpSliceError::*;

        // slice header, extension headers and identify payload range
        let ip = IpSlice::from_ip_slice(self.slice).map_err(|err| {
            use err::ip::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::IpHeaders(err) => Ip(err),
            }
        })?;

        // safe data needed
        let payload = ip.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(ip);

        // continue to the lower layers
        if payload.fragmented {
            self.result.payload = PayloadSlice::Ip(payload);
            Ok(self.result)
        } else {
            match payload.ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
                    }
                }),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                _ => {
                    self.result.payload = PayloadSlice::Ip(payload);
                    Ok(self.result)
                }
            }
        }
    }

    pub fn slice_ip_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::IpSliceError> {
        use err::packet::IpSliceError::*;

        // slice header, extension headers and identify payload range
        let ip = IpSlice::from_ip_slice_lax(self.slice).map_err(|err| {
            use err::ip::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::IpHeaders(err) => Ip(err),
            }
        })?;

        // safe data needed
        let payload = ip.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(ip);

        // continue to the lower layers
        if payload.fragmented {
            self.result.payload = PayloadSlice::Ip(payload);
            Ok(self.result)
        } else {
            match payload.ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
                    }
                }),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                _ => {
                    self.result.payload = PayloadSlice::Ip(payload);
                    Ok(self.result)
                }
            }
        }
    }

    pub fn slice_ipv4(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        // slice ipv4 header & extension headers
        let ipv4 = Ipv4Slice::from_slice(self.slice).map_err(|err| {
            use err::ipv4::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv4(err),
                I::Exts(err) => Ipv4Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload = ipv4.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(IpSlice::Ipv4(ipv4));

        if payload.fragmented {
            self.result.payload = PayloadSlice::Ip(payload);
            Ok(self.result)
        } else {
            match payload.ip_number {
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
                    }
                }),
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                _ => {
                    self.result.payload = PayloadSlice::Ip(payload);
                    Ok(self.result)
                }
            }
        }
    }

    pub fn slice_ipv4_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        // slice ipv4 header & extension headers
        let ipv4 = Ipv4Slice::from_slice_lax(self.slice).map_err(|err| {
            use err::ipv4::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv4(err),
                I::Exts(err) => Ipv4Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload = ipv4.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            payload.payload.as_ptr().offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = payload.len_source;
        self.slice = payload.payload;
        self.result.ip = Some(IpSlice::Ipv4(ipv4));

        if payload.fragmented {
            self.result.payload = PayloadSlice::Ip(payload);
            Ok(self.result)
        } else {
            match payload.ip_number {
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
                    }
                }),
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                _ => {
                    self.result.payload = PayloadSlice::Ip(payload);
                    Ok(self.result)
                }
            }
        }
    }

    pub fn slice_ipv6(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        let ipv6 = Ipv6Slice::from_slice(self.slice).map_err(|err| {
            use err::ipv6::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv6(err),
                I::Exts(err) => Ipv6Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload = ipv6.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            ipv6.payload()
                .payload
                .as_ptr()
                .offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = ipv6.payload().len_source;
        self.slice = ipv6.payload().payload;
        self.result.ip = Some(IpSlice::Ipv6(ipv6));

        // only try to decode the transport layer if the payload
        // is not fragmented
        if payload.fragmented {
            self.result.payload = PayloadSlice::Ip(payload);
            Ok(self.result)
        } else {
            //parse the data bellow
            match payload.ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
                    }
                }),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                _ => {
                    self.result.payload = PayloadSlice::Ip(payload);
                    Ok(self.result)
                }
            }
        }
    }

    pub fn slice_ipv6_lax(mut self) -> Result<SlicedPacket<'a>, err::packet::EthSliceError> {
        use err::packet::EthSliceError::*;

        let ipv6 = Ipv6Slice::from_slice_lax(self.slice).map_err(|err| {
            use err::ipv6::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::Header(err) => Ipv6(err),
                I::Exts(err) => Ipv6Exts(err),
            }
        })?;

        // safe data needed in following steps
        let payload = ipv6.payload().clone();

        // set the new data
        self.offset += unsafe {
            // SAFETY: The payload is a subslice of self.slice.
            // therefor calculating the offset from it is safe and
            // the result should always be a positive number.
            ipv6.payload()
                .payload
                .as_ptr()
                .offset_from(self.slice.as_ptr()) as usize
        };
        self.len_source = ipv6.payload().len_source;
        self.slice = ipv6.payload().payload;
        self.result.ip = Some(IpSlice::Ipv6(ipv6));

        // only try to decode the transport layer if the payload
        // is not fragmented
        if payload.fragmented {
            self.result.payload = PayloadSlice::Ip(payload);
            Ok(self.result)
        } else {
            //parse the data bellow
            match payload.ip_number {
                ip_number::ICMP => self.slice_icmp4().map_err(Len),
                ip_number::UDP => self.slice_udp().map_err(Len),
                ip_number::TCP => self.slice_tcp().map_err(|err| {
                    use err::tcp::HeaderSliceError as I;
                    match err {
                        I::Len(err) => Len(err),
                        I::Content(err) => Tcp(err),
                    }
                }),
                ip_number::IPV6_ICMP => self.slice_icmp6().map_err(Len),
                _ => {
                    self.result.payload = PayloadSlice::Ip(payload);
                    Ok(self.result)
                }
            }
        }
    }

    pub fn slice_icmp4(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = Icmpv4Slice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Icmpv4(result.clone()));

        //done
        self.result.payload = PayloadSlice::Icmpv4(result.payload());
        Ok(self.result)
    }

    pub fn slice_icmp6(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = Icmpv6Slice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Icmpv6(result.clone()));

        //done
        self.result.payload = PayloadSlice::Icmpv6(result.payload());
        Ok(self.result)
    }

    pub fn slice_udp(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = UdpHeaderSlice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Udp(result));

        // done
        self.result.payload = PayloadSlice::Udp(self.slice);
        Ok(self.result)
    }

    pub fn slice_tcp(mut self) -> Result<SlicedPacket<'a>, err::tcp::HeaderSliceError> {
        use crate::TransportSlice::*;

        let result = TcpHeaderSlice::from_slice(self.slice).map_err(|mut err| {
            use err::tcp::HeaderSliceError::Len;
            if let Len(err) = &mut err {
                err.layer_start_offset += self.offset;
                if LenSource::Slice == err.len_source {
                    err.len_source = self.len_source;
                }
            }
            err
        })?;

        //set the new data
        self.move_by_slice(result.slice());
        self.result.transport = Some(Tcp(result));

        //done
        self.result.payload = PayloadSlice::Tcp(self.slice);
        Ok(self.result)
    }
}
