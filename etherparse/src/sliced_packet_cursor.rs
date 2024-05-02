use crate::*;

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
                net: None,
                transport: None,
            },
        }
    }

    fn move_by(&mut self, len: usize) {
        unsafe {
            use core::slice::from_raw_parts;
            self.slice = from_raw_parts(self.slice.as_ptr().add(len), self.slice.len() - len);
        }
        self.offset += len;
    }

    pub fn slice_ethernet2(mut self) -> Result<SlicedPacket<'a>, err::packet::SliceError> {
        use err::packet::SliceError::*;
        use ether_type::*;
        use LinkSlice::*;

        let result = Ethernet2Slice::from_slice_without_fcs(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;

        //cache the ether_type for later
        let ether_type = result.ether_type();

        //set the new data
        self.move_by(result.header_len());
        self.result.link = Some(Ethernet2(result));

        //continue parsing (if required)
        match ether_type {
            IPV4 => self.slice_ipv4(),
            IPV6 => self.slice_ipv6(),
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => self.slice_vlan(),
            _ => Ok(self.result),
        }
    }

    pub fn slice_linux_sll(mut self) -> Result<SlicedPacket<'a>, err::packet::SliceError> {
        use err::packet::SliceError::*;

        let result = LinuxSllSlice::from_slice(self.slice).map_err(|err| match err {
            err::linux_sll::HeaderSliceError::Len(len) => Len(len.add_offset(self.offset)),
            err::linux_sll::HeaderSliceError::Content(content) => {
                err::packet::SliceError::LinuxSll(content)
            }
        })?;

        //cache the protocol type for later
        let protocol_type = result.protocol_type();

        //set the new data
        self.move_by(result.header_len());
        self.result.link = Some(LinkSlice::LinuxSll(result));

        //continue parsing (if required)
        match protocol_type {
            LinuxSllProtocolType::EtherType(EtherType::IPV4) => self.slice_ipv4(),
            LinuxSllProtocolType::EtherType(EtherType::IPV6) => self.slice_ipv6(),
            _ => Ok(self.result),
        }
    }

    pub fn slice_vlan(mut self) -> Result<SlicedPacket<'a>, err::packet::SliceError> {
        use err::packet::SliceError::*;
        use ether_type::*;
        use VlanSlice::*;

        // cache the starting slice so the later combining
        // of outer & inner vlan is defined behavior (for miri)
        let outer_start_slice = self.slice;
        let outer = SingleVlanSlice::from_slice(self.slice)
            .map_err(|err| Len(err.add_offset(self.offset)))?;
        self.result.vlan = Some(SingleVlan(outer.clone()));
        self.move_by(outer.header_len());

        //check if it is a double vlan header
        match outer.ether_type() {
            //in case of a double vlan header continue with the inner
            VLAN_TAGGED_FRAME | PROVIDER_BRIDGING | VLAN_DOUBLE_TAGGED_FRAME => {
                let inner = SingleVlanSlice::from_slice(self.slice)
                    .map_err(|err| Len(err.add_offset(self.offset)))?;
                self.move_by(inner.header_len());

                let inner_ether_type = inner.ether_type();
                self.result.vlan = Some(DoubleVlan(DoubleVlanSlice {
                    slice: outer_start_slice,
                }));

                match inner_ether_type {
                    IPV4 => self.slice_ipv4(),
                    IPV6 => self.slice_ipv6(),
                    _ => Ok(self.result),
                }
            }
            IPV4 => self.slice_ipv4(),
            IPV6 => self.slice_ipv6(),
            _ => Ok(self.result),
        }
    }

    pub fn slice_ip(mut self) -> Result<SlicedPacket<'a>, err::packet::SliceError> {
        use err::packet::SliceError::*;

        // slice header, extension headers and identify payload range
        let ip = IpSlice::from_slice(self.slice).map_err(|err| {
            use err::ip::SliceError as I;
            match err {
                I::Len(mut err) => {
                    err.layer_start_offset += self.offset;
                    Len(err)
                }
                I::IpHeaders(err) => match err {
                    err::ip::HeadersError::Ip(err) => Ip(err),
                    err::ip::HeadersError::Ipv4Ext(err) => Ipv4Exts(err),
                    err::ip::HeadersError::Ipv6Ext(err) => Ipv6Exts(err),
                },
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
        self.result.net = Some(ip.into());

        // continue to the lower layers
        if payload.fragmented {
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
                _ => Ok(self.result),
            }
        }
    }

    pub fn slice_ipv4(mut self) -> Result<SlicedPacket<'a>, err::packet::SliceError> {
        use err::packet::SliceError::*;

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
        self.result.net = Some(NetSlice::Ipv4(ipv4));

        if payload.fragmented {
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
                _ => Ok(self.result),
            }
        }
    }

    pub fn slice_ipv6(mut self) -> Result<SlicedPacket<'a>, err::packet::SliceError> {
        use err::packet::SliceError::*;

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
        self.result.net = Some(NetSlice::Ipv6(ipv6));

        // only try to decode the transport layer if the payload
        // is not fragmented
        if payload.fragmented {
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
                _ => Ok(self.result),
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
        self.move_by(result.slice().len());
        self.result.transport = Some(Icmpv4(result.clone()));

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
        self.move_by(result.slice().len());
        self.result.transport = Some(Icmpv6(result.clone()));

        //done
        Ok(self.result)
    }

    pub fn slice_udp(mut self) -> Result<SlicedPacket<'a>, err::LenError> {
        use crate::TransportSlice::*;

        let result = UdpSlice::from_slice(self.slice).map_err(|mut err| {
            err.layer_start_offset += self.offset;
            if LenSource::Slice == err.len_source {
                err.len_source = self.len_source;
            }
            err
        })?;

        //set the new data
        self.move_by(result.slice().len());
        self.result.transport = Some(Udp(result));

        // done
        Ok(self.result)
    }

    pub fn slice_tcp(mut self) -> Result<SlicedPacket<'a>, err::tcp::HeaderSliceError> {
        use crate::TransportSlice::*;

        let result = TcpSlice::from_slice(self.slice).map_err(|mut err| {
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
        self.move_by(result.slice().len());
        self.result.transport = Some(Tcp(result));

        // done
        Ok(self.result)
    }
}
